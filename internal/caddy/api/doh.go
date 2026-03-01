package api

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

const (
	dohContentType = "application/dns-message"
	// dohMaxBodySize is the maximum DNS message size per RFC 8484 (64 KB).
	dohMaxBodySize = 65535
)

// DoHHandler implements DNS over HTTPS per RFC 8484.
// Supports GET (?dns=<base64url>) and POST (application/dns-message).
// The endpoint is public (no auth), analogous to port 53 UDP/TCP.
type DoHHandler struct {
	handler dns.Handler
	path    string
}

// NewDoHHandler creates a DoH handler.
// handler is a dns.Handler (e.g. dnsserver.Server.GetHandler()).
// path is the HTTP path (e.g. "/dns-query").
func NewDoHHandler(handler dns.Handler, path string) *DoHHandler {
	if path == "" {
		path = "/dns-query"
	}
	return &DoHHandler{
		handler: handler,
		path:    path,
	}
}

// ServeHTTP implements http.Handler.
func (h *DoHHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var wireQuery []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		wireQuery, err = h.decodeGET(r)
		if err != nil {
			log.Debug().Err(err).Msg("doh: invalid GET query")
			http.Error(w, "Bad Request: "+err.Error(), http.StatusBadRequest)
			return
		}

	case http.MethodPost:
		ct := r.Header.Get("Content-Type")
		// Only check Content-Type if provided; some clients omit it.
		if ct != "" && !strings.HasPrefix(ct, dohContentType) {
			http.Error(w, "Unsupported Media Type: expected application/dns-message", http.StatusUnsupportedMediaType)
			return
		}
		wireQuery, err = h.decodePOST(r)
		if err != nil {
			log.Debug().Err(err).Msg("doh: invalid POST body")
			http.Error(w, "Bad Request: "+err.Error(), http.StatusBadRequest)
			return
		}

	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse DNS message
	query := new(dns.Msg)
	if err := query.Unpack(wireQuery); err != nil {
		log.Debug().Err(err).Msg("doh: failed to unpack DNS message")
		http.Error(w, "Bad Request: invalid DNS message", http.StatusBadRequest)
		return
	}

	// Determine client IP for query logging
	clientAddr := dohClientAddr(r)

	// Intercept response via httpDNSWriter
	rw := &httpDNSWriter{
		remoteAddr: clientAddr,
		localAddr:  &net.TCPAddr{IP: net.IPv4zero, Port: 443},
	}

	h.handler.ServeDNS(rw, query)

	if rw.msg == nil {
		// No WriteMsg called — send SERVFAIL
		resp := new(dns.Msg)
		resp.SetRcode(query, dns.RcodeServerFailure)
		rw.msg = resp
	}

	// Encode DNS response in wire format
	wireResp, err := rw.msg.Pack()
	if err != nil {
		log.Error().Err(err).Msg("doh: failed to pack DNS response")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Cache-Control: min(TTL) of all response RRs; at least 0
	maxAge := minTTL(rw.msg)

	w.Header().Set("Content-Type", dohContentType)
	if maxAge > 0 {
		w.Header().Set("Cache-Control", "max-age="+itoa(maxAge))
	} else {
		w.Header().Set("Cache-Control", "no-cache, no-store")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(wireResp)
}

// decodeGET decodes the base64url-encoded ?dns= parameter (RFC 8484 §4.1).
func (h *DoHHandler) decodeGET(r *http.Request) ([]byte, error) {
	param := r.URL.Query().Get("dns")
	if param == "" {
		return nil, errorf("missing 'dns' query parameter")
	}
	// RFC 8484: base64url without padding
	b, err := base64.RawURLEncoding.DecodeString(param)
	if err != nil {
		// Fallback: try with padding (some clients send it anyway)
		b, err = base64.URLEncoding.DecodeString(param)
		if err != nil {
			return nil, errorf("invalid base64url encoding")
		}
	}
	if len(b) > dohMaxBodySize {
		return nil, errorf("DNS message too large")
	}
	return b, nil
}

// decodePOST reads the POST body (DNS wire format).
func (h *DoHHandler) decodePOST(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, dohMaxBodySize+1))
	if err != nil {
		return nil, errorf("failed to read request body")
	}
	if len(body) > dohMaxBodySize {
		return nil, errorf("DNS message too large")
	}
	if len(body) == 0 {
		return nil, errorf("empty request body")
	}
	return body, nil
}

// dohClientAddr extracts the client IP from the HTTP request.
// Considers X-Real-IP and X-Forwarded-For for reverse proxy setups.
func dohClientAddr(r *http.Request) net.Addr {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed != nil {
			return &net.TCPAddr{IP: parsed, Port: 0}
		}
	}
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		// First element is the original client
		first := strings.SplitN(fwd, ",", 2)[0]
		if parsed := net.ParseIP(strings.TrimSpace(first)); parsed != nil {
			return &net.TCPAddr{IP: parsed, Port: 0}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if parsed := net.ParseIP(host); parsed != nil {
		return &net.TCPAddr{IP: parsed, Port: 0}
	}
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// minTTL returns the smallest TTL value of all RRs (for Cache-Control header).
func minTTL(msg *dns.Msg) uint32 {
	var min uint32
	first := true
	for _, rr := range append(append(msg.Answer, msg.Ns...), msg.Extra...) {
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		ttl := rr.Header().Ttl
		if first || ttl < min {
			min = ttl
			first = false
		}
	}
	return min
}

// itoa converts uint32 → string (without fmt import).
func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	buf := [10]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func errorf(msg string) error {
	return &dohError{msg: msg}
}

type dohError struct{ msg string }

func (e *dohError) Error() string { return e.msg }

// httpDNSWriter is a dns.ResponseWriter adapter for HTTP responses.
// It intercepts WriteMsg() and stores the DNS answer for later Pack()+Write().
type httpDNSWriter struct {
	remoteAddr net.Addr
	localAddr  net.Addr
	msg        *dns.Msg
}

func (w *httpDNSWriter) LocalAddr() net.Addr         { return w.localAddr }
func (w *httpDNSWriter) RemoteAddr() net.Addr        { return w.remoteAddr }
func (w *httpDNSWriter) WriteMsg(m *dns.Msg) error   { w.msg = m; return nil }
func (w *httpDNSWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *httpDNSWriter) Close() error                { return nil }
func (w *httpDNSWriter) TsigStatus() error           { return nil }
func (w *httpDNSWriter) TsigTimersOnly(_ bool)       {}
func (w *httpDNSWriter) Hijack()                     {}
