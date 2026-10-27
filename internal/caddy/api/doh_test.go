package api

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"
)

// mockDNSHandler is a simple dns.Handler mock for tests.
// It responds to all requests with an empty NOERROR answer.
type mockDNSHandler struct {
	// respondFn can optionally be set to provide custom responses.
	respondFn func(w dns.ResponseWriter, r *dns.Msg)
}

func (m *mockDNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if m.respondFn != nil {
		m.respondFn(w, r)
		return
	}
	// Default: empty NOERROR response
	resp := new(dns.Msg)
	resp.SetReply(r)
	_ = w.WriteMsg(resp)
}

// buildDNSQuery creates a DNS A query for the given domain in wire format.
func buildDNSQuery(t *testing.T, domain string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack DNS query: %v", err)
	}
	return b
}

func TestDoHHandler_GET(t *testing.T) {
	handler := &mockDNSHandler{}
	doh := NewDoHHandler(handler, "/dns-query")
	wire := buildDNSQuery(t, "google.com")

	tests := []struct {
		name       string
		dnsParam   string
		wantStatus int
	}{
		{
			name:       "valid base64url query without padding",
			dnsParam:   base64.RawURLEncoding.EncodeToString(wire),
			wantStatus: http.StatusOK,
		},
		{
			name:       "valid base64url query with padding",
			dnsParam:   base64.URLEncoding.EncodeToString(wire),
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing dns parameter",
			dnsParam:   "",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid base64 string",
			dnsParam:   "!!!nicht-base64!!!",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "too short DNS message (incomplete)",
			dnsParam:   base64.RawURLEncoding.EncodeToString([]byte{0x00}),
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/dns-query"
			if tt.dnsParam != "" {
				url += "?dns=" + tt.dnsParam
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			w := httptest.NewRecorder()
			doh.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.wantStatus == http.StatusOK {
				if ct := w.Header().Get("Content-Type"); ct != dohContentType {
					t.Errorf("Content-Type = %q, want %q", ct, dohContentType)
				}
				// Response must be parseable
				resp := new(dns.Msg)
				if err := resp.Unpack(w.Body.Bytes()); err != nil {
					t.Errorf("response not valid DNS wire format: %v", err)
				}
			}
		})
	}
}

func TestDoHHandler_POST(t *testing.T) {
	handler := &mockDNSHandler{}
	doh := NewDoHHandler(handler, "/dns-query")
	wire := buildDNSQuery(t, "example.com")

	tests := []struct {
		name        string
		body        []byte
		contentType string
		wantStatus  int
	}{
		{
			name:        "valid POST request",
			body:        wire,
			contentType: "application/dns-message",
			wantStatus:  http.StatusOK,
		},
		{
			name:        "valid POST without Content-Type",
			body:        wire,
			contentType: "",
			wantStatus:  http.StatusOK,
		},
		{
			name:        "wrong Content-Type",
			body:        wire,
			contentType: "application/json",
			wantStatus:  http.StatusUnsupportedMediaType,
		},
		{
			name:        "empty body",
			body:        []byte{},
			contentType: "application/dns-message",
			wantStatus:  http.StatusBadRequest,
		},
		{
			name:        "invalid DNS message in body",
			body:        []byte{0xDE, 0xAD, 0xBE, 0xEF},
			contentType: "application/dns-message",
			wantStatus:  http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(tt.body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			w := httptest.NewRecorder()
			doh.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.wantStatus == http.StatusOK {
				if ct := w.Header().Get("Content-Type"); ct != dohContentType {
					t.Errorf("Content-Type = %q, want %q", ct, dohContentType)
				}
			}
		})
	}
}

func TestDoHHandler_MethodNotAllowed(t *testing.T) {
	doh := NewDoHHandler(&mockDNSHandler{}, "/dns-query")

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/dns-query", nil)
			w := httptest.NewRecorder()
			doh.ServeHTTP(w, req)
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func TestDoHHandler_ResponseContent(t *testing.T) {
	// Handler with custom response
	handler := &mockDNSHandler{
		respondFn: func(w dns.ResponseWriter, r *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(r)
			rr, _ := dns.NewRR("google.com. 300 IN A 1.2.3.4")
			resp.Answer = append(resp.Answer, rr)
			_ = w.WriteMsg(resp)
		},
	}
	doh := NewDoHHandler(handler, "/dns-query")

	wire := buildDNSQuery(t, "google.com")
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(wire))
	req.Header.Set("Content-Type", dohContentType)
	w := httptest.NewRecorder()
	doh.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	// Parse response and check A record
	resp := new(dns.Msg)
	if err := resp.Unpack(w.Body.Bytes()); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer[0] is %T, want *dns.A", resp.Answer[0])
	}
	if a.A.String() != "1.2.3.4" {
		t.Errorf("A record = %s, want 1.2.3.4", a.A.String())
	}

	// Check Cache-Control header (TTL 300 → max-age=300)
	cc := w.Header().Get("Cache-Control")
	if cc != "max-age=300" {
		t.Errorf("Cache-Control = %q, want %q", cc, "max-age=300")
	}
}

func TestDoHHandler_ClientIPExtraction(t *testing.T) {
	var capturedRemoteAddr string
	handler := &mockDNSHandler{
		respondFn: func(w dns.ResponseWriter, r *dns.Msg) {
			capturedRemoteAddr = w.RemoteAddr().String()
			resp := new(dns.Msg)
			resp.SetReply(r)
			_ = w.WriteMsg(resp)
		},
	}
	doh := NewDoHHandler(handler, "/dns-query")
	wire := buildDNSQuery(t, "test.example.com")

	tests := []struct {
		name       string
		header     string
		value      string
		wantIPPart string
	}{
		{
			name:       "X-Real-IP",
			header:     "X-Real-IP",
			value:      "192.168.1.100",
			wantIPPart: "192.168.1.100",
		},
		{
			name:       "X-Forwarded-For",
			header:     "X-Forwarded-For",
			value:      "10.0.0.1, 172.16.0.1",
			wantIPPart: "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(wire))
			req.Header.Set("Content-Type", dohContentType)
			req.Header.Set(tt.header, tt.value)
			w := httptest.NewRecorder()
			doh.ServeHTTP(w, req)

			if !bytes.Contains([]byte(capturedRemoteAddr), []byte(tt.wantIPPart)) {
				t.Errorf("remoteAddr = %q, want to contain %q", capturedRemoteAddr, tt.wantIPPart)
			}
		})
	}
}

func TestMinTTL(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeA)
	rr1, _ := dns.NewRR("google.com. 300 IN A 1.2.3.4")
	rr2, _ := dns.NewRR("google.com. 120 IN A 5.6.7.8")
	msg.Answer = []dns.RR{rr1, rr2}

	if got := minTTL(msg); got != 120 {
		t.Errorf("minTTL = %d, want 120", got)
	}
}

func TestMinTTL_Empty(t *testing.T) {
	msg := new(dns.Msg)
	if got := minTTL(msg); got != 0 {
		t.Errorf("minTTL (empty) = %d, want 0", got)
	}
}
