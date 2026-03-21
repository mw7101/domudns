package blocklist

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const maxBlocklistSize = 10 * 1024 * 1024 // 10MB

// privateIPRanges lists CIDR ranges that must not be contacted via blocklist fetches (SSRF prevention).
var privateIPRanges []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // loopback
		"::1/128",        // IPv6 loopback
		"10.0.0.0/8",     // RFC-1918
		"172.16.0.0/12",  // RFC-1918
		"192.168.0.0/16", // RFC-1918
		"169.254.0.0/16", // link-local
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique-local
		"0.0.0.0/8",      // unspecified
	} {
		_, block, _ := net.ParseCIDR(cidr)
		if block != nil {
			privateIPRanges = append(privateIPRanges, block)
		}
	}
}

// isPrivateIP returns true when ip falls into a private, loopback, or link-local range.
func isPrivateIP(ip net.IP) bool {
	for _, block := range privateIPRanges {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// safeDialContext is a net.Dialer DialContext wrapper that rejects connections to private IPs.
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip != nil && isPrivateIP(ip) {
			return nil, fmt.Errorf("blocklist fetch denied: %q resolves to private IP %s", host, ipStr)
		}
	}
	return (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, network, net.JoinHostPort(host, port))
}

// FetchURL fetches blocklist content from url and returns parsed domains.
// Connections to private/loopback IPs and redirects to such addresses are blocked (SSRF prevention).
func FetchURL(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	transport := &http.Transport{
		DialContext: safeDialContext,
	}
	client := &http.Client{
		Timeout:   60 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			host := req.URL.Hostname()
			if host == "" {
				return fmt.Errorf("redirect to empty host denied")
			}
			ips, err := net.LookupHost(host)
			if err != nil {
				return fmt.Errorf("redirect resolve %q: %w", host, err)
			}
			for _, ipStr := range ips {
				ip := net.ParseIP(ipStr)
				if ip != nil && isPrivateIP(ip) {
					return fmt.Errorf("blocklist redirect denied: %q resolves to private IP %s", host, ipStr)
				}
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, maxBlocklistSize)
	content, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return ParseHostsOrDomains(string(content)), nil
}
