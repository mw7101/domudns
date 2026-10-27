package dnsserver

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// mockACMEReader is a simple in-memory ACMEChallengeReader for testing.
// Lookup is case-insensitive and trailing-dot-agnostic, matching the real FileStore.
type mockACMEReader struct {
	entries map[string]string
}

func (m *mockACMEReader) GetACMEChallenge(_ context.Context, fqdn string) (string, bool) {
	fqdn = strings.TrimSuffix(fqdn, ".")
	for k, v := range m.entries {
		if strings.EqualFold(strings.TrimSuffix(k, "."), fqdn) {
			return v, true
		}
	}
	return "", false
}

func newTestHandler() *Handler {
	// Use a non-reachable upstream so the pipeline can run without panic.
	// Tests that hit the ACME phase before upstream are not affected.
	return NewHandler([]string{"127.0.0.1:15353"}, nil, nil, nil, "0.0.0.0", "::", nil, false)
}

func newQuery(qname string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	return m
}

// Test 1: TXT query for _acme-challenge with matching entry → RcodeSuccess + TXT answer.
func TestACMEChallengeHandlerHit(t *testing.T) {
	h := newTestHandler()
	h.acme = &mockACMEReader{entries: map[string]string{
		"_acme-challenge.example.com.": "TOKEN123",
	}}

	w := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5353}}
	r := newQuery("_acme-challenge.example.com.", dns.TypeTXT)

	h.ServeDNS(w, r)

	if w.written == nil {
		t.Fatal("expected response, got nil")
	}
	if w.written.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %d", w.written.Rcode)
	}
	if len(w.written.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(w.written.Answer))
	}
	txt, ok := w.written.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatal("expected TXT record")
	}
	if len(txt.Txt) != 1 || txt.Txt[0] != "TOKEN123" {
		t.Fatalf("expected TXT value 'TOKEN123', got %v", txt.Txt)
	}
}

// Test 2: TXT query for unknown _acme-challenge → handler falls through (no authoritative answer set,
// response is not set by phase 2.9, so w.written == nil or pipeline continues).
func TestACMEChallengeHandlerMiss(t *testing.T) {
	h := newTestHandler()
	h.acme = &mockACMEReader{entries: map[string]string{}}

	w := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5353}}
	r := newQuery("_acme-challenge.unknown.com.", dns.TypeTXT)

	h.ServeDNS(w, r)

	// Phase 2.9 did not respond (miss), pipeline continues.
	// With no forwarder, no zones, and no cache the handler will not write a valid response
	// but it should NOT write an ACME TXT answer.
	if w.written != nil {
		for _, rr := range w.written.Answer {
			if _, ok := rr.(*dns.TXT); ok {
				if len(w.written.Answer) > 0 {
					t.Fatal("expected no TXT answer from ACME phase, but got one")
				}
			}
		}
	}
}

// Test: TXT query with mixed-case name (e.g. _acME-challenge.*) → phase 2.9 still matches.
// miekg/dns preserves the original case from the wire; the HasPrefix check must be case-insensitive.
// Regression test for: https://letsencrypt.org validators sending mixed-case _acme-challenge names.
func TestACMEChallengeHandlerMixedCase(t *testing.T) {
	h := newTestHandler()
	h.acme = &mockACMEReader{entries: map[string]string{
		"_acme-challenge.example.com.": "TOKEN123",
	}}

	w := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5353}}
	// Simulate Let's Encrypt validator sending mixed-case query name (as seen in Fritzbox logs)
	r := newQuery("_acME-challenge.example.com.", dns.TypeTXT)

	h.ServeDNS(w, r)

	if w.written == nil {
		t.Fatal("expected response, got nil")
	}
	if w.written.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR for mixed-case query, got rcode %d", w.written.Rcode)
	}
	if len(w.written.Answer) != 1 {
		t.Fatalf("expected 1 TXT answer for mixed-case query, got %d", len(w.written.Answer))
	}
	txt, ok := w.written.Answer[0].(*dns.TXT)
	if !ok || txt.Txt[0] != "TOKEN123" {
		t.Fatalf("expected TXT value 'TOKEN123', got %v", w.written.Answer)
	}
}

// Test 3: A query on _acme-challenge.* (qtype ≠ TXT) → phase 2.9 is skipped.
func TestACMEChallengeHandlerWrongQtype(t *testing.T) {
	h := newTestHandler()
	h.acme = &mockACMEReader{entries: map[string]string{
		"_acme-challenge.example.com.": "TOKEN123",
	}}

	w := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5353}}
	r := newQuery("_acme-challenge.example.com.", dns.TypeA)

	h.ServeDNS(w, r)

	// ACME phase must not fire for A queries — no TXT answer expected
	if w.written != nil {
		for _, rr := range w.written.Answer {
			if _, ok := rr.(*dns.TXT); ok {
				t.Fatal("ACME phase must not respond to A queries")
			}
		}
	}
}
