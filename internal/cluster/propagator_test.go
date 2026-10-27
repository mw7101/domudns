package cluster

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewPropagator_DefaultTimeout(t *testing.T) {
	p := NewPropagator(nil, "", 0)
	if p.pushTimeout != 30*time.Second {
		t.Fatalf("default push timeout = %v, want 30s", p.pushTimeout)
	}
	if p.client == nil || p.client.Timeout != 30*time.Second {
		t.Fatalf("http client timeout = %v, want 30s", p.client.Timeout)
	}
}

func TestNewPropagator_ExplicitTimeoutKept(t *testing.T) {
	p := NewPropagator(nil, "", 7*time.Second)
	if p.pushTimeout != 7*time.Second {
		t.Fatalf("push timeout = %v, want 7s", p.pushTimeout)
	}
}

// TestPropagator_PushRetriesTransientFailure verifies that 5xx responses are
// retried and a later success is reported as success.
func TestPropagator_PushRetriesTransientFailure(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	p := NewPropagator([]string{srv.URL}, "secret", time.Second)
	p.retryBackoff = []time.Duration{0, time.Millisecond, time.Millisecond}

	if err := p.pushToSlave(srv.URL, []byte(`{}`), "hmac"); err != nil {
		t.Fatalf("pushToSlave after transient failures: %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}

// TestPropagator_NoRetryOn4xx verifies that a terminal status is not retried.
func TestPropagator_NoRetryOn4xx(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := NewPropagator([]string{srv.URL}, "secret", time.Second)
	p.retryBackoff = []time.Duration{0, time.Millisecond, time.Millisecond}

	if err := p.pushToSlave(srv.URL, []byte(`{}`), "hmac"); err == nil {
		t.Fatal("expected an error on 401")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("4xx must not be retried, attempts = %d", got)
	}
}

// TestPropagator_PushSucceedsFirstTry verifies the happy path does one attempt.
func TestPropagator_PushSucceedsFirstTry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	p := NewPropagator([]string{srv.URL}, "secret", time.Second)
	p.retryBackoff = []time.Duration{0, time.Millisecond}

	if err := p.pushToSlave(srv.URL, []byte(`{}`), "hmac"); err != nil {
		t.Fatalf("pushToSlave: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected 1 attempt, got %d", got)
	}
}

// TestPropagator_RetryExhaustedReturnsError verifies the last error surfaces
// after all attempts are used.
func TestPropagator_RetryExhaustedReturnsError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	p := NewPropagator([]string{srv.URL}, "secret", time.Second)
	p.retryBackoff = []time.Duration{0, time.Millisecond, time.Millisecond}

	if err := p.pushToSlave(srv.URL, []byte(`{}`), "hmac"); err == nil {
		t.Fatal("expected an error after exhausting retries")
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}
