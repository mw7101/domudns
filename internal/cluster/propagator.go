package cluster

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// defaultPushRetryBackoff is the delay before each push attempt; index 0 is the
// first attempt (no delay). A large blocklist URL (100k+ domains) takes several
// seconds to clean and gzip on a Raspberry Pi, so the former 5s-only single
// attempt produced spurious "context deadline exceeded" warnings; the timeout is
// now 30s and transient failures get one or two retries.
var defaultPushRetryBackoff = []time.Duration{0, 2 * time.Second, 5 * time.Second}

// Propagator pusht Sync-Events von Master an alle Slaves.
type Propagator struct {
	slaves       []string
	secret       string
	pushTimeout  time.Duration
	client       *http.Client
	retryBackoff []time.Duration
}

// NewPropagator erstellt einen neuen Propagator.
func NewPropagator(slaves []string, secret string, pushTimeout time.Duration) *Propagator {
	if pushTimeout <= 0 {
		// 30s tolerates a large url_domains write (clean + gzip + fsync) on a Pi 3B.
		pushTimeout = 30 * time.Second
	}
	return &Propagator{
		slaves:       slaves,
		secret:       secret,
		pushTimeout:  pushTimeout,
		client:       &http.Client{Timeout: pushTimeout},
		retryBackoff: defaultPushRetryBackoff,
	}
}

// Push sendet ein Sync-Event an alle Slaves (concurrent, best-effort).
// Fehler werden geloggt, aber der Push wird nicht wiederholt.
func (p *Propagator) Push(eventType SyncEventType, data interface{}) {
	if len(p.slaves) == 0 {
		return
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		log.Warn().Err(err).Str("event", string(eventType)).Msg("cluster: marshal sync data failed")
		return
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		log.Warn().Err(err).Msg("cluster: generate nonce failed")
		return
	}
	nonce := hex.EncodeToString(nonceBytes)
	timestamp := time.Now().UnixNano()
	req := SyncRequest{
		Type:      eventType,
		Data:      json.RawMessage(dataBytes),
		Timestamp: timestamp,
		Nonce:     nonce,
	}
	body, err := json.Marshal(req)
	if err != nil {
		log.Warn().Err(err).Msg("cluster: marshal sync request failed")
		return
	}
	hmacValue := computeHMAC(p.secret, eventType, timestamp, nonce, dataBytes)

	var wg sync.WaitGroup
	for _, slave := range p.slaves {
		slave := slave
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.pushToSlave(slave, body, hmacValue); err != nil {
				log.Warn().
					Err(err).
					Str("slave", slave).
					Str("event", string(eventType)).
					Msg("cluster: push to slave failed")
			} else {
				log.Debug().
					Str("slave", slave).
					Str("event", string(eventType)).
					Msg("cluster: pushed to slave")
			}
		}()
	}
	wg.Wait()
}

// PushAsync sendet ein Sync-Event asynchron (non-blocking).
func (p *Propagator) PushAsync(eventType SyncEventType, data interface{}) {
	go p.Push(eventType, data)
}

// pushToSlave sends one HTTP POST to a single slave, retrying transient
// failures (transport errors, 5xx) with a short backoff.
func (p *Propagator) pushToSlave(slaveURL string, body []byte, hmacValue string) error {
	backoff := p.retryBackoff
	if len(backoff) == 0 {
		backoff = []time.Duration{0}
	}

	var lastErr error
	for attempt, delay := range backoff {
		if delay > 0 {
			time.Sleep(delay)
		}
		retryable, err := p.postToSlave(slaveURL, body, hmacValue)
		if err == nil {
			if attempt > 0 {
				log.Info().Str("slave", slaveURL).Int("attempts", attempt+1).Msg("cluster: push to slave succeeded after retry")
			}
			return nil
		}
		lastErr = err
		if !retryable {
			return err
		}
		log.Debug().Err(err).Str("slave", slaveURL).Int("attempt", attempt+1).Msg("cluster: push attempt failed, retrying")
	}
	return lastErr
}

// postToSlave performs a single POST. retryable reports whether another attempt
// may help: transport errors and 5xx are retryable, other status codes are not.
func (p *Propagator) postToSlave(slaveURL string, body []byte, hmacValue string) (retryable bool, err error) {
	url := slaveURL + "/api/internal/sync"
	ctx, cancel := context.WithTimeout(context.Background(), p.pushTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Sync-HMAC", hmacValue)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return true, fmt.Errorf("http post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return false, nil
	}
	return resp.StatusCode >= 500, fmt.Errorf("slave returned %d", resp.StatusCode)
}
