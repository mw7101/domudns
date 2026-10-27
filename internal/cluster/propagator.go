package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Propagator pusht Sync-Events von Master an alle Slaves.
type Propagator struct {
	slaves      []string
	secret      string
	pushTimeout time.Duration
	client      *http.Client
}

// NewPropagator erstellt einen neuen Propagator.
func NewPropagator(slaves []string, secret string, pushTimeout time.Duration) *Propagator {
	if pushTimeout <= 0 {
		pushTimeout = 5 * time.Second
	}
	return &Propagator{
		slaves:      slaves,
		secret:      secret,
		pushTimeout: pushTimeout,
		client: &http.Client{
			Timeout: pushTimeout,
		},
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
	req := SyncRequest{
		Type: eventType,
		Data: json.RawMessage(dataBytes),
	}
	body, err := json.Marshal(req)
	if err != nil {
		log.Warn().Err(err).Msg("cluster: marshal sync request failed")
		return
	}
	hmacValue := computeHMAC(p.secret, eventType, dataBytes)

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

// pushToSlave sendet einen HTTP-POST an einen einzelnen Slave.
func (p *Propagator) pushToSlave(slaveURL string, body []byte, hmacValue string) error {
	url := slaveURL + "/api/internal/sync"
	ctx, cancel := context.WithTimeout(context.Background(), p.pushTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Sync-HMAC", hmacValue)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("slave returned %d", resp.StatusCode)
	}
	return nil
}
