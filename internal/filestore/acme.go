package filestore

import (
	"context"
	"strings"
	"time"
)

// acmeChallenge represents an ACME DNS-01 TXT record in the file system.
type acmeChallenge struct {
	FQDN      string    `json:"fqdn"`
	Value     string    `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
}

// PutACMEChallenge stores an ACME DNS-01 challenge TXT record.
func (s *FileStore) PutACMEChallenge(_ context.Context, fqdn, value string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var challenges []acmeChallenge
	_ = readJSON(s.acmePath(), &challenges)

	// Replace existing challenge for this FQDN
	found := false
	for i := range challenges {
		if challenges[i].FQDN == fqdn {
			challenges[i].Value = value
			challenges[i].ExpiresAt = time.Now().Add(ttl)
			found = true
			break
		}
	}
	if !found {
		challenges = append(challenges, acmeChallenge{
			FQDN:      fqdn,
			Value:     value,
			ExpiresAt: time.Now().Add(ttl),
		})
	}
	return atomicWriteJSON(s.acmePath(), challenges)
}

// GetACMEChallenge returns the TXT value for a stored, non-expired ACME challenge.
// fqdn may optionally have a trailing dot (miekg/dns format).
func (s *FileStore) GetACMEChallenge(_ context.Context, fqdn string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	fqdn = strings.TrimSuffix(fqdn, ".")

	var challenges []acmeChallenge
	if err := readJSON(s.acmePath(), &challenges); err != nil {
		return "", false
	}
	for _, c := range challenges {
		if strings.EqualFold(c.FQDN, fqdn) {
			if c.ExpiresAt.After(time.Now()) {
				return c.Value, true
			}
		}
	}
	return "", false
}

// DeleteACMEChallenge removes an ACME challenge TXT record.
func (s *FileStore) DeleteACMEChallenge(_ context.Context, fqdn string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var challenges []acmeChallenge
	if err := readJSON(s.acmePath(), &challenges); err != nil {
		return err
	}
	newChallenges := make([]acmeChallenge, 0, len(challenges))
	for _, c := range challenges {
		if !strings.EqualFold(c.FQDN, fqdn) {
			newChallenges = append(newChallenges, c)
		}
	}
	return atomicWriteJSON(s.acmePath(), newChallenges)
}
