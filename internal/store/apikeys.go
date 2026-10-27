package store

import "time"

// NamedAPIKey is an API key with a human-readable name.
// The Key field is only populated on creation and for cluster sync.
// It is omitted from list responses (Key == "").
type NamedAPIKey struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Key         string    `json:"key,omitempty"` // only on creation / cluster sync
	CreatedAt   time.Time `json:"created_at"`
}
