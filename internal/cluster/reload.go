package cluster

import (
	"sync"

	"github.com/rs/zerolog/log"
)

// WithSharedReloadScheduler returns a copy of c whose reload callbacks are
// serialized and coalesced per kind across every path that uses the returned
// value — the slave poll loop and the push receiver share one scheduler, so a
// poll-driven reload and a push-driven reload of the same kind never overlap.
//
// Call this exactly once, when building the ReloadCallbacks that is handed to
// both paths (see cmd/domudns). Without it, trigger falls back to the original
// fire-and-forget goroutine per call.
func (c ReloadCallbacks) WithSharedReloadScheduler() ReloadCallbacks {
	c.scheduler = &reloadScheduler{}
	return c
}

// trigger schedules callback under name when changed is true and callback is
// non-nil. With a shared scheduler (WithSharedReloadScheduler) same-kind
// callbacks are serialized and coalesced; otherwise it preserves the original
// behaviour of one goroutine per call.
func (c ReloadCallbacks) trigger(changed bool, callback func() error, name string) {
	if c.scheduler != nil {
		c.scheduler.trigger(changed, callback, name)
		return
	}
	if !changed || callback == nil {
		return
	}
	go func() {
		if err := callback(); err != nil {
			log.Warn().Err(err).Msgf("cluster: %s reload failed", name)
		}
	}()
}

// reloadScheduler serializes reload callbacks by name.
//
// At most one callback of a given kind ("zone", "blocklist", …) runs at a time.
// A trigger that arrives while a callback of the same kind is already running
// does not start a second concurrent run; instead it schedules exactly one
// follow-up run for when the current one finishes (coalescing). This prevents
// redundant concurrent work — reloading zones or blocklists twice in parallel
// on a 1 GB Raspberry Pi — while still guaranteeing that the newest state is
// loaded: the follow-up run reads the store after the update has been written.
//
// Different kinds are independent and may run concurrently.
//
// The zero value is ready to use and safe for concurrent use.
type reloadScheduler struct {
	mu      sync.Mutex
	runners map[string]*reloadRunner
}

// trigger schedules callback under name when changed is true and callback is
// non-nil. It returns immediately; the callback runs in a goroutine.
func (s *reloadScheduler) trigger(changed bool, callback func() error, name string) {
	if !changed || callback == nil {
		return
	}

	s.mu.Lock()
	if s.runners == nil {
		s.runners = make(map[string]*reloadRunner)
	}
	r := s.runners[name]
	if r == nil {
		r = &reloadRunner{}
		s.runners[name] = r
	}
	s.mu.Unlock()

	r.trigger(callback, name)
}

// reloadRunner runs a single kind of callback sequentially with coalescing.
type reloadRunner struct {
	mu       sync.Mutex
	running  bool
	pending  bool
	callback func() error
	name     string
}

// trigger starts the runner if idle, otherwise marks a follow-up run. The
// stored callback/name are refreshed so a pending run uses the latest values.
func (r *reloadRunner) trigger(callback func() error, name string) {
	r.mu.Lock()
	r.callback = callback
	r.name = name
	if r.running {
		r.pending = true
		r.mu.Unlock()
		return
	}
	r.running = true
	r.mu.Unlock()

	go r.loop()
}

// loop runs the callback until no follow-up was requested while it ran.
func (r *reloadRunner) loop() {
	for {
		r.mu.Lock()
		callback := r.callback
		name := r.name
		r.mu.Unlock()

		if err := callback(); err != nil {
			log.Warn().Err(err).Msgf("cluster: %s reload after poll failed", name)
		}

		r.mu.Lock()
		if !r.pending {
			r.running = false
			r.mu.Unlock()
			return
		}
		r.pending = false
		r.mu.Unlock()
	}
}
