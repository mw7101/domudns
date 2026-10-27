package dnsserver

import "github.com/mw7101/domudns/pkg/logger"

// ConfigUpdate contains optional fields for ApplyConfig. Nil fields are no-ops.
type ConfigUpdate struct {
	Upstream            []string
	ConditionalForwards []ConditionalForwardRule
	RebindingEnabled    *bool
	RebindingWhitelist  []string
	BlockMode           *string
	LogLevel            *string
}

// ApplyConfig applies all non-nil config fields atomically under s.mu.
// Replaces the 5 separate Update* calls in the configReloader that had a race
// window between them.
func (s *Server) ApplyConfig(u ConfigUpdate) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if u.Upstream != nil {
		s.handler.forwarder.UpdateUpstream(u.Upstream)
	}
	if u.ConditionalForwards != nil {
		if s.handler.conditionalForwarder == nil {
			s.handler.conditionalForwarder = NewConditionalForwarder(u.ConditionalForwards)
		} else {
			s.handler.conditionalForwarder.UpdateRules(u.ConditionalForwards)
		}
	}
	if u.RebindingEnabled != nil {
		if s.handler.rebinding != nil {
			s.handler.rebinding.Update(*u.RebindingEnabled, u.RebindingWhitelist)
		}
	}
	if u.BlockMode != nil {
		mode := *u.BlockMode
		if mode != "nxdomain" {
			mode = "zero_ip"
		}
		s.handler.blockMode.Store(mode)
	}
	if u.LogLevel != nil {
		logger.SetLevel(*u.LogLevel)
	}
}
