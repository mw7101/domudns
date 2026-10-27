package api

import (
	"context"
	"time"

	"github.com/mw7101/domudns/internal/blocklist"
	"github.com/rs/zerolog/log"
)

// regenDebounceLoop runs in background and regenerates hosts file max once per 5 seconds.
// This prevents excessive I/O when multiple blocklist changes happen in quick succession.
func (h *BlocklistHandler) regenDebounceLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	pending := false
	for {
		select {
		case <-h.regenCh:
			pending = true
		case <-ticker.C:
			if pending {
				ctx := context.Background()
				cfg := &h.cfg.Blocklist
				if err := blocklist.RegenerateHostsFile(ctx, h.store, cfg.FilePath, cfg.BlockIP4, cfg.BlockIP6); err != nil {
					log.Warn().Err(err).Msg("failed to regenerate blocklist hosts file")
				}
				pending = false
			}
		}
	}
}
