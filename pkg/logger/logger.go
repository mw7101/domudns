package logger

import (
	"io"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Config holds logger configuration.
type Config struct {
	Level  string // debug, info, warn, error
	Format string // json or text
}

// SetLevel changes the global log level at runtime.
func SetLevel(level string) {
	zerolog.SetGlobalLevel(parseLevel(level))
}

// Init configures the global zerolog logger.
func Init(cfg Config) {
	var w io.Writer = os.Stdout
	if cfg.Format == "text" {
		w = zerolog.ConsoleWriter{Out: os.Stdout}
	}

	level := parseLevel(cfg.Level)
	zerolog.SetGlobalLevel(level)
	log.Logger = zerolog.New(w).With().Timestamp().Logger()
}

func parseLevel(s string) zerolog.Level {
	switch s {
	case "debug":
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn", "warning":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}
