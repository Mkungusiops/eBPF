// Package logging configures the engine's slog handler and bridges
// the stdlib `log` package onto it.
//
// The default text format is human-readable for `make fake` / dev work;
// production deployments should set format=json so journald → Vector
// → Loki/Elastic can index structured fields. Either format goes to
// stdout (systemd captures it via StandardOutput=journal).
//
// Calling Setup() returns a configured *slog.Logger AND installs it
// as both slog.Default() and the destination of the stdlib log package.
// That last bit means existing log.Printf("...") calls in the engine
// keep working but emit structured records — no per-call migration
// required for non-critical lines.
package logging

import (
	"log"
	"log/slog"
	"os"
	"strings"
)

// Setup builds a slog.Logger with the requested format and level, sets
// it as the process default, and rewires the stdlib log package's
// output through it. Subsequent log.Printf / log.Fatalf calls emit
// structured records too.
//
// format: "json" | "text" (default text on empty input).
// level:  "debug" | "info" | "warn" | "error" (default info).
func Setup(format, level string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(level)}
	var h slog.Handler
	switch strings.ToLower(format) {
	case "json":
		h = slog.NewJSONHandler(os.Stdout, opts)
	default:
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	logger := slog.New(h).With(slog.String("service", "ebpf-engine"))
	slog.SetDefault(logger)

	// Bridge stdlib log -> slog at INFO. log.Fatalf still calls os.Exit(1)
	// after the line is written; slog records it first.
	log.SetFlags(0)
	log.SetOutput(slogWriter{logger: logger})
	return logger
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

// slogWriter adapts io.Writer-shaped log.Output calls onto slog. Used
// only as the destination for the stdlib log package; not recommended
// for new code (use slog directly with structured attributes instead).
type slogWriter struct{ logger *slog.Logger }

func (w slogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	// Heuristic level extraction: existing engine code prefixes lines
	// like "[ALERT critical] …" or "[gateway] …" — surface those as
	// the slog "component" attribute so JSON consumers can filter.
	component := ""
	if strings.HasPrefix(msg, "[") {
		if i := strings.Index(msg, "]"); i > 0 {
			component = msg[1:i]
			msg = strings.TrimSpace(msg[i+1:])
			if strings.HasPrefix(msg, ":") {
				msg = strings.TrimSpace(msg[1:])
			}
		}
	}
	if component != "" {
		w.logger.Info(msg, slog.String("component", component))
	} else {
		w.logger.Info(msg)
	}
	return len(p), nil
}

// RedactDSN masks the password in a database DSN so it can be logged.
//
// Shared rather than copied: cmd/engine and cmd/agent each carried an identical
// private version, and a redaction helper that drifts between two binaries is a
// credential-in-logs bug waiting to happen in whichever copy nobody re-reads.
func RedactDSN(dsn string) string {
	at := strings.LastIndex(dsn, "@")
	if at < 0 {
		return dsn
	}
	scheme := strings.Index(dsn, "://")
	if scheme < 0 || scheme >= at {
		return dsn
	}
	colon := strings.Index(dsn[scheme+3:at], ":")
	if colon < 0 {
		return dsn
	}
	return dsn[:scheme+3+colon+1] + "***" + dsn[at:]
}
