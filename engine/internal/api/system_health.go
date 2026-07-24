package api

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// SystemInfo carries the engine's static configuration plus closures
// for live state. Static fields are populated at startup; live fields
// are evaluated each request so the dashboard sees current values
// without round-tripping through the metrics pipeline.
//
// Set via Server.SetSystemInfo() from main.go after all wiring completes.
type SystemInfo struct {
	Version      string
	StartedAt    time.Time
	StoreBackend string // "sqlite" | "postgres"
	StoreTarget  string // file path or redacted DSN
	BPFBackend   string // "cilium-ebpf" | "noop"
	OTLPEndpoint string // "" disabled | "stdout" | URL
	LogFormat    string // "json" | "text"
	LogLevel     string

	// Live accessors. Nil-safe — handler treats nil as "unknown".
	BPFLinks          func() int
	BPFEntries        func() int
	TetragonConnected func() bool
}

var (
	sysInfoMu sync.RWMutex
	sysInfo   SystemInfo
)

// SetSystemInfo records the engine-wide configuration snapshot. main()
// calls this after every subsystem is up so /api/system-health reports
// the actual running shape, not the desired one.
func (s *Server) SetSystemInfo(info SystemInfo) {
	sysInfoMu.Lock()
	sysInfo = info
	sysInfoMu.Unlock()
}

// handleSystemHealth returns the live system snapshot. Used by the
// "System Health" panel in choke.html — polled every 5s, no auth flag
// beyond the global middleware.
func (s *Server) handleSystemHealth(w http.ResponseWriter, r *http.Request) {
	sysInfoMu.RLock()
	info := sysInfo
	sysInfoMu.RUnlock()

	links := -1
	if info.BPFLinks != nil {
		links = info.BPFLinks()
	}
	entries := -1
	if info.BPFEntries != nil {
		entries = info.BPFEntries()
	}
	tetragon := false
	if info.TetragonConnected != nil {
		tetragon = info.TetragonConnected()
	}

	uptime := ""
	if !info.StartedAt.IsZero() {
		uptime = time.Since(info.StartedAt).Round(time.Second).String()
	}

	payload := map[string]interface{}{
		"version":    info.Version,
		"started_at": info.StartedAt.UTC().Format(time.RFC3339),
		"uptime":     uptime,

		"store": map[string]interface{}{
			"backend": info.StoreBackend,
			"target":  info.StoreTarget,
		},

		"bpf": map[string]interface{}{
			"backend":        info.BPFBackend,
			"attached_links": links,
			"map_entries":    entries,
			"expected_links": 4,
			"healthy":        info.BPFBackend == "cilium-ebpf" && links == 4,
		},

		"tetragon": map[string]interface{}{
			"connected": tetragon,
		},

		"observability": map[string]interface{}{
			"otlp_endpoint":   info.OTLPEndpoint,
			"log_format":      info.LogFormat,
			"log_level":       info.LogLevel,
			"metrics_enabled": info.OTLPEndpoint != "",
		},

		"auth": map[string]interface{}{
			"hash":       "bcrypt",
			"sessions":   "hmac-signed cookie",
			"csrf":       "double-submit cookie",
			"rate_limit": "5/min per IP",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}
