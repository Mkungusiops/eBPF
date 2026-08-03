package api

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/metrics"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
)

// versionSHA is a hash of the embedded frontend assets. It changes whenever
// the binary is rebuilt with frontend changes — used by the dashboard's
// version watcher to prompt a soft reload when a new version is deployed.
var (
	versionSHA = computeVersionSHA()
	startedAt  = time.Now().UTC()
)

func computeVersionSHA() string {
	h := sha256.New()
	if n, err := hashEmbeddedWebDist(h); err == nil && n > 0 {
		return hex.EncodeToString(h.Sum(nil))[:12]
	}
	h.Write([]byte("web-dist-missing"))
	return hex.EncodeToString(h.Sum(nil))[:12]
}

type Broadcast struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

type Server struct {
	store     *store.Store
	tree      *tree.Tree
	broadcast <-chan Broadcast
	// outbound is the writable side of the same channel — owned by main()
	// and shared with the server so it can publish decision events back
	// onto the bus without going through main's send() helper.
	outbound chan<- Broadcast
	auth     *Auth
	// gateway is wired in after construction via SetGateway() so the HTTP
	// listener can start before all the choke wiring has finished.
	gateway *choke.Gateway
	// deviceGW is the optional network (per-MAC) choke gateway, wired via
	// SetDeviceGateway() when the engine runs with -devchoke-iface. nil
	// otherwise; the /api/choke/device-* handlers 503 in that case.
	deviceGW *choke.DeviceGateway
	// fleet is the optional Tier-1 multi-host control plane. nil when the
	// engine was started without --fleet-hosts; the /api/fleet/* handlers
	// 503 in that case.
	fleet *Fleet
	// originSnapshotFn returns a copy of the origin tracker's pid→Origin
	// map for the /api/origin debug endpoint. Wired by main.go; nil
	// means the endpoint reports "{}" (still 200) so it's safe to probe.
	originSnapshotFn func() map[uint32]map[string]interface{}

	subsMu sync.Mutex
	subs   map[chan Broadcast]struct{}
}

func NewServer(st *store.Store, pt *tree.Tree, broadcast chan Broadcast, auth *Auth) *Server {
	return &Server{
		store:     st,
		tree:      pt,
		broadcast: broadcast,
		outbound:  broadcast,
		auth:      auth,
		subs:      make(map[chan Broadcast]struct{}),
	}
}

func (s *Server) Start(addr string) error {
	go s.fanout()
	mux := http.NewServeMux()

	// Public auth endpoints
	mux.HandleFunc("/login", s.handleLoginPage)
	mux.HandleFunc("/api/login", s.auth.HandleLogin)
	mux.HandleFunc("/favicon.svg", s.handleFavicon)
	mux.HandleFunc("/favicon.ico", s.handleFavicon)
	mux.HandleFunc("/favicon-light.svg", s.handleFaviconLight)
	mux.HandleFunc("/assets/", s.handleWebAssets)

	// PWA support files live at the dist root and are public so the worker,
	// manifest, and icons load before authentication (see web_assets.go).
	mux.HandleFunc("/sw.js", s.handlePWAFile)
	mux.HandleFunc("/pwa-install-bridge.js", s.handlePWAFile)
	mux.HandleFunc("/manifest.webmanifest", s.handlePWAFile)
	mux.HandleFunc("/pwa-192x192.png", s.handlePWAFile)
	mux.HandleFunc("/pwa-512x512.png", s.handlePWAFile)
	mux.HandleFunc("/pwa-maskable-512x512.png", s.handlePWAFile)
	mux.HandleFunc("/apple-touch-icon.png", s.handlePWAFile)

	// Protected endpoints (registered raw; the global middleware enforces auth)
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/process/", s.handleProcess)
	mux.HandleFunc("/api/stream", s.handleSSE)
	mux.HandleFunc("/api/whoami", s.auth.HandleWhoami)
	mux.HandleFunc("/api/logout", s.auth.HandleLogout)
	mux.HandleFunc("/api/policies", s.handlePolicies)
	mux.HandleFunc("/api/attacks", s.handleAttackList)
	mux.HandleFunc("/api/run-attack", s.handleAttackRun)
	mux.HandleFunc("/api/honeypots", s.handleHoneypots)
	mux.HandleFunc("/api/policy-stats", s.handlePolicyStats)
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/api/system-health", s.handleSystemHealth)
	mux.HandleFunc("/api/decisions", s.handleDecisions)
	mux.HandleFunc("/api/verify-chain", s.handleVerifyChain)
	mux.HandleFunc("/api/origin", s.handleOrigin)

	// Choke Gateway Console — separate page, separate API namespace.
	mux.HandleFunc("/choke", s.handleChokeConsole)
	mux.HandleFunc("/api/choke/state", s.handleChokeState)
	mux.HandleFunc("/api/choke/circuits", s.handleChokeCircuits)
	mux.HandleFunc("/api/choke/buckets", s.handleChokeBuckets)
	mux.HandleFunc("/api/choke/thresholds", s.handleChokeThresholds)
	mux.HandleFunc("/api/choke/manual", s.handleChokeManual)
	mux.HandleFunc("/api/choke/kill-switch", s.handleChokeKillSwitch)
	mux.HandleFunc("/api/choke/policies", s.handleChokePolicies)
	mux.HandleFunc("/api/choke/policy/preview", s.handleChokePolicyPreview)
	// Enterprise actions: presets, bulk, forget, thaw, annotate, snapshot, drill-in.
	mux.HandleFunc("/api/choke/preset", s.handleChokePreset)
	mux.HandleFunc("/api/choke/mode", s.handleChokeMode)
	mux.HandleFunc("/api/choke/bulk-manual", s.handleChokeBulkManual)
	mux.HandleFunc("/api/choke/forget", s.handleChokeForget)
	mux.HandleFunc("/api/choke/thaw", s.handleChokeThaw)
	mux.HandleFunc("/api/choke/cgroups", s.handleChokeCgroups)
	mux.HandleFunc("/api/choke/annotate", s.handleChokeAnnotate)
	mux.HandleFunc("/api/choke/forensic-snapshot", s.handleChokeForensicSnapshot)
	mux.HandleFunc("/api/choke/process/", s.handleChokeProcess)
	mux.HandleFunc("/api/choke/processes", s.handleChokeProcesses)
	mux.HandleFunc("/api/choke/proc/", s.handleChokeProcLive)
	mux.HandleFunc("/api/choke/jail", s.handleChokeJail)

	// Network choke (per-device / MAC) — separate console + API namespace.
	// Routes are always registered so they 503 cleanly with a useful
	// message when the engine runs without -devchoke-iface.
	mux.HandleFunc("/devices", s.handleDevicesConsole)
	mux.HandleFunc("/api/choke/devices", s.handleChokeDevices)
	mux.HandleFunc("/api/choke/device-state", s.handleChokeDeviceState)
	mux.HandleFunc("/api/choke/device-flows", s.handleChokeDeviceFlows)
	mux.HandleFunc("/api/choke/device-jail", s.handleChokeDeviceJail)
	mux.HandleFunc("/api/choke/device-thaw", s.handleChokeDeviceThaw)
	mux.HandleFunc("/api/choke/device-mode", s.handleChokeDeviceMode)
	mux.HandleFunc("/api/choke/device-kill-switch", s.handleChokeDeviceKillSwitch)

	// Tier 1 fleet console — only mounted when --fleet-hosts was set.
	// Routes are always registered so the UI 503s cleanly with a useful
	// message rather than 404ing when fleet mode is disabled.
	mux.HandleFunc("/fleet", s.handleFleetConsole)
	mux.HandleFunc("/api/fleet/hosts", s.handleFleetHosts)
	mux.HandleFunc("/api/fleet/probe", s.handleFleetProbe)
	mux.HandleFunc("/api/fleet/state", s.handleFleetState)
	mux.HandleFunc("/api/fleet/cgroups", s.handleFleetCgroups)
	mux.HandleFunc("/api/fleet/decisions", s.handleFleetDecisions)
	mux.HandleFunc("/api/fleet/alerts", s.handleFleetAlerts)
	mux.HandleFunc("/api/fleet/preset", s.handleFleetPreset)
	mux.HandleFunc("/api/fleet/thresholds", s.handleFleetThresholds)
	mux.HandleFunc("/api/fleet/kill-switch", s.handleFleetKillSwitch)
	mux.HandleFunc("/api/fleet/thaw", s.handleFleetThaw)
	mux.HandleFunc("/api/fleet/devices", s.handleFleetDevices)
	mux.HandleFunc("/api/fleet/device-jail", s.handleFleetDeviceJail)

	log.Printf("HTTP listening on %s (auth: user=%s)", addr, s.auth.Username())
	return http.ListenAndServe(addr, metricsMiddleware(s.auth.Middleware(mux)))
}

// metricsMiddleware times every request and records the duration into
// the OTel histogram. Path is bucketed at the first segment to keep
// label cardinality bounded — without this, /api/process/<exec_id>
// would explode the cardinality with one series per process.
func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		metrics.ObserveHTTPRequest(
			time.Since(start).Seconds(),
			bucketPath(r.URL.Path),
			httpStatusBucket(rec.status),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Flush forwards to the wrapped writer if it supports http.Flusher.
// Without this, the SSE handler's `w.(http.Flusher)` assertion fails
// when the metrics middleware is in the chain — it returns 500
// "streaming unsupported" and the dashboard shows STREAM offline.
// Same reason ResponseController exists in net/http now.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack proxies the connection takeover used by SSE/websockets when
// the upstream supports it. Same rationale as Flush — preserve the
// ResponseWriter's optional interfaces through the wrapper.
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := s.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Unwrap lets net/http's ResponseController find optional interfaces
// (Flusher, Hijacker, Pusher, …) on the underlying writer when the
// wrapper itself doesn't implement them. The Go 1.20+ way.
func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

// bucketPath collapses high-cardinality paths to a fixed prefix so the
// metric stays usable. /api/process/<exec_id> -> /api/process/_, etc.
func bucketPath(p string) string {
	switch {
	case strings.HasPrefix(p, "/api/process/"):
		return "/api/process/_"
	case strings.HasPrefix(p, "/api/choke/decisions/"):
		return "/api/choke/decisions/_"
	}
	return p
}

func httpStatusBucket(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	case code >= 200:
		return "2xx"
	}
	return "1xx"
}

func (s *Server) fanout() {
	for b := range s.broadcast {
		s.subsMu.Lock()
		for ch := range s.subs {
			select {
			case ch <- b:
			default:
			}
		}
		s.subsMu.Unlock()
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if s.serveEmbeddedWebPage(w, "index.html") {
		return
	}
	serveMissingEmbeddedWeb(w)
}

// handleVersion returns the build SHA + start time. The dashboard polls
// this every 30s; if the SHA changes between polls, a "new version
// deployed — reload" toast is shown so users get fresh UI without a
// blind hard refresh.
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]interface{}{
		"sha":        versionSHA,
		"started_at": startedAt.Format(time.RFC3339),
		"server_now": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(faviconSVG)
}

func (s *Server) handleFaviconLight(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(faviconLightSVG)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	events, err := s.store.RecentEvents(200)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, events)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, err := s.store.RecentAlerts(100)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, alerts)
}

func (s *Server) handleProcess(w http.ResponseWriter, r *http.Request) {
	execID := r.URL.Path[len("/api/process/"):]
	if execID == "" {
		http.Error(w, "missing exec_id", 400)
		return
	}
	chain := s.tree.Ancestors(execID, 10)
	events, _ := s.store.EventsByExecID(execID)
	// Origin attribution: look up the matching circuit entry. The
	// gateway computes origin via the live tracker on every Snapshot()
	// call, so the value reflects current attribution rather than
	// whatever was written to the audit row when the decision fired.
	var origin interface{}
	if s.gateway != nil {
		for _, e := range s.gateway.Snapshot() {
			if e.ExecID == execID {
				if e.Origin != nil {
					origin = e.Origin
				}
				break
			}
		}
	}
	writeJSON(w, map[string]interface{}{
		"chain":  chain,
		"events": events,
		"origin": origin,
	})
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Disable nginx buffering for this response. Without this, nginx
	// holds events in a buffer until it's full or the connection closes,
	// regardless of `proxy_buffering off` in the location block — gzip
	// and HTTP/2 both reintroduce buffering at higher layers. nginx
	// respects this header and disables buffering for *this response*
	// only. Has no effect when nginx isn't in front.
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}

	ch := make(chan Broadcast, 64)
	s.subsMu.Lock()
	s.subs[ch] = struct{}{}
	s.subsMu.Unlock()
	defer func() {
		s.subsMu.Lock()
		delete(s.subs, ch)
		close(ch)
		s.subsMu.Unlock()
	}()

	ctx := r.Context()
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case b := <-ch:
			data, _ := json.Marshal(b)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-keepalive.C:
			// Send a real data: heartbeat (not a comment). EventSource
			// fires onmessage for data: only, so this lets the client
			// confirm liveness during quiet periods.
			fmt.Fprint(w, "data: {\"type\":\"heartbeat\"}\n\n")
			flusher.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
