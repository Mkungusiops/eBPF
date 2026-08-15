package api

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/buildinfo"
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
	// srv is the running HTTP server, captured in Start so Shutdown can stop
	// it gracefully. Guarded because Start runs in its own goroutine.
	srvMu sync.Mutex
	srv   *http.Server

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
	mux.HandleFunc("/favicon.ico", s.handleFaviconICO)
	mux.HandleFunc("/favicon-light.svg", s.handleFaviconLight)
	mux.HandleFunc("/assets/", s.handleWebAssets)

	// Probes are public: a load balancer or uptime check holds no session, and
	// gating them behind auth is the same as not having them.
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)

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
	mux.HandleFunc("/api/alert-stats", s.handleAlertStats)
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
	// Explicit timeouts. http.ListenAndServe leaves all four unset, so a client
	// that opens a connection and dribbles a request holds a goroutine and a file
	// descriptor indefinitely — slowloris against the console of a security
	// product. WriteTimeout is deliberately 0: /api/stream is Server-Sent Events
	// and a write deadline would sever every live console after it elapsed.
	// ReadHeaderTimeout is the one that actually bounds the attack.
	srv := &http.Server{
		Addr:              addr,
		Handler:           metricsMiddleware(s.auth.Middleware(mux)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	s.srvMu.Lock()
	s.srv = srv
	s.srvMu.Unlock()
	return srv.ListenAndServe()
}

// Shutdown stops the HTTP server, letting in-flight requests finish.
//
// Previously there was none: the process exited from under whatever an operator
// had just clicked, so a containment request could be severed mid-dispatch with
// no record of whether it landed.
func (s *Server) Shutdown(ctx context.Context) error {
	s.srvMu.Lock()
	srv := s.srv
	s.srvMu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
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

// handleVersion returns the build identity + start time. The dashboard polls
// this every 30s; if `sha` changes between polls, a "new version deployed —
// reload" toast is shown so users get fresh UI without a blind hard refresh.
//
// `sha` stays the EMBEDDED-ASSET hash on purpose: it is the reload signal, and
// it must move whenever the shipped UI moves — including for a rebuild from an
// uncommitted tree, which is how this project actually deploys. The source
// revision is reported alongside it, because the asset hash cannot answer
// "which code is this box running?" — a Go-only fix leaves it unchanged.
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	b := buildinfo.Get()
	writeJSON(w, map[string]interface{}{
		"sha": versionSHA, // asset hash — drives the reload toast
		// The release name. A revision answers "which commit"; a customer asks
		// "which version", and only a tag answers that. Empty on a non-release
		// build, which is the honest answer rather than a fabricated number.
		"version":    b.Version,
		"released":   b.Released(),
		"revision":   b.Revision,
		"build":      b.String(),
		"dirty":      b.Dirty,
		"built_at":   b.BuiltAt,
		"started_at": startedAt.Format(time.RFC3339),
		"server_now": time.Now().UTC().Format(time.RFC3339),
	})
}

// handleAlertStats serves server-computed counts for a window — the numbers the
// dashboard's KPI tiles, posture score, deltas and timeline are built from.
//
// The console previously derived all of these by filtering its buffer of recent
// alerts, which silently under-reports any window longer than the buffer spans
// (~20 minutes at this fleet's rate) and made "vs prior" deltas meaningless,
// because the preceding window was never in the buffer at all. Aggregating here
// is O(window) on an indexed column and ships counts instead of rows, so a 24h
// range costs about what a 5m range costs.
//
// ?window_min= window length in minutes (default 30, max 7 days)
// ?buckets=    timeline columns (default 30, max 240)
func (s *Server) handleAlertStats(w http.ResponseWriter, r *http.Request) {
	windowMin := intParam(r, "window_min", 30, 60*24*7)
	buckets := intParam(r, "buckets", 30, 240)
	to := time.Now().UTC()
	from := to.Add(-time.Duration(windowMin) * time.Minute)
	stats, err := s.store.AlertStats(from, to, buckets)
	if err != nil {
		log.Printf("alert stats: %v", err)
		http.Error(w, "stats failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, stats)
}

// handleHealthz is liveness: the process is up and serving HTTP. Deliberately a
// constant — a liveness probe that fails on a dependency turns a transient
// database blip into a restart loop.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]interface{}{"status": "ok"})
}

// handleReadyz is readiness: can this engine actually serve an operator?
//
// This box had NO probe of any kind — no /healthz, no /readyz — so nothing
// outside it could distinguish "serving" from "up but useless". The control
// plane's equivalent outage on 2026-08-05 stayed invisible for hours for
// exactly this reason, and it at least had a (constant) /healthz.
//
// The probe reads one row through the same store the API reads, so a corrupt,
// locked or unreadable database fails it rather than being discovered by an
// operator staring at an empty dashboard. Public, and deliberately terse: it
// must be usable by a load balancer that holds no session.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, err := s.store.RecentAlerts(1); err != nil {
		log.Printf("readiness probe failed: store unreadable: %v", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]interface{}{
			"status": "unready", "store": "unreadable",
			"detail": "engine cannot read its local store; see the journal for the driver error",
		})
		return
	}
	writeJSON(w, map[string]interface{}{"status": "ready", "store": "ok"})
}

// Icon assets fall into two cacheability classes, and conflating them is what
// let a corrected icon sit unseen in a browser for a day.
//
// The SVGs are only ever requested with a ?v= the app controls, so a change of
// artwork is a change of URL and they can be cached hard. /favicon.ico cannot
// be: browsers request that exact path by convention, with no query, and
// several surfaces — vertical tab strips, bookmark and history lists — prefer
// it. There is no way to invalidate it by URL, so the only lever is
// revalidation. It shipped with a blind max-age=86400 and NO validator, so a
// client had no way to ask "is this still current?" and no reason to.
const (
	cacheVersioned = "public, max-age=86400"
	// Store it, but check every time. The 304 costs a round trip and no body.
	cacheRevalidate = "public, no-cache"
)

var (
	faviconSVGETag      = assetETag(faviconSVG)
	faviconLightSVGETag = assetETag(faviconLightSVG)
	faviconICOETag      = assetETag(faviconICO)
)

// assetETag is a strong validator over the bytes themselves, computed once at
// startup. Content-derived, so it changes exactly when the artwork does.
func assetETag(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// etagMatches reports whether an If-None-Match header covers etag. The header
// is a comma-separated list and may use the weak "W/" prefix, which for our
// purposes compares equal — we never serve two variants under one URL.
func etagMatches(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" {
			return true
		}
		if strings.TrimPrefix(candidate, "W/") == strings.TrimPrefix(etag, "W/") {
			return true
		}
	}
	return false
}

func serveAsset(w http.ResponseWriter, r *http.Request, body []byte, etag, contentType, cacheControl string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", cacheControl)
	w.Header().Set("ETag", etag)
	if match := r.Header.Get("If-None-Match"); match != "" && etagMatches(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(body)
}

func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	serveAsset(w, r, faviconSVG, faviconSVGETag, "image/svg+xml", cacheVersioned)
}

func (s *Server) handleFaviconICO(w http.ResponseWriter, r *http.Request) {
	serveAsset(w, r, faviconICO, faviconICOETag, "image/x-icon", cacheRevalidate)
}

func (s *Server) handleFaviconLight(w http.ResponseWriter, r *http.Request) {
	serveAsset(w, r, faviconLightSVG, faviconLightSVGETag, "image/svg+xml", cacheVersioned)
}

// intParam reads a named positive integer query parameter, falling back to def
// and clamping to max.
func intParam(r *http.Request, name string, def, max int) int {
	v := def
	if q := r.URL.Query().Get(name); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			v = n
		}
	}
	if v > max {
		v = max
	}
	return v
}

// queryLimit reads ?limit, falling back to def and clamping to max.
//
// These two endpoints used to hardcode their row counts and ignore ?limit
// entirely, which the console had no way to detect: it asked for 1000 alerts,
// silently received 100, and rendered them as a complete 24h window. A capped
// feed that does not say it is capped is indistinguishable from a quiet estate.
// handleDecisions already did this; alerts and events did not.
func queryLimit(r *http.Request, def, max int) int {
	limit := def
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > max {
		limit = max
	}
	return limit
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	events, err := s.store.RecentEvents(queryLimit(r, 500, 5000))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, events)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, err := s.store.RecentAlerts(queryLimit(r, 200, 2000))
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
	// The status line and headers are already out by the time Encode can fail,
	// so the client gets a truncated body either way — but a silent failure
	// here looks identical to an empty result set on a console panel, so log it.
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[api] writeJSON: %v", err)
	}
}
