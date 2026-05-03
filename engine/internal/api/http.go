package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
)

// versionSHA is a hash of the embedded HTML+favicon. It changes whenever
// the binary is rebuilt with frontend changes — used by the dashboard's
// version watcher to prompt a soft reload when a new version is deployed.
var (
	versionSHA = computeVersionSHA()
	startedAt  = time.Now().UTC()
)

func computeVersionSHA() string {
	h := sha256.New()
	h.Write([]byte(indexHTML))
	h.Write([]byte(loginHTML))
	h.Write(faviconSVG)
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
	// fleet is the optional Tier-1 multi-host control plane. nil when the
	// engine was started without --fleet-hosts; the /api/fleet/* handlers
	// 503 in that case.
	fleet *Fleet

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
	mux.HandleFunc("/login", s.auth.HandleLoginPage)
	mux.HandleFunc("/api/login", s.auth.HandleLogin)
	mux.HandleFunc("/favicon.svg", s.handleFavicon)
	mux.HandleFunc("/favicon.ico", s.handleFavicon)
	mux.HandleFunc("/favicon-light.svg", s.handleFaviconLight)

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
	mux.HandleFunc("/api/decisions", s.handleDecisions)
	mux.HandleFunc("/api/verify-chain", s.handleVerifyChain)

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

	// Tier 1 fleet console — only mounted when --fleet-hosts was set.
	// Routes are always registered so the UI 503s cleanly with a useful
	// message rather than 404ing when fleet mode is disabled.
	mux.HandleFunc("/fleet", s.handleFleetConsole)
	mux.HandleFunc("/api/fleet/hosts", s.handleFleetHosts)
	mux.HandleFunc("/api/fleet/state", s.handleFleetState)
	mux.HandleFunc("/api/fleet/cgroups", s.handleFleetCgroups)
	mux.HandleFunc("/api/fleet/decisions", s.handleFleetDecisions)
	mux.HandleFunc("/api/fleet/alerts", s.handleFleetAlerts)
	mux.HandleFunc("/api/fleet/preset", s.handleFleetPreset)
	mux.HandleFunc("/api/fleet/thresholds", s.handleFleetThresholds)
	mux.HandleFunc("/api/fleet/kill-switch", s.handleFleetKillSwitch)
	mux.HandleFunc("/api/fleet/thaw", s.handleFleetThaw)

	log.Printf("HTTP listening on %s (auth: user=%s)", addr, s.auth.Username())
	return http.ListenAndServe(addr, s.auth.Middleware(mux))
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	fmt.Fprint(w, indexHTML)
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
	writeJSON(w, map[string]interface{}{
		"chain":  chain,
		"events": events,
	})
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

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
