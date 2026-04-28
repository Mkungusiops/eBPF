package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
)

type Broadcast struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

type Server struct {
	store     *store.Store
	tree      *tree.Tree
	broadcast <-chan Broadcast
	auth      *Auth

	subsMu sync.Mutex
	subs   map[chan Broadcast]struct{}
}

func NewServer(st *store.Store, pt *tree.Tree, broadcast <-chan Broadcast, auth *Auth) *Server {
	return &Server{
		store:     st,
		tree:      pt,
		broadcast: broadcast,
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

func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(faviconSVG)
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
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
