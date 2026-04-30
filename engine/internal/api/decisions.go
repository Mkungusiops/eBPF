package api

import (
	"net/http"
	"strconv"
)

// Broadcast implements choke.Broadcaster. It pushes a payload onto the
// shared broadcast channel as a typed event so the SSE fan-out picks it
// up. Non-blocking — drops on overflow rather than back-pressuring the
// gateway, which matches the existing send() helper in main.go.
func (s *Server) Broadcast(eventType string, payload interface{}) {
	if s.outbound == nil {
		return
	}
	select {
	case s.outbound <- Broadcast{Type: eventType, Payload: payload}:
	default:
	}
}

// handleDecisions returns the most recent enforcement decisions, newest
// first. ?limit=N caps the response (default 100, max 500).
func (s *Server) handleDecisions(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 500 {
		limit = 500
	}
	decisions, err := s.store.RecentDecisions(limit)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, decisions)
}

// handleVerifyChain re-walks the audit chain and reports whether it is
// intact. Useful for the dashboard's "audit OK" badge and for offline
// verification.
func (s *Server) handleVerifyChain(w http.ResponseWriter, r *http.Request) {
	res, err := s.store.VerifyDecisionChain()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, res)
}
