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

// SetOriginSnapshotFn wires the origin tracker's snapshot accessor for
// the /api/origin debug endpoint. main.go installs a closure that
// adapts the tracker's pid→origin.Origin map into a JSON-shaped
// pid→map view so the api package stays free of an origin import.
func (s *Server) SetOriginSnapshotFn(fn func() map[uint32]map[string]interface{}) {
	s.originSnapshotFn = fn
}

// handleOrigin returns the live tracker contents — every PID currently
// attributed to a remote client, plus the per-PID origin metadata. Used
// to verify that the journald tailer is feeding entries and to diagnose
// rows that show "—" in the choke console's ORIGIN column.
func (s *Server) handleOrigin(w http.ResponseWriter, _ *http.Request) {
	if s.originSnapshotFn == nil {
		writeJSON(w, map[string]interface{}{
			"available": false,
			"entries":   map[string]interface{}{},
		})
		return
	}
	snap := s.originSnapshotFn()
	writeJSON(w, map[string]interface{}{
		"available": true,
		"count":     len(snap),
		"entries":   snap,
	})
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
