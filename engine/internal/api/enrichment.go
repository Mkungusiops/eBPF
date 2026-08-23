package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/jeffmk/ebpf-poc-engine/internal/baseline"
	"github.com/jeffmk/ebpf-poc-engine/internal/findings"
	"github.com/jeffmk/ebpf-poc-engine/internal/intel"
	"github.com/jeffmk/ebpf-poc-engine/internal/platformdoc"
)

// Read endpoints for the two enrichment layers.
//
//	GET /api/baseline            the host's learned profile and its readiness
//	GET /api/baseline/anomalies  recent behavioural findings
//	GET /api/intel               loaded feeds, counts and refresh state
//	GET /api/intel/matches       recent indicator hits
//	GET /api/intel/lookup?q=     is this indicator known to the feeds?
//
// Every one is a GET that reports state. There is deliberately no route that
// adds an indicator, edits the allowlist or resets the profile: feeds are files
// an operator owns, and a console that can rewrite the detection content is a
// console whose detection content can be rewritten by whoever gets a session.

// EnrichmentSource is what the server needs from the host's enrichment wiring.
// An interface so cmd/engine and cmd/agent both satisfy it, and so a test can
// hand the server a stub.
type EnrichmentSource interface {
	BaselineStatus(topN int) (baseline.Status, bool)
	IntelStatus() (intel.Status, bool)
	IntelRefreshStatus() intel.RefreshStatus
	RecentFindings(kind string, limit int) []findings.Finding
	FindingTotals() (anomalies, intelHits uint64)
	LookupIndicator(value string) (intel.Match, bool)
}

// SetEnrichment wires the enrichment reader. Left nil on a deployment that
// runs neither layer, in which case these endpoints answer 503 with a reason
// rather than 404 — the console distinguishes "switched off" from "broken",
// and it can only do that if the server says which.
func (s *Server) SetEnrichment(e EnrichmentSource) { s.enrichment = e }

func (s *Server) enrichmentReady(w http.ResponseWriter) bool {
	if s.enrichment == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{
			"error": "enrichment is not enabled on this deployment",
		})
		return false
	}
	return true
}

// baselineResponse wraps the profile status.
//
// `enabled` is separate from `ready` and both are separate from an empty
// anomaly list, because the three mean different things and an operator has to
// tell them apart: switched off, still learning, or learning and finding
// nothing. Collapsing them is how a broken detector looks like a clean estate —
// the same distinction /api/system-health already draws for telemetry.
type baselineResponse struct {
	Enabled bool            `json:"enabled"`
	Status  baseline.Status `json:"status"`
	// Anomalies is the lifetime count of behavioural findings, which the
	// bounded ring cannot report once it has wrapped.
	Anomalies uint64 `json:"anomalies_total"`
}

func (s *Server) handleBaseline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.enrichmentReady(w) {
		return
	}
	st, ok := s.enrichment.BaselineStatus(clampInt(r.URL.Query().Get("top"), 10, 1, 50))
	anomalies, _ := s.enrichment.FindingTotals()
	writeJSONStatus(w, http.StatusOK, baselineResponse{Enabled: ok, Status: st, Anomalies: anomalies})
}

func (s *Server) handleBaselineAnomalies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.enrichmentReady(w) {
		return
	}
	limit := clampInt(r.URL.Query().Get("limit"), 50, 1, 500)
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"findings": s.enrichment.RecentFindings("anomaly", limit),
	})
}

type intelResponse struct {
	Status  intel.Status        `json:"status"`
	Refresh intel.RefreshStatus `json:"refresh"`
	Matches uint64              `json:"matches_total"`
}

func (s *Server) handleIntel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.enrichmentReady(w) {
		return
	}
	st, _ := s.enrichment.IntelStatus()
	_, hits := s.enrichment.FindingTotals()
	writeJSONStatus(w, http.StatusOK, intelResponse{
		Status: st, Refresh: s.enrichment.IntelRefreshStatus(), Matches: hits,
	})
}

func (s *Server) handleIntelMatches(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.enrichmentReady(w) {
		return
	}
	limit := clampInt(r.URL.Query().Get("limit"), 50, 1, 500)
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"findings": s.enrichment.RecentFindings("intel", limit),
	})
}

// handleIntelLookup answers "is this indicator known".
//
// A miss is 200 with matched:false, not 404. The question was answered — the
// indicator is not in the feeds — and a 404 would read as "the endpoint is
// missing", which is the opposite conclusion.
func (s *Server) handleIntelLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.enrichmentReady(w) {
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "q is required"})
		return
	}
	// Bounded: this is an authenticated endpoint, but an unbounded string still
	// walks the domain-suffix ladder once per label.
	if len(q) > 256 {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "indicator too long"})
		return
	}
	m, ok := s.enrichment.LookupIndicator(q)
	out := map[string]any{"query": q, "matched": ok}
	if ok {
		out["match"] = m
	}
	writeJSONStatus(w, http.StatusOK, out)
}

// clampInt parses a bounded query integer, falling back to def.
func clampInt(raw string, def, min, max int) int {
	if strings.TrimSpace(raw) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

// handlePlatformDoc serves the product glossary.
//
//	GET /api/platform-doc          every topic
//	GET /api/platform-doc?topic=x  one topic
//
// Public-shaped but registered on the protected mux like every other read: it
// describes how containment behaves on this deployment, which is not something
// to hand to an unauthenticated caller.
//
// An unknown topic is 200 with the full list and matched:false, not 404. The
// caller here is usually a model, and a 404 teaches it the endpoint is broken;
// returning the available topics teaches it what it may ask for next.
func (s *Server) handlePlatformDoc(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if id := strings.TrimSpace(r.URL.Query().Get("topic")); id != "" {
		if t, ok := platformdoc.Get(id); ok {
			writeJSONStatus(w, http.StatusOK, map[string]any{"matched": true, "topic": t})
			return
		}
		writeJSONStatus(w, http.StatusOK, map[string]any{
			"matched": false, "requested": id, "topics": platformdoc.List(),
		})
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"topics": platformdoc.List()})
}
