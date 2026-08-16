package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/assistant"
)

// Assistant endpoints.
//
//	GET  /api/assistant       capability: is it configured, which agents exist
//	POST /api/assistant/ask   run one agent, return a grounded answer
//
// Both sit behind the console's existing session auth (registered on the
// protected mux). That matters more than usual here: the assistant reads alerts,
// decisions and process trees, so an unauthenticated caller would obtain a
// natural-language summary of the estate's security posture from a single
// endpoint — a nicer exfiltration surface than any individual API it wraps.

type assistantCapabilityResponse struct {
	Enabled bool             `json:"enabled"`
	Model   string           `json:"model,omitempty"`
	Agents  []assistantAgent `json:"agents"`
	Reason  string           `json:"reason,omitempty"`
}

type assistantAgent struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Conversational tells the console which agent takes a QUESTION. Without it
	// a chat surface has to guess by list position, and it guessed a button.
	Conversational bool `json:"conversational,omitempty"`
}

func (s *Server) handleAssistantCapability(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := s.assistantCfg

	// Unconfigured is a 200 with enabled:false, not a 404. The console asks this
	// on every drill-panel open; a 404 would be indistinguishable from a routing
	// bug and would put a red line in the browser console on a healthy box.
	if !cfg.Enabled() {
		writeJSONStatus(w, http.StatusOK, assistantCapabilityResponse{
			Enabled: false, Agents: []assistantAgent{},
			Reason: "no model configured for this deployment",
		})
		return
	}
	if cfg.APIKey() == "" {
		writeJSONStatus(w, http.StatusOK, assistantCapabilityResponse{
			Enabled: false, Agents: []assistantAgent{},
			Reason: cfg.APIKeyEnv + " is not set on this host",
		})
		return
	}

	out := assistantCapabilityResponse{Enabled: true, Model: cfg.Model}
	for _, a := range assistant.Agents() {
		out.Agents = append(out.Agents, assistantAgent{ID: a.ID, Title: a.Title, Conversational: a.Conversational})
	}
	writeJSONStatus(w, http.StatusOK, out)
}

type assistantAskRequest struct {
	Agent    string `json:"agent"`
	Question string `json:"question"`
	ExecID   string `json:"exec_id"`
}

func (s *Server) handleAssistantAsk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := s.assistantCfg
	if !cfg.Enabled() || cfg.APIKey() == "" {
		writeJSONStatus(w, http.StatusServiceUnavailable,
			map[string]string{"error": "the assistant is not configured on this deployment"})
		return
	}

	// Bounded read: an unbounded body on an authenticated endpoint is still a
	// memory-exhaustion surface, and no legitimate question is 64KB.
	var req assistantAskRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	if strings.TrimSpace(req.Agent) == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "agent is required"})
		return
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := contextWithTimeout(r, timeout)
	defer cancel()

	runner := &assistant.Runner{
		Provider: assistant.NewOpenAICompatible(cfg, nil),
		Tools:    assistant.DefaultTools(),
		// The read-only client. Even if a tool were changed to build a POST,
		// this transport refuses it (internal/assistant/doc.go).
		Client:   assistant.NewReadOnlyClient(timeout, nil),
		BaseURL:  s.selfBaseURL(),
		Cookie:   r.Header.Get("Cookie"),
		MaxCalls: cfg.MaxToolCalls,
	}

	ans, err := runner.Run(ctx, req.Agent, req.Question, req.ExecID)
	if err != nil {
		// Logged with the agent for correlation, returned WITHOUT internals: the
		// error can carry an upstream provider message, and this response goes
		// to a browser.
		slog.Warn("assistant run failed", "agent", req.Agent, "error", err)
		writeJSONStatus(w, http.StatusBadGateway,
			map[string]string{"error": "the assistant could not complete this request"})
		return
	}

	// Audit trail. In a SOC, who asked what about which incident is evidence
	// handling, not telemetry — a post-incident review must be able to
	// reconstruct which conclusions were assisted.
	slog.Info("assistant answered",
		"agent", req.Agent, "exec_id", req.ExecID,
		"steps", len(ans.Steps), "truncated", ans.Truncated, "duration", ans.Duration)

	writeJSONStatus(w, http.StatusOK, ans)
}

// ── local helpers ──────────────────────────────────────────────────────────
// Defined here rather than added to http.go: they exist for this endpoint pair,
// and the package's existing writeJSON has no status parameter because every
// other handler answers 200 or nothing.

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("assistant: writing response", "error", err)
	}
}

// contextWithTimeout bounds the run AND inherits cancellation from the request,
// so an analyst closing the drill panel stops the work rather than leaving a
// tool loop running against a browser nobody is watching.
func contextWithTimeout(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}

// selfBaseURL is the origin the assistant's tools call back into — this same
// engine.
//
// Loopback, always, and never derived from the Host header. Tools are GETs
// against our own read endpoints; taking the origin from a client-supplied
// header would let a caller point the tool loop at a host of their choosing
// and turn this endpoint into a request forwarder authenticated as the engine.
func (s *Server) selfBaseURL() string {
	addr := s.selfAddr
	if addr == "" {
		addr = ":8090"
	}
	// ":8090" and "0.0.0.0:8090" both mean "this process"; dial loopback.
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		addr = "127.0.0.1" + addr[i:]
	}
	return "http://" + addr
}

// SetAssistantConfig enables the analyst assistant. Called from main() when the
// deployment configures a model; left unset otherwise.
func (s *Server) SetAssistantConfig(cfg assistant.Config) { s.assistantCfg = cfg }

// handleAssistantChatsUnavailable answers the chat-history routes on the
// single-tenant engine.
//
// This engine stores to SQLite. Chat history is protected by Postgres RLS —
// that is what keeps one operator's conversations out of another's — and there
// is no SQLite equivalent, so rather than persist conversations with weaker
// isolation than every other tenant-partitioned table, this deployment simply
// has no history.
//
// 503 with a reason, never 401 or 404: the console distinguishes "switched off"
// from "broken", and it can only do that if the server says which. A silent
// fall-through told operators a feature had failed when it was never built for
// this deployment.
func (s *Server) handleAssistantChatsUnavailable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": "chat history is not enabled on this deployment",
	})
}
