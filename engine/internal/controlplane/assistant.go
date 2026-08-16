package controlplane

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/assistant"
)

// The analyst assistant on the MULTI-TENANT control plane.
//
// The engine has its own copy of these handlers (internal/api/assistant.go).
// They stay separate rather than shared because the two servers differ in the
// one way that matters here: on the control plane every read is TENANT-SCOPED,
// so the assistant's tool calls must carry the caller's session and be answered
// through the same tenant predicate as the console. Sharing a handler would
// invite a future edit that "simplifies" the credential forwarding and silently
// gives the assistant cross-tenant reach.
//
//	GET  /api/assistant       capability
//	POST /api/assistant/ask   run one agent

type assistantCapability struct {
	Enabled bool      `json:"enabled"`
	Model   string    `json:"model,omitempty"`
	Agents  []cpAgent `json:"agents"`
	Reason  string    `json:"reason,omitempty"`
}

type cpAgent struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

func (s *Server) registerAssistantRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/assistant", s.handleAssistantCapability)
	mux.HandleFunc("/api/assistant/ask", s.handleAssistantAsk)
}

func (s *Server) handleAssistantCapability(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	cfg := s.cfg.Assistant

	// 200 with enabled:false, never 404. The console asks on every drill-panel
	// open; a 404 is indistinguishable from a routing bug and puts a red line in
	// the browser console on a perfectly healthy deployment.
	switch {
	case !cfg.Enabled():
		writeJSON(w, http.StatusOK, assistantCapability{
			Agents: []cpAgent{}, Reason: "no model configured for this deployment"})
	case cfg.APIKey() == "":
		writeJSON(w, http.StatusOK, assistantCapability{
			Agents: []cpAgent{}, Reason: cfg.APIKeyEnv + " is not set on this host"})
	default:
		out := assistantCapability{Enabled: true, Model: cfg.Model}
		for _, a := range assistant.Agents() {
			out.Agents = append(out.Agents, cpAgent{ID: a.ID, Title: a.Title})
		}
		writeJSON(w, http.StatusOK, out)
	}
}

type cpAskRequest struct {
	Agent    string `json:"agent"`
	Question string `json:"question"`
	ExecID   string `json:"exec_id"`
}

func (s *Server) handleAssistantAsk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	cfg := s.cfg.Assistant
	if !cfg.Enabled() || cfg.APIKey() == "" {
		writeJSON(w, http.StatusServiceUnavailable,
			map[string]string{"error": "the assistant is not configured on this deployment"})
		return
	}

	var req cpAskRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	if strings.TrimSpace(req.Agent) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent is required"})
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
		Client:   assistant.NewReadOnlyClient(timeout, nil),
		BaseURL:  s.selfBaseURL(),
		// The caller's session, forwarded verbatim. On a multi-tenant control
		// plane this is what keeps the assistant inside the asking analyst's
		// tenant: the tools read the same endpoints the console does, and those
		// derive tenant from the session. Without it the calls are
		// unauthenticated; with a privileged identity of its own the assistant
		// would read across tenants, which is the isolation invariant this
		// product is built on.
		Cookie:   r.Header.Get("Cookie"),
		MaxCalls: cfg.MaxToolCalls,
	}

	ans, err := runner.Run(ctx, req.Agent, req.Question, req.ExecID)
	if err != nil {
		// The upstream message can carry provider detail; log it, do not return
		// it to a browser.
		slog.Warn("assistant run failed", "agent", req.Agent, "error", err)
		writeJSON(w, http.StatusBadGateway,
			map[string]string{"error": "the assistant could not complete this request"})
		return
	}

	// Who asked what, about which incident. In a SOC that is evidence handling:
	// a post-incident review has to be able to tell which conclusions were
	// assisted.
	slog.Info("assistant answered", "agent", req.Agent, "exec_id", req.ExecID,
		"steps", len(ans.Steps), "grounded", ans.Grounded, "duration", ans.Duration)

	writeJSON(w, http.StatusOK, ans)
}

// contextWithTimeout bounds the run and inherits the request's cancellation, so
// an analyst closing the panel stops the work instead of leaving a tool loop
// running for a browser nobody is watching.
func contextWithTimeout(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}

// selfBaseURL is the loopback origin the assistant's tools read from.
func (s *Server) selfBaseURL() string {
	addr := s.selfAddr
	if addr == "" {
		addr = ":9090"
	}
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		addr = "127.0.0.1" + addr[i:]
	}
	return "http://" + addr
}
