package controlplane

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/assistant"
	"github.com/jeffmk/ebpf-poc-engine/internal/chatstore"
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
	// Conversational tells the console which agent takes a QUESTION. Without it
	// a chat surface has to guess by list position, and it guessed a button.
	Conversational bool `json:"conversational,omitempty"`
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
			out.Agents = append(out.Agents, cpAgent{ID: a.ID, Title: a.Title, Conversational: a.Conversational})
		}
		writeJSON(w, http.StatusOK, out)
	}
}

type cpAskRequest struct {
	Agent    string `json:"agent"`
	Question string `json:"question"`
	ExecID   string `json:"exec_id"`
	// ChatID, when present, records this exchange in that conversation.
	//
	// ABSENT MEANS INCOGNITO, and that is the default on purpose
	// (platform-assistant.md §3): an analyst may ask about a live breach before
	// it is classified, and the safe default for an unclassified question is to
	// leave no record. Persistence is opt-in per ask, not a mode you can forget
	// you are in.
	ChatID string `json:"chat_id"`
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
		// Keep the QUESTION even though there is no answer. Otherwise a failed
		// ask leaves a conversation that exists in the list and is empty when
		// reopened, which reads as data loss rather than as a failed request —
		// and the analyst loses what they typed.
		s.recordQuestion(r, req)
		writeJSON(w, http.StatusBadGateway,
			map[string]string{"error": "the assistant could not complete this request"})
		return
	}

	// Who asked what, about which incident. In a SOC that is evidence handling:
	// a post-incident review has to be able to tell which conclusions were
	// assisted.
	slog.Info("assistant answered", "agent", req.Agent, "exec_id", req.ExecID,
		"steps", len(ans.Steps), "grounded", ans.Grounded, "duration", ans.Duration)

	s.recordExchange(r, req, ans)

	writeJSON(w, http.StatusOK, ans)
}

// recordExchange stores the question and the answer, when the caller asked for
// it and this deployment has history.
//
// Two rules, both deliberate:
//
// IT NEVER FAILS THE ANSWER. The analyst has their answer already; losing the
// history copy is a logged annoyance, not a reason to turn a good response into
// an error. Anything else makes a storage hiccup look like the assistant broke.
//
// IT NEVER WIDENS SCOPE. The chat id comes from the request, so it is
// attacker-controlled — but AppendMessage re-checks ownership against the
// caller's Scope, and an id belonging to someone else returns ErrNotFound
// rather than appending. That check lives in the store, not here, so it cannot
// be skipped by a second caller added later.
// recordQuestion stores just the analyst's question, for the case where the run
// failed and there is no answer to pair with it.
func (s *Server) recordQuestion(r *http.Request, req cpAskRequest) {
	sc, ok := s.chatScopeFor(r, req)
	if !ok {
		return
	}
	if _, err := s.chats.AppendMessage(sc, req.ChatID, chatstore.Message{
		Role: "user", Content: req.Question,
	}); err != nil {
		slog.Warn("assistant history: question not stored", "chat", req.ChatID, "error", err)
	}
}

// chatScopeFor resolves the caller's scope for a recording, or reports that
// this exchange must not be recorded at all. One place, so the incognito rule
// and the unauthenticated rule cannot be applied inconsistently by a second
// caller.
func (s *Server) chatScopeFor(r *http.Request, req cpAskRequest) (chatstore.Scope, bool) {
	if s.chats == nil || strings.TrimSpace(req.ChatID) == "" {
		return chatstore.Scope{}, false // history disabled, or an incognito ask
	}
	p, ok := s.principal(r)
	if !ok {
		return chatstore.Scope{}, false
	}
	sc, err := scopeFor(p)
	if err != nil {
		return chatstore.Scope{}, false
	}
	return sc, true
}

func (s *Server) recordExchange(r *http.Request, req cpAskRequest, ans assistant.Answer) {
	sc, ok := s.chatScopeFor(r, req)
	if !ok {
		return
	}

	// Provenance is part of the record: a post-incident review has to see which
	// endpoints an assisted conclusion was built from. If the trace will not
	// marshal, keep the message and lose the trace — a stored answer with no
	// steps still beats no record of the exchange at all.
	steps, err := json.Marshal(ans.Steps)
	if err != nil {
		slog.Warn("assistant steps not serialisable; storing the answer without its trace", "error", err)
		steps = nil
	}

	if _, err := s.chats.AppendMessage(sc, req.ChatID, chatstore.Message{
		Role: "user", Content: req.Question,
	}); err != nil {
		// ErrNotFound here is the ownership check doing its job on a chat id
		// that is not the caller's — expected, not alarming.
		slog.Warn("assistant history: question not stored", "chat", req.ChatID, "error", err)
		return
	}
	if _, err := s.chats.AppendMessage(sc, req.ChatID, chatstore.Message{
		Role: "assistant", Content: ans.Content, Model: s.cfg.Assistant.Model,
		Steps: string(steps), Grounded: ans.Grounded,
	}); err != nil {
		slog.Warn("assistant history: answer not stored", "chat", req.ChatID, "error", err)
	}
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
