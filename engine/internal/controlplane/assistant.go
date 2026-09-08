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
// so the assistant's tool calls must carry the caller's session AND the
// customer the question named, and be answered through the same tenant
// predicate as the console. Sharing a handler would invite a future edit that
// "simplifies" the credential forwarding and silently gives the assistant
// cross-tenant reach.
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
	mux.HandleFunc("/api/assistant/stream", s.handleAssistantStream)
}

func (s *Server) handleAssistantCapability(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if _, ok := s.principal(r); !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
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
		// ?surface= names the console panel asking, so the agent list comes back
		// scoped to what makes sense there. Absent or unknown returns the full
		// set — which is what an older console gets, and is harmless.
		out := assistantCapability{Enabled: true, Model: cfg.Model}
		for _, a := range assistant.AgentsFor(r.URL.Query().Get("surface")) {
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
	// Conversation marks a sustained exchange in the history sidebar, as
	// opposed to a drill panel's one-shot question.
	//
	// A FALLBACK, not the authority. When the exchange has a chat, that chat's
	// stored model wins — a fact this server owns. This only decides the case
	// where the sidebar has no chat to point at, which is not hypothetical:
	// when the chat store is unreachable the sidebar still works, still sends
	// no chat id, and would otherwise be silently answered by the panel model
	// with nothing anywhere saying why.
	//
	// Harmless if a client lies: the only reachable outcome is the other
	// configured model. It cannot widen what the assistant may read.
	Conversation bool `json:"conversation"`
	// Surface is which console panel asked. Framing only — it changes what the
	// model is told, never what it may read. On a multi-tenant control plane
	// that separation is the point: which customer an ask reads is decided by
	// ?tenant= put through the same Authorize as every other read (see
	// assistantScope), and nothing a caller puts in the BODY can widen it.
	Surface string `json:"surface"`
}

// historyFor loads the conversation so far from the CHAT STORE, not from the
// request.
//
// The control plane already persists every exchange, scoped and RLS-protected,
// so the authoritative transcript is on the server. Reading it here rather than
// trusting a client-supplied thread means the model sees what was actually
// said, and it means the ownership check that guards the write also guards the
// read: ListMessages takes the caller's Scope, so a chat id belonging to
// another operator returns nothing rather than someone else's conversation.
//
// Failure is never fatal to the ask. Losing history costs the model context;
// refusing the question because history could not be loaded costs the analyst
// their answer during an incident.
func (s *Server) historyFor(r *http.Request, req cpAskRequest) ([]assistant.Message, bool) {
	sc, ok := s.chatScopeFor(r, req)
	if !ok {
		return nil, false // incognito ask, or history disabled — both mean no context
	}
	// One more than the replay bound, so the cap is applied to the newest turns
	// rather than by an arbitrary database limit.
	msgs, err := s.chats.ListMessages(sc, req.ChatID, 64)
	if err != nil {
		slog.Warn("assistant history: could not load prior turns", "chat", req.ChatID, "error", err)
		return nil, false
	}
	out := make([]assistant.Message, 0, len(msgs))
	grounded := false
	for _, m := range msgs {
		out = append(out, assistant.Message{Role: m.Role, Content: m.Content})
		// Whether this conversation has ANY verified reading behind it, taken
		// from what was stored at the time rather than re-derived — on this
		// deployment the transcript is the server's own record, so the flag is
		// a fact and not a client assertion.
		if m.Role == "assistant" && m.Grounded {
			grounded = true
		}
	}
	return assistant.SanitiseHistory(out), grounded
}

// assistantScope answers the two questions that must be settled before a single
// token is spent: WHO is asking, and WHICH CUSTOMER they are asking about.
//
// The second one was missing, and its absence was the last surface under the
// provider banner that answered about the wrong customer. The console's
// customer switcher puts ?tenant= on every request its funnel sends; the
// assistant's client did not go through that funnel, and this handler read no
// tenant even when one arrived, building a Runner from the session cookie
// alone. Every tool call therefore reached the console's own read endpoints
// naming no customer, which authorizeRead resolves to the account's DEFAULT
// one (authz.DefaultTenant). A provider who had switched the console to
// customer B asked a question and got a fluent, confident answer assembled
// entirely from customer A's telemetry — no column header, no row count, no
// banner on the paragraph an analyst pastes into a handover.
//
// IT IS authorizeReadAs, NOT A CHECK OF ITS OWN. That is the whole point: an
// ask is a read of a customer's data by other means, so it resolves, authorizes
// and audits through exactly the function every panel read goes through — same
// default for a request that names no tenant, same 404 for a customer this
// operator may not reach (a 403 would confirm the customer exists), same
// cross-tenant audit row for the provider who may. A private resolution here is
// the only shape this defect can return in, which is why the AST test in
// assistantscope_test.go pins the call.
//
// It runs BEFORE the "is the assistant configured" check on purpose. An
// unauthorized caller must not be told what this deployment has configured, and
// a run that cannot legitimately read anything should not reach an inference
// endpoint at all — the same argument that put the authentication gate here in
// the first place.
func (s *Server) assistantScope(w http.ResponseWriter, r *http.Request) (string, bool) {
	// AUTHENTICATE FIRST.
	//
	// This gate was missing. The tools forward the caller's cookie and every
	// read endpoint they hit checks the tenant, so an unauthenticated caller
	// could never obtain data — the tool calls simply failed and the run
	// returned the ungrounded refusal. But it could still START A RUN, which
	// means an unauthenticated request to a public control plane drove a full
	// tool-calling loop against a paid inference endpoint. Confidentiality was
	// intact; cost and availability were not, and "it fails safe downstream" is
	// not a reason to leave the front door open.
	//
	// Checked here rather than relying on the tools failing, because the answer
	// to "who may ask this assistant anything" should not be an emergent
	// property of six other handlers.
	//
	// This 401 is JSON where the refusals authorizeReadAs writes are plain text.
	// Deliberate: the console reads an error body as JSON and falls back to the
	// status, and this particular sentence has been the shape it is since the
	// gate was added, while a tenant refusal must look like every other read's.
	p, ok := s.principal(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return "", false
	}
	return s.authorizeReadAs(w, r, p)
}

func (s *Server) handleAssistantAsk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	// Who is asking, and about which customer. See assistantScope.
	tenant, ok := s.assistantScope(w, r)
	if !ok {
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

	// The RUN budget, NOT the per-completion timeout. These used to be the same
	// number, so Runner.Run — which issues up to MaxToolCalls completions plus
	// a closing one — had to finish seven provider calls inside the time
	// allotted to a single call. That was invisible while upstream answered in
	// ~1s and became every-request-fails the day upstream slowed down.
	budget := cfg.RunBudget
	if budget <= 0 {
		budget = 150 * time.Second
	}
	// The per-call timeout stays separate: it bounds each tool read below, and
	// the provider client bounds each completion with the same value.
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	ctx, cancel := contextWithTimeout(r, budget)
	defer cancel()

	// One conversation, one model. See assistantmodel.go.
	model := s.modelForExchange(r, req)
	runner := &assistant.Runner{
		Provider: providerFor(cfg, model),
		Tools:    assistant.DefaultTools(),
		Client:   assistant.NewReadOnlyClient(timeout, nil),
		BaseURL:  s.selfBaseURL(),
		// The caller's session, forwarded verbatim: the tools read the same
		// endpoints the console does, so the assistant is authorized exactly as
		// the person asking is. Without it the calls are unauthenticated; with
		// a privileged identity of its own the assistant would read across
		// tenants, which is the isolation invariant this product is built on.
		Cookie: r.Header.Get("Cookie"),
		// The customer the ASK named, put on every tool call — the session says
		// who, and on a provider account that does not say about whom. The
		// value is the one assistantScope already authorized and audited above,
		// so naming it here widens nothing: it decides which customer's rows
		// the tools ask for, out of the customers this session may already
		// read.
		Tenant:   tenant,
		Surface:  req.Surface,
		MaxCalls: cfg.MaxToolCalls,
	}
	runner.History, runner.HistoryGrounded = s.historyFor(r, req)

	ans, err := runner.Run(ctx, req.Agent, req.Question, req.ExecID)
	if err != nil {
		// Keep the QUESTION even though there is no answer. Otherwise a failed
		// ask leaves a conversation that exists in the list and is empty when
		// reopened, which reads as data loss rather than as a failed request —
		// and the analyst loses what they typed. True whether upstream failed
		// or the analyst walked away.
		s.recordQuestion(r, req)
		// The caller hung up. Nothing is wrong here and nobody is listening.
		if assistant.ClientAbandoned(err) {
			slog.Info("assistant run abandoned by caller", "agent", req.Agent, "surface", req.Surface)
			return
		}
		// The upstream message can carry provider detail; log it, do not return
		// it to a browser. OperatorMessage picks from a fixed set of sentences.
		slog.Warn("assistant run failed", "agent", req.Agent, "error", err)
		writeJSON(w, http.StatusBadGateway,
			map[string]string{"error": assistant.OperatorMessage(err)})
		return
	}

	// Who asked what, about which incident. In a SOC that is evidence handling:
	// a post-incident review has to be able to tell which conclusions were
	// assisted.
	slog.Info("assistant answered", "agent", req.Agent, "surface", req.Surface, "exec_id", req.ExecID,
		"steps", len(ans.Steps), "grounded", ans.Grounded, "duration", ans.Duration)

	s.recordExchange(r, req, ans, model)

	writeJSON(w, http.StatusOK, ans)
}

// handleAssistantStream is handleAssistantAsk with the investigation streamed.
//
//	POST /api/assistant/stream   same body as /ask, replies text/event-stream
//
// The tenant rules are identical to the non-streaming path and are worth
// restating because streaming is where they are easiest to lose: the caller's
// cookie is forwarded verbatim, the history write goes through the same
// scope-checked recordExchange, and nothing here constructs a runner without a
// session.
func (s *Server) handleAssistantStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	// Who is asking, and about which customer — the SAME assistantScope call as
	// the non-streaming path, not a re-implementation of it, so the customer is
	// resolved, authorized and audited here exactly as it is there. A second
	// copy of a handler is where a rule stops being applied twice, which is why
	// TestBothAssistantAsksUseTheSharedGate pins both entry points to this call
	// rather than only checking what the gate does. (Said in the body rather
	// than in the doc comment above: scripts/ci/gen-openapi.py publishes that
	// comment as this route's API description, and the spec is regenerated
	// centrally.)
	tenant, ok := s.assistantScope(w, r)
	if !ok {
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

	// Upgrade before running: once the first event is written the status and
	// headers are already sent, so an un-streamable writer has to be reported
	// while a JSON error is still possible.
	stream, ok := assistant.NewStreamWriter(w)
	if !ok {
		writeJSON(w, http.StatusInternalServerError,
			map[string]string{"error": "this server cannot stream"})
		return
	}

	// The RUN budget, NOT the per-completion timeout. These used to be the same
	// number, so Runner.Run — which issues up to MaxToolCalls completions plus
	// a closing one — had to finish seven provider calls inside the time
	// allotted to a single call. That was invisible while upstream answered in
	// ~1s and became every-request-fails the day upstream slowed down.
	budget := cfg.RunBudget
	if budget <= 0 {
		budget = 150 * time.Second
	}
	// The per-call timeout stays separate: it bounds each tool read below, and
	// the provider client bounds each completion with the same value.
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	ctx, cancel := contextWithTimeout(r, budget)
	defer cancel()

	// One conversation, one model. See assistantmodel.go.
	model := s.modelForExchange(r, req)
	runner := &assistant.Runner{
		Provider: providerFor(cfg, model),
		Tools:    assistant.DefaultTools(),
		Client:   assistant.NewReadOnlyClient(timeout, nil),
		BaseURL:  s.selfBaseURL(),
		Cookie:   r.Header.Get("Cookie"),
		// The customer the ask named, exactly as on the non-streaming path.
		Tenant:   tenant,
		Surface:  req.Surface,
		MaxCalls: cfg.MaxToolCalls,
		OnStep:   stream.Step,
	}
	runner.History, runner.HistoryGrounded = s.historyFor(r, req)

	ans, err := runner.Run(ctx, req.Agent, req.Question, req.ExecID)
	if err != nil {
		s.recordQuestion(r, req)
		if assistant.ClientAbandoned(err) {
			slog.Info("assistant stream abandoned by caller", "agent", req.Agent, "surface", req.Surface)
			return
		}
		slog.Warn("assistant stream failed", "agent", req.Agent, "error", err)
		stream.Error(assistant.OperatorMessage(err))
		return
	}

	slog.Info("assistant answered (streamed)", "agent", req.Agent, "surface", req.Surface,
		"exec_id", req.ExecID, "steps", len(ans.Steps), "grounded", ans.Grounded, "duration", ans.Duration)

	s.recordExchange(r, req, ans, model)
	stream.Answer(ans)
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

func (s *Server) recordExchange(r *http.Request, req cpAskRequest, ans assistant.Answer, model string) {
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
		// The model that actually answered, not the deployment default. With
		// two models configured the default is wrong for half the traffic, and
		// a history that misattributes its own turns cannot answer "which
		// model said that?" after an assisted conclusion turns out to be wrong.
		Role: "assistant", Content: ans.Content, Model: model,
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
