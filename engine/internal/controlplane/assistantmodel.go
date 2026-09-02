package controlplane

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/jeffmk/ebpf-poc-engine/internal/assistant"
)

// Choosing which model answers an exchange.
//
// # One conversation, one model
//
// A deployment may run a fast model for drill panels — where an analyst asks
// one focused question with the panel still open — and a stronger, slower one
// for sustained investigation in the history sidebar.
//
// The choice is made ONCE, when the conversation is created, and stored on the
// chat. Resolving it per request would put two models in a single thread: same
// history, different voice, different failure modes, mid-investigation. That is
// precisely the incoherence AssistantChatProvider was written to prevent —
// "two assistants that look alike but do not share history is the worst
// outcome" — and a thread that silently changes reasoner is a subtler version
// of it.
//
// Storing it also survives a config change: a conversation started last week on
// the deep model keeps answering on the deep model, so an analyst rereading
// their own investigation is not comparing turns from two different systems.
//
// # Why a panel gets the fast model without being asked
//
// The drill panels are incognito by design and send no chat id, so there is no
// conversation to bind and nothing to look up. Absence of a chat id IS the
// signal, which means no new field has to be trusted from the client to decide
// which model runs.
func (s *Server) modelForExchange(r *http.Request, req cpAskRequest) string {
	cfg := s.cfg.Assistant
	chatID := strings.TrimSpace(req.ChatID)
	if chatID == "" {
		// No conversation to bind to. Normally a drill panel's one-shot
		// question — but ALSO the sidebar when the chat store is unreachable,
		// which is why this defers to what the client says it is rather than
		// assuming. Treating every chat-less ask as a panel meant a history
		// outage silently downgraded the sidebar's model, with the answer
		// looking entirely normal.
		return cfg.ModelFor(req.Conversation)
	}
	// A recorded conversation. Its own model wins, whatever the config now says.
	if sc, ok := s.chatScopeFor(r, req); ok && s.chats != nil {
		if c, err := s.chats.GetChat(sc, chatID); err == nil {
			if m := strings.TrimSpace(c.Model); m != "" {
				if cfg.KnownModel(m) {
					return m
				}
				// The row names a model this deployment is not configured to
				// use — a chat from before a model was retired, or an edited
				// row. Fall back rather than send an unrecognised id to the
				// inference endpoint, and say so, because silently answering
				// from a different model than the thread's other turns is the
				// thing this whole file exists to avoid.
				slog.Warn("assistant: conversation names an unconfigured model; using the default",
					"chat", chatID, "stored_model", m, "using", cfg.Model)
				return cfg.ModelFor(false)
			}
		}
	}
	// A conversation with no model recorded: created before the split existed,
	// or the lookup failed. Deep, because only the sidebar creates chats.
	return cfg.ModelFor(true)
}

// providerFor builds a provider pinned to one model id.
//
// A copy of the config rather than a mutable field, so two concurrent requests
// on different models cannot race into each other's answer.
func providerFor(cfg assistant.Config, model string) *assistant.OpenAICompatible {
	return assistant.NewOpenAICompatible(cfg.WithModel(model), nil)
}
