package controlplane

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/assistant"
	"github.com/jeffmk/ebpf-poc-engine/internal/chatstore"
)

// One conversation, one model.
//
// AssistantChatProvider states the rule these protect: "a question started
// inside a drill panel has to be the SAME conversation, opened wider". A
// deployment running a fast model for panels and a stronger one for the
// sidebar must not turn that into one thread answered by two models — same
// history, different voice, different failure modes, mid-investigation.

func splitServer(t *testing.T, chats chatstore.Store) *Server {
	t.Helper()
	s := &Server{chats: chats}
	s.cfg.AdminToken = "test-token"
	s.cfg.Assistant.BaseURL = "https://x/v1"
	s.cfg.Assistant.Model = "fast"
	s.cfg.Assistant.DeepModel = "deep"
	return s
}

// askFor builds a request the scope resolver will accept, so modelForExchange
// reaches the store rather than bailing on an unauthenticated caller.
func askFor(chatID string) (*http.Request, cpAskRequest) {
	r := httptest.NewRequest(http.MethodPost, "/api/assistant/ask", nil)
	r.Header.Set("Authorization", "Bearer test-token")
	return r, cpAskRequest{Question: "what happened?", ChatID: chatID}
}

func TestASidebarWithNoChatStillGetsTheDeepModel(t *testing.T) {
	// The regression this exists to stop. The chat store went unreachable, the
	// sidebar kept working and kept sending no chat id, and every ask was
	// answered by the PANEL model — an entirely normal-looking answer from the
	// wrong reasoner, with nothing on screen saying so.
	s := splitServer(t, &fakeChats{})
	r, req := askFor("")
	req.Conversation = true
	if got := s.modelForExchange(r, req); got != "deep" {
		t.Fatalf("model = %q — a history outage silently downgraded the sidebar", got)
	}
}

func TestADrillPanelGetsTheFastModel(t *testing.T) {
	// Panels are incognito and send no chat id. Absence IS the signal, so no
	// new client-supplied field decides which model runs.
	s := splitServer(t, &fakeChats{})
	r, req := askFor("")
	if got := s.modelForExchange(r, req); got != "fast" {
		t.Fatalf("panel model = %q, want fast", got)
	}
}

func TestAConversationKeepsTheModelItWasCreatedWith(t *testing.T) {
	// The whole point. Even after the deployment's defaults change, a thread
	// answers from the model its earlier turns came from.
	s := splitServer(t, &fakeChats{chat: chatstore.Chat{Model: "deep"}})
	r, req := askFor("chat-1")
	if got := s.modelForExchange(r, req); got != "deep" {
		t.Fatalf("conversation model = %q, want the stored deep model", got)
	}

	// Config now says something different. The conversation does not follow it.
	s.cfg.Assistant.Model = "deep"
	s.cfg.Assistant.DeepModel = "fast"
	if got := s.modelForExchange(r, req); got != "deep" {
		t.Fatalf("a config change moved a live conversation to %q", got)
	}
}

func TestAConversationNamingAnUnconfiguredModelFallsBack(t *testing.T) {
	// The id comes out of Postgres. A retired model, a bad migration or an
	// edited row must not become a request against something nobody
	// configured.
	s := splitServer(t, &fakeChats{chat: chatstore.Chat{Model: "retired-model"}})
	r, req := askFor("chat-1")
	if got := s.modelForExchange(r, req); got != "fast" {
		t.Fatalf("model = %q, want the configured default", got)
	}
}

func TestAPreSplitConversationGetsTheDeepModel(t *testing.T) {
	// Chats created before the split have no model recorded. Only the sidebar
	// creates chats, so the honest reading of a blank is "a conversation".
	s := splitServer(t, &fakeChats{chat: chatstore.Chat{Model: ""}})
	r, req := askFor("chat-legacy")
	if got := s.modelForExchange(r, req); got != "deep" {
		t.Fatalf("legacy conversation model = %q, want deep", got)
	}
}

func TestASingleModelDeploymentAnswersEverythingTheSameWay(t *testing.T) {
	// The default, and the one that must not regress: every existing
	// deployment has no DeepModel and must keep one model everywhere.
	s := splitServer(t, &fakeChats{chat: chatstore.Chat{Model: ""}})
	s.cfg.Assistant.DeepModel = ""

	rPanel, reqPanel := askFor("")
	rChat, reqChat := askFor("chat-1")
	if a, b := s.modelForExchange(rPanel, reqPanel), s.modelForExchange(rChat, reqChat); a != "fast" || b != "fast" {
		t.Fatalf("single-model deployment split anyway: panel=%q sidebar=%q", a, b)
	}
}

func TestTheStoredTurnIsStampedWithTheModelThatAnswered(t *testing.T) {
	// A history that misattributes its own turns cannot answer "which model
	// said that?" after an assisted conclusion turns out to be wrong — and
	// with two models the deployment default is wrong for half the traffic.
	f := &fakeChats{chat: chatstore.Chat{Model: "deep"}}
	s := splitServer(t, f)
	r, req := askFor("chat-1")

	s.recordExchange(r, req, assistant.Answer{Content: "an answer", Grounded: true}, s.modelForExchange(r, req))

	var stamped string
	for _, m := range f.appended {
		if m.Role == "assistant" {
			stamped = m.Model
		}
	}
	if stamped != "deep" {
		t.Fatalf("answer stamped %q, want the model that actually answered", stamped)
	}
	if stamped == s.cfg.Assistant.Model {
		t.Fatal("the stamp is the deployment default, which is the bug this guards")
	}
}
