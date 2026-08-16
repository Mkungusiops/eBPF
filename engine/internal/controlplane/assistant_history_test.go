package controlplane

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/assistant"
	"github.com/jeffmk/ebpf-poc-engine/internal/chatstore"
)

// fakeChats records what recordExchange asks the store to do. It implements the
// whole Store interface so that a method ADDED to Store fails to compile here,
// rather than silently going untested.
type fakeChats struct {
	appended []chatstore.Message
	scopes   []chatstore.Scope
	err      error
}

func (f *fakeChats) AppendMessage(s chatstore.Scope, chatID string, m chatstore.Message) (chatstore.Message, error) {
	if f.err != nil {
		return chatstore.Message{}, f.err
	}
	m.ChatID = chatID
	f.appended = append(f.appended, m)
	f.scopes = append(f.scopes, s)
	return m, nil
}

func (f *fakeChats) CreateChat(chatstore.Scope, string, string) (chatstore.Chat, error) {
	return chatstore.Chat{}, nil
}
func (f *fakeChats) ListChats(chatstore.Scope, int) ([]chatstore.Chat, error) { return nil, nil }
func (f *fakeChats) GetChat(chatstore.Scope, string) (chatstore.Chat, error) {
	return chatstore.Chat{}, nil
}
func (f *fakeChats) RenameChat(chatstore.Scope, string, string) error { return nil }
func (f *fakeChats) PinChat(chatstore.Scope, string, bool) error      { return nil }
func (f *fakeChats) DeleteChat(chatstore.Scope, string) error         { return nil }
func (f *fakeChats) ListMessages(chatstore.Scope, string, int) ([]chatstore.Message, error) {
	return nil, nil
}
func (f *fakeChats) Search(chatstore.Scope, string, int) ([]chatstore.Chat, error) { return nil, nil }

// serverWithChats builds the smallest Server that can resolve a principal.
func serverWithChats(store chatstore.Store) *Server {
	s := &Server{chats: store}
	s.cfg.AdminToken = "test-token"
	s.cfg.Assistant.Model = "test-model"
	return s
}

func TestIncognitoAskPersistsNothing(t *testing.T) {
	// The default is no record, and it has to STAY the default: an analyst may
	// ask about a live breach before it is classified. A change that starts
	// persisting un-ided asks would be invisible to everyone except the person
	// whose unclassified question ended up in a database.
	f := &fakeChats{}
	s := serverWithChats(f)
	r := httptest.NewRequest("POST", "/api/assistant/ask", nil)
	r.Header.Set("Authorization", "Bearer test-token")

	s.recordExchange(r, cpAskRequest{Agent: "triage", Question: "is this a breach?"},
		assistant.Answer{Content: "no"})

	if len(f.appended) != 0 {
		t.Errorf("an ask with no chat_id persisted %d messages; incognito must leave no record",
			len(f.appended))
	}
}

func TestAskWithChatIDStoresBothTurnsWithProvenance(t *testing.T) {
	f := &fakeChats{}
	s := serverWithChats(f)
	r := httptest.NewRequest("POST", "/api/assistant/ask", nil)
	r.Header.Set("Authorization", "Bearer test-token")

	s.recordExchange(r,
		cpAskRequest{Agent: "triage", Question: "what happened on host-3?", ChatID: "c1"},
		assistant.Answer{
			Content:  "curl read /etc/shadow",
			Steps:    []assistant.Step{{Tool: "soc_alerts"}},
			Grounded: true,
		})

	if len(f.appended) != 2 {
		t.Fatalf("stored %d messages, want the question and the answer", len(f.appended))
	}
	if f.appended[0].Role != "user" || f.appended[0].Content != "what happened on host-3?" {
		t.Errorf("first stored message is %+v, want the analyst's question", f.appended[0])
	}
	a := f.appended[1]
	if a.Role != "assistant" || a.Content != "curl read /etc/shadow" {
		t.Errorf("second stored message is %+v, want the answer", a)
	}
	// Provenance is the reason this is stored at all. Text alone is unusable as
	// evidence in a post-incident review.
	if !a.Grounded {
		t.Error("a grounded answer was stored as ungrounded")
	}
	if a.Steps == "" || a.Steps == "null" {
		t.Errorf("the answer's tool trace was not stored (steps=%q)", a.Steps)
	}
	if a.Model == "" {
		t.Error("the answering model was not stored; a review cannot attribute the answer")
	}
}

func TestUngroundedAnswersAreStoredAsUngrounded(t *testing.T) {
	// The field a reviewer wants most is the one recording that the assistant
	// could not ground its answer. Dropping or defaulting it would make every
	// stored answer look verified.
	f := &fakeChats{}
	s := serverWithChats(f)
	r := httptest.NewRequest("POST", "/api/assistant/ask", nil)
	r.Header.Set("Authorization", "Bearer test-token")

	s.recordExchange(r, cpAskRequest{Agent: "triage", Question: "q", ChatID: "c1"},
		assistant.Answer{Content: "could not ground an answer", Grounded: false})

	if len(f.appended) != 2 {
		t.Fatalf("stored %d messages, want 2", len(f.appended))
	}
	if f.appended[1].Grounded {
		t.Error("an ungrounded answer was stored as grounded")
	}
}

func TestHistoryFailuresNeverPropagate(t *testing.T) {
	// The analyst already has their answer. A store outage must not be able to
	// turn a good response into an error, and a nil store must not panic — that
	// is the state of every deployment without Postgres.
	for name, s := range map[string]*Server{
		"store errors":   serverWithChats(&fakeChats{err: errors.New("db down")}),
		"store disabled": serverWithChats(nil),
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/api/assistant/ask", nil)
			r.Header.Set("Authorization", "Bearer test-token")
			// No panic, no return value to check: the contract is that this is
			// side-effect only and cannot affect the response.
			s.recordExchange(r, cpAskRequest{Question: "q", ChatID: "c1"},
				assistant.Answer{Content: "a"})
		})
	}
}

func TestUnauthenticatedAskIsNeverPersisted(t *testing.T) {
	// recordExchange derives the owning scope from the verified session. With no
	// principal there is no owner, and a message stored without one would belong
	// to whoever has an empty user id.
	f := &fakeChats{}
	s := serverWithChats(f)
	r := httptest.NewRequest("POST", "/api/assistant/ask", nil) // no Authorization

	s.recordExchange(r, cpAskRequest{Question: "q", ChatID: "c1"}, assistant.Answer{Content: "a"})

	if len(f.appended) != 0 {
		t.Errorf("stored %d messages for an unauthenticated caller; every row must have "+
			"an owner derived from a verified session", len(f.appended))
	}
}

func TestStoredScopeComesFromTheSessionNotTheRequest(t *testing.T) {
	// The chat id is attacker-controlled; the SCOPE must not be. Whatever id is
	// passed, the scope handed to the store is the caller's own.
	f := &fakeChats{}
	s := serverWithChats(f)
	r := httptest.NewRequest("POST", "/api/assistant/ask", nil)
	r.Header.Set("Authorization", "Bearer test-token")

	s.recordExchange(r, cpAskRequest{Question: "q", ChatID: "someone-elses-chat"},
		assistant.Answer{Content: "a"})

	if len(f.scopes) == 0 {
		t.Fatal("nothing was stored")
	}
	for _, sc := range f.scopes {
		if sc.UserID != "admin" {
			t.Errorf("stored under user %q, want the authenticated subject", sc.UserID)
		}
		if err := sc.Validate(); err != nil {
			t.Errorf("an invalid scope reached the store: %v", err)
		}
	}
}
