// Package chatstore persists the platform assistant's conversations.
//
// Design: docs/plan/platform-assistant.md.
//
// # The rule this package exists to enforce
//
// "Intelligence across the whole platform" collides with tenant isolation. The
// resolution (platform-assistant.md §1):
//
//	CHAT HISTORY may span tenants — it is the operator's own conversation.
//	THE ANSWERS INSIDE IT never widen — the assistant's tools read
//	tenant-scoped endpoints as the caller, so scope follows the person asking.
//
// A menu-bar chat FEELS like one pane of glass, which is exactly what invites a
// later "optimisation": give the runner a service identity so it can answer
// platform-wide questions. That single change would defeat RLS and every guard
// in internal/isolationguard. So this package never holds an identity of its
// own — every call takes the caller's Scope, and Scope is derived from the
// session upstream, never from a request payload.
//
// Storage mirrors internal/centralstore: Postgres with RLS both ENABLEd and
// FORCEd, reads carrying no tenant predicate so a forgotten WHERE cannot leak.
package chatstore

import (
	"errors"
	"strings"
	"time"
)

// Scope is the caller's authority. It is the ONLY way to reach any row.
//
// Deliberately not a bare tenant string: CrossTenant has to be an explicit,
// greppable field so that "which code can read another tenant's chats" is a
// question with a short answer.
type Scope struct {
	// TenantID is the tenant the caller is acting in. Never taken from a
	// payload — derived from the verified session upstream.
	TenantID string
	// UserID owns the conversations. History is per-operator, not per-tenant:
	// two analysts in one tenant do not share a chat list.
	UserID string
	// CrossTenant is true only for a cross-tenant role (msoc-admin). It widens
	// which of the CALLER'S OWN chats are visible; it never widens whose chats
	// they are, and it has no effect on what the assistant can read when
	// answering — that is governed by the forwarded session.
	CrossTenant bool
}

func (s Scope) valid() error {
	if strings.TrimSpace(s.UserID) == "" {
		return ErrNoScope
	}
	// A cross-tenant caller legitimately has no single tenant.
	if !s.CrossTenant && strings.TrimSpace(s.TenantID) == "" {
		return ErrNoScope
	}
	return nil
}

// Chat is one conversation.
type Chat struct {
	ID       string
	TenantID string
	UserID   string
	Title    string
	// Mode distinguishes an incident conversation from an ad-hoc one; reserved
	// for the per-incident grouping in platform-assistant.md §3.
	Mode string
	// CompactedSummary holds an earlier span of the conversation, summarised.
	//
	// Present from the first migration on purpose. A long incident conversation
	// WILL exceed the model's context, and retrofitting compaction later means
	// either truncating silently (the analyst loses the start of their own
	// investigation) or a migration under pressure.
	CompactedSummary string
	PinnedAt         *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Message is one turn.
type Message struct {
	ID      string
	ChatID  string
	Role    string // user | assistant
	Content string
	Model   string
	// Steps and Grounded are STORED, not recomputed.
	//
	// An answer's provenance is part of the record: a post-incident review has
	// to be able to see which endpoints an assisted conclusion was built from,
	// and whether it was grounded at all. Text without them is unusable as
	// evidence — and "grounded" is exactly the field a reviewer will want when
	// an assisted conclusion turns out to be wrong.
	Steps     string // the answer's tool trace, as JSON
	Grounded  bool
	CreatedAt time.Time
}

var (
	// ErrNoScope is returned when a call arrives without a caller identity.
	//
	// This is the package's central guard. It exists so that the convenient
	// mistake — running the assistant with no caller so it can "see
	// everything" — fails loudly at the first store call instead of quietly
	// returning another tenant's conversations.
	ErrNoScope = errors.New("chatstore: refusing to act without a caller scope")
	// ErrNotFound covers both absent and out-of-scope, deliberately: telling a
	// caller a chat EXISTS but is not theirs is a cross-tenant existence oracle.
	ErrNotFound = errors.New("chatstore: not found")
)

// Store is the persistence contract. Every method takes a Scope.
//
// There is intentionally no method that omits it, and no "admin" variant. A
// caller that wants wider reach must present a Scope that grants it, which
// means the widening is visible at the call site and in review.
type Store interface {
	CreateChat(s Scope, title, mode string) (Chat, error)
	ListChats(s Scope, limit int) ([]Chat, error)
	GetChat(s Scope, id string) (Chat, error)
	RenameChat(s Scope, id, title string) error
	PinChat(s Scope, id string, pinned bool) error
	DeleteChat(s Scope, id string) error

	AppendMessage(s Scope, chatID string, m Message) (Message, error)
	ListMessages(s Scope, chatID string, limit int) ([]Message, error)

	// Search matches titles AND message content.
	//
	// Content search is not a nicety: an operator remembers "the one where curl
	// hit /etc/shadow", not a title they never wrote. History that can only be
	// searched by title is write-only.
	Search(s Scope, query string, limit int) ([]Chat, error)
}
