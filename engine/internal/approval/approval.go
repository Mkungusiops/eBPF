// Package approval is change-control for destructive fleet actions
// (threat-model EN-2, roadmap Phase 2 exit gate).
//
// EN-2 is the risk that ONE command quarantines or severs many hosts — whether
// through operator error, a stolen console session, or a compromised control
// plane. A reason string, which the choke API already requires, records WHY
// afterwards; it does not stop a single person from doing it. Dual control does:
// a destructive action is held until a SECOND operator approves it, and the
// approver may not be the requester.
//
// # What is gated, and what must never be
//
// Only the DANGEROUS DIRECTION is gated. Approvals that can block containment
// during an incident turn a safety control into an outage, so:
//
//   - Gated: quarantine and sever (disruptive/irreversible), and fleet-wide
//     arming — switching a whole tenant into enforcing, or applying the
//     mass-choke containment preset.
//   - NEVER gated: thaw and the reversible rungs (throttle/tarpit); the
//     kill-switch, which is the emergency stop — requiring a quorum to STOP
//     enforcing is how a bad rollout becomes an incident; and disarming a
//     tenant back to detect-only.
//
// Also never gated: the agent's own score-driven enforcement. Automatic
// containment on a host is untouched by any of this. Approvals gate a human
// reaching across the fleet from a console, which is precisely the EN-2 threat,
// and is why holding those requests cannot leave a host undefended.
package approval

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Status is where a request sits in its lifecycle.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusExpired  Status = "expired"
)

// Errors callers turn into HTTP responses.
var (
	ErrNotFound = errors.New("no such approval request")
	ErrDecided  = errors.New("this request has already been decided")
	ErrExpired  = errors.New("this request has expired; re-issue the action")
	// ErrSelfApproval is the control this package exists for.
	ErrSelfApproval = errors.New("the operator who requested an action cannot approve it; a second operator must")
)

// DefaultTTL bounds how long a pending request may be approved.
//
// A destructive action approved hours after it was asked for is not the action
// anyone reviewed — the process may be gone and its PID reused, and the incident
// that justified it is over. Short enough that approval means "still true now",
// long enough for a second operator to actually be found.
const DefaultTTL = 30 * time.Minute

// Request is one destructive action awaiting a second pair of eyes. It doubles
// as the audit record: who asked, who decided, when, and what happened.
type Request struct {
	ID      string `json:"id"`
	Tenant  string `json:"tenant"`
	Action  string `json:"action"`
	ExecID  string `json:"exec_id,omitempty"`
	PID     uint32 `json:"pid,omitempty"`
	AgentID string `json:"agent_id,omitempty"`
	MAC     string `json:"mac,omitempty"`
	// Scope distinguishes a single target from a fleet-wide change, because the
	// blast radius is what the approver is being asked to judge.
	Scope     string    `json:"scope"` // "target" | "fleet"
	Reason    string    `json:"reason"`
	Requester string    `json:"requester"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`

	Status     Status    `json:"status"`
	Approver   string    `json:"approver,omitempty"`
	DecidedAt  time.Time `json:"decided_at,omitempty"`
	DecideNote string    `json:"decide_note,omitempty"`
	// Outcome is what happened when the approved action actually ran, so the
	// record answers "was it applied?", not merely "was it allowed?".
	Outcome  string `json:"outcome,omitempty"`
	Executed bool   `json:"executed"`
}

// Expired reports whether r is past its window (evaluated at t).
func (r Request) Expired(t time.Time) bool { return t.After(r.ExpiresAt) }

// RequiresApproval reports whether a per-target choke action needs dual control.
// See the package doc for why the reversible rungs and thaw are excluded.
func RequiresApproval(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "quarantine", "sever":
		return true
	default:
		return false
	}
}

// FleetChangeRequiresApproval reports whether a fleet-wide posture change needs
// dual control. Only ARMING does: disarming to detect-only, and the kill-switch,
// are the ways out of a bad state and must never need a quorum.
func FleetChangeRequiresApproval(change string, arming bool) bool {
	switch strings.ToLower(strings.TrimSpace(change)) {
	case "mode":
		return arming
	case "preset":
		return arming // only the mass-choke containment preset sets this
	default:
		return false
	}
}

// Store holds pending and recently-decided requests, tenant-scoped.
//
// In-memory for now, like the rest of the Phase 1 control state that has not
// moved to Postgres yet. Losing pending requests on restart fails CLOSED — a
// destructive action that was never approved simply does not happen — which is
// the right direction for a change-control record to fail in.
type Store struct {
	mu      sync.Mutex
	byID    map[string]*Request
	ttl     time.Duration
	history int // how many decided requests to retain per tenant
	now     func() time.Time
}

func NewStore(ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Store{byID: map[string]*Request{}, ttl: ttl, history: 200, now: time.Now}
}

// Create records a new pending request and returns it.
func (s *Store) Create(r Request) Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	r.ID = newID()
	r.CreatedAt = now
	r.ExpiresAt = now.Add(s.ttl)
	r.Status = StatusPending
	if r.Scope == "" {
		r.Scope = "target"
	}
	s.byID[r.ID] = &r
	s.gcLocked()
	return r
}

// Get returns a request, tenant-scoped so one tenant can never read or act on
// another's change-control queue.
func (s *Store) Get(tenant, id string) (Request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[id]
	if !ok || r.Tenant != tenant {
		return Request{}, false
	}
	out := *r
	if out.Status == StatusPending && out.Expired(s.now()) {
		out.Status = StatusExpired
	}
	return out, true
}

// List returns the tenant's requests, pending first, newest first within each
// group. Expiry is materialised on read so a stale request never displays as
// actionable.
func (s *Store) List(tenant string) []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	out := []Request{}
	for _, r := range s.byID {
		if r.Tenant != tenant {
			continue
		}
		c := *r
		if c.Status == StatusPending && c.Expired(now) {
			c.Status = StatusExpired
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		ip, jp := out[i].Status == StatusPending, out[j].Status == StatusPending
		if ip != jp {
			return ip
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}

// Decide approves or denies a pending request on behalf of approver.
//
// The four-eyes check is here, not in the handler, so it cannot be forgotten by
// a new call site: whoever asked for a destructive action may never be the one
// who authorizes it, no matter what role they hold.
func (s *Store) Decide(tenant, id, approver, note string, approve bool) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[id]
	if !ok || r.Tenant != tenant {
		return Request{}, ErrNotFound
	}
	if r.Status != StatusPending {
		return *r, fmt.Errorf("%w (%s)", ErrDecided, r.Status)
	}
	now := s.now()
	if r.Expired(now) {
		r.Status = StatusExpired
		return *r, ErrExpired
	}
	// Dual control. Compared case-insensitively because the same human can
	// arrive as "Op@example.com" and "op@example.com" from different sessions,
	// and a control defeated by capitalisation is not a control.
	if strings.EqualFold(strings.TrimSpace(approver), strings.TrimSpace(r.Requester)) {
		return *r, ErrSelfApproval
	}
	if approve {
		r.Status = StatusApproved
	} else {
		r.Status = StatusDenied
	}
	r.Approver = approver
	r.DecidedAt = now
	r.DecideNote = note
	return *r, nil
}

// MarkExecuted records what actually happened when an approved action ran.
func (s *Store) MarkExecuted(tenant, id, outcome string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.byID[id]; ok && r.Tenant == tenant {
		r.Executed = true
		r.Outcome = outcome
	}
}

// PendingCount is the tenant's outstanding approval queue depth.
func (s *Store) PendingCount(tenant string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for _, r := range s.byID {
		if r.Tenant == tenant && r.Status == StatusPending && !r.Expired(now) {
			n++
		}
	}
	return n
}

// gcLocked drops decided/expired records beyond the retention window. Pending
// requests are never dropped — they expire by time, not by pressure.
func (s *Store) gcLocked() {
	if len(s.byID) <= s.history {
		return
	}
	type kv struct {
		id string
		at time.Time
	}
	var decided []kv
	for id, r := range s.byID {
		if r.Status != StatusPending {
			decided = append(decided, kv{id, r.CreatedAt})
		}
	}
	sort.Slice(decided, func(i, j int) bool { return decided[i].at.Before(decided[j].at) })
	for i := 0; i < len(decided) && len(s.byID) > s.history; i++ {
		delete(s.byID, decided[i].id)
	}
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "apr-" + hex.EncodeToString(b)
}
