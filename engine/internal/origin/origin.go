// Package origin attributes processes to the remote client that triggered
// them. The choke gateway calls Lookup on every Decision so the audit row
// records *who* set off the chain, not just *what* the server-side
// process did.
//
// Sources of attribution live in sibling files (sshd_tailer_*.go,
// future http_middleware.go, future tracingpolicy_accept.go). Each
// source calls Record with an (pid, Origin) pair; this file is a thin
// concurrent map with TTL eviction and ancestor-walk lookup.
package origin

import (
	"sync"
	"time"
)

// Kind labels where the attribution came from. Used by the UI to pick a
// badge / colour and by the operator to filter ("show me ssh-originated
// chains only").
type Kind string

const (
	KindSSH     Kind = "ssh"
	KindHTTP    Kind = "http"
	KindLocal   Kind = "local" // local daemon (cron, systemd timer, …)
	KindUnknown Kind = ""      // not yet attributed — UI renders as "—"
)

// Origin describes the remote client that initiated the activity. All
// fields except Kind are best-effort: a generic inbound TCP accept will
// fill IP/Port but not Fingerprint; an SSH session populates Fingerprint
// via the journald tailer.
type Origin struct {
	Kind        Kind      `json:"kind,omitempty"`
	RemoteIP    string    `json:"remote_ip,omitempty"`
	RemotePort  uint16    `json:"remote_port,omitempty"`
	User        string    `json:"user,omitempty"`        // login user (ssh)
	Fingerprint string    `json:"fingerprint,omitempty"` // ssh key fp, e.g. "ED25519 SHA256:abc..."
	FirstSeen   time.Time `json:"first_seen,omitempty"`
}

// HasAttribution reports whether the Origin carries any useful identity
// beyond "we know it exists". Used by the UI to choose between rendering
// the row's columns and showing the "—" placeholder.
func (o Origin) HasAttribution() bool {
	return o.RemoteIP != "" || o.Fingerprint != "" || o.User != ""
}

// AncestorsFn is the process-tree walk callback supplied by the engine.
// Given a PID, it returns its ancestors (parent, grandparent, …) up to
// some depth. The tracker uses it so a grandchild process inherits the
// nearest ancestor's Origin — the typical sshd → bash → curl chain works
// out of the box.
type AncestorsFn func(pid uint32) []uint32

// Tracker is the in-memory store. Safe for concurrent use. Entries are
// evicted after TTL since LastSeen; default TTL is 30 min which covers
// the lifetime of typical SSH sessions without unbounded growth.
type Tracker struct {
	mu    sync.RWMutex
	byPID map[uint32]entry
	ttl   time.Duration
	now   func() time.Time // override-able for tests
}

type entry struct {
	o        Origin
	lastSeen time.Time
}

// NewTracker returns a Tracker with the given TTL. Zero or negative TTL
// disables eviction (callers should provide a sane default).
func NewTracker(ttl time.Duration) *Tracker {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &Tracker{
		byPID: make(map[uint32]entry),
		ttl:   ttl,
		now:   time.Now,
	}
}

// Record stores an Origin for the given PID. If an entry already exists,
// the new Origin merges over it field-by-field (non-empty new fields win)
// so a sshd-tailer Fingerprint update doesn't wipe an earlier RemoteIP.
func (t *Tracker) Record(pid uint32, o Origin) {
	if pid == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if e, ok := t.byPID[pid]; ok {
		e.o = merge(e.o, o)
		e.lastSeen = now
		t.byPID[pid] = e
		return
	}
	if o.FirstSeen.IsZero() {
		o.FirstSeen = now
	}
	t.byPID[pid] = entry{o: o, lastSeen: now}
}

// Lookup returns the Origin for a PID. If the PID has no direct entry,
// the ancestors function (typically the engine's process tree) is walked
// and the nearest ancestor's Origin is returned — that's what gives the
// "bash inherits its sshd parent's origin" behavior. Returns Origin{}, false
// if neither the pid nor any ancestor has an attribution.
func (t *Tracker) Lookup(pid uint32, ancestors AncestorsFn) (Origin, bool) {
	if pid == 0 {
		return Origin{}, false
	}
	t.mu.RLock()
	if e, ok := t.byPID[pid]; ok {
		t.mu.RUnlock()
		return e.o, true
	}
	t.mu.RUnlock()
	if ancestors == nil {
		return Origin{}, false
	}
	for _, ppid := range ancestors(pid) {
		t.mu.RLock()
		e, ok := t.byPID[ppid]
		t.mu.RUnlock()
		if ok {
			return e.o, true
		}
	}
	return Origin{}, false
}

// Forget drops a PID's attribution. Called when the engine sees a
// process exit so the map stays bounded even if the TTL sweeper hasn't
// run yet.
func (t *Tracker) Forget(pid uint32) {
	t.mu.Lock()
	delete(t.byPID, pid)
	t.mu.Unlock()
}

// Sweep evicts entries older than TTL. Safe to call from a ticker
// goroutine; cheap (O(n) map walk under the write lock).
func (t *Tracker) Sweep() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := t.now().Add(-t.ttl)
	n := 0
	for pid, e := range t.byPID {
		if e.lastSeen.Before(cutoff) {
			delete(t.byPID, pid)
			n++
		}
	}
	return n
}

// Snapshot returns a copy of every tracked (pid, Origin). Used by the
// /api/origin debug endpoint and by tests.
func (t *Tracker) Snapshot() map[uint32]Origin {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[uint32]Origin, len(t.byPID))
	for pid, e := range t.byPID {
		out[pid] = e.o
	}
	return out
}

// merge overlays new non-empty fields onto old. Order matters: the
// sshd_tailer fires after the accept event (a few ms typically) so
// later writes are richer — we want them to win.
func merge(old, new Origin) Origin {
	if new.Kind != KindUnknown {
		old.Kind = new.Kind
	}
	if new.RemoteIP != "" {
		old.RemoteIP = new.RemoteIP
	}
	if new.RemotePort != 0 {
		old.RemotePort = new.RemotePort
	}
	if new.User != "" {
		old.User = new.User
	}
	if new.Fingerprint != "" {
		old.Fingerprint = new.Fingerprint
	}
	if !new.FirstSeen.IsZero() && (old.FirstSeen.IsZero() || new.FirstSeen.Before(old.FirstSeen)) {
		old.FirstSeen = new.FirstSeen
	}
	return old
}
