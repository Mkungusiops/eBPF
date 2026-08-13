package tree

import (
	"sync"
	"time"
)

type Node struct {
	ExecID    string    `json:"exec_id"`
	PID       uint32    `json:"pid"`
	ParentID  string    `json:"parent_id"`
	Binary    string    `json:"binary"`
	Args      string    `json:"args"`
	UID       uint32    `json:"uid"`
	StartTime time.Time `json:"start_time"`
	Score     int       `json:"score"`
	Events    []string  `json:"events"`

	// AlertBand is the highest severity band already alerted for the chain
	// ROOTED at this node (see EscalateAlert). Held on the root rather than
	// per-process because ChainScore is inherited: a shell that has done one
	// bad thing taints every command run after it, so each of its short-lived
	// children starts at the parent's accumulated score and alerts at the same
	// severity. Deduplicating per-process barely helps — on a measured run
	// there were 64 distinct exec_ids behind 100 alerts and only 5 distinct
	// descriptions.
	AlertBand int `json:"alert_band"`

	// alertedReasons is the set of distinct findings already reported for this
	// chain. Band escalation alone is not enough: whichever event happens to
	// cross a band first claims the alert, and a later, more informative event
	// on the same chain is then silenced. Measured — deduplicating on band
	// only, the reverse-shell, living-off-the-land and webshell simulations
	// each stopped producing any alert naming them, because an earlier
	// file-read had already pushed the chain to critical.
	alertedReasons map[string]bool
}

// maxAlertedReasons bounds the per-chain reason set. Reasons come from a small
// fixed vocabulary in the scorer, but the set is keyed by the formatted string
// (which embeds a file path), so a process touching thousands of paths would
// otherwise grow it without limit for as long as the chain lives.
const maxAlertedReasons = 32

type Tree struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	ttl   time.Duration
}

func New(ttl time.Duration) *Tree {
	t := &Tree{
		nodes: make(map[string]*Node),
		ttl:   ttl,
	}
	go t.gcLoop()
	return t
}

func (t *Tree) Add(n *Node) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nodes[n.ExecID] = n
}

func (t *Tree) Get(execID string) (*Node, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	n, ok := t.nodes[execID]
	return n, ok
}

func (t *Tree) AddScore(execID string, delta int, eventType string) (*Node, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n, ok := t.nodes[execID]
	if !ok {
		return nil, false
	}
	n.Score += delta
	n.Events = append(n.Events, eventType)
	return n, true
}

// EscalateAlert reports whether this event is worth an alert on its chain, and
// records it if so. It says yes when either:
//
//   - `band` is a new high-water severity for the chain — an escalation is news
//     even if the finding behind it was already reported; or
//   - `reason` is a finding not yet reported on this chain — a new KIND of bad
//     behaviour is news even when the severity has already peaked.
//
// Neither test is sufficient alone. Alerting on every event above the threshold
// made 91 of 100 alerts critical on a measured run, because chain scores are
// cumulative and never fall. But deduplicating on band alone silenced three of
// six attack simulations outright: an early file-read pushed the chain to
// critical, so the later event that actually identified the reverse shell had
// no band left to climb and never surfaced.
//
// The state lives on the chain root so a whole session is deduplicated
// together, matching how ChainScore already attributes a descendant's score to
// its ancestors. Enforcement is unaffected: the choke gateway is dispatched on
// every event regardless of whether an alert is emitted.
func (t *Tree) EscalateAlert(execID string, band int, reason string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	root, ok := t.nodes[execID]
	if !ok {
		// No node means no chain to attribute this to. Let it alert rather
		// than swallowing it — silence here would hide a real event.
		return true
	}
	for i := 0; i < 10 && root.ParentID != ""; i++ {
		parent, ok := t.nodes[root.ParentID]
		if !ok {
			break
		}
		root = parent
	}

	escalated := band > root.AlertBand
	if escalated {
		root.AlertBand = band
	}

	novel := false
	if reason != "" {
		if root.alertedReasons == nil {
			root.alertedReasons = make(map[string]bool, 8)
		}
		if !root.alertedReasons[reason] {
			// Past the cap, stop recording but keep reporting escalations —
			// dropping those would hide a genuine rise in severity.
			if len(root.alertedReasons) < maxAlertedReasons {
				root.alertedReasons[reason] = true
				novel = true
			}
		}
	}

	return escalated || novel
}

func (t *Tree) Ancestors(execID string, max int) []*Node {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var chain []*Node
	cur := execID
	for i := 0; i < max; i++ {
		n, ok := t.nodes[cur]
		if !ok {
			break
		}
		chain = append([]*Node{n}, chain...)
		if n.ParentID == "" {
			break
		}
		cur = n.ParentID
	}
	return chain
}

func (t *Tree) ChainScore(execID string) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	score := 0
	cur := execID
	for i := 0; i < 10; i++ {
		n, ok := t.nodes[cur]
		if !ok {
			break
		}
		score += n.Score
		if n.ParentID == "" {
			break
		}
		cur = n.ParentID
	}
	return score
}

func (t *Tree) gcLoop() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for range tick.C {
		t.gc()
	}
}

func (t *Tree) gc() {
	cutoff := time.Now().Add(-t.ttl)
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, n := range t.nodes {
		if n.StartTime.Before(cutoff) {
			delete(t.nodes, k)
		}
	}
}
