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
}

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
