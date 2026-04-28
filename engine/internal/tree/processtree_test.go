package tree

import (
	"testing"
	"time"
)

func TestAddGet(t *testing.T) {
	tr := New(time.Hour)
	n := &Node{ExecID: "a", PID: 1, Binary: "/bin/bash", StartTime: time.Now()}
	tr.Add(n)
	got, ok := tr.Get("a")
	if !ok {
		t.Fatalf("expected node a")
	}
	if got.Binary != "/bin/bash" {
		t.Fatalf("binary mismatch: %s", got.Binary)
	}
}

func TestAncestorsAndChainScore(t *testing.T) {
	tr := New(time.Hour)
	now := time.Now()
	tr.Add(&Node{ExecID: "root", Binary: "/bin/bash", StartTime: now, Score: 1})
	tr.Add(&Node{ExecID: "mid", ParentID: "root", Binary: "/usr/bin/curl", StartTime: now, Score: 25})
	tr.Add(&Node{ExecID: "leaf", ParentID: "mid", Binary: "/bin/sh", StartTime: now, Score: 5})

	chain := tr.Ancestors("leaf", 10)
	if len(chain) != 3 {
		t.Fatalf("expected 3 ancestors, got %d", len(chain))
	}
	if chain[0].ExecID != "root" || chain[2].ExecID != "leaf" {
		t.Fatalf("chain order wrong: %v", chain)
	}

	if got := tr.ChainScore("leaf"); got != 31 {
		t.Fatalf("ChainScore=%d want 31", got)
	}
}

func TestAddScore(t *testing.T) {
	tr := New(time.Hour)
	tr.Add(&Node{ExecID: "a", StartTime: time.Now()})
	if _, ok := tr.AddScore("a", 7, "process_exec"); !ok {
		t.Fatalf("expected AddScore to find a")
	}
	if _, ok := tr.AddScore("missing", 7, "x"); ok {
		t.Fatalf("expected AddScore to miss")
	}
	got, _ := tr.Get("a")
	if got.Score != 7 || len(got.Events) != 1 {
		t.Fatalf("score/events not updated: score=%d events=%v", got.Score, got.Events)
	}
}

func TestGCExpiresOldNodes(t *testing.T) {
	tr := New(50 * time.Millisecond)
	tr.Add(&Node{ExecID: "old", StartTime: time.Now().Add(-time.Hour)})
	tr.Add(&Node{ExecID: "new", StartTime: time.Now()})
	tr.gc()
	if _, ok := tr.Get("old"); ok {
		t.Fatalf("expected 'old' to be GC'd")
	}
	if _, ok := tr.Get("new"); !ok {
		t.Fatalf("expected 'new' to survive GC")
	}
}

func TestAncestorsBreaksOnMissingParent(t *testing.T) {
	tr := New(time.Hour)
	tr.Add(&Node{ExecID: "child", ParentID: "ghost", StartTime: time.Now()})
	chain := tr.Ancestors("child", 10)
	if len(chain) != 1 {
		t.Fatalf("expected chain length 1, got %d", len(chain))
	}
}
