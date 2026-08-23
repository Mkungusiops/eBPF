package api

import (
	"testing"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
)

// An ALERT carries exec_id and nothing else — no pid, no binary. Before the
// engine decoded exec_id, the console's alert-to-contain path could not name a
// target at all and every attempt answered 400.
func TestExecIDResolvesToAPIDThroughTheTree(t *testing.T) {
	tr := tree.New(time.Minute)
	tr.Add(&tree.Node{ExecID: "abc123", PID: 4242, Binary: "/usr/bin/curl", StartTime: time.Now()})

	n, ok := tr.Get("abc123")
	if !ok || n.PID != 4242 {
		t.Fatalf("precondition: the tree must resolve exec_id -> pid, got %v/%v", n, ok)
	}
}

// The tree is authoritative rather than the /proc scan precisely because it
// still knows the pid of a process that has since exited. A jail on a dead pid
// is a harmless no-op with an honest audit row; refusing to name a target at
// all is a 400 in the operator's face.
func TestUnknownExecIDYieldsNoTargetRatherThanAWrongOne(t *testing.T) {
	tr := tree.New(time.Minute)
	if _, ok := tr.Get("never-seen"); ok {
		t.Fatal("an unknown exec_id must not resolve to a target")
	}
}
