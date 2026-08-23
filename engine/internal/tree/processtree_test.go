package tree

import (
	"fmt"
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

// Alerting on every event above the threshold made 91 of 100 alerts critical on
// a measured run: chain scores are cumulative and never fall, so once a chain
// crosses a band every later event repeats it. Alerts must fire on the
// TRANSITION instead.
func TestEscalateAlertOnlyOnIncrease(t *testing.T) {
	tr := New(time.Hour)
	tr.Add(&Node{ExecID: "root", Binary: "/bin/bash", StartTime: time.Now()})

	if !tr.EscalateAlert("root", 2, "r1") {
		t.Fatalf("first escalation to medium must alert")
	}
	if tr.EscalateAlert("root", 2, "r1") {
		t.Fatalf("a repeat at the SAME band must not alert — this is the 91-of-100 bug")
	}
	if tr.EscalateAlert("root", 1, "r1") {
		t.Fatalf("a LOWER band must not alert")
	}
	if !tr.EscalateAlert("root", 4, "r1") {
		t.Fatalf("a rise to critical must alert — escalations are the news")
	}
	if tr.EscalateAlert("root", 4, "r1") {
		t.Fatalf("critical must not repeat once reported")
	}
}

// The high-water mark lives on the chain ROOT. A tainted shell passes its
// accumulated score to every child, so each short-lived child would otherwise
// alert at the parent's severity — 64 distinct exec_ids produced 100 alerts on
// the measured run.
func TestEscalateAlertIsPerChainNotPerProcess(t *testing.T) {
	tr := New(time.Hour)
	tr.Add(&Node{ExecID: "shell", Binary: "/bin/bash", StartTime: time.Now()})
	tr.Add(&Node{ExecID: "c1", ParentID: "shell", Binary: "/bin/cat", StartTime: time.Now()})
	tr.Add(&Node{ExecID: "c2", ParentID: "shell", Binary: "/bin/cat", StartTime: time.Now()})

	if !tr.EscalateAlert("c1", 4, "same-finding") {
		t.Fatalf("the first child to reach critical must alert")
	}
	if tr.EscalateAlert("c2", 4, "same-finding") {
		t.Fatalf("a sibling inheriting the same chain score must NOT raise a second critical")
	}
}

// An event for a process we never saw exec must still alert: silently dropping
// it would hide a real signal, which is worse than a duplicate.
func TestEscalateAlertUnknownProcessStillAlerts(t *testing.T) {
	tr := New(time.Hour)
	if !tr.EscalateAlert("never-seen", 3, "r") {
		t.Fatalf("an unknown exec_id must alert rather than be swallowed")
	}
}

// Deduplicating on band alone silenced three of six attack simulations on the
// live rig: an early file-read pushed the chain to critical, so the later event
// that actually identified the reverse shell had no band left to climb. A new
// KIND of finding must alert even when severity has already peaked.
func TestEscalateAlertReportsNewFindingsAtAPeakedBand(t *testing.T) {
	tr := New(time.Hour)
	tr.Add(&Node{ExecID: "shell", Binary: "/bin/bash", StartTime: time.Now()})

	if !tr.EscalateAlert("shell", 4, "Access to credential file: /etc/shadow") {
		t.Fatalf("first finding must alert")
	}
	if tr.EscalateAlert("shell", 4, "Access to credential file: /etc/shadow") {
		t.Fatalf("the same finding at the same band must not repeat")
	}
	if !tr.EscalateAlert("shell", 4, "Reverse shell tool with -e or shell argument") {
		t.Fatalf("a DIFFERENT finding must alert even though the band has peaked")
	}
}

// The reason set is keyed by a formatted string embedding a file path, so a
// process touching many paths must not grow it without bound.
func TestEscalateAlertReasonSetIsBounded(t *testing.T) {
	tr := New(time.Hour)
	tr.Add(&Node{ExecID: "shell", Binary: "/bin/bash", StartTime: time.Now()})
	for i := 0; i < maxAlertedReasons*3; i++ {
		tr.EscalateAlert("shell", 2, fmt.Sprintf("Sensitive file accessed: /tmp/f%d", i))
	}
	n, _ := tr.Get("shell")
	if len(n.alertedReasons) > maxAlertedReasons {
		t.Fatalf("reason set grew to %d, cap is %d", len(n.alertedReasons), maxAlertedReasons)
	}
	// Escalation must still be reported once the cap is reached.
	if !tr.EscalateAlert("shell", 4, "anything") {
		t.Fatalf("a severity escalation must still alert after the reason cap")
	}
}

// AddIfAbsent exists for the kprobe path, which learns of a process from a side
// effect rather than from its exec. The weaker record must never clobber a
// richer one that an exec already built.
func TestAddIfAbsentDoesNotClobberAnExecNode(t *testing.T) {
	tr := New(time.Minute)
	tr.Add(&Node{ExecID: "e1", PID: 10, Binary: "/usr/bin/sudo", Args: "-n true", StartTime: time.Now()})

	if inserted := tr.AddIfAbsent(&Node{ExecID: "e1", PID: 10, Binary: "/usr/bin/sudo"}); inserted {
		t.Fatal("AddIfAbsent must not insert over an existing node")
	}
	n, _ := tr.Get("e1")
	if n.Args != "-n true" {
		t.Fatalf("the exec node's args were clobbered: %q", n.Args)
	}

	if inserted := tr.AddIfAbsent(&Node{ExecID: "e2", PID: 11, Binary: "/usr/bin/sudo"}); !inserted {
		t.Fatal("AddIfAbsent must insert when the id is absent")
	}
}

// THE DEFECT THIS FIXES. sudo fork()s and the CHILD calls setuid(0) between
// clone() and execve(); Tetragon gives that child its own exec_id and never
// emits a ProcessExec for it. Without a node, AddScore silently no-ops and
// ChainScore returns 0, so the +15 for T1548 never reaches the alert threshold.
// Measured live: 22 of 22 sudo setuid kprobes had no matching exec.
func TestForkChildScoreReachesTheChainOnceSynthesised(t *testing.T) {
	tr := New(time.Minute)
	tr.Add(&Node{ExecID: "shell", PID: 1, Binary: "/bin/bash", StartTime: time.Now()})
	tr.Add(&Node{ExecID: "sudo", PID: 2, ParentID: "shell", Binary: "/usr/bin/sudo", StartTime: time.Now()})

	// The forked child the exec stream never announces.
	const child = "sudo-fork-child"
	if _, ok := tr.AddScore(child, 15, "process_kprobe:privilege-escalation"); ok {
		t.Fatal("precondition: an unknown exec_id must not accept score")
	}
	if got := tr.ChainScore(child); got != 0 {
		t.Fatalf("precondition: ChainScore for an unknown id = %d, want 0", got)
	}

	tr.AddIfAbsent(&Node{ExecID: child, PID: 2, ParentID: "sudo", Binary: "/usr/bin/sudo", StartTime: time.Now()})
	if _, ok := tr.AddScore(child, 15, "process_kprobe:privilege-escalation"); !ok {
		t.Fatal("after synthesis the score must land")
	}
	if got := tr.ChainScore(child); got != 15 {
		t.Fatalf("ChainScore = %d, want 15 — the setuid points must reach the chain", got)
	}
	// And it must join the REAL chain, so ancestors are attributed.
	names := []string{}
	for _, n := range tr.Ancestors(child, 8) {
		names = append(names, n.Binary)
	}
	if len(names) != 3 || names[0] != "/bin/bash" {
		t.Fatalf("synthesised node did not join the chain: %v", names)
	}
}
