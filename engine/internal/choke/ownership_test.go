package choke

import (
	"context"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
)

// The multi-agent false-containment defense. A containment command may reach
// several agents at once because the control plane cannot always tell which one
// is running the target; each must answer with what it can actually prove.

// TestOwnsRequiresEvidence: an agent that has neither observed the exec_id nor
// has the pid live must disown the target outright. This is the case that used
// to ack APPLIED for a process the host never ran — and, for a sever, SIGKILL
// whatever local process held that PID number.
func TestOwnsRequiresEvidence(t *testing.T) {
	g, _, _, _, _ := newTestGateway(t, false)
	g.SetPIDLiveFn(func(uint32) bool { return false })

	if got := g.Owns("someone-elses-exec-id", 4021); got != MatchNone {
		t.Fatalf("Owns on an unrelated host = %v, want MatchNone", got)
	}
}

// TestOwnsFromTelemetryIsDefinitive: an exec_id this host actually observed is
// proof of ownership, and outranks a mere pid coincidence.
func TestOwnsFromTelemetryIsDefinitive(t *testing.T) {
	g, _, _, _, _ := newTestGateway(t, false)
	g.SetPIDLiveFn(func(uint32) bool { return true })

	g.OnEvent(context.Background(), Observation{
		ExecID: "mine", PID: 4021, Binary: "/usr/bin/curl", Score: 1, Reason: "exec",
	})
	if got := g.Owns("mine", 4021); got != MatchExecID {
		t.Fatalf("Owns on an observed exec_id = %v, want MatchExecID", got)
	}
}

// TestOwnsPidOnlyIsWeak: with no exec_id evidence, a live pid is the best the
// host can offer — but it is a guess, because PID numbers are per-host and
// collide across a fleet. It must be graded below an exec_id match so the
// control plane can refuse to send an irreversible action on it alone.
func TestOwnsPidOnlyIsWeak(t *testing.T) {
	g, _, _, _, _ := newTestGateway(t, false)
	g.SetPIDLiveFn(func(pid uint32) bool { return pid == 4021 })

	if got := g.Owns("never-seen-here", 4021); got != MatchPID {
		t.Fatalf("Owns with only a live pid = %v, want MatchPID", got)
	}
	if got := g.Owns("never-seen-here", 9999); got != MatchNone {
		t.Fatalf("Owns with a dead pid = %v, want MatchNone", got)
	}
}

// TestCommandTargetDoesNotConferOwnership is the poisoning guard.
//
// Manual() caches every target it is handed so the drill-in panel can show it.
// If that cache counted as evidence, one fan-out command would teach an
// innocent agent the exec_id and it would then claim DEFINITIVE ownership of
// another host's process on the next command — the control plane would route
// all subsequent containment, including the sever, to the wrong machine.
func TestCommandTargetDoesNotConferOwnership(t *testing.T) {
	g, _, _, _, _ := newTestGateway(t, false)
	// The pid is live here purely by coincidence, as on any busy host.
	g.SetPIDLiveFn(func(uint32) bool { return true })

	if got := g.Owns("victim-on-another-host", 4021); got != MatchPID {
		t.Fatalf("before any command: %v, want MatchPID", got)
	}
	// A fan-out throttle lands here and is applied on the weak pid match.
	if _, err := g.Manual(context.Background(), ManualRequest{
		ExecID: "victim-on-another-host", PID: 4021, Action: circuit.ActThrottle,
		Reason: "fleet fan-out", Actor: "control-plane",
	}); err != nil {
		t.Fatal(err)
	}
	// It must NOT have been promoted to proof by having been named.
	if got := g.Owns("victim-on-another-host", 4021); got != MatchPID {
		t.Fatalf("after being named by a command: %v, want MatchPID (being told about a "+
			"process is not evidence this host runs it)", got)
	}
}

// TestDeviceOwnsRequiresSeeingTheMAC: an agent whose segment the device is not
// on writes a tc rule that matches nothing, so it must not claim the device.
func TestDeviceOwnsRequiresSeeingTheMAC(t *testing.T) {
	g, _, _ := newTestDeviceGateway(t)
	if g.Owns("de:ad:be:ef:00:01") {
		t.Fatal("claimed a MAC never seen on this host's LAN")
	}
	if g.Owns("not-a-mac") {
		t.Fatal("claimed an unparseable MAC")
	}
}
