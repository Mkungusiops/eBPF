package controlplane

import (
	"net/http"
	"testing"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
)

// The fleet Thaw control.
//
// The console's "Thaw quarantine" button posts {reason, targets} and nothing
// else — on both the Fleet page and the Choke Gateway. The control plane
// answered 400 "exec_id or pid required" to that shape, so a button that works
// on the single-host engine (whose reason-only thaw releases the quarantine
// tier) was dead on every multi-tenant deployment, and the operator's way OUT
// of containment was the one control that did not work.
//
// The protocol has no fleet-wide release command, but the control plane already
// knows what each agent holds: agents report their choke snapshot on every
// heartbeat and the Choke Gateway renders it. So a fleet thaw is one Thaw per
// contained process against the targeted agents.

// jailed builds a choke summary in a named state.
func jailed(execID string, pid uint32, state string) *ebpfsocv1.ChokeSummary {
	return &ebpfsocv1.ChokeSummary{ExecId: execID, Pid: pid, State: state}
}

// TestFleetThawReleasesWhatTheFleetIsHolding is the defect: the reason-only
// thaw must dispatch, not 400.
func TestFleetThawReleasesWhatTheFleetIsHolding(t *testing.T) {
	s := targetingServer(t)
	seed(s, "acme", "agent-a", jailed("exec-a1", 11, "quarantined"), jailed("exec-a2", 12, "throttled"))
	seed(s, "acme", "agent-b", jailed("exec-b1", 21, "tarpit"))

	code, body := fleetWrite(t, s, s.handleChokeThaw, "POST", "/api/fleet/thaw?tenant=acme",
		map[string]any{"reason": "incident closed"})
	if code != 200 {
		t.Fatalf("a fleet thaw returned %d, want 200 — the operator's way out of containment: %v", code, body)
	}
	if n := s.dispatcher.Pending("agent-a"); n != 2 {
		t.Fatalf("agent-a was sent %d release(s), want one per contained process (2)", n)
	}
	if n := s.dispatcher.Pending("agent-b"); n != 1 {
		t.Fatalf("agent-b was sent %d release(s), want 1", n)
	}
	// The fan-out envelope the console summarises. Without these keys even a
	// complete release renders as "coverage unknown".
	if got := hostNames(t, body); len(got) != 2 {
		t.Fatalf("hosts = %v, want both agents", got)
	}
	for _, key := range []string{"applied", "total", "detail", "released", "contained"} {
		if _, ok := body[key]; !ok {
			t.Fatalf("the response dropped %q, so the operator cannot tell what came back: %v", key, body)
		}
	}
	if body["contained"].(float64) != 3 {
		t.Fatalf("contained = %v, want the 3 processes the fleet reported", body["contained"])
	}
}

// TestFleetThawNeverClaimsToReleaseASeveredProcess. sever is a SIGKILL: the
// process is gone and no thaw brings it back. Sending one and reporting it as
// released would tell an operator a killed process is running again.
func TestFleetThawNeverClaimsToReleaseASeveredProcess(t *testing.T) {
	s := targetingServer(t)
	seed(s, "acme", "agent-a", jailed("exec-dead", 11, "severed"), jailed("exec-idle", 12, "pristine"))

	code, body := fleetWrite(t, s, s.handleChokeThaw, "POST", "/api/fleet/thaw?tenant=acme",
		map[string]any{"reason": "incident closed", "targets": []string{"agent-a"}})
	if code != 200 {
		t.Fatalf("status %d: %v", code, body)
	}
	if n := s.dispatcher.Pending("agent-a"); n != 0 {
		t.Fatalf("%d release(s) were sent for processes that are severed or were never contained", n)
	}
	if body["contained"].(float64) != 0 {
		t.Fatalf("contained = %v, want 0 — neither a severed nor a pristine process is releasable", body["contained"])
	}
}

// TestFleetThawWithNoHostsSaysSoRatherThanClaimingSuccess: 0 of 0 hosts is not
// a release, and a green toast over it is how an operator concludes an estate
// is free when nothing was reached.
func TestFleetThawWithNoHostsSaysSoRatherThanClaimingSuccess(t *testing.T) {
	s := targetingServer(t)

	code, body := fleetWrite(t, s, s.handleChokeThaw, "POST", "/api/fleet/thaw?tenant=empty",
		map[string]any{"reason": "incident closed"})
	if code != 200 {
		t.Fatalf("status %d: %v", code, body)
	}
	if ok, _ := body["ok"].(bool); ok {
		t.Fatalf("a thaw that reached no host reported ok: %v", body)
	}
	if body["total"].(float64) != 0 || body["error"] == nil {
		t.Fatalf("the response does not state that nothing was reached: %v", body)
	}
}

// TestReleaseOutcomeReportsPerHostTruth. The folding rules, with no live agent:
// a host that only half released is not applied, a process that has since
// exited is not a failure, an unacked release is unconfirmed rather than
// refused, and a host holding nothing is not a red mark against the release.
func TestReleaseOutcomeReportsPerHostTruth(t *testing.T) {
	agents := []string{"agent-a", "agent-b", "agent-c", "agent-d"}
	held := map[string][]containedProcess{
		"agent-a": {{execID: "a1"}, {execID: "a2"}},
		"agent-b": {{execID: "b1"}, {execID: "b2"}},
		"agent-c": {{execID: "c1"}},
		// agent-d holds nothing.
	}
	cmds := []sentRelease{
		{agent: "agent-a", id: "1"}, {agent: "agent-a", id: "2"},
		{agent: "agent-b", id: "3"}, {agent: "agent-b", id: "4"},
		{agent: "agent-c", id: "5"},
	}
	acks := map[int]*ebpfsocv1.CommandAck{
		0: {Status: ebpfsocv1.CommandAck_STATUS_APPLIED},
		// agent-a's second release: the process had already exited.
		1: {Status: ebpfsocv1.CommandAck_STATUS_NOT_TARGET},
		2: {Status: ebpfsocv1.CommandAck_STATUS_APPLIED},
		// agent-b's second was refused; agent-c never answered.
		3: {Status: ebpfsocv1.CommandAck_STATUS_REJECTED, Detail: "enforcement is kill-switched"},
	}

	out := releaseOutcome(agents, held, cmds, acks)

	if out.contained != 5 || out.released != 2 || out.gone != 1 {
		t.Fatalf("contained/released/gone = %d/%d/%d, want 5/2/1", out.contained, out.released, out.gone)
	}
	byName := map[string]fleetHostResult{}
	for _, h := range out.hosts {
		byName[h.Name] = h
	}
	if h := byName["agent-a"]; !h.OK || h.Status != "STATUS_APPLIED" {
		t.Fatalf("agent-a released everything it held (one had exited) and reported %+v", h)
	}
	if h := byName["agent-b"]; h.OK || h.Status != "STATUS_REJECTED" || h.Error == "" {
		t.Fatalf("agent-b is still holding a process and reported %+v", h)
	}
	if h := byName["agent-c"]; h.OK || h.Status != "timeout" {
		t.Fatalf("agent-c never answered; silence must read as unconfirmed, not refused: %+v", h)
	}
	if h := byName["agent-d"]; !h.OK || h.Status != "STATUS_NOTHING_TO_RELEASE" {
		t.Fatalf("agent-d held nothing and was scored as a failure: %+v", h)
	}
	// 2 of 4 hosts are in the state the operator asked for.
	if out.applied != 2 || out.total != 4 {
		t.Fatalf("applied/total = %d/%d, want 2/4", out.applied, out.total)
	}
}

// TestFleetThawStillRefusesAnUnknownHost. Targeting rules do not relax because
// the action is a release: a host set the server only half understood must not
// half apply.
func TestFleetThawStillRefusesAnUnknownHost(t *testing.T) {
	s := targetingServer(t)
	seed(s, "acme", "agent-a", jailed("exec-a1", 11, "quarantined"))

	code, body := fleetWrite(t, s, s.handleChokeThaw, "POST", "/api/fleet/thaw?tenant=acme",
		map[string]any{"reason": "incident closed", "targets": []string{"agent-a", "agent-ghost"}})
	if code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 for a host this tenant does not have: %v", code, body)
	}
	if n := s.dispatcher.Pending("agent-a"); n != 0 {
		t.Fatalf("the refused write still dispatched %d release(s) to agent-a", n)
	}
}
