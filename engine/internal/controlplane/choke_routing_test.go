package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
)

// Routing and reporting for containment on a MULTI-AGENT tenant.
//
// The failure these guard against: a tenant with two agents, a process running
// on one of them, and a sever that reports applied while the process survives.
// The command was fanned out to every agent, the non-owner SIGKILLed whatever
// local process held the same PID number, and its ack counted as containment.

// routingServer builds a Server with just the pieces resolveTarget needs.
func routingServer(t *testing.T) *Server {
	t.Helper()
	return &Server{registry: heartbeat.NewRegistry(), owners: newOwnerCache()}
}

// seed registers an agent reporting the given (exec_id, pid) chokes.
func seed(s *Server, tenant, agent string, chokes ...*ebpfsocv1.ChokeSummary) {
	s.registry.Record(tenant, agent, &ebpfsocv1.HeartbeatRequest{Chokes: chokes})
}

func choke(execID string, pid uint32) *ebpfsocv1.ChokeSummary {
	return &ebpfsocv1.ChokeSummary{ExecId: execID, Pid: pid, State: "throttled"}
}

// TestResolveByExecIDPicksTheOwner: exec_ids are node-scoped, so the agent
// reporting one names the host. Only that agent may be sent the command.
func TestResolveByExecIDPicksTheOwner(t *testing.T) {
	s := routingServer(t)
	seed(s, "acme", "agent-a", choke("exec-on-a", 100))
	seed(s, "acme", "agent-b", choke("exec-on-b", 200))

	res := s.resolveTarget("acme", "exec-on-b", 200, "")
	if !res.unique || len(res.agents) != 1 || res.agents[0] != "agent-b" {
		t.Fatalf("resolved to %v (unique=%v), want just agent-b", res.agents, res.unique)
	}
}

// TestResolveRefusesToGuessBetweenCollidingPIDs is the routing half of the bug.
//
// Two hosts, same PID number, no exec_id evidence. Picking either one is a coin
// flip, and the old code took the first match — sending containment to a host
// that was not running the target while the real process kept going.
func TestResolveAmbiguousWhenPIDsCollide(t *testing.T) {
	s := routingServer(t)
	seed(s, "acme", "agent-a", choke("exec-on-a", 4021))
	seed(s, "acme", "agent-b", choke("exec-on-b", 4021))

	res := s.resolveTarget("acme", "", 4021, "")
	if res.unique {
		t.Fatalf("resolved %v as unique — a colliding PID is not an owner", res.agents)
	}
	if len(res.agents) != 2 {
		t.Fatalf("candidates = %v, want both agents", res.agents)
	}
}

// TestResolveHonorsExplicitAgent: the console knows which host a row came from
// and sends it back. Most specific evidence available.
func TestResolveHonorsExplicitAgent(t *testing.T) {
	s := routingServer(t)
	seed(s, "acme", "agent-a", choke("exec-on-a", 4021))
	seed(s, "acme", "agent-b", choke("exec-on-b", 4021))

	res := s.resolveTarget("acme", "", 4021, "agent-b")
	if !res.unique || len(res.agents) != 1 || res.agents[0] != "agent-b" {
		t.Fatalf("resolved to %v (unique=%v), want just agent-b", res.agents, res.unique)
	}
}

// TestResolveIgnoresAgentFromAnotherTenant: an agent_id must be validated
// against the tenant, or the parameter becomes a cross-tenant targeting oracle.
func TestResolveIgnoresAgentFromAnotherTenant(t *testing.T) {
	s := routingServer(t)
	seed(s, "acme", "agent-a", choke("exec-on-a", 100))
	seed(s, "other-corp", "agent-x", choke("exec-on-x", 100))

	res := s.resolveTarget("acme", "exec-on-a", 100, "agent-x")
	for _, a := range res.agents {
		if a == "agent-x" {
			t.Fatal("routed a tenant's containment to another tenant's agent")
		}
	}
}

// TestOwnerCacheSurvivesHeartbeatLag: an operator climbing the ladder sends the
// next rung seconds after the last, well inside a heartbeat interval. The owner
// learned from the previous ack must route the follow-up, or the sever falls
// back to guessing by PID — exactly what sent it to the wrong host.
func TestOwnerCacheSurvivesHeartbeatLag(t *testing.T) {
	s := routingServer(t)
	// Neither agent reports the target yet: the snapshot is stale.
	seed(s, "acme", "agent-a")
	seed(s, "acme", "agent-b")

	if res := s.resolveTarget("acme", "victim", 4021, ""); res.unique {
		t.Fatal("unreported target resolved as unique before any agent confirmed it")
	}
	// agent-b proved ownership on an earlier rung.
	s.owners.put("acme", "victim", "agent-b")

	res := s.resolveTarget("acme", "victim", 4021, "")
	if !res.unique || len(res.agents) != 1 || res.agents[0] != "agent-b" {
		t.Fatalf("resolved to %v (unique=%v), want just agent-b from the ack-learned owner", res.agents, res.unique)
	}
}

// TestSingleAgentTenantIsNeverAmbiguous keeps the common deployment frictionless:
// with one agent there is nothing to disambiguate, so a sever still works
// against a target no heartbeat has reported yet.
func TestSingleAgentTenantIsNeverAmbiguous(t *testing.T) {
	s := routingServer(t)
	seed(s, "solo", "only-agent")

	res := s.resolveTarget("solo", "brand-new-exec", 4021, "")
	if !res.unique || len(res.agents) != 1 || res.agents[0] != "only-agent" {
		t.Fatalf("resolved to %v (unique=%v), want the tenant's only agent", res.agents, res.unique)
	}
}

// ─────────── Reducing acks to one honest answer ──────────────────────────

func ack(status ebpfsocv1.CommandAck_Status, match ebpfsocv1.CommandAck_TargetMatch) *ebpfsocv1.CommandAck {
	return &ebpfsocv1.CommandAck{Status: status, TargetMatch: match}
}

// TestNoOpAcksAreNotContainment is the reporting half of the bug: every agent
// disowned the target, so the answer must be an explicit "nobody is running
// this", never ok.
func TestNoOpAcksAreNotContainment(t *testing.T) {
	agents := []string{"agent-a", "agent-b"}
	out := reduceAcks(map[string]*ebpfsocv1.CommandAck{
		"agent-a": ack(ebpfsocv1.CommandAck_STATUS_NOT_TARGET, ebpfsocv1.CommandAck_TARGET_MATCH_NONE),
		"agent-b": ack(ebpfsocv1.CommandAck_STATUS_NOT_TARGET, ebpfsocv1.CommandAck_TARGET_MATCH_NONE),
	}, agents)

	if out.applied {
		t.Fatal("reported containment when every agent said the target was not theirs")
	}
	if out.status != "STATUS_NOT_TARGET" {
		t.Fatalf("status = %q, want STATUS_NOT_TARGET", out.status)
	}
}

// TestOwnerAttributionPrefersProof: when one agent applied on a real exec_id
// match and another on a PID coincidence, the action is attributed to the one
// that proved it, and only that makes the result cacheable as the owner.
func TestOwnerAttributionPrefersProof(t *testing.T) {
	agents := []string{"agent-a", "agent-b"}
	out := reduceAcks(map[string]*ebpfsocv1.CommandAck{
		"agent-a": ack(ebpfsocv1.CommandAck_STATUS_APPLIED, ebpfsocv1.CommandAck_TARGET_MATCH_PID),
		"agent-b": ack(ebpfsocv1.CommandAck_STATUS_APPLIED, ebpfsocv1.CommandAck_TARGET_MATCH_EXEC_ID),
	}, agents)

	if !out.applied {
		t.Fatal("want applied")
	}
	if out.owner != "agent-b" {
		t.Fatalf("owner = %q, want agent-b (the exec_id match is the proven one)", out.owner)
	}
	if !out.definitive {
		t.Fatal("an exec_id match must mark the outcome definitive")
	}
	if len(out.appliedBy) != 2 {
		t.Fatalf("applied_by = %v, want both agents reported", out.appliedBy)
	}
}

// TestSingleCandidateWeakMatchIsRoutable: dispatched to one agent, which
// applied on a pid match. There is no second candidate for that pid to be
// confused with, so attributing and routing to it is sound — the ambiguity this
// whole mechanism guards against only exists between multiple agents.
func TestSingleCandidateWeakMatchIsRoutable(t *testing.T) {
	out := reduceAcks(map[string]*ebpfsocv1.CommandAck{
		"agent-a": ack(ebpfsocv1.CommandAck_STATUS_APPLIED, ebpfsocv1.CommandAck_TARGET_MATCH_PID),
	}, []string{"agent-a"})

	if !out.applied || out.owner != "agent-a" {
		t.Fatalf("applied=%v owner=%q, want applied on agent-a", out.applied, out.owner)
	}
	if !out.definitive {
		t.Fatal("the only agent dispatched to, and it applied — nothing else can own the target")
	}
}

// TestRejectionSurfacesItsReason: a guardrail refusal must not be flattened
// into a generic failure, or the operator cannot tell a protected binary from
// an offline fleet.
func TestRejectionSurfacesItsReason(t *testing.T) {
	out := reduceAcks(map[string]*ebpfsocv1.CommandAck{
		"agent-a": {Status: ebpfsocv1.CommandAck_STATUS_REJECTED, Detail: "kill-switch engaged"},
	}, []string{"agent-a"})

	if out.applied {
		t.Fatal("a rejection is not containment")
	}
	if out.status != "STATUS_REJECTED" || out.detail != "kill-switch engaged" {
		t.Fatalf("status=%q detail=%q, want the agent's rejection reason", out.status, out.detail)
	}
}

// TestOwnerCacheExpiresNothingUnderTTL / eviction sanity.
func TestOwnerCacheRoundTrip(t *testing.T) {
	c := newOwnerCache()
	if got := c.get("acme", "nope"); got != "" {
		t.Fatalf("empty cache returned %q", got)
	}
	c.put("acme", "victim", "agent-b")
	if got := c.get("acme", "victim"); got != "agent-b" {
		t.Fatalf("get = %q, want agent-b", got)
	}
	// Tenant-scoped: one tenant's learned owner must not answer for another.
	if got := c.get("other", "victim"); got != "" {
		t.Fatalf("cross-tenant get = %q, want empty", got)
	}
	// Ungradeable inputs are never cached.
	c.put("acme", "", "agent-a")
	c.put("acme", "x", "")
	if got := c.get("acme", ""); got != "" {
		t.Fatalf("cached an empty exec_id: %q", got)
	}
}

// TestSeverIsNeverBroadcast is the safety property that makes the rest of this
// safe to get wrong: a sever is a SIGKILL and no thaw undoes it, so when the
// control plane cannot say WHICH host is running the process it must refuse
// rather than send the kill to every agent and let each decide. It stops before
// dispatching anything, and hands the operator the candidate hosts.
func TestSeverIsNeverBroadcast(t *testing.T) {
	s := routingServer(t)
	seed(s, "acme", "agent-a", choke("exec-on-a", 4021))
	seed(s, "acme", "agent-b", choke("exec-on-b", 4021))

	w := httptest.NewRecorder()
	// s.dispatcher is nil: if this path dispatches at all, the test panics —
	// which is the point. Nothing may go out on an unroutable sever.
	s.dispatchChoke(w, "acme", "", 4021, "sever", "confirmed C2 beacon", "")

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 refusing to broadcast an irreversible action", w.Code)
	}
	var body struct {
		OK         bool     `json:"ok"`
		Status     string   `json:"status"`
		Candidates []string `json:"candidates"`
		Error      string   `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.OK {
		t.Fatal("a refused sever must never report ok")
	}
	if body.Status != "AMBIGUOUS_TARGET" {
		t.Fatalf("status = %q, want AMBIGUOUS_TARGET", body.Status)
	}
	if len(body.Candidates) != 2 {
		t.Fatalf("candidates = %v, want both agents so the operator can re-issue", body.Candidates)
	}
	// The console lifts "error" out of a non-2xx body; without it the operator
	// sees a bare "Conflict" for the one refusal they most need to understand.
	if !strings.Contains(body.Error, "agent_id") {
		t.Fatalf("error = %q, want it to tell the operator to re-issue with agent_id", body.Error)
	}
}

// TestReversibleTierStillFansOut: the refusal above is scoped to irreversible
// actions. A throttle landing on the wrong host is undone by a thaw, so
// blocking it would cost containment speed for no safety gain — the non-owners
// no-op and say so.
func TestReversibleTierStillFansOut(t *testing.T) {
	s := routingServer(t)
	seed(s, "acme", "agent-a", choke("exec-on-a", 4021))
	seed(s, "acme", "agent-b", choke("exec-on-b", 4021))

	res := s.resolveTarget("acme", "", 4021, "")
	if irreversible("throttle") {
		t.Fatal("throttle must not be classified irreversible")
	}
	if !irreversible("sever") {
		t.Fatal("sever must be classified irreversible")
	}
	if len(res.agents) != 2 {
		t.Fatalf("candidates = %v, want the reversible tier to reach both", res.agents)
	}
}

// TestSoleApplierWithUnanimousDisownIsDefinitive: first contact with a target
// no agent has reported yet can only match on pid, which is a guess on its own.
// But when every other agent in the tenant explicitly disowns it, exactly one
// candidate remains — enough to route the rest of the ladder, including the
// sever, instead of re-guessing at each rung.
func TestSoleApplierWithUnanimousDisownIsDefinitive(t *testing.T) {
	agents := []string{"agent-a", "agent-b"}
	out := reduceAcks(map[string]*ebpfsocv1.CommandAck{
		"agent-a": ack(ebpfsocv1.CommandAck_STATUS_NOT_TARGET, ebpfsocv1.CommandAck_TARGET_MATCH_NONE),
		"agent-b": ack(ebpfsocv1.CommandAck_STATUS_APPLIED, ebpfsocv1.CommandAck_TARGET_MATCH_PID),
	}, agents)

	if !out.applied || out.owner != "agent-b" {
		t.Fatalf("applied=%v owner=%q, want applied on agent-b", out.applied, out.owner)
	}
	if !out.definitive {
		t.Fatal("sole applier with every other agent disowning the target must be treated as the owner")
	}
}

// TestSilentAgentBlocksOwnership: an agent that never acked has NOT disowned
// anything — it may be the real owner, momentarily disconnected. Treating
// silence as a disown would cache the wrong host and send the sever there.
func TestSilentAgentBlocksOwnership(t *testing.T) {
	agents := []string{"agent-a", "agent-b", "agent-c"} // c never answers
	out := reduceAcks(map[string]*ebpfsocv1.CommandAck{
		"agent-a": ack(ebpfsocv1.CommandAck_STATUS_NOT_TARGET, ebpfsocv1.CommandAck_TARGET_MATCH_NONE),
		"agent-b": ack(ebpfsocv1.CommandAck_STATUS_APPLIED, ebpfsocv1.CommandAck_TARGET_MATCH_PID),
	}, agents)

	if !out.applied {
		t.Fatal("agent-b did enforce; that must still be reported")
	}
	if out.definitive {
		t.Fatal("silence is not a disown — ownership must not be inferred while an agent is unheard from")
	}
}

// TestTwoWeakAppliersAreNotAnOwner: a pid number live on two hosts leaves the
// owner genuinely unknown. Caching either would send the next sever to a
// coin-flip host.
func TestTwoWeakAppliersAreNotAnOwner(t *testing.T) {
	agents := []string{"agent-a", "agent-b"}
	out := reduceAcks(map[string]*ebpfsocv1.CommandAck{
		"agent-a": ack(ebpfsocv1.CommandAck_STATUS_APPLIED, ebpfsocv1.CommandAck_TARGET_MATCH_PID),
		"agent-b": ack(ebpfsocv1.CommandAck_STATUS_APPLIED, ebpfsocv1.CommandAck_TARGET_MATCH_PID),
	}, agents)

	if out.definitive {
		t.Fatal("two hosts holding the same PID number does not identify an owner")
	}
	if len(out.appliedBy) != 2 {
		t.Fatalf("applied_by = %v, want both reported so the operator sees the spread", out.appliedBy)
	}
}
