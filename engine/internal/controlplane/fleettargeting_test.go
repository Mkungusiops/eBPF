package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/approval"
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/command"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
)

// Blast radius, multi-tenant half.
//
// The Fleet page lets an operator tick one host, says "Writes target 1 selected
// host." and posts that host list as "targets". No handler here decoded it: the
// fleet-wide writes called dispatchAll, which enqueues to EVERY agent in the
// tenant. Selecting one host and pressing Containment contained the fleet.
//
// The second failure is the report afterwards. The response carried only
// applied/total, and the console summarises result.hosts — so a write that
// reached two agents rendered "0/0 hosts succeeded" in a green toast.

// targetingServer builds a Server with the pieces the fleet writes touch, two
// agents in the tenant, and an ack deadline short enough that a test does not
// spend ten seconds waiting for agents that were never connected.
func targetingServer(t *testing.T) *Server {
	t.Helper()
	signer, _, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		registry:   heartbeat.NewRegistry(),
		owners:     newOwnerCache(),
		approvals:  approval.NewStore(approval.DefaultTTL),
		dispatcher: command.NewDispatcher(signer, time.Minute),
		auditor:    authz.NewMemAuditor(),
	}
	s.cfg.Logf = func(string, ...any) {}
	s.cfg.AdminToken = "admin-secret"
	seed(s, "acme", "agent-a")
	seed(s, "acme", "agent-b")

	restore := ackTimeout
	ackTimeout = 50 * time.Millisecond
	t.Cleanup(func() { ackTimeout = restore })
	return s
}

// fleetWrite posts body to path as an authorized operator and decodes the reply.
func fleetWrite(t *testing.T, s *Server, h http.HandlerFunc, method, path string, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, strings.NewReader(string(raw)))
	req.Header.Set("Authorization", "Bearer admin-secret")
	w := httptest.NewRecorder()
	h(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func hostNames(t *testing.T, body map[string]any) []string {
	t.Helper()
	raw, ok := body["hosts"]
	if !ok {
		t.Fatalf("the response carries no hosts key, so the console summarises it as 0/0: %v", body)
	}
	entries, ok := raw.([]any)
	if !ok {
		t.Fatalf("hosts was %T, want an array", raw)
	}
	names := []string{}
	for _, e := range entries {
		names = append(names, e.(map[string]any)["name"].(string))
	}
	return names
}

// TestTargetedPresetReachesOnlyTheNamedAgent is the defect itself: the unnamed
// agent's queue must be untouched. A containment aimed at one host that lands
// on two is the difference between isolating an intruder and halting a fleet.
func TestTargetedPresetReachesOnlyTheNamedAgent(t *testing.T) {
	s := targetingServer(t)

	code, body := fleetWrite(t, s, s.handleChokePreset, "POST", "/api/fleet/preset?tenant=acme",
		map[string]any{"name": "containment", "reason": "IR-4821", "targets": []string{"agent-a"}})
	if code != 200 {
		t.Fatalf("status %d: %v", code, body)
	}
	if n := s.dispatcher.Pending("agent-b"); n != 0 {
		t.Fatalf("%d command(s) reached agent-b, which the operator did not select", n)
	}
	if n := s.dispatcher.Pending("agent-a"); n != 1 {
		t.Fatalf("agent-a has %d queued commands, want the 1 that was targeted at it", n)
	}
	// The envelope reports exactly the hosts it dispatched to, and keeps every
	// key the current readers already use.
	if got := hostNames(t, body); len(got) != 1 || got[0] != "agent-a" {
		t.Fatalf("hosts = %v, want just agent-a", got)
	}
	for _, key := range []string{"applied", "total", "detail", "preset", "ok"} {
		if _, ok := body[key]; !ok {
			t.Fatalf("the response dropped the existing %q key: %v", key, body)
		}
	}
	if body["total"].(float64) != 1 {
		t.Fatalf("total = %v, want 1 — total counts the hosts written to, not the tenant", body["total"])
	}
}

// TestUntargetedWriteStillReachesEveryAgent: absent targets is the historical
// behaviour and must stay it, or the fix turns every fleet-wide action into a
// no-op for callers that never sent a host list.
func TestUntargetedWriteStillReachesEveryAgent(t *testing.T) {
	s := targetingServer(t)

	code, body := fleetWrite(t, s, s.handleChokePreset, "POST", "/api/fleet/preset?tenant=acme",
		map[string]any{"name": "default", "reason": "routine"})
	if code != 200 {
		t.Fatalf("status %d: %v", code, body)
	}
	for _, agent := range []string{"agent-a", "agent-b"} {
		if n := s.dispatcher.Pending(agent); n != 1 {
			t.Fatalf("%s has %d queued commands, want 1 — an untargeted write covers the tenant", agent, n)
		}
	}
	if got := hostNames(t, body); len(got) != 2 {
		t.Fatalf("hosts = %v, want both agents", got)
	}
}

// TestUnknownTargetIsRefusedAndDispatchesNothing. Half-applying a write whose
// target set the server only partly understood is the worst outcome: the
// operator is told about the name we did not recognise while the hosts we did
// recognise have already been changed.
func TestUnknownTargetIsRefusedAndDispatchesNothing(t *testing.T) {
	s := targetingServer(t)

	code, body := fleetWrite(t, s, s.handleChokePreset, "POST", "/api/fleet/preset?tenant=acme",
		map[string]any{"name": "containment", "reason": "IR-4821", "targets": []string{"agent-a", "ghost-edge"}})
	if code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 for an unknown host: %v", code, body)
	}
	unknown, _ := body["unknown"].([]any)
	if len(unknown) != 1 || unknown[0] != "ghost-edge" {
		t.Fatalf("unknown = %v, want [ghost-edge] — the operator cannot fix a list they are not shown", body["unknown"])
	}
	for _, agent := range []string{"agent-a", "agent-b"} {
		if n := s.dispatcher.Pending(agent); n != 0 {
			t.Fatalf("%s received %d command(s) from a write that was refused", agent, n)
		}
	}
}

// TestEmptyTargetListNeverMeansEveryHost. "Selected hosts only" with nothing
// selected is the one input that must not degrade to a fleet-wide write.
func TestEmptyTargetListNeverMeansEveryHost(t *testing.T) {
	s := targetingServer(t)

	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		method  string
		path    string
		body    map[string]any
	}{
		{"preset", s.handleChokePreset, "POST", "/api/fleet/preset?tenant=acme",
			map[string]any{"name": "containment", "reason": "r", "targets": []string{}}},
		{"kill-switch", s.handleChokeKill, "POST", "/api/fleet/kill-switch?tenant=acme",
			map[string]any{"on": true, "reason": "r", "targets": []string{}}},
		{"thresholds", s.handleChokeThresh, "PUT", "/api/fleet/thresholds?tenant=acme",
			map[string]any{"throttle_at": 5, "tarpit_at": 10, "quarantine_at": 20, "sever_at": 40, "targets": []string{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := fleetWrite(t, s, tc.handler, tc.method, tc.path, tc.body)
			if code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400 for an empty target list: %v", code, body)
			}
			for _, agent := range []string{"agent-a", "agent-b"} {
				if n := s.dispatcher.Pending(agent); n != 0 {
					t.Fatalf("%s received %d command(s) from a write with no host selected", agent, n)
				}
			}
		})
	}
}

// TestTargetedKillSwitchAndThresholdsScopeToo — the preset is not a special
// case. Every fleet-wide write on this surface carries the same host list, and
// a kill-switch that ignores it halts enforcement estate-wide.
func TestTargetedKillSwitchAndThresholdsScopeToo(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   map[string]any
		pick   func(*Server) http.HandlerFunc
	}{
		{"kill-switch", "POST", "/api/fleet/kill-switch?tenant=acme",
			map[string]any{"on": true, "reason": "r", "targets": []string{"agent-b"}},
			func(s *Server) http.HandlerFunc { return s.handleChokeKill }},
		{"thresholds", "PUT", "/api/fleet/thresholds?tenant=acme",
			map[string]any{"throttle_at": 5, "tarpit_at": 10, "quarantine_at": 20, "sever_at": 40, "targets": []string{"agent-b"}},
			func(s *Server) http.HandlerFunc { return s.handleChokeThresh }},
		{"mode", "POST", "/api/choke/mode?tenant=acme",
			map[string]any{"enforcing": true, "reason": "r", "targets": []string{"agent-b"}},
			func(s *Server) http.HandlerFunc { return s.handleChokeMode }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := targetingServer(t)
			code, body := fleetWrite(t, s, tc.pick(s), tc.method, tc.path, tc.body)
			if code != 200 {
				t.Fatalf("status %d: %v", code, body)
			}
			if n := s.dispatcher.Pending("agent-a"); n != 0 {
				t.Fatalf("the %s reached agent-a (%d queued), which was not selected", tc.name, n)
			}
			if n := s.dispatcher.Pending("agent-b"); n != 1 {
				t.Fatalf("the %s did not reach the selected agent-b (%d queued)", tc.name, n)
			}
			if got := hostNames(t, body); len(got) != 1 || got[0] != "agent-b" {
				t.Fatalf("hosts = %v, want just agent-b", got)
			}
		})
	}
}

// TestTargetedThawReleasesOnlyOnNamedHosts. A thaw is a per-process release,
// so a host list means "release it on these hosts", not "thaw these hosts" —
// there is no fleet-wide release command to mean the latter.
func TestTargetedThawReleasesOnlyOnNamedHosts(t *testing.T) {
	s := targetingServer(t)

	code, body := fleetWrite(t, s, s.handleChokeThaw, "POST", "/api/fleet/thaw?tenant=acme",
		map[string]any{"exec_id": "exec-1", "reason": "false positive", "targets": []string{"agent-a"}})
	if code != 200 {
		t.Fatalf("status %d: %v", code, body)
	}
	if n := s.dispatcher.Pending("agent-b"); n != 0 {
		t.Fatalf("the thaw reached agent-b (%d queued), which was not selected", n)
	}
	if n := s.dispatcher.Pending("agent-a"); n != 1 {
		t.Fatalf("agent-a has %d queued commands, want the targeted thaw", n)
	}
	if got := hostNames(t, body); len(got) != 1 || got[0] != "agent-a" {
		t.Fatalf("hosts = %v, want just agent-a", got)
	}
	// And a reason-only thaw — the console's "Thaw quarantine" button, which
	// sends {reason, targets} and nothing else — releases what the NAMED hosts
	// are holding. It used to 400 ("exec_id or pid required"), so the control
	// was dead on the control plane; it must still not reach agent-b.
	seed(s, "acme", "agent-a", choke("exec-a1", 111), choke("exec-a2", 222))
	seed(s, "acme", "agent-b", choke("exec-b1", 333))
	before := s.dispatcher.Pending("agent-a")

	code, body = fleetWrite(t, s, s.handleChokeThaw, "POST", "/api/fleet/thaw?tenant=acme",
		map[string]any{"reason": "false positive", "targets": []string{"agent-a"}})
	if code != 200 {
		t.Fatalf("a reason-only fleet thaw returned %d, want 200: %v", code, body)
	}
	if n := s.dispatcher.Pending("agent-a") - before; n != 2 {
		t.Fatalf("agent-a was sent %d release(s), want one per contained process (2): %v", n, body)
	}
	if n := s.dispatcher.Pending("agent-b"); n != 0 {
		t.Fatalf("the fleet thaw reached agent-b (%d queued), which was not selected", n)
	}
	if got := hostNames(t, body); len(got) != 1 || got[0] != "agent-a" {
		t.Fatalf("hosts = %v, want just agent-a", got)
	}
}

// TestTargetedContainmentStillNeedsASecondOperator. Narrowing a containment to
// two hosts does not make it something other than containment, so the approval
// gate must still fire — and it must PARK the request, carrying the host list,
// rather than refuse it. Refusing withheld host-scoped containment from exactly
// the tenants that run four-eyes, and did it while still accepting the wider
// untargeted form of the same ask.
func TestTargetedContainmentStillNeedsASecondOperator(t *testing.T) {
	s := targetingServer(t)
	s.cfg.RequireApproval = true

	code, body := fleetWrite(t, s, s.handleChokePreset, "POST", "/api/fleet/preset?tenant=acme",
		map[string]any{"name": "containment", "reason": "IR-4821", "targets": []string{"agent-a"}})
	if code != http.StatusAccepted {
		t.Fatalf("a targeted containment returned %d, want 202 (held for a second operator): %v", code, body)
	}
	if ok, _ := body["ok"].(bool); ok {
		t.Fatalf("a held containment reported ok — nothing has been applied: %v", body)
	}
	for _, agent := range []string{"agent-a", "agent-b"} {
		if n := s.dispatcher.Pending(agent); n != 0 {
			t.Fatalf("%s received %d command(s) from a containment that is still awaiting approval", agent, n)
		}
	}
	if s.approvals.PendingCount("acme") != 1 {
		t.Fatal("the targeted containment was neither applied nor parked — the operator has no way to proceed")
	}
	// The parked request states its blast radius. An approval that does not is
	// worth little: the approver would be judging "containment" with no idea
	// whether it reaches one host or the estate.
	if got := targetsOf(body["targets"]); len(got) != 1 || got[0] != "agent-a" {
		t.Fatalf("the parking response reported targets %v, want [agent-a]: %v", got, body)
	}

	// Untargeted, the existing gate is unchanged: parked for a second operator.
	code, _ = fleetWrite(t, s, s.handleChokePreset, "POST", "/api/fleet/preset?tenant=acme",
		map[string]any{"name": "containment", "reason": "IR-4821"})
	if code != http.StatusAccepted {
		t.Fatalf("a fleet-wide containment returned %d, want 202 — the approval gate must not have moved", code)
	}
	if s.approvals.PendingCount("acme") != 2 {
		t.Fatal("the fleet-wide containment was not parked for approval")
	}
}

// targetsOf reads a host list out of a response body. Both shapes are real: a
// body that went through JSON carries []any, one read straight off a handler's
// return value carries []string.
func targetsOf(raw any) []string {
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := []string{}
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// TestFleetOutcomeReportsWhatEachAgentActuallySaid. The reporting rules, with
// no live agent: an applied ack is the only thing counted as success, a
// rejection carries its detail, and an agent that never answered is reported as
// a timeout rather than as a refusal — silence is not a rejection, and calling
// it one would send an operator chasing a host that did take the change.
func TestFleetOutcomeReportsWhatEachAgentActuallySaid(t *testing.T) {
	agents := []string{"agent-a", "agent-b", "agent-c", "agent-d"}
	ids := map[string]string{"agent-a": "c1", "agent-b": "c2", "agent-c": "c3", "agent-d": ""}
	acks := map[string]*ebpfsocv1.CommandAck{
		"agent-a": {Status: ebpfsocv1.CommandAck_STATUS_APPLIED, Detail: "preset applied"},
		"agent-b": {Status: ebpfsocv1.CommandAck_STATUS_REJECTED, Detail: "enforcement is kill-switched"},
		// agent-c never answered; agent-d was never dispatched to at all.
	}

	out := fleetOutcome(agents, ids, acks)
	if out.total != 4 || out.applied != 1 {
		t.Fatalf("applied/total = %d/%d, want 1/4", out.applied, out.total)
	}
	if len(out.hosts) != 4 {
		t.Fatalf("hosts = %v, want one entry per dispatched agent in order", out.hosts)
	}
	for i, want := range agents {
		if out.hosts[i].Name != want {
			t.Fatalf("hosts[%d] = %q, want %q — the order must not depend on map iteration", i, out.hosts[i].Name, want)
		}
	}
	if !out.hosts[0].OK || out.hosts[0].Status != "STATUS_APPLIED" {
		t.Fatalf("the applying agent was reported as %+v", out.hosts[0])
	}
	if out.hosts[1].OK || out.hosts[1].Error != "enforcement is kill-switched" {
		t.Fatalf("the rejecting agent was reported as %+v — its reason is what tells the operator whether to retry", out.hosts[1])
	}
	if out.hosts[2].OK || out.hosts[2].Status != "timeout" {
		t.Fatalf("the silent agent was reported as %+v, want an unconfirmed timeout", out.hosts[2])
	}
	if out.hosts[3].OK || out.hosts[3].Status != "not_dispatched" {
		t.Fatalf("an agent nothing was sent to was reported as %+v", out.hosts[3])
	}
	if out.detail == "" {
		t.Fatal("no detail survived the fan-out, so the envelope says nothing about why a host refused")
	}
}

// TestResolveFleetTargetsIsTenantScoped: another tenant's agent id must not
// become a targeting oracle, and must be refused by name like any other host
// this tenant does not have.
func TestResolveFleetTargetsIsTenantScoped(t *testing.T) {
	s := targetingServer(t)
	seed(s, "other-corp", "agent-x")

	targets := []string{"agent-x"}
	agents, unknown, err := s.resolveFleetTargets("acme", &targets)
	if err == nil {
		t.Fatalf("another tenant's agent resolved as targetable: %v", agents)
	}
	if len(unknown) != 1 || unknown[0] != "agent-x" {
		t.Fatalf("unknown = %v, want [agent-x]", unknown)
	}
	if len(agents) != 0 {
		t.Fatalf("agents = %v, want nothing dispatchable", agents)
	}
}
