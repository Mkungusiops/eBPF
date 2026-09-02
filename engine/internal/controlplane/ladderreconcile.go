package controlplane

import (
	"fmt"
	"sync"
	"time"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
)

// Keeping every agent in a tenant on that tenant's containment ladder.
//
// # Why dispatching once is not enough
//
// A fleet threshold change reaches the agents that exist at that moment. An
// agent enrolled tomorrow starts on whatever the deploy configured, so a
// tenant that deliberately tightened its ladder silently acquires a host
// running the old one — and nothing on the console says so, because the
// console reports what it dispatched, not what each host is running.
//
// # Why this reconciles rather than fires on enrolment
//
// Every heartbeat already carries the agent's CURRENT ladder, so the control
// plane can compare rather than assume. That covers the enrolment case and two
// others it would have missed: an agent that was offline when the change went
// out, and one whose local override drifted from the tenant policy.
//
// It is self-limiting by construction. A dispatch is only sent when the agent's
// reported ladder differs from the stored one; the agent applies it and reports
// the new ladder on its next heartbeat, so the difference disappears and the
// dispatch stops. No bookkeeping to get wrong, and nothing to reset when an
// agent is replaced.
const ladderReconcileInterval = 2 * time.Minute

// setReconcileInterval is how often the sets that cannot be compared are
// re-pushed. Far slower than the ladder pass: a blind re-dispatch is
// unconditional traffic, so it runs at a cadence that closes an offline
// agent's gap within an hour rather than adding a command every two minutes
// to every agent in the fleet forever.
const setReconcileInterval = 30 * time.Minute

// startLadderReconciler runs the convergence loop for the life of the process.
func (s *Server) startLadderReconciler() {
	if s.registry == nil || s.dispatcher == nil {
		return
	}
	// Two cadences, because the two passes cost different things. The ladder
	// pass only dispatches on an observed difference, so it can run often. The
	// set pass re-pushes blind, so running it at the ladder's cadence would
	// add a command to every agent in the fleet every two minutes, forever.
	go func() {
		for range time.Tick(ladderReconcileInterval) {
			s.reconcileLadders()
		}
	}()
	go func() {
		for range time.Tick(setReconcileInterval) {
			s.reconcileTenantSets()
		}
	}()
}

// reconcileTenantSets re-pushes the stored protect-list and suppressions.
//
// Blind re-dispatch, and it says so: without a heartbeat field to compare
// against, the control plane cannot tell a converged agent from a drifted one.
// The honest options were to re-push periodically or to leave offline agents
// silently different, and a redundant command costs one signature verification
// where the alternative costs a tenant its guardrails on one host.
func (s *Server) reconcileTenantSets() {
	pg, ok := s.pgStore()
	if !ok {
		return
	}
	for tenant := range s.agentsByTenant() {
		if entries, err := pg.ProtectedList(tenant); err == nil && len(entries) > 0 {
			bins, macs := splitProtected(entries)
			s.dispatchToTenantAgents(tenant, &ebpfsocv1.Command{
				Actor: "policy:tenant-protect-list",
				Action: &ebpfsocv1.Command_UpdateProtectedList{
					UpdateProtectedList: &ebpfsocv1.UpdateProtectedList{
						ProtectedBinaries: bins, ProtectedMacs: macs}}})
		}
		if rules, err := pg.Suppressions(tenant); err == nil && len(rules) > 0 {
			wire := make([]*ebpfsocv1.Suppression, 0, len(rules))
			for _, x := range rules {
				wire = append(wire, &ebpfsocv1.Suppression{
					Binary: x.Binary, Policy: x.Policy, Parent: x.Parent, Reason: x.Reason})
			}
			s.dispatchToTenantAgents(tenant, &ebpfsocv1.Command{
				Actor: "policy:tenant-suppressions",
				Action: &ebpfsocv1.Command_UpdateSuppressions{
					UpdateSuppressions: &ebpfsocv1.UpdateSuppressions{
						Suppressions: wire, Reason: "periodic reconciliation"}}})
		}
	}
}

// dispatchToTenantAgents enqueues one command for every agent in a tenant
// without waiting for acks.
//
// Deliberately fire-and-forget: this runs on a timer with no operator waiting,
// and blocking a background pass on ack timeouts would let one unreachable
// agent stall convergence for every other tenant.
func (s *Server) dispatchToTenantAgents(tenant string, cmd *ebpfsocv1.Command) {
	for _, rec := range s.registry.ListTenant(tenant) {
		s.dispatcher.Enqueue(rec.AgentID, cmd)
	}
}

func (s *Server) reconcileLadders() {
	pg, ok := s.pgStore()
	if !ok {
		return // no tenant policy to converge on
	}
	for tenant, agents := range s.agentsByTenant() {
		want, err := pg.ThresholdsFor(tenant)
		if err != nil {
			continue // never set, or unreadable — the deployed ladder stands
		}
		for _, rec := range agents {
			if sameLadder(rec.Thresholds, want.Config) {
				continue
			}
			// Reported as a drift correction rather than a routine push: an
			// agent running thresholds its tenant did not choose is worth a
			// line in the log, and a repeating line means it is not applying
			// them — which is the failure this would otherwise hide.
			s.cfg.Logf("[ladder] %s/%s runs %s, tenant policy is %s — dispatching",
				tenant, rec.AgentID, ladderString(rec.Thresholds), circuitString(want.Config))
			// Recorded, not only logged. An operator who set a ladder on one
			// host directly — through that agent's own console, which is a
			// supported thing to do — watches it revert within two minutes
			// with nothing anywhere saying why. A log line on the control
			// plane is not an answer they can reach.
			s.ladderCorrections.record(ladderCorrection{
				Tenant: tenant, Agent: rec.AgentID,
				From: ladderString(rec.Thresholds), To: circuitString(want.Config),
				At: time.Now().UTC(),
			})
			s.dispatcher.Enqueue(rec.AgentID, &ebpfsocv1.Command{
				Actor: "policy:tenant-ladder",
				Action: &ebpfsocv1.Command_SetThresholds{SetThresholds: &ebpfsocv1.SetThresholds{
					ThrottleAt:   int32(want.Config.ThrottleAt),
					TarpitAt:     int32(want.Config.TarpitAt),
					QuarantineAt: int32(want.Config.QuarantineAt),
					SeverAt:      int32(want.Config.SeverAt),
				}},
			})
		}
	}
}

// agentsByTenant groups the live registry by tenant.
func (s *Server) agentsByTenant() map[string][]heartbeat.Record {
	out := map[string][]heartbeat.Record{}
	for _, tenant := range s.registry.Tenants() {
		out[tenant] = s.registry.ListTenant(tenant)
	}
	return out
}

// ladderString renders an agent's reported ladder for a log line.
func ladderString(t *ebpfsocv1.ChokeThresholds) string {
	if t == nil {
		return "unreported"
	}
	return fmt.Sprintf("%d/%d/%d/%d",
		t.GetThrottleAt(), t.GetTarpitAt(), t.GetQuarantineAt(), t.GetSeverAt())
}

// circuitString renders the tenant policy in the same shape, so the two are
// comparable at a glance in the log.
func circuitString(c circuit.Config) string {
	return fmt.Sprintf("%d/%d/%d/%d", c.ThrottleAt, c.TarpitAt, c.QuarantineAt, c.SeverAt)
}

// sameLadder compares an agent's reported ladder with the tenant policy.
//
// An agent that reports NO ladder is treated as matching, deliberately. That
// is an older agent, or one that has not populated the field yet, and
// dispatching to it every two minutes forever would be a storm against a host
// that can never confirm it converged.
func sameLadder(got *ebpfsocv1.ChokeThresholds, want circuit.Config) bool {
	if got == nil {
		return true
	}
	return int(got.GetThrottleAt()) == want.ThrottleAt &&
		int(got.GetTarpitAt()) == want.TarpitAt &&
		int(got.GetQuarantineAt()) == want.QuarantineAt &&
		int(got.GetSeverAt()) == want.SeverAt
}

// A record of the reconciler overriding one host's ladder.
//
// # Why this is not just a log line
//
// Setting a ladder on a single host is supported: the agent serves its own
// console and accepts a SetThresholds over the command channel. But the tenant
// policy is authoritative, so the reconciler corrects that host within two
// minutes — correctly, and silently. The operator sees their change apply and
// then vanish, with the explanation sitting in a control-plane log they have no
// route to.
//
// Adopting the host's value as the new tenant policy — "fold it in on first
// write" — was the other candidate and is the dangerous one: it lets a change
// made on one host silently rewrite the containment ladder for every other host
// in the fleet, which is precisely the blast radius this platform spends its
// effort bounding elsewhere.
//
// So the correction stands and becomes VISIBLE instead.
type ladderCorrection struct {
	Tenant string    `json:"-"`
	Agent  string    `json:"agent"`
	From   string    `json:"from"`
	To     string    `json:"to"`
	At     time.Time `json:"at"`
}

// ladderCorrectionCap bounds the ring. Corrections are rare by construction —
// each one stops the drift that produced it — so a small ring holds a long
// history, and an unbounded one would be a slow leak on a process that runs for
// months.
const ladderCorrectionCap = 200

type ladderCorrectionLog struct {
	mu      sync.Mutex
	records []ladderCorrection
}

func (l *ladderCorrectionLog) record(c ladderCorrection) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, c)
	if excess := len(l.records) - ladderCorrectionCap; excess > 0 {
		l.records = append(l.records[:0], l.records[excess:]...)
	}
}

// forTenant returns the newest corrections for one tenant, newest first.
func (l *ladderCorrectionLog) forTenant(tenant string, limit int) []ladderCorrection {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []ladderCorrection{}
	for i := len(l.records) - 1; i >= 0 && len(out) < limit; i-- {
		if l.records[i].Tenant == tenant {
			out = append(out, l.records[i])
		}
	}
	return out
}
