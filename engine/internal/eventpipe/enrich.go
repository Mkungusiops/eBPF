package eventpipe

import (
	"strings"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/baseline"
	"github.com/jeffmk/ebpf-poc-engine/internal/findings"
	"github.com/jeffmk/ebpf-poc-engine/internal/intel"
	"github.com/jeffmk/ebpf-poc-engine/internal/metrics"
)

// Enrichment: the behavioural baseline and the threat-intelligence match,
// applied to an event on its way through the pipeline.
//
// # Where this sits, and why
//
// It runs AFTER the rule scorer and BEFORE the alert decision. That ordering is
// the whole design:
//
//   - After the rules, because enrichment MODIFIES a suspicion the rules
//     established. It is layered on the chain scorer, not a competing scorer.
//   - Before the alert decision, so an event that the rules alone would have
//     left below the threshold can still raise an alert when it is both novel
//     and talking to a known-bad address — which is exactly the case a static
//     rule table cannot express and the reason this exists.
//
// # Failure posture
//
// Every step here is best-effort and independently optional. A nil profile, a
// nil indicator set, an unreadable binary and an unready baseline all degrade
// to "no contribution" rather than to an error. Enrichment must never be able
// to fail an event: this is the path containment latency is measured on, and a
// detection improvement that can drop events is a regression.

// enrichment is the combined result for one event.
type enrichment struct {
	points  int
	reasons []string
	matches []intel.Match
	novel   bool
}

// describe renders the enrichment as a clause for an alert description, or ""
// when there is nothing to say.
//
// Intel first, then behaviour. An analyst reading one line wants the externally
// corroborated fact before the inferred one.
func (e enrichment) describe() string {
	if len(e.matches) == 0 && len(e.reasons) == 0 {
		return ""
	}
	parts := make([]string, 0, len(e.matches)+len(e.reasons))
	for _, m := range e.matches {
		parts = append(parts, intel.Describe(m))
	}
	parts = append(parts, e.reasons...)
	return strings.Join(parts, "; ")
}

// enrichExec assesses a process execution.
//
// The baseline is asked BEFORE it is taught (baseline.Assess then Observe). The
// other order folds the event into the profile first, so it has already made
// itself normal, every assessment comes back "routine", and the feature appears
// to work while reporting nothing forever.
func (p *Pipeline) enrichExec(execID, binary, parentBinary, args string, uid, pid uint32, at time.Time) enrichment {
	var out enrichment

	if p.Baseline != nil {
		o := baseline.Observation{Binary: binary, ParentBinary: parentBinary, UID: uid, At: at}
		a := p.Baseline.Assess(o)
		p.Baseline.Observe(o)

		out.novel = a.Novel
		if a.Points > 0 {
			// The budget is applied by the tree, which owns the chain root.
			// applied may be less than a.Points, or zero once the chain has
			// spent its allowance — the reasons are still reported either way,
			// because an analyst reading the alert needs to know the behaviour
			// was novel even when it no longer moved the number.
			applied := p.Tree.AddAnomaly(execID, a.Points, chainAnomalyBudget)
			out.points += applied
			out.reasons = append(out.reasons, a.Reasons...)
			metrics.IncEvent("baseline_anomaly")
			p.record(findings.Finding{
				At: at, Kind: "anomaly", ExecID: execID, PID: pid, Binary: binary,
				Points: applied, Reasons: a.Reasons,
			})
		}
	}

	if p.Intel != nil {
		cands := intel.FromCommandLine(binary, args)
		// Hashing is gated on novelty: a binary this host has executed ten
		// thousand times does not need its digest recomputed and re-checked on
		// run ten thousand and one, and reading files on the event path is the
		// one cost this package cannot absorb casually.
		if h := p.hashIfNovel(binary, out.novel); h != "" {
			cands = append(cands, intel.Candidate{Value: h, Kind: intel.KindSHA256, Where: "binary"})
		}
		out.applyMatches(p, intel.MatchAll(p.Intel, cands), execID, pid, binary, at)
	}
	return out
}

// enrichKprobe assesses a policy-triggered kernel event.
//
// The high-value case: tetrabridge renders a socket argument as "daddr:dport",
// so an outbound-connections event carries the destination of a connection that
// ACTUALLY HAPPENED. That is the strongest observable this platform produces —
// no parsing of user-controlled text, no inference — and it is why an indicator
// hit here is scored at full weight while the same address on a command line is
// halved.
//
// No behavioural assessment here. The baseline's facets are all about process
// lineage, and a kprobe fires on a process the exec handler has already
// assessed; assessing it again would double-count the same novelty once per
// file the process touches.
func (p *Pipeline) enrichKprobe(execID, policyName, binary, args string, pid uint32, at time.Time) enrichment {
	var out enrichment
	if p.Intel == nil {
		return out
	}
	out.applyMatches(p, intel.MatchAll(p.Intel, intel.FromKprobe(policyName, args)), execID, pid, binary, at)
	return out
}

// applyMatches folds indicator hits into the enrichment and the chain score.
//
// Indicator points go through AddScore, NOT the anomaly budget. The budget
// exists to stop ordinary novelty marching a chain to critical; an indicator
// hit is the opposite case — external corroboration that a destination is
// malicious, which is precisely the evidence that SHOULD be able to carry a
// chain to critical on its own.
func (e *enrichment) applyMatches(p *Pipeline, matches []intel.Match, execID string, pid uint32, binary string, at time.Time) {
	for _, m := range matches {
		if m.Points > 0 {
			p.Tree.AddScore(execID, m.Points, "intel:"+m.Kind)
			e.points += m.Points
		}
		e.matches = append(e.matches, m)
		metrics.IncEvent("intel_match")
		match := m
		p.record(findings.Finding{
			At: at, Kind: "intel", ExecID: execID, PID: pid, Binary: binary,
			Points: m.Points, Match: &match,
			Reasons: []string{intel.Describe(m)},
		})
	}
}

// hashIfNovel returns the binary's digest when it is worth computing.
func (p *Pipeline) hashIfNovel(binary string, novel bool) string {
	if p.Hasher == nil || !novel || binary == "" {
		return ""
	}
	h, ok := p.Hasher.Hash(binary)
	if !ok {
		return ""
	}
	return h
}

func (p *Pipeline) record(f findings.Finding) {
	if p.Findings != nil {
		p.Findings.Add(f)
	}
}

// BaselineStatus reports the profile's readiness for the API, nil-safe.
func (p *Pipeline) BaselineStatus(topN int) (baseline.Status, bool) {
	if p.Baseline == nil {
		return baseline.Status{}, false
	}
	return p.Baseline.Status(topN), true
}
