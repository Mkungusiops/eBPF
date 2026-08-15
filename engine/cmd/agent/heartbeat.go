package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
)

// policyVersion fingerprints the policy set this host is ACTUALLY running, so
// the console can spot an agent that has drifted from the rest of the fleet.
//
// The wire contract has carried applied_policy_version since the beginning and
// the control plane already displays it — but nothing ever set it, so every
// agent reported an empty string and drift was invisible. That is not
// hypothetical: `tetra tracingpolicy add` is create-only, so an edited policy
// keeps running the version loaded at start, and a policy deleted at runtime
// returns from a stale file on the next restart. Both leave a host quietly
// running something different from its neighbours.
//
// Derived from the LOADED set (name + mode + enabled), never from files on
// disk, for exactly that reason: what is on disk is what someone intended, and
// the whole class of bug here is the two disagreeing. Mode is included because
// the same policies in enforce rather than monitor mode is a different — and
// much more dangerous — posture, and it should not hash identically.
func policyVersion(pols []*ebpfsocv1.KernelPolicy) string {
	if len(pols) == 0 {
		return ""
	}
	lines := make([]string, 0, len(pols))
	for _, p := range pols {
		lines = append(lines, fmt.Sprintf("%s\x00%s\x00%t", p.GetName(), p.GetMode(), p.GetEnabled()))
	}
	// Tetragon does not promise an order, so sort before hashing or the same
	// fleet-wide policy set would fingerprint differently per host and every
	// agent would look like it had drifted.
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:8])
}

func tracingPolicyMode(m tetragon.TracingPolicyMode) string {
	switch m {
	case tetragon.TracingPolicyMode_TP_MODE_ENFORCE:
		return "enforce"
	case tetragon.TracingPolicyMode_TP_MODE_MONITOR:
		return "monitor"
	default:
		return "unknown"
	}
}

// deviceGatewayMode maps the device gateway's mode string onto the wire enum.
// The device gateway reports "kill-switched" as a mode of its own; on the wire
// that is still detect-only (nothing is being applied), and the kill-switch is
// reported separately.
func deviceGatewayMode(g *choke.DeviceGateway) ebpfsocv1.EnforcementMode {
	if g == nil {
		return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED
	}
	switch g.Mode() {
	case "enforcing":
		return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING
	case "dry-run":
		return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DRY_RUN
	default:
		return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DETECT_ONLY
	}
}

// gatewayMode maps the choke gateway's runtime mode onto the wire enum for
// heartbeat reporting.
func gatewayMode(g *choke.Gateway) ebpfsocv1.EnforcementMode {
	switch g.Mode() {
	case choke.ModeEnforcing:
		return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING
	case choke.ModeDryRun:
		return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DRY_RUN
	case choke.ModeDetectOnly:
		return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DETECT_ONLY
	default:
		// Gateway.Mode() returns a FOURTH value, Mode("kill-switched"), which is
		// not among the three declared constants. It fell to this default and
		// went on the wire as UNSPECIFIED, so the fleet console showed
		// "unspecified" for the one posture an operator most needs to see:
		// enforcement globally halted. Nothing is being applied while the
		// kill-switch is engaged, so detect-only is the honest wire value, and
		// the kill-switch itself is reported separately on the heartbeat.
		//
		// deviceGatewayMode, this function's twin, was fixed for exactly this
		// case and carries the same reasoning; the fix was never applied here.
		return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DETECT_ONLY
	}
}

// chokeSummaries builds the compact, capped choke snapshot the agent puts on
// each heartbeat so the central console can render a per-tenant Choke view.
// Highest-score first (the processes an operator cares about); the rich
// interactive surface stays agent-local.
func chokeSummaries(g *choke.Gateway) []*ebpfsocv1.ChokeSummary {
	if g == nil {
		return nil
	}
	snap := g.Snapshot()
	sort.Slice(snap, func(i, j int) bool { return snap[i].Score > snap[j].Score })
	if len(snap) > 100 {
		snap = snap[:100]
	}
	out := make([]*ebpfsocv1.ChokeSummary, 0, len(snap))
	for _, e := range snap {
		out = append(out, &ebpfsocv1.ChokeSummary{
			ExecId: e.ExecID, Pid: e.PID, Binary: e.Binary, State: e.State, Score: int32(e.Score),
		})
	}
	return out
}

// Caps for the drill detail reported on each heartbeat. These panels are a
// fleet SCAN surface — the agent-local API remains authoritative — so they are
// bounded rather than complete. Uncapped, a busy host would ship its entire
// process table to the control plane every 30 seconds, for every agent.
const (
	maxReportedBuckets   = 200
	maxReportedProcesses = 200
)

// bucketSummaries reports the kernel token buckets the choke gateway installed.
//
// This is the evidence that a throttle actually reached the kernel rather than
// only being written as a decision row. Without it the control plane's "Choke
// Map (kernel)" panel is empty on every tenant while the single-host console
// shows hundreds of live buckets.
func bucketSummaries(g *choke.Gateway) []*ebpfsocv1.BucketSummary {
	if g == nil {
		return nil
	}
	snap, err := g.BucketsSnapshot()
	if err != nil || len(snap) == 0 {
		return nil
	}
	out := make([]*ebpfsocv1.BucketSummary, 0, len(snap))
	for pid, b := range snap {
		out = append(out, &ebpfsocv1.BucketSummary{
			Pid: pid, RatePerSec: uint64(b.RatePerSec), Burst: uint64(b.Burst),
			Tokens: uint64(b.Tokens), Flags: b.Flags,
		})
	}
	// Deterministic order before truncating, so the reported subset is stable
	// between heartbeats instead of flickering with Go's map iteration.
	sort.Slice(out, func(i, j int) bool { return out[i].GetPid() < out[j].GetPid() })
	if len(out) > maxReportedBuckets {
		out = out[:maxReportedBuckets]
	}
	return out
}

// cgroupSummaries reports which PIDs the kernel says are inside each choke
// cgroup — what is ACTUALLY confined, as opposed to what a decision row claims.
func cgroupSummaries(g *choke.Gateway) []*ebpfsocv1.CgroupSummary {
	if g == nil {
		return nil
	}
	m, err := g.CgroupInhabitants()
	if err != nil || len(m) == 0 {
		return nil
	}
	tiers := make([]string, 0, len(m))
	for tier := range m {
		tiers = append(tiers, tier)
	}
	sort.Strings(tiers)
	out := make([]*ebpfsocv1.CgroupSummary, 0, len(tiers))
	for _, tier := range tiers {
		out = append(out, &ebpfsocv1.CgroupSummary{Tier: tier, Pids: m[tier]})
	}
	return out
}

// processSummaries reports the live host process table joined with choke state,
// which is what the console's process picker offers an operator. On the control
// plane that picker had nothing to pick from.
func processSummaries(g *choke.Gateway) []*ebpfsocv1.ProcessSummary {
	if g == nil {
		return nil
	}
	procs, err := g.HostProcesses()
	if err != nil || len(procs) == 0 {
		return nil
	}
	// Tracked processes first, then by score: an operator scanning a fleet cares
	// about what the gateway is already acting on, and truncation must not drop
	// exactly those rows.
	sort.Slice(procs, func(i, j int) bool {
		if procs[i].Tracked != procs[j].Tracked {
			return procs[i].Tracked
		}
		if procs[i].Score != procs[j].Score {
			return procs[i].Score > procs[j].Score
		}
		return procs[i].PID < procs[j].PID
	})
	if len(procs) > maxReportedProcesses {
		procs = procs[:maxReportedProcesses]
	}
	out := make([]*ebpfsocv1.ProcessSummary, 0, len(procs))
	for _, p := range procs {
		out = append(out, &ebpfsocv1.ProcessSummary{
			Pid: p.PID, Ppid: p.PPID, Uid: p.UID, Comm: p.Comm, Exe: p.Exe,
			Cmdline: p.Cmdline, Tracked: p.Tracked, State: p.State,
			Score: int32(p.Score), ExecId: p.ExecID,
		})
	}
	return out
}

// deviceSummaries builds the compact device snapshot for the heartbeat (empty
// when the device data plane is inactive, as on a host with no -devchoke-iface).
func deviceSummaries(g *choke.DeviceGateway) []*ebpfsocv1.DeviceSummary {
	if g == nil {
		return nil
	}
	snap := g.Snapshot()
	if len(snap) > 100 {
		snap = snap[:100]
	}
	out := make([]*ebpfsocv1.DeviceSummary, 0, len(snap))
	for _, d := range snap {
		label := d.Hostname
		if label == "" {
			label = d.Vendor
		}
		out = append(out, &ebpfsocv1.DeviceSummary{
			Mac: d.MAC, State: d.State, Label: label,
			LastIp: d.LastIP, Protected: d.Protected,
		})
	}
	return out
}
