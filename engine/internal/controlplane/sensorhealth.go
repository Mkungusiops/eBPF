package controlplane

import (
	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
	"github.com/jeffmk/ebpf-poc-engine/internal/mitre"
)

// Sensor health and coverage: can this tenant's detection actually see anything
// right now, and is it losing evidence?
//
// # Why this replaces "Kprobe performance"
//
// The panel this serves used to be a per-policy post-count table labelled
// "Kprobe performance". It measured THROUGHPUT — posts per minute, derived in
// the browser from deltas between polls — and called it performance. It showed
// no CPU, no memory, no latency and, critically, no event loss, so it could not
// answer the question a customer actually gates a deployment on: what does the
// agent cost my hosts, and are you dropping events?
//
// It was also half-dead on the multi-tenant console. It wanted nine fields off
// /api/policy-stats; the control plane serves two (name, posts), so it lost
// `mode`, `state` and `kernel_memory` — including the one that says a Tetragon
// policy is in ENFORCE rather than monitor, which is the second enforcement
// authority on a host and the one that cost this project a lockout.
//
// So the question changed from "how fast are the kprobes" to "is detection
// running, everywhere it should be, and is any of it being lost". Every input
// below already existed; almost none of it had reached the console.
//
// # Silence is not health
//
// An agent that has not reported contributes UNKNOWN, never OK. A fleet view
// that treats a missing heartbeat as a quiet host is the failure this whole
// surface exists to prevent — it is exactly how a dead sensor looks like a
// clean estate.
// issue is one finding with a machine-readable kind. Mirrors the engine's
// internal/api type verbatim: one console renders both planes, so the codes
// have to be the same closed set or the remedy mapping silently misses half of
// them.
type issue struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

const (
	issueKernelUnreadable = "kernel-unreadable"
	issuePoliciesMissing  = "policies-missing"
	issueNoTetragon       = "no-tetragon"
	issuePolicyEnforcing  = "policy-enforcing"
	issueStaleHeartbeat   = "stale-heartbeat"
	issueEvidenceLost     = "evidence-lost"

	// Enforcement findings — faults, they lower status.
	issueDevicePlaneDetached = "device-plane-detached"
	issueContainmentShadowed = "containment-shadowed"

	// Notes — true, worth stating, NOT faults. Kept out of Issues so a
	// deployment choice cannot inflate "needing attention".
	noteManualOnly     = "containment-manual-only"
	noteNoNetworkChoke = "no-kernel-network-choke"
	noteNoDevicePlane  = "no-device-plane"
)

var _ = issueNoTetragon // engine-only; kept so the set is one list

// containment mirrors the engine's per-host capability verdict.
//
// # What this plane can and cannot know
//
// The engine computes its verdict from live closures on the host it runs on.
// The control plane has only the agent heartbeat, and DataPlaneState carries
// process_plane, process_links, device_plane, device_links, mode and
// device_mode — and NOTHING about dry-run, the kill-switch, or whether cgroup
// v2 is available and un-degraded.
//
// So freeze, resource_caps and manual_lands are genuinely UNKNOWN here, and are
// reported as such. That forces the verdict to "partial-unknown", which is the
// honest answer and also a finding in its own right: an MSSP console cannot
// today verify that a customer's host is able to contain anything. Closing that
// means adding posture fields to DataPlaneState and having the agent populate
// them — a wire change, deliberately not faked with a default here.
type containment struct {
	Verdict string `json:"verdict"`
	Summary string `json:"summary"`

	Kill         string `json:"kill"`
	Freeze       string `json:"freeze"`
	ResourceCaps string `json:"resource_caps"`
	NetProcess   string `json:"net_process"`
	NetDevice    string `json:"net_device"`
	Auto         string `json:"auto"`
	AutoDevice   string `json:"auto_device,omitempty"`
	ManualLands  bool   `json:"manual_lands"`
	/** Unknowns is what this plane could not read, named so the console can say why. */
	Unknowns []string `json:"unknowns,omitempty"`
}

type sensorAgent struct {
	AgentID string `json:"agent_id"`
	Version string `json:"version"`
	Kernel  string `json:"kernel,omitempty"`

	LastSeen    time.Time `json:"last_seen"`
	LastSeenAge float64   `json:"last_seen_age_seconds"`
	// Fresh is heartbeat recency, the precondition for trusting anything else
	// in this row. A stale row's other fields describe the past, not now.
	Fresh bool `json:"fresh"`

	// Detection: what the KERNEL has loaded, not what a config file says.
	PoliciesLoaded   int      `json:"policies_loaded"`
	PoliciesEnforce  int      `json:"policies_enforce"`
	MissingPolicies  []string `json:"missing_policies"`
	KernelObservable bool     `json:"kernel_observable"`

	// Enforcement data planes. "noop" means the ladder is modelled in userspace
	// and never reaches the kernel.
	ProcessPlane string `json:"process_plane"`
	ProcessLinks int32  `json:"process_links"`
	DevicePlane  string `json:"device_plane"`
	DeviceLinks  int32  `json:"device_links"`

	// Evidence loss. BufferDepth still drains; DroppedRecords never will.
	BufferDepth      uint64 `json:"buffer_depth"`
	DroppedRecords   uint64 `json:"dropped_records"`
	DroppedBroadcast uint64 `json:"dropped_broadcast"`

	Thresholds map[string]int `json:"thresholds,omitempty"`

	// PolicyVersion is this host's fingerprint of the detection set the KERNEL
	// actually has: sha256 over the sorted (name, mode, enabled) tuples, taken
	// fresh on every heartbeat (cmd/agent/heartbeat.go policyVersion).
	//
	// It has been collected on every heartbeat since the field was added and
	// rendered NOWHERE — grep for policy_version across web/src returned zero
	// hits. That is the one measurement that answers "is my fleet running the
	// same detections", which is the question a change to a policy creates. Two
	// agents with different fingerprints are running different detections, and
	// nothing in the product said so.
	PolicyVersion string `json:"policy_version,omitempty"`

	// Status is the row's verdict: ok | degraded | stale | unknown. Computed
	// server-side so the console and any exported report cannot disagree.
	Status      string       `json:"status"`
	Issues      []issue      `json:"issues"`
	Notes       []issue      `json:"notes,omitempty"`
	Containment *containment `json:"containment,omitempty"`
}

// staleAfter is how long a heartbeat stays trustworthy. Agents beat well inside
// this; a row past it describes a host that may already be gone.
const staleAfter = 90 * time.Second

// expectedPolicies is the detection set this build ships. A tenant missing one
// has a blind spot that no alert count can reveal — the absence of alerts from
// an unloaded policy looks exactly like a quiet estate.
func expectedPolicies() []string {
	out := mitre.PolicyNames()
	sort.Strings(out)
	return out
}

func (s *Server) handleSensorHealth(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	now := time.Now().UTC()
	expected := expectedPolicies()

	recs := s.registry.ListTenant(tenant)
	agents := make([]sensorAgent, 0, len(recs))
	var fresh, losing int
	var totalDropped uint64

	for _, rec := range recs {
		age := now.Sub(rec.LastSeen).Seconds()
		row := sensorAgent{
			AgentID:          rec.AgentID,
			Version:          rec.Version,
			Kernel:           rec.Kernel,
			LastSeen:         rec.LastSeen.UTC(),
			LastSeenAge:      age,
			Fresh:            now.Sub(rec.LastSeen) < staleAfter,
			ProcessPlane:     planeOrUnknown(rec.ProcessPlane),
			ProcessLinks:     rec.ProcessLinks,
			DevicePlane:      planeOrUnknown(rec.DevicePlane),
			DeviceLinks:      rec.DeviceLinks,
			BufferDepth:      rec.BufferDepth,
			DroppedRecords:   rec.DroppedRecords,
			DroppedBroadcast: rec.DroppedBroadcast,
			Thresholds:       chokeThresholds([]heartbeat.Record{rec}),
			PolicyVersion:    rec.AppliedPolicyVersion,
		}

		loaded := map[string]bool{}
		for _, p := range rec.KernelPolicies {
			if !p.GetEnabled() {
				continue
			}
			loaded[p.GetName()] = true
			row.PoliciesLoaded++
			if p.GetMode() == "enforce" {
				row.PoliciesEnforce++
			}
		}
		// An agent that reported no kernel policies at all could not read
		// Tetragon. That is NOT the same as a host with none loaded, and
		// reporting it as zero-loaded would invent a blind spot; reporting it as
		// fine would hide one.
		row.KernelObservable = len(rec.KernelPolicies) > 0
		if row.KernelObservable {
			for _, name := range expected {
				if !loaded[name] {
					row.MissingPolicies = append(row.MissingPolicies, name)
				}
			}
		}

		switch {
		case !row.Fresh:
			row.Status = "stale"
			row.Issues = append(row.Issues, issue{Code: issueStaleHeartbeat,
				Detail: "no heartbeat within 90s — this row describes the past"})
		default:
			fresh++
			row.Status = "ok"
		}
		if !row.KernelObservable {
			row.Status = worst(row.Status, "unknown")
			row.Issues = append(row.Issues, issue{Code: issueKernelUnreadable,
				Detail: "agent could not read Tetragon — detection state unknown"})
		}
		if len(row.MissingPolicies) > 0 {
			row.Status = worst(row.Status, "degraded")
			row.Issues = append(row.Issues, issue{Code: issuePoliciesMissing,
				Detail: "detection policies not loaded in the kernel: " + strings.Join(row.MissingPolicies, ", ")})
		}
		if row.PoliciesEnforce > 0 {
			row.Status = worst(row.Status, "degraded")
			row.Issues = append(row.Issues, issue{Code: issuePolicyEnforcing,
				Detail: "a Tetragon policy is in ENFORCE mode — it acts independently of the choke ladder, with no audit row and no kill-switch"})
		}
		if row.DroppedRecords > 0 {
			losing++
			row.Status = worst(row.Status, "degraded")
			row.Issues = append(row.Issues, issue{Code: issueEvidenceLost,
				Detail: "telemetry permanently lost to the uplink cap"})
		}
		totalDropped += row.DroppedRecords

		// CONTAINMENT. What this host can do, graded — and explicit about the
		// mechanisms the wire does not carry, rather than assuming them.
		cont, contIssues := assessRemoteContainment(row,
			enforcementModeLabel(rec.Mode), enforcementModeLabel(rec.DeviceMode))
		row.Containment = cont
		row.Issues = append(row.Issues, contIssues...)
		if len(contIssues) > 0 {
			row.Status = worst(row.Status, "degraded")
		}
		// Notes: true, worth stating, not faults. Kept out of Issues so they
		// cannot lower status or inflate "needing attention".
		if cont.NetProcess == capNo {
			row.Notes = append(row.Notes, issue{Code: noteNoNetworkChoke,
				Detail: "per-PID network containment is not deployed on this host: throttle and tarpit cap CPU, memory, IO and process count — they do not rate-limit outbound traffic"})
		}
		if cont.NetDevice == capNo {
			row.Notes = append(row.Notes, issue{Code: noteNoDevicePlane,
				Detail: "no network device containment on this host — device decisions are recorded and no frame is dropped. Correct for a host that does not sit inline on a network segment"})
		}
		if cont.Auto != "enforcing" && cont.Auto != capUnknown {
			row.Notes = append(row.Notes, issue{Code: noteManualOnly,
				Detail: "automatic containment is off (detect-only): the score ladder will record a decision and act on nothing. An action an operator presses does still reach the kernel — that path bypasses detect-only by design"})
		}

		agents = append(agents, row)
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].AgentID < agents[j].AgentID })

	// Detection DRIFT: distinct kernel-policy fingerprints across the reporting
	// fleet. One is agreement. More than one means hosts are running different
	// detections, which is invisible in every other panel — an alert count
	// cannot show you the host that quietly lost a policy.
	//
	// Counted over FRESH agents only: a stale row's fingerprint describes
	// whatever it was running when it stopped reporting, and folding that in
	// would report drift that may have healed, or hide drift that has not.
	versions := map[string]int{}
	for _, a := range agents {
		if a.Fresh && a.PolicyVersion != "" {
			versions[a.PolicyVersion]++
		}
	}

	writeJSON(w, 200, map[string]any{
		"tenant": tenant,
		"agents": agents,
		// Coverage is reporting agents over known agents. It is NOT an estate
		// coverage figure and must not be read as one: this platform only knows
		// about hosts that have enrolled, so it cannot see a host with no agent.
		// Saying so here is the difference between a coverage number and a
		// comforting one.
		"agents_total":        len(agents),
		"agents_fresh":        fresh,
		"agents_losing":       losing,
		"dropped_records":     totalDropped,
		"expected_policies":   expected,
		"policy_versions":     versions,
		"policy_drift":        len(versions) > 1,
		"coverage_caveat":     "counts enrolled agents only — a host that never enrolled is invisible to this platform",
		"stale_after_seconds": staleAfter.Seconds(),
		"generated_at":        now,
	})
}

func planeOrUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

// worst keeps the most serious verdict seen. Ordering: ok < degraded < unknown
// < stale — "stale" outranks everything because a stale row's other fields
// cannot be trusted at all.
func worst(a, b string) string {
	rank := map[string]int{"ok": 0, "degraded": 1, "unknown": 2, "stale": 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// driftVersions is exported for tests: the distinct kernel-policy fingerprints
// across the FRESH agents in a set. Split out so the rule "stale agents do not
// vote" is pinnable without standing up an HTTP server.
func driftVersions(agents []sensorAgent) map[string]int {
	out := map[string]int{}
	for _, a := range agents {
		if a.Fresh && a.PolicyVersion != "" {
			out[a.PolicyVersion]++
		}
	}
	return out
}

// assessRemoteContainment grades what a REMOTE host can do, from the heartbeat
// alone.
//
// Deliberately conservative: every mechanism the wire does not carry is
// "unknown", never a default. A default here would be the platform telling an
// MSSP that a customer's host can freeze a process when nothing has ever
// checked — which is the exact class of claim this codebase keeps having to
// walk back.
func assessRemoteContainment(a sensorAgent, autoMode, autoDeviceMode string) (*containment, []issue) {
	var issues []issue
	c := &containment{
		// Not on the wire. See the type comment.
		Freeze:       capUnknown,
		ResourceCaps: capUnknown,
		Kill:         capUnknown,
		ManualLands:  true,
		Unknowns: []string{
			"whether cgroup v2 containment (freeze, throttle, tarpit) is available and un-degraded",
			"whether the enforcement kill-switch is engaged",
		},
	}
	// Dry-run IS on the wire, as its own enum value — it is the one posture in
	// which an action the operator presses themselves does nothing, so it must
	// never be folded into detect-only.
	if autoMode == "dry-run" {
		c.ManualLands = false
		c.Kill = capNo
		issues = append(issues, issue{Code: issueContainmentShadowed,
			Detail: "dry-run is engaged on this host — every containment action is recorded and none is executed, including one an operator presses"})
	}

	c.Auto = autoMode
	if c.Auto == "" {
		c.Auto = capUnknown
	}
	c.AutoDevice = autoDeviceMode

	// Per-PID network choke: needs the compiled object, reported as the
	// process plane backend.
	switch {
	case a.ProcessPlane == "" || a.ProcessPlane == "unknown":
		c.NetProcess = capUnknown
	case a.ProcessPlane == "noop" || a.ProcessPlane == "disabled":
		c.NetProcess = capNo
	case a.ProcessLinks == 0:
		c.NetProcess = capDegraded
	default:
		c.NetProcess = capYes
	}

	switch {
	case a.DevicePlane == "" || a.DevicePlane == "unknown":
		c.NetDevice = capUnknown
	case a.DevicePlane == "noop" || a.DevicePlane == "disabled":
		c.NetDevice = capNo
	case a.DeviceLinks == 0:
		// A tc program attached to nothing: recorded, and touching no packet.
		c.NetDevice = capDegraded
		issues = append(issues, issue{Code: issueDevicePlaneDetached,
			Detail: "the device data plane loaded but is attached to no interface — device containment will be recorded and will not touch a packet"})
	default:
		c.NetDevice = capYes
	}

	// Verdict. Unknown mechanisms can never produce "full".
	switch {
	case !c.ManualLands:
		c.Verdict = "none"
		c.Summary = "Nothing reaches the kernel on this host — including a containment action an operator presses. It is in dry-run."
	case c.NetDevice == capDegraded || c.NetProcess == capDegraded:
		c.Verdict = "partial-degraded"
		c.Summary = "Something in this host's containment stack is degraded — see the findings below. This console cannot read its cgroup or dry-run state, so this is not a complete picture."
	default:
		c.Verdict = "partial-unknown"
		c.Summary = "This console cannot verify what this host can contain: the agent reports its data planes but not whether cgroup containment is available or whether enforcement is shadowed. Check the host's own console for a full answer."
	}
	return c, issues
}

const (
	capYes      = "yes"
	capNo       = "no"
	capDegraded = "degraded"
	capUnknown  = "unknown"
)

// enforcementModeLabel renders the wire enum as the word the console uses.
// An unset enum is "" rather than a guess: an agent predating the field has
// not told us its posture, and defaulting to either answer would be an
// assertion nobody measured.
func enforcementModeLabel(m ebpfsocv1.EnforcementMode) string {
	switch m {
	case ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING:
		return "enforcing"
	case ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DETECT_ONLY:
		return "detect-only"
	case ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DRY_RUN:
		// A distinct posture, not a flavour of detect-only: in dry-run even an
		// action the operator presses themselves is recorded and not executed.
		return "dry-run"
	default:
		return ""
	}
}
