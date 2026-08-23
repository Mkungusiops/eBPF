package api

import "fmt"

// What this host can actually DO to a process, as a graded verdict.
//
// # Why the panel needed this
//
// Sensor Health computed its status from detection facts alone — kernel
// readable, policies loaded, Tetragon up. Not one branch read an enforcement
// mechanism, so a host reported a green "ok" while the panel said nothing at
// all about whether it could contain anything. It rendered `process plane:
// noop` as a bare word beside that green tick, which only a reader of this
// codebase can interpret.
//
// # Mechanisms, not component names
//
// Every field below is a CAPABILITY an operator can reason about — can this
// host kill a process, freeze it, cap its resources, touch its traffic — and
// never a backend name. "noop" is meaningless to a SOC analyst; "cannot
// rate-limit this process's network traffic" is not.
//
// # Two channels, because two different facts
//
// A mechanism absent BY DEPLOYMENT is not a fault, and alarming on it trains
// operators to ignore the panel. A mechanism that failed, or that is armed
// against the operator, is. The first goes to notes and leaves status alone;
// the second is an issue and lowers it. Getting that split wrong in either
// direction is what makes a trust surface useless.
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

	// ManualLands is the single most consequential fact here: whether an
	// action the operator presses themselves reaches the kernel. It is TRUE
	// even in detect-only mode — the gateway routes a manual action through
	// the real enforcer by design, and only dry-run or the kill-switch stop it.
	// An earlier draft of this feature was going to tell operators their sever
	// would not land on a detect-only host. It would have been false, and it
	// would have been the most damaging thing this panel could say.
	ManualLands bool `json:"manual_lands"`
}

const (
	capYes      = "yes"
	capNo       = "no"
	capDegraded = "degraded"
	capUnknown  = "unknown"
)

// assessContainment turns the live posture closures into a verdict.
//
// Anything this deployment cannot read becomes "unknown" and forces a verdict
// that is never "full" — an unmeasured mechanism must not be counted as a
// working one.
func assessContainment(info SystemInfo) (containment, []issue, []issue) {
	var issues, notes []issue

	dryRun := info.ChokeDryRun != nil && info.ChokeDryRun()
	killSwitched := info.ChokeKillSwitch != nil && info.ChokeKillSwitch()
	manualLands := !dryRun && !killSwitched

	c := containment{ManualLands: manualLands}

	// Auto posture.
	c.Auto = capUnknown
	if info.ChokeAutoMode != nil {
		c.Auto = info.ChokeAutoMode()
	}
	if info.DeviceAutoMode != nil {
		c.AutoDevice = info.DeviceAutoMode()
	}

	// cgroup mechanisms: freeze and the resource caps.
	switch {
	case info.CgroupAvailable == nil:
		c.Freeze, c.ResourceCaps = capUnknown, capUnknown
	case !info.CgroupAvailable():
		c.Freeze, c.ResourceCaps = capNo, capNo
		issues = append(issues, issue{Code: issueNoProcessContainment,
			Detail: "cgroup v2 is not available at the configured root — throttle, tarpit and quarantine cannot be applied on this host; only sever (SIGKILL) still works"})
	default:
		c.Freeze, c.ResourceCaps = capYes, capYes
		if info.CgroupDegraded != nil {
			if d := info.CgroupDegraded(); len(d) > 0 {
				// A limit the kernel refused. Recorded at boot and printed
				// once; nothing has ever surfaced it to an operator.
				c.ResourceCaps = capDegraded
				c.Freeze = capDegraded
				issues = append(issues, issue{Code: issueEnforcementDegraded,
					Detail: fmt.Sprintf("the kernel refused %d configured containment limit(s): %v. Quarantine still works — it freezes the process — but the CPU cap meant to back that freeze up is not installed", len(d), d)})
			}
		}
	}

	// Sever is SIGKILL and does not depend on cgroups or on any BPF object.
	// It is only unavailable when nothing lands at all.
	c.Kill = capYes
	if !manualLands {
		c.Kill = capNo
	}

	// Per-PID network containment needs the compiled choke object.
	c.NetProcess = capNo
	if info.BPFBackend == "cilium-ebpf" {
		c.NetProcess = capYes
		if info.BPFLinks != nil && info.BPFLinks() == 0 {
			c.NetProcess = capDegraded
		}
	}

	// Device plane.
	plane := ""
	if info.DevicePlane != nil {
		plane = info.DevicePlane()
	}
	links := 0
	if info.DeviceLinks != nil {
		links = info.DeviceLinks()
	}
	switch {
	case plane == "" || plane == "noop" || plane == "disabled":
		c.NetDevice = capNo
	case links == 0:
		// A tc program attached to nothing is the failure that looks healthy.
		c.NetDevice = capDegraded
		issues = append(issues, issue{Code: issueDevicePlaneDetached,
			Detail: "the device data plane loaded but is attached to no interface — device containment will be recorded and will not touch a packet"})
	default:
		c.NetDevice = capYes
	}

	// The two postures that stop even an operator's own action.
	if dryRun {
		issues = append(issues, issue{Code: issueContainmentShadowed,
			Detail: "dry-run is engaged — every containment action is recorded and none is executed, including one you press yourself"})
	}
	if killSwitched {
		issues = append(issues, issue{Code: issueKillSwitched,
			Detail: "the enforcement kill-switch is engaged — all containment is bypassed, including manual operator actions"})
	}

	// NOTES: true, worth saying, not faults.
	if c.Auto != "enforcing" && manualLands {
		notes = append(notes, issue{Code: noteManualOnly,
			Detail: "automatic containment is off (detect-only): the score ladder will record a decision at the sever threshold and kill nothing. An action you press yourself does still reach the kernel — that path bypasses detect-only by design"})
	}
	if c.NetProcess == capNo {
		notes = append(notes, issue{Code: noteNoNetworkChoke,
			Detail: "per-PID network containment is not deployed on this host: throttle and tarpit cap CPU, memory, IO and process count — they do not rate-limit outbound traffic, and quarantine relies on the freeze rather than on blocking connect()"})
	}
	if c.NetDevice == capNo {
		notes = append(notes, issue{Code: noteNoDevicePlane,
			Detail: "no network device containment on this host — device decisions are recorded and no frame is dropped. Correct for a host that does not sit inline on a network segment"})
	}

	c.Verdict, c.Summary = verdictFor(c)
	return c, issues, notes
}

// verdictFor grades the whole, in strict precedence order. An unknown never
// reaches "full": a mechanism nobody measured is not a mechanism that works.
func verdictFor(c containment) (string, string) {
	switch {
	case !c.ManualLands:
		return "none", "Nothing this console does reaches the kernel — including a containment action you press yourself."
	case c.Freeze == capNo || c.ResourceCaps == capNo:
		return "kill-only", "Only sever (SIGKILL) works on this host. Throttle, tarpit and quarantine cannot be applied."
	case c.Freeze == capDegraded || c.ResourceCaps == capDegraded || c.NetDevice == capDegraded || c.NetProcess == capDegraded:
		return "partial-degraded", "Kill and freeze work and an action you press lands. Something in the containment stack is degraded — see the findings below."
	case c.Freeze == capUnknown || c.ResourceCaps == capUnknown:
		return "partial-unknown", "Some containment mechanisms could not be read on this host, so this is not a clean bill of health."
	case c.NetProcess == capNo || c.NetDevice == capNo:
		if c.Auto == "enforcing" {
			return "partial", "Kill, freeze and resource caps are live and the score ladder is armed. Network-level containment is not deployed on this host."
		}
		return "partial", "Kill, freeze and resource caps are live and an action you press lands immediately. Network-level containment is not deployed here, and the score ladder will not act on its own."
	case c.Auto == "enforcing":
		return "full", "Every containment mechanism is live and the score ladder will act on its own."
	default:
		return "full", "Every containment mechanism is live and an action you press lands immediately. The score ladder will not act on its own."
	}
}
