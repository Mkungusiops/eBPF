package assistant

import "strings"

// A Surface is WHERE ON THE CONSOLE the analyst asked from.
//
// # Why this exists
//
// The assistant is mounted on eight panels. Until this type existed, all eight
// sent an identical request: an agent id, a question, and sometimes an exec id.
// The model therefore had no idea whether it had been opened over a process
// tree, a device inventory, a KPI tile or the containment posture — so an
// "intelligence across the whole platform" was in practice one prompt answering
// from whatever it happened to fetch first.
//
// The failure this produced is specific and was visible in the product: the
// Devices panels rendered "Investigating the device fleet" above an assistant
// with no device tool, and the KPI drill passed no context at all. An assistant
// that does not know what it is looking at does not say so. It answers about
// something else, confidently, and an analyst reads it as an answer to what
// they asked.
//
// A surface is not authorization. It changes what the model is TOLD, never what
// it may READ — the tool registry and the caller's session are still the only
// things that decide that. A forged surface string can therefore mis-frame an
// answer for the person who forged it and nothing else, which is why this is
// free-form-ish input validated against a known set rather than a permission.
type Surface struct {
	// ID is the wire value the console sends.
	ID string
	// Label is how a human refers to this panel.
	Label string
	// Briefing is prepended to the system prompt: what the analyst is looking
	// at, and which tools answer questions asked from here.
	//
	// Kept to a few lines on purpose. This is paid on every request, and a long
	// preamble competes with the shared rules for the model's attention — the
	// thing those rules are protecting is answer discipline.
	Briefing string
}

// The eight surfaces, one per panel the console mounts an assistant on. If a
// ninth panel appears and does not name itself, it degrades to the generic
// briefing rather than silently borrowing another panel's.
//
// # These are DESCRIPTIONS, not instructions
//
// Every briefing says two things and only two: WHAT THE ANALYST IS LOOKING AT,
// and WHICH TOOLS READ THAT SUBJECT. None of them says how to answer.
//
// That restraint was learned by breaking it. The first version told the model
// things like "lead with the arming state" and "start from process_tree" —
// reasonable-sounding, and duplicated from the task agents that already say so.
// The effect was that "Hello" on the Devices Assurance panel returned a
// device-plane posture report: the briefing's imperative outranked the `ask`
// agent's explicit greeting clause. Moving the briefing earlier in the prompt
// did NOT fix it, because the problem was never ordering — an instruction
// competes with an instruction wherever you put it.
//
// So the split is by KIND, not position:
//
//	surface  → where you are, and what you can read here   (context)
//	agent    → what to do, and when not to do it           (behaviour)
//
// A task agent that wants "lead with X" states it in its own instructions,
// where it applies to that task and to nothing else.
var surfaces = map[string]Surface{
	"alert-drill": {
		ID:    "alert-drill",
		Label: "Alert drill-down",
		Briefing: "The analyst has one ALERT open, and its process is named by the exec id " +
			"below. Tools that read this subject: process_tree, list_alerts, list_decisions.",
	},
	"process-action": {
		ID:    "process-action",
		Label: "Process action",
		Briefing: "The analyst is looking at ONE PROCESS, on the panel where a containment " +
			"decision is taken. Tools that read this subject: process_tree, list_decisions, " +
			"list_choked_processes.",
	},
	"graph": {
		ID:    "graph",
		Label: "Correlation graph",
		Briefing: "The analyst has selected a node in the CORRELATION GRAPH and can see how it " +
			"relates to what surrounds it. Tools that read this subject: process_tree, " +
			"list_events.",
	},
	"kpi-drill": {
		ID:    "kpi-drill",
		Label: "KPI drill",
		Briefing: "The analyst is looking at ESTATE-WIDE COUNTS for a time window, not at one " +
			"incident. Tools that read this subject: alert_statistics, policy_stats, " +
			"system_health.",
	},
	"choke-process": {
		ID:    "choke-process",
		Label: "Choke Gateway process drill",
		Briefing: "The analyst is in the CHOKE GATEWAY, looking at one process that is throttled, " +
			"tarpitted or quarantined. Tools that read this subject: list_choked_processes, " +
			"process_tree, list_decisions.",
	},
	"choke-assurance": {
		ID:    "choke-assurance",
		Label: "Choke Assurance",
		Briefing: "This panel is about whether CONTAINMENT WOULD WORK, not about what happened. " +
			"Tools that read this subject: fleet_state, list_choked_processes, list_decisions, " +
			"list_fleet_hosts.",
	},
	"devices": {
		ID:    "devices",
		Label: "Devices",
		Briefing: "The analyst is looking at the DEVICE INVENTORY — machines on the network, not " +
			"processes. Tools that read this subject: list_devices, device_flows, " +
			"device_plane_state. Process and alert tools do not describe devices.",
	},
	"behaviour": {
		ID:    "behaviour",
		Label: "Behaviour & Reputation",
		Briefing: "The analyst is looking at what this deployment has LEARNED IS NORMAL, what " +
			"departed from it, and what matched a threat-intelligence feed — not at one " +
			"incident. Tools that read this subject: baseline_profile, behavioural_anomalies, " +
			"threat_intel_status, threat_intel_matches, lookup_indicator. An empty finding list " +
			"on this panel has three possible causes and they are not interchangeable: the " +
			"layer is off, the baseline is still warming up, or no indicators are loaded. " +
			"baseline_profile and threat_intel_status are what tell them apart.",
	},
	"devices-assurance": {
		ID:    "devices-assurance",
		Label: "Devices Assurance",
		Briefing: "This panel is about whether DEVICE containment would work. The data plane can " +
			"be armed or audit-only, and that changes what a severed device means. Tools that " +
			"read this subject: device_plane_state, list_devices, device_flows.",
	},
}

// SurfaceFor resolves a wire value to its briefing.
//
// An unknown or empty surface is NOT an error. The console is deployed
// independently of the engine, so an older console that names a surface this
// build has never heard of must still get an answer — just a generically framed
// one. Failing the request would turn a cosmetic version skew into a broken
// assistant.
func SurfaceFor(id string) (Surface, bool) {
	s, ok := surfaces[strings.TrimSpace(strings.ToLower(id))]
	return s, ok
}

// SurfaceIDs lists the known surfaces, for tests and for documentation.
func SurfaceIDs() []string {
	out := make([]string, 0, len(surfaces))
	for id := range surfaces {
		out = append(out, id)
	}
	return out
}
