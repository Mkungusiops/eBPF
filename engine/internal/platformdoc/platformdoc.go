// Package platformdoc is the assistant's knowledge of THIS PRODUCT — what a
// tarpit is, what a chain score means, what the behavioural baseline does.
//
// # Why an assistant needs this at all
//
// Every other tool answers "what is happening on the estate". None of them
// answers "what does this word mean here", and an analyst asks that constantly:
// what is the difference between throttle and tarpit, what is severity derived
// from, does a severed device stay severed after a reboot.
//
// Before this existed the assistant had two ways to handle those, and both were
// bad. It could refuse — "I cannot ground an answer in this engine's data" —
// which is technically true and reads as a malfunction, because the question
// never needed telemetry. Or it could answer from the model's general knowledge
// of security products, which produces confident, plausible, generic prose
// about what a tarpit usually is, in a console where "tarpit" is a specific
// thing with specific thresholds. The second is worse: it is indistinguishable
// from a correct answer and it teaches the analyst something false about the
// tool they are about to press a button in.
//
// So the product's own vocabulary is written down, served as an ordinary read
// endpoint, and grounded exactly like every other fact.
//
// # Keeping it honest
//
// These entries describe BEHAVIOUR THIS CODE IMPLEMENTS, and the numbers in
// them are the numbers in the code. When a threshold changes, this changes with
// it — a glossary that drifts from the implementation is a confident liar, and
// it is worse than nothing because the assistant will cite it.
package platformdoc

import (
	"sort"
	"strings"
)

// Topic is one explainable concept.
type Topic struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Body    string   `json:"body"`
	Related []string `json:"related,omitempty"`
}

var topics = map[string]Topic{
	"chain-score": {
		ID:    "chain-score",
		Title: "Chain score",
		Body: "Every process belongs to a chain: itself and its ancestors. The chain score is " +
			"the sum of points earned by every process in that chain. Points come from three " +
			"places — detection rules (a curl piped to a shell scores 25), the behavioural " +
			"baseline (novel activity, capped at 25 per chain), and threat-intelligence " +
			"matches (up to 30 for a high-confidence hit).\n\n" +
			"Scores only ever rise. That is deliberate — a shell that has already done " +
			"something bad taints the commands it runs afterwards — but it means a high score " +
			"tells you the chain has accumulated suspicion, not that its most recent event was " +
			"itself severe.",
		Related: []string{"severity", "behavioural-baseline", "threat-intel"},
	},
	"severity": {
		ID:    "severity",
		Title: "Severity bands",
		Body: "Severity is derived from the chain score, not set by a rule: info below 5, low " +
			"at 5, medium at 10, high at 20, critical at 40.\n\n" +
			"Because chain scores only rise, an alert is raised on an INCREASE in band or on a " +
			"finding the chain has not reported before — not on every event above a threshold. " +
			"Without that, a busy chain produced a critical alert per event and 91 of 100 " +
			"alerts were critical, which carries no triage information at all.",
		Related: []string{"chain-score"},
	},
	"choke-tiers": {
		ID:    "choke-tiers",
		Title: "Throttle, tarpit, quarantine, sever",
		Body: "The four containment tiers, applied to a process as its chain score climbs.\n\n" +
			"- Throttle: CPU and I/O are constrained. The process keeps running and keeps " +
			"producing evidence.\n" +
			"- Tarpit: network syscalls are delayed. An exfiltration or a C2 beacon slows to " +
			"the point of uselessness while the session stays observable.\n" +
			"- Quarantine: the process is confined — no new network, restricted filesystem.\n" +
			"- Sever: the process is stopped.\n\n" +
			"Tiers are monotonic: a process moves up, never down, without an operator thawing " +
			"it. The gateway is dispatched on EVERY event regardless of whether an alert was " +
			"raised, so a process can be throttled before it has ever produced one.",
		Related: []string{"chain-score", "kill-switch"},
	},
	"behavioural-baseline": {
		ID:    "behavioural-baseline",
		Title: "Behavioural baseline",
		Body: "The deployment learns what is normal for itself and scores departures from it. " +
			"It tracks four things: which executables run here, which parent launches which " +
			"child, which user runs what, and when the host is active. Counts decay with a " +
			"14-day half-life, so a host that changes role stops being alarming within a " +
			"fortnight.\n\n" +
			"The most useful facet is process lineage. A rule cannot express 'nginx has never " +
			"launched a shell on this machine'; the baseline can, and that single fact ends " +
			"most triage.\n\n" +
			"It refuses to score until it has learned enough — check whether it reports ready. " +
			"An unready baseline reporting no anomalies means 'still learning', which is not " +
			"the same as 'nothing unusual'. Novelty is capped at 25 points per chain and can " +
			"never reach the critical band on its own: a software update legitimately makes a " +
			"host do many things for the first time.",
		Related: []string{"chain-score", "threat-intel"},
	},
	"threat-intel": {
		ID:    "threat-intel",
		Title: "Threat-intelligence matching",
		Body: "Observed IP addresses, domains and file hashes are matched against indicator " +
			"feeds loaded on this deployment. Matching is entirely local: feeds are pulled in " +
			"as files, and an observed address is never sent anywhere to be checked. That is a " +
			"privacy requirement — querying a reputation API would disclose the customer's " +
			"traffic to a third party.\n\n" +
			"A hit is the strongest evidence available here, because it is external " +
			"corroboration rather than inference. A high-confidence match on a real connection " +
			"scores 30; the same address merely named on a command line scores half, because " +
			"an argument is an intention and a socket is a fact.\n\n" +
			"Private, loopback and link-local addresses never match, so internal traffic " +
			"cannot light up against a public feed. A negative result means 'not in the feeds " +
			"we have loaded' — check how many indicators are actually loaded before reading it " +
			"as clean.",
		Related: []string{"behavioural-baseline", "chain-score"},
	},
	"kill-switch": {
		ID:    "kill-switch",
		Title: "Kill switch",
		Body: "Disarms enforcement across the deployment at once, leaving detection running. " +
			"It is the control for the case where containment itself is the problem — a rule " +
			"is severing something critical. Detection, alerting and the audit chain continue; " +
			"only the acting stops.",
		Related: []string{"choke-tiers"},
	},
	"device-plane": {
		ID:    "device-plane",
		Title: "Device choke plane",
		Body: "The second containment gateway, operating on network devices by MAC address " +
			"rather than on processes. It arms independently of the process plane, and that " +
			"distinction matters when reading the console: in audit-only mode the panel will " +
			"show devices as severed that are not actually severed. Always check the plane's " +
			"arming state before treating a device containment as real.",
		Related: []string{"choke-tiers"},
	},
	"decisions": {
		ID:    "decisions",
		Title: "Decisions and the audit chain",
		Body: "Every enforcement action is recorded as a decision: what was done, to which " +
			"process, why, and what the outcome was. The records are hash-chained, so the log " +
			"is tamper-evident and can be verified.\n\n" +
			"Outcome is the field that matters during an incident. A decision that was ISSUED " +
			"but never acknowledged as applied is not a containment — it is a request that may " +
			"not have landed.",
		Related: []string{"choke-tiers"},
	},
	"tenant-isolation": {
		ID:    "tenant-isolation",
		Title: "Tenant isolation",
		Body: "On the multi-tenant control plane, a tenant is derived from the agent's mTLS " +
			"client certificate at the collector — never from anything in the payload, and " +
			"never from a query parameter. Reads are scoped by the operator's session and " +
			"enforced again in the database by row-level security.\n\n" +
			"This is why an agent has no per-tenant view of its own: it does not know its " +
			"tenant, by design. Tenant-wide behaviour can only be assembled on the control " +
			"plane, on the far side of that boundary.",
		Related: []string{"behavioural-baseline"},
	},
}

// Get returns one topic.
func Get(id string) (Topic, bool) {
	t, ok := topics[strings.ToLower(strings.TrimSpace(id))]
	return t, ok
}

// List returns every topic, id-sorted so the response is stable. An unstable
// order changes the model's prompt for an unchanged question.
func List() []Topic {
	ids := make([]string, 0, len(topics))
	for id := range topics {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Topic, 0, len(ids))
	for _, id := range ids {
		out = append(out, topics[id])
	}
	return out
}

// IDs returns the topic ids, for the tool description and for tests.
func IDs() []string {
	out := make([]string, 0, len(topics))
	for id := range topics {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
