package assistant

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/platformdoc"
)

// DefaultTools is the production tool set: the questions an analyst already
// answers by hand, and nothing else.
//
// Every entry is a read. There is deliberately no "contain", "jail", "thaw" or
// "set mode" tool, and adding one is a build failure — see registry_test.go.
//
// MustRegister, not Register: a mis-specified tool must stop the process at
// startup, where an engineer is watching, rather than surface as a strange
// answer during an incident.
//
// # Why the set is this wide
//
// It used to be six tools covering alerts, events, decisions and one process
// tree. That was the right start and the wrong end state, because the console
// mounts this assistant on EIGHT surfaces and three of them — Choke Assurance,
// Devices and Devices Assurance — are about the device plane and the fleet,
// which none of those six tools could see. The panel said "Investigating the
// device fleet" above an assistant that had no way to read a device. An
// assistant that cannot see its own subject does not decline; it answers from
// the nearest data it has, which is the failure mode this package exists to
// prevent.
//
// Every addition is still a GET on the read allowlist, still routed through the
// caller's session, and still covered by the ratchet.
func DefaultTools() *Registry {
	r := NewRegistry()

	// list_alerts takes FILTERS, not just a limit.
	//
	// It used to take only limit and since, so answering "any critical alerts on
	// this host in the last hour" meant pulling 200 rows and eyeballing them —
	// which the model did, badly, and which silently truncated the moment the
	// answer lay outside the newest 200. A filter the server applies is both
	// cheaper and honest; a filter the model applies by reading is neither.
	r.MustRegister(NewReadTool(
		"list_alerts",
		"List security alerts, most recent first. Filter by severity, host, process or free "+
			"text rather than pulling everything and reading it — an unfiltered list is capped "+
			"and will silently omit the alert you are looking for. Returns alert id, timestamp, "+
			"severity, rule, host and process.",
		"/api/alerts",
		objSchema(map[string]any{
			"limit":    intProp("How many alerts to return (1-200, default 50)."),
			"since":    strProp("Only alerts at or after this RFC3339 timestamp."),
			"severity": strProp("Only this severity: critical, high, medium, low or info."),
			"host":     strProp("Restrict to one host id."),
			"exec_id":  strProp("Only alerts for this process chain."),
			"q":        strProp("Free-text match against the alert title and description."),
		}),
		func(a map[string]any) (string, string, error) {
			q := url.Values{}
			if err := putInt(q, a, "limit", 1, 200); err != nil {
				return "", "", err
			}
			if err := putEnum(q, a, "severity", "critical", "high", "medium", "low", "info"); err != nil {
				return "", "", err
			}
			putStr(q, a, "since")
			putStr(q, a, "host")
			putStr(q, a, "exec_id")
			putStr(q, a, "q")
			return "", q.Encode(), nil
		},
	))

	r.MustRegister(NewReadTool(
		"alert_statistics",
		"Aggregate alert counts by severity over a time window, with per-bucket totals for a "+
			"timeline and the counts for the PRECEDING window so a trend is a real comparison. "+
			"Use this for 'how bad is it' and trend questions rather than counting individual "+
			"alerts yourself.",
		"/api/alert-stats",
		objSchema(map[string]any{
			"span": strProp("Window to summarise, e.g. '30m', '6h', '24h' or '7d'. Default 24h."),
		}),
		func(a map[string]any) (string, string, error) {
			// THE SERVER READS window_min, IN MINUTES. It has never read `span`.
			//
			// This tool advertised a `span` string and sent it verbatim, so both
			// servers ignored it and answered with their own 30-minute default
			// while the model believed it had asked for 24 hours — then narrated
			// the answer as a day's trend. That is the "do not invent values"
			// rule being broken by the tool contract rather than by the model,
			// which is worse: no amount of prompting can fix it and the trace
			// looks correct.
			//
			// The model still gets to say "24h", because that is how an analyst
			// thinks. The translation happens here, once.
			q := url.Values{}
			mins := 24 * 60
			if s, ok := a["span"].(string); ok && strings.TrimSpace(s) != "" {
				parsed, err := spanMinutes(s)
				if err != nil {
					return "", "", err
				}
				mins = parsed
			}
			q.Set("window_min", strconv.Itoa(mins))
			// Bucket count drives the timeline the console draws; ask for the
			// same shape it does so the model's view and the analyst's agree.
			q.Set("buckets", "30")
			return "", q.Encode(), nil
		},
	))

	r.MustRegister(NewReadTool(
		"list_events",
		"List raw kernel-observed process events. Use this when an alert is not enough and you "+
			"need the underlying execve/open/connect activity.",
		"/api/events",
		objSchema(map[string]any{
			"limit":  intProp("How many events to return (1-500, default 100)."),
			"host":   strProp("Restrict to one host id."),
			"since":  strProp("Only events at or after this RFC3339 timestamp."),
			"binary": strProp("Restrict to executions of this binary path."),
			"policy": strProp("Restrict to events raised by this detection policy."),
			"q":      strProp("Free-text match against the binary and its arguments."),
		}),
		func(a map[string]any) (string, string, error) {
			q := url.Values{}
			if err := putInt(q, a, "limit", 1, 500); err != nil {
				return "", "", err
			}
			putStr(q, a, "host")
			putStr(q, a, "since")
			putStr(q, a, "binary")
			putStr(q, a, "policy")
			putStr(q, a, "q")
			return "", q.Encode(), nil
		},
	))

	r.MustRegister(NewReadTool(
		"list_decisions",
		"List enforcement decisions the engine has recorded: what action was taken against which "+
			"process, why, and the outcome. This is the tamper-evident audit chain. Use it to "+
			"answer 'what did we do about it' and to check whether a containment already happened.",
		"/api/decisions",
		objSchema(map[string]any{
			"limit": intProp("How many decisions to return (1-200, default 50)."),
		}),
		func(a map[string]any) (string, string, error) {
			q := url.Values{}
			if err := putInt(q, a, "limit", 1, 200); err != nil {
				return "", "", err
			}
			return "", q.Encode(), nil
		},
	))

	r.MustRegister(NewReadTool(
		"process_tree",
		"Fetch the ancestry and children of one process by exec id: the chain that led to it. "+
			"This is the primary tool for 'explain this process chain' and for justifying a score.",
		"/api/process/",
		objSchema(map[string]any{
			"exec_id": strProp("The exec id of the process. Required."),
		}),
		func(a map[string]any) (string, string, error) {
			id, _ := a["exec_id"].(string)
			id = strings.TrimSpace(id)
			if id == "" {
				return "", "", fmt.Errorf("exec_id is required")
			}
			// A PATH SUFFIX, not a query: the endpoint is /api/process/{exec_id}.
			// PathEscape so a crafted id cannot close the segment and reach
			// another endpoint; Call re-checks the result for "/" and "..".
			return url.PathEscape(id), "", nil
		},
	))

	r.MustRegister(NewReadTool(
		"list_choked_processes",
		"List processes currently under a choke (throttled, tarpitted or quarantined) and their "+
			"scores. Read-only: this reports state, it cannot change it.",
		"/api/choke/processes",
		objSchema(map[string]any{}),
		func(map[string]any) (string, string, error) { return "", "", nil },
	))

	// ── The device plane ───────────────────────────────────────────────────
	// Three of the eight console surfaces the assistant is mounted on are about
	// devices. Without these it was answering device questions from process
	// data.

	r.MustRegister(NewReadTool(
		"list_devices",
		"List the devices the platform can see on the network: identity, host, last seen, and "+
			"whether each is currently severed or free. Use this for any question about the "+
			"device fleet, device exposure, or which devices are contained. Read-only.",
		"/api/choke/devices",
		objSchema(map[string]any{}),
		func(map[string]any) (string, string, error) { return "", "", nil },
	))

	r.MustRegister(NewReadTool(
		"device_plane_state",
		"Report the device-choke plane's posture: whether the enforcement data plane is armed or "+
			"in audit-only mode, and its current thresholds. Use this before saying whether a "+
			"device containment would actually take effect. Read-only: it reports arming, it "+
			"cannot arm.",
		"/api/choke/device-state",
		objSchema(map[string]any{}),
		func(map[string]any) (string, string, error) { return "", "", nil },
	))

	r.MustRegister(NewReadTool(
		"device_flows",
		"List recent network flows observed between devices — who talked to whom. Use it to "+
			"justify whether a device is exposed or has been communicating with something it "+
			"should not.",
		"/api/choke/device-flows",
		objSchema(map[string]any{}),
		func(map[string]any) (string, string, error) { return "", "", nil },
	))

	// ── The fleet ──────────────────────────────────────────────────────────

	r.MustRegister(NewReadTool(
		"list_fleet_hosts",
		"List the hosts (agents) reporting into this deployment, with their last heartbeat. Use "+
			"this to answer 'which hosts do we cover', to check whether a sensor has gone quiet, "+
			"and before claiming anything about estate-wide coverage.",
		"/api/fleet/hosts",
		objSchema(map[string]any{}),
		func(map[string]any) (string, string, error) { return "", "", nil },
	))

	r.MustRegister(NewReadTool(
		"fleet_state",
		"Report per-host enforcement posture across the fleet: mode, thresholds and how many "+
			"processes each host currently holds. Use it for 'what is our posture' questions. "+
			"Read-only: it reports the posture, it cannot change it.",
		"/api/fleet/state",
		objSchema(map[string]any{}),
		func(map[string]any) (string, string, error) { return "", "", nil },
	))

	// ── Detection coverage ─────────────────────────────────────────────────

	r.MustRegister(NewReadTool(
		"list_policies",
		"List the detection policies loaded on this deployment, including their MITRE ATT&CK "+
			"technique mapping where they carry one. This is how you answer ATT&CK coverage "+
			"questions and how you tell 'no technique observed' apart from 'this deployment "+
			"publishes no mapping' — which are different answers and must not be conflated.",
		"/api/policies",
		objSchema(map[string]any{}),
		func(map[string]any) (string, string, error) { return "", "", nil },
	))

	r.MustRegister(NewReadTool(
		"policy_stats",
		"Report how often each detection policy has actually fired. Use it to tell a noisy rule "+
			"from a real signal — if one policy accounts for most of the volume, say so, because "+
			"a high alert count driven by one chatty rule is not a busy estate.",
		"/api/policy-stats",
		objSchema(map[string]any{}),
		func(map[string]any) (string, string, error) { return "", "", nil },
	))

	// ── Enrichment: behaviour and reputation ───────────────────────────────
	//
	// These answer the two questions the rule-based tools structurally cannot:
	// "is this NORMAL HERE" and "is this address KNOWN BAD". Without them the
	// model could read every alert on the estate and still have no way to tell
	// a first-ever occurrence from a daily one.

	r.MustRegister(NewReadTool(
		"baseline_profile",
		"Report what this deployment has learned is NORMAL — which executables run here, which "+
			"parent launches which child, which users run what — plus whether the profile has "+
			"learned enough to be trusted yet. Use it to answer 'is this unusual for us' and "+
			"BEFORE calling something anomalous. If it reports ready=false the profile is still "+
			"warming up: say that plainly rather than reporting that nothing is unusual, "+
			"because those are different answers. Readiness needs BOTH gates: observations >= "+
			"need_observations AND span_seconds >= need_span_seconds. Check which one is "+
			"outstanding before saying what it is waiting for — a profile with plenty of "+
			"observations may still be too young, and saying it needs more data would be wrong.",
		"/api/baseline",
		objSchema(map[string]any{
			"top": intProp("How many of the most common keys to sample per facet (1-50, default 10)."),
		}),
		func(a map[string]any) (string, string, error) {
			q := url.Values{}
			if err := putInt(q, a, "top", 1, 50); err != nil {
				return "", "", err
			}
			return "", q.Encode(), nil
		},
	))

	r.MustRegister(NewReadTool(
		"behavioural_anomalies",
		"List recent behavioural findings: processes that departed from this deployment's "+
			"learned normal, with the reason in plain language (a lineage never seen before, an "+
			"executable never run here, a user who has never run it). Use this for 'what is "+
			"unusual right now' — it finds things no detection rule describes.",
		"/api/baseline/anomalies",
		objSchema(map[string]any{
			"limit": intProp("How many findings to return (1-500, default 50)."),
		}),
		func(a map[string]any) (string, string, error) {
			q := url.Values{}
			if err := putInt(q, a, "limit", 1, 500); err != nil {
				return "", "", err
			}
			return "", q.Encode(), nil
		},
	))

	r.MustRegister(NewReadTool(
		"threat_intel_status",
		"Report the threat-intelligence feeds loaded on this deployment: how many indicators, "+
			"from which sources, when they were last refreshed, and any feed that failed to "+
			"parse. Check this before saying an address is clean — no matches against zero "+
			"loaded indicators is not evidence of anything.",
		"/api/intel",
		objSchema(map[string]any{}),
		func(map[string]any) (string, string, error) { return "", "", nil },
	))

	r.MustRegister(NewReadTool(
		"threat_intel_matches",
		"List recent threat-intelligence hits: observed IPs, domains or file hashes that matched "+
			"a feed, with the source, category and confidence. This is the strongest evidence "+
			"this platform produces, because it is external corroboration rather than inference.",
		"/api/intel/matches",
		objSchema(map[string]any{
			"limit": intProp("How many matches to return (1-500, default 50)."),
		}),
		func(a map[string]any) (string, string, error) {
			q := url.Values{}
			if err := putInt(q, a, "limit", 1, 500); err != nil {
				return "", "", err
			}
			return "", q.Encode(), nil
		},
	))

	r.MustRegister(NewReadTool(
		"lookup_indicator",
		"Check ONE IP address, domain or SHA-256 hash against the loaded threat-intelligence "+
			"feeds. Use it when an analyst names an address or a file and asks whether it is "+
			"known. A negative result means 'not in these feeds', which is not the same as "+
			"'safe' — say so.",
		"/api/intel/lookup",
		objSchema(map[string]any{
			"indicator": strProp("The IP, domain or SHA-256 hash to check. Required."),
		}),
		func(a map[string]any) (string, string, error) {
			v, _ := a["indicator"].(string)
			v = strings.TrimSpace(v)
			if v == "" {
				return "", "", fmt.Errorf("indicator is required")
			}
			if len(v) > 256 {
				return "", "", fmt.Errorf("indicator is too long")
			}
			q := url.Values{}
			q.Set("q", v)
			return "", q.Encode(), nil
		},
	))

	r.MustRegister(NewReadTool(
		"explain_platform",
		"Explain how THIS PLATFORM works: what a tarpit does, what the chain score is built "+
			"from, how severity is derived, what the behavioural baseline learns, what a "+
			"decision outcome means. Use it whenever the analyst asks what something MEANS "+
			"rather than what is happening — that question needs no telemetry, and answering "+
			"it from general knowledge of security products produces confident prose about a "+
			"different product. Topics: "+strings.Join(platformdoc.IDs(), ", ")+
			". Omit the topic to list them all.",
		"/api/platform-doc",
		objSchema(map[string]any{
			"topic": strProp("Which concept to explain. Omit to list every topic."),
		}),
		func(a map[string]any) (string, string, error) {
			q := url.Values{}
			putStr(q, a, "topic")
			return "", q.Encode(), nil
		},
	))

	// ── Whether the data can be trusted at all ─────────────────────────────

	r.MustRegister(NewReadTool(
		"system_health",
		"Report telemetry health: whether the feeds are arriving and the store is answering. "+
			"Check this before presenting counts as a measurement — a quiet window and a broken "+
			"feed look identical in the numbers and mean opposite things.",
		"/api/system-health",
		objSchema(map[string]any{}),
		func(map[string]any) (string, string, error) { return "", "", nil },
	))

	return r
}

// spanMinutes parses the human window an analyst (and therefore a model) would
// write into the minutes the API takes.
//
// Deliberately strict: an unparseable span is an ERROR handed back to the model,
// not a silent fallback to a default. A tool that quietly substitutes a
// different window than the one requested is how the previous version produced
// confident answers about the wrong day.
func spanMinutes(s string) (int, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	// time.ParseDuration handles h/m/s but not the "d" an analyst writes.
	if strings.HasSuffix(s, "d") {
		days, err := strconv.ParseFloat(strings.TrimSuffix(s, "d"), 64)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("span %q is not a duration I can read; use forms like 30m, 6h, 24h or 7d", s)
		}
		return clampMinutes(int(days * 24 * 60)), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("span %q is not a duration I can read; use forms like 30m, 6h, 24h or 7d", s)
	}
	return clampMinutes(int(d.Minutes())), nil
}

// clampMinutes keeps the request inside what the endpoint will honour (7 days),
// so the model is never told a window it did not receive.
func clampMinutes(m int) int {
	const maxMinutes = 7 * 24 * 60
	if m < 1 {
		return 1
	}
	if m > maxMinutes {
		return maxMinutes
	}
	return m
}

// ── schema helpers ─────────────────────────────────────────────────────────

func objSchema(props map[string]any) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	return map[string]any{"type": "object", "properties": props}
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func intProp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

// putInt validates and copies a bounded integer argument.
//
// Bounded on purpose: a model asking for limit=1000000 against a live incident
// console is a denial of service written in good faith.
func putInt(q url.Values, a map[string]any, key string, min, max int) error {
	v, ok := a[key]
	if !ok || v == nil {
		return nil
	}
	var n int
	switch t := v.(type) {
	case float64: // JSON numbers decode as float64
		n = int(t)
	case int:
		n = t
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return fmt.Errorf("%s must be an integer", key)
		}
		n = parsed
	default:
		return fmt.Errorf("%s must be an integer", key)
	}
	if n < min || n > max {
		return fmt.Errorf("%s must be between %d and %d", key, min, max)
	}
	q.Set(key, strconv.Itoa(n))
	return nil
}

// putEnum validates a string argument against a fixed set.
//
// An invalid value is an ERROR back to the model, never a silent drop. A filter
// that is quietly ignored is how the previous alert_statistics bug worked: the
// model believed it had narrowed the query, the server answered a wider one,
// and the answer was narrated as though the filter had applied.
func putEnum(q url.Values, a map[string]any, key string, allowed ...string) error {
	raw, ok := a[key].(string)
	if !ok || strings.TrimSpace(raw) == "" {
		return nil
	}
	v := strings.ToLower(strings.TrimSpace(raw))
	for _, ok := range allowed {
		if v == ok {
			q.Set(key, v)
			return nil
		}
	}
	return fmt.Errorf("%s must be one of %s", key, strings.Join(allowed, ", "))
}

func putStr(q url.Values, a map[string]any, key string) {
	if s, ok := a[key].(string); ok && strings.TrimSpace(s) != "" {
		q.Set(key, strings.TrimSpace(s))
	}
}
