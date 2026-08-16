package assistant

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
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
func DefaultTools() *Registry {
	r := NewRegistry()

	r.MustRegister(NewReadTool(
		"list_alerts",
		"List recent security alerts, most recent first. Use this to establish what happened "+
			"and when. Returns alert id, timestamp, severity, rule, host and process.",
		"/api/alerts",
		objSchema(map[string]any{
			"limit": intProp("How many alerts to return (1-200, default 50)."),
			"since": strProp("Only alerts at or after this RFC3339 timestamp."),
		}),
		func(a map[string]any) (string, string, error) {
			q := url.Values{}
			if err := putInt(q, a, "limit", 1, 200); err != nil {
				return "", "", err
			}
			putStr(q, a, "since")
			return "", q.Encode(), nil
		},
	))

	r.MustRegister(NewReadTool(
		"alert_statistics",
		"Aggregate alert counts by severity over a time window, with per-bucket totals for a "+
			"timeline. Use this for 'how bad is it' and trend questions rather than counting "+
			"individual alerts yourself.",
		"/api/alert-stats",
		objSchema(map[string]any{
			"span": strProp("Window, e.g. '24h' or '7d'. Default 24h."),
		}),
		func(a map[string]any) (string, string, error) {
			q := url.Values{}
			putStr(q, a, "span")
			return "", q.Encode(), nil
		},
	))

	r.MustRegister(NewReadTool(
		"list_events",
		"List raw kernel-observed process events. Use this when an alert is not enough and you "+
			"need the underlying execve/open/connect activity.",
		"/api/events",
		objSchema(map[string]any{
			"limit": intProp("How many events to return (1-500, default 100)."),
			"host":  strProp("Restrict to one host id."),
		}),
		func(a map[string]any) (string, string, error) {
			q := url.Values{}
			if err := putInt(q, a, "limit", 1, 500); err != nil {
				return "", "", err
			}
			putStr(q, a, "host")
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

	return r
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

func putStr(q url.Values, a map[string]any, key string) {
	if s, ok := a[key].(string); ok && strings.TrimSpace(s) != "" {
		q.Set(key, strings.TrimSpace(s))
	}
}
