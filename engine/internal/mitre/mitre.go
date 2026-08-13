// Package mitre maps a Tetragon tracing-policy name to the ATT&CK technique
// that policy detects.
//
// This map is the ONLY place the console's technique attribution comes from.
// Alerts do not carry a technique: the agent builds them from a cumulative
// chain score (see internal/score), not from a single policy, so there is no
// one technique to stamp on them. The console therefore joins
// event.policy_name → policy.mitre, which means every server that answers
// /api/policies must return this field or the console's MITRE coverage panel
// is empty by construction — it was, on the multi-tenant control plane, which
// reported "no techniques observed" no matter what the fleet was doing.
//
// Keys match `metadata.name` inside each policy YAML in /policies and what
// `tetra tracingpolicy list` reports.
package mitre

import "sort"

// Entry is the console-facing metadata for one tracing policy.
type Entry struct {
	// File is the policy's YAML basename in the policy directory.
	File string
	// Description is what the policy hooks, in an analyst's terms.
	Description string
	// Technique is "Txxxx Name" — the ID first, so callers can split on the
	// first space to get a bare technique ID.
	Technique string
	// Tactic is the ATT&CK tactic the technique sits under.
	Tactic string
}

var byPolicy = map[string]Entry{
	"outbound-connections": {
		File:        "network-watch.yaml",
		Description: "tcp_connect kprobe filtered to bash/sh/nc/socat — catches shells calling out",
		Technique:   "T1071 Application Layer Protocol",
		Tactic:      "command-and-control",
	},
	"privilege-escalation": {
		File:        "privilege-escalation.yaml",
		Description: "setuid hooks — catches gain-of-root events",
		Technique:   "T1548 Abuse Elevation Control Mechanism",
		Tactic:      "privilege-escalation",
	},
	"sensitive-file-access": {
		File:        "sensitive-files.yaml",
		Description: "security_file_permission kprobe on /etc/shadow, /etc/passwd, /etc/sudoers, /root/.ssh",
		Technique:   "T1003 OS Credential Dumping",
		Tactic:      "credential-access",
	},
	"override-credential-read": {
		File:        "override-credential-read.yaml",
		Description: "credential stores sensitive-file-access does not watch — /etc/gshadow and the user's ~/.ssh, ~/.aws, ~/.kube, ~/.gnupg, ~/.netrc",
		Technique:   "T1552 Unsecured Credentials",
		Tactic:      "credential-access",
	},
}

// Lookup returns the entry for a policy name, and whether one exists. An
// unmapped policy is not an error — the fleet can load policies this build
// does not know about, and the caller should emit an empty technique rather
// than invent one.
func Lookup(policy string) (Entry, bool) {
	e, ok := byPolicy[policy]
	return e, ok
}

// Technique returns the "Txxxx Name" string for a policy, or "" when unmapped.
func Technique(policy string) string {
	return byPolicy[policy].Technique
}

// Tactic returns the ATT&CK tactic for a policy, or "" when unmapped.
func Tactic(policy string) string {
	return byPolicy[policy].Tactic
}

// Policies returns every mapped policy name, sorted.
func Policies() []string {
	names := make([]string, 0, len(byPolicy))
	for name := range byPolicy {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
