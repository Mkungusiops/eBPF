package eventpipe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The outbound-connections policy must cover the binaries that actually make
// outbound connections.
//
// # What this catches
//
// Measured on the production estate, 2026-08-25: the policy had matched only
// shells, nc, ncat and socat since it shipped. The store held 3,032
// outbound-connections events, ALL of them /usr/bin/bash, newest 25 hours old,
// against 1.32M events overall from the same agent in the same period. Every
// one of the 3,032 was the demo attack loop's reverse shell to 127.0.0.1:4444,
// removed when the estate moved to DATA_MODE=none.
//
// So "this platform detects outbound connections" was true only for a shell
// dialling out. C2 over curl, wget or python was invisible on every host — and
// nothing failed, alerted, or looked wrong, because a detection that matches
// nothing produces exactly the same silence as an estate with nothing to find.
//
// # Why a test and not a runtime check
//
// At runtime the two are genuinely indistinguishable without a baseline. Here
// they are not: the policy either names the binary or it does not.
func TestOutboundPolicyCoversTheBinariesThatMakeConnections(t *testing.T) {
	path := policyPath(t, "network-watch.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("policy not readable from here: %v", err)
	}
	body := string(raw)

	// The tools an intrusion actually reaches for. Each absence is a class of
	// C2 this platform cannot see.
	required := map[string]string{
		"/usr/bin/curl":    "the most common stage-two and C2 transport on Linux",
		"/usr/bin/wget":    "as above",
		"/usr/bin/python3": "scripted C2 and reverse shells",
		"/usr/bin/perl":    "scripted reverse shells",
		"/usr/bin/ssh":     "outbound ssh is how an intrusion moves laterally",
		"/usr/bin/openssl": "the manual way to reach a TLS C2 endpoint",
		"/usr/bin/nc":      "the classic, and the only class this ever caught",
		"/usr/bin/bash":    "reverse shell",
	}
	for bin, why := range required {
		if !strings.Contains(body, `"`+bin+`"`) {
			t.Errorf("outbound-connections does not match %s (%s) — that traffic is invisible", bin, why)
		}
	}

	// The policy must stay detect-only. Enforcement belongs to the choke
	// gateway, which is reversible and audited.
	if !strings.Contains(body, `value: "monitor"`) {
		t.Error("the policy is no longer declaratively monitor-only")
	}
	// And it must stay a closed list. Removing matchBinaries entirely would
	// post every sshd session, every apt run and the agent's own uplink,
	// burying the signal this exists to surface.
	if !strings.Contains(body, "matchBinaries") {
		t.Error("matchBinaries was removed — unfiltered tcp_connect buries the signal")
	}
}

// policyPath walks up to the repo root and resolves a policy by name.
func policyPath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		p := filepath.Join(dir, "policies", name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("policies directory not found from the test's working directory")
	return ""
}
