package hoststack

import (
	"strings"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/devbpf"
)

// All of this lived inside two 600+ line main() functions where no test could
// reach it. The startup banner, the exemption list, and the protected-MAC set
// are each a statement about what this host will and will not enforce on, and
// each was previously verified only by reading a log line by hand.

// The banner is how an operator confirms what they just started. A host with
// both dry-run and enforce set is recording decisions it will not execute;
// calling that "DETECT-ONLY" would hide that the enforcer chain is armed
// behind it.
func TestBootModeLabel(t *testing.T) {
	cases := []struct {
		dryRun, enforcing bool
		want              string
	}{
		{false, true, "ENFORCING"},
		{false, false, "DETECT-ONLY"},
		{true, false, "DRY-RUN"},
		{true, true, "DRY-RUN"},
	}
	for _, c := range cases {
		if got := BootModeLabel(c.dryRun, c.enforcing); got != c.want {
			t.Errorf("BootModeLabel(dryRun=%v, enforcing=%v) = %q, want %q",
				c.dryRun, c.enforcing, got, c.want)
		}
	}
}

// An empty override must fall back to the safe list. Losing it means score
// driven enforcement can throttle sshd and lock the operator out of the host.
func TestSystemCriticalBinariesDefaultsWhenUnset(t *testing.T) {
	got := systemCriticalBinaries("")
	if len(got) == 0 {
		t.Fatal("empty override produced an empty exemption list — sshd/systemd would be auto-enforceable")
	}
	if len(got) != len(choke.DefaultSystemCriticalBinaries()) {
		t.Errorf("exemption list = %d entries, want the package default (%d)",
			len(got), len(choke.DefaultSystemCriticalBinaries()))
	}
}

func TestSystemCriticalBinariesOverride(t *testing.T) {
	got := systemCriticalBinaries(" sshd , my-daemon ,, ")
	want := []string{"sshd", "my-daemon"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// An override of only separators resolves to an EMPTY list, not the defaults.
// The operator asked for their own list, however malformed, and silently
// reinstating protection they did not ask for would misreport what this host
// actually exempts.
func TestSystemCriticalBinariesBlankOverrideIsEmptyNotDefault(t *testing.T) {
	if got := systemCriticalBinaries(" , , "); len(got) != 0 {
		t.Errorf("blank override = %v, want an empty list", got)
	}
}

// A typo in the allow-list must cost that one address, not the whole boot: a
// host that refuses to start has no enforcement at all, which is strictly worse
// than one MAC going unprotected.
func TestProtectedMACsSkipsMalformedEntries(t *testing.T) {
	got := protectedMACs("aa:bb:cc:dd:ee:01, not-a-mac ,aa:bb:cc:dd:ee:02", nil)
	if len(got) != 2 {
		t.Fatalf("protected set has %d entries, want 2 (the malformed one skipped)", len(got))
	}
	for _, s := range []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"} {
		mac, err := devbpf.ParseMAC(s)
		if err != nil {
			t.Fatal(err)
		}
		if !got[mac] {
			t.Errorf("%s missing from the protected set", s)
		}
	}
}

func TestProtectedMACsEmptyInput(t *testing.T) {
	if got := protectedMACs("", nil); len(got) != 0 {
		t.Errorf("protected set = %v, want empty", got)
	}
}

// SECURITY (Phase 0, deliverable #3). The demo default is gone, so an
// unconfigured host must fail here rather than stand up a console every
// deployment shares a password for.
func TestResolveConsoleCredentialRefusesAnEmptyCredential(t *testing.T) {
	_, err := ResolveConsoleCredential("", "", "dashboard")
	if err == nil {
		t.Fatal("no credential configured returned nil error — a blank-password console would start")
	}
	if !strings.Contains(err.Error(), "dashboard") {
		t.Errorf("error names the wrong surface: %v", err)
	}
	// The agent protects a differently named surface and its operators grep
	// for that word.
	_, err = ResolveConsoleCredential("", "", "console")
	if err == nil || !strings.Contains(err.Error(), "console") {
		t.Errorf("agent surface error = %v", err)
	}
}

// A pre-hashed bcrypt value cannot be composition-checked, so it passes through
// untouched — and it must win over any plaintext supplied alongside it, or an
// operator who set both would silently be authenticated against the weaker one.
func TestResolveConsoleCredentialPrefersTheHash(t *testing.T) {
	const hash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	got, err := ResolveConsoleCredential("weak", hash, "console")
	if err != nil {
		t.Fatalf("bcrypt hash rejected: %v", err)
	}
	if got != hash {
		t.Errorf("credential = %q, want the hash", got)
	}
}

// Plaintext is held to the same policy the login page displays; a password the
// console would refuse to accept must not be the one it boots with.
func TestResolveConsoleCredentialEnforcesThePolicyOnPlaintext(t *testing.T) {
	if _, err := ResolveConsoleCredential("short", "", "console"); err == nil {
		t.Error("a policy-violating password was accepted at startup")
	}
	strong := "Str0ng!P@ssw0rd#7"
	got, err := ResolveConsoleCredential(strong, "", "console")
	if err != nil {
		t.Fatalf("compliant password rejected: %v", err)
	}
	if got != strong {
		t.Errorf("credential = %q, want %q", got, strong)
	}
}
