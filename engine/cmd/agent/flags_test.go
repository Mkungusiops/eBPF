package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/hoststack"
)

// The flag surface was declared inside main(), so nothing could assert on it.
// These cases cover the two ways an operator configures a production agent —
// systemd ExecStart flags and /etc/ebpf-engine/engine.yaml — and the precedence
// between them.

func TestAgentDefaults(t *testing.T) {
	c := parseAgentFlags(nil)
	if c.Version != agentVersion {
		t.Errorf("Version = %q, want %q", c.Version, agentVersion)
	}
	if c.TetragonAddr != hoststack.DefaultTetragonAddr {
		t.Errorf("TetragonAddr = %q", c.TetragonAddr)
	}
	// Detect-only by default is the whole safety posture: an agent that armed
	// itself on install would start SIGKILLing on first boot.
	if c.Enforce || c.DryRun {
		t.Errorf("Enforce=%v DryRun=%v, want a detect-only default", c.Enforce, c.DryRun)
	}
	if c.ThrottleAt != 5 || c.TarpitAt != 15 || c.QuarantineAt != 25 || c.SeverAt != 40 {
		t.Errorf("thresholds = %d/%d/%d/%d, want 5/15/25/40",
			c.ThrottleAt, c.TarpitAt, c.QuarantineAt, c.SeverAt)
	}
	// No control plane configured means a fully standalone agent.
	if c.controlPlane != "" || c.cpStateDir != "" || c.bootstrapToken != "" {
		t.Errorf("control-plane settings are not empty by default: %+v", c)
	}
	// SECURITY (Phase 0, deliverable #3): there is no built-in credential.
	if c.AuthPass != "" || c.AuthHash != "" {
		t.Errorf("a credential default has reappeared: pass=%q hash=%q", c.AuthPass, c.AuthHash)
	}
}

func TestAgentFlagsOverrideDefaults(t *testing.T) {
	c := parseAgentFlags([]string{
		"-enforce", "-sever-at=99", "-store=postgres", "-pg-dsn=postgres://u:p@h/db",
		"-controlplane=cp.example.com:8443", "-state-dir=/var/lib/agent",
		"-devchoke-iface=eth0,eth1",
	})
	if !c.Enforce {
		t.Error("-enforce did not arm the agent")
	}
	if c.SeverAt != 99 {
		t.Errorf("SeverAt = %d, want 99", c.SeverAt)
	}
	if c.StoreKind != "postgres" || c.PgDSN != "postgres://u:p@h/db" {
		t.Errorf("store = %q dsn = %q", c.StoreKind, c.PgDSN)
	}
	if c.controlPlane != "cp.example.com:8443" || c.cpStateDir != "/var/lib/agent" {
		t.Errorf("control-plane flags = %q / %q", c.controlPlane, c.cpStateDir)
	}
	if c.DevchokeIfaces != "eth0,eth1" {
		t.Errorf("DevchokeIfaces = %q", c.DevchokeIfaces)
	}
}

// The config file is shared verbatim with cmd/engine, so an operator's
// engine.yaml has to drop straight onto an agent — and an explicit flag must
// still beat it.
func TestAgentConfigFileMergesAndFlagsStillWin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "engine.yaml")
	yaml := "" +
		"tetragon: unix:///tmp/t.sock\n" +
		"enforce: true\n" +
		"sever_at: 60\n" +
		"log_level: debug\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	c := parseAgentFlags([]string{"-config=" + path, "-sever-at=99"})
	if c.TetragonAddr != "unix:///tmp/t.sock" {
		t.Errorf("TetragonAddr = %q, want the file's value", c.TetragonAddr)
	}
	if !c.Enforce {
		t.Error("enforce: true in the file did not arm the agent")
	}
	if c.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug", c.LogLevel)
	}
	if c.SeverAt != 99 {
		t.Errorf("SeverAt = %d — the config file overrode an explicit -sever-at", c.SeverAt)
	}
}

// hostOnly supplies the TLS server name when the operator did not name one, so
// a bare host and an IPv6 endpoint both have to resolve to something a
// certificate can be verified against.
func TestHostOnly(t *testing.T) {
	cases := map[string]string{
		"cp.example.com:8443": "cp.example.com",
		"cp.example.com":      "cp.example.com",
		"10.0.0.4:8443":       "10.0.0.4",
		"[fd00::1]:8443":      "fd00::1",
	}
	for in, want := range cases {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q, want %q", in, got, want)
		}
	}
}

// pidLive is the fallback evidence behind Gateway.Owns for a containment target
// named by PID. Getting it wrong in either direction is a real incident: a
// false "not here" leaves a threat uncontained, a false "here" is how one
// agent SIGKILLs an unrelated local process holding the same PID number.
func TestPIDLive(t *testing.T) {
	if pidLive(0) {
		t.Error("pid 0 reported live — it is not a process, it is a signal wildcard")
	}
	if !pidLive(uint32(os.Getpid())) {
		t.Error("this test's own pid reported not live")
	}
	// PIDs are bounded well below this on every platform we ship on.
	if pidLive(1 << 30) {
		t.Error("an impossible pid reported live")
	}
}
