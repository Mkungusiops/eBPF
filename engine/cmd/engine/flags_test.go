package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/hoststack"
)

// cmd/engine had no test at all: every flag, default, and config-file
// precedence rule was declared inside a 634-line main() and verified by
// starting the binary and reading the log.

func TestEngineDefaults(t *testing.T) {
	c := parseEngineFlags(nil)
	if c.Version != engineVersion {
		t.Errorf("Version = %q, want %q", c.Version, engineVersion)
	}
	if c.TetragonAddr != hoststack.DefaultTetragonAddr {
		t.Errorf("TetragonAddr = %q", c.TetragonAddr)
	}
	if c.Enforce || c.DryRun {
		t.Errorf("Enforce=%v DryRun=%v, want a detect-only default", c.Enforce, c.DryRun)
	}
	if c.ThrottleAt != 5 || c.TarpitAt != 15 || c.QuarantineAt != 25 || c.SeverAt != 40 {
		t.Errorf("thresholds = %d/%d/%d/%d, want 5/15/25/40",
			c.ThrottleAt, c.TarpitAt, c.QuarantineAt, c.SeverAt)
	}
	// Fake mode fabricates telemetry; it must never be the default on a binary
	// an operator can point at a real host.
	if c.fakeMode {
		t.Error("fake mode is on by default")
	}
	// The login rate limit is the dashboard's only brute-force defence.
	if c.loginRate != 5 {
		t.Errorf("loginRate = %d, want 5", c.loginRate)
	}
	if c.fleetHosts != "" {
		t.Errorf("fleetHosts = %q, want the fan-out off by default", c.fleetHosts)
	}
	if c.AuthPass != "" || c.AuthHash != "" {
		t.Errorf("a credential default has reappeared: pass=%q hash=%q", c.AuthPass, c.AuthHash)
	}
}

func TestEngineFlagsOverrideDefaults(t *testing.T) {
	c := parseEngineFlags([]string{
		"-fake", "-login-rate=0", "-fleet-hosts=/etc/chokectl.hosts",
		"-dry-run", "-throttle-at=3", "-bpf-obj=/opt/choke.o",
	})
	if !c.fakeMode {
		t.Error("-fake ignored")
	}
	if c.loginRate != 0 {
		t.Errorf("loginRate = %d, want 0 (disabled for dev/E2E)", c.loginRate)
	}
	if c.fleetHosts != "/etc/chokectl.hosts" {
		t.Errorf("fleetHosts = %q", c.fleetHosts)
	}
	if !c.DryRun || c.ThrottleAt != 3 || c.BPFObj != "/opt/choke.o" {
		t.Errorf("dryRun=%v throttleAt=%d bpfObj=%q", c.DryRun, c.ThrottleAt, c.BPFObj)
	}
}

// fleet_hosts is the one merged field the engine has and the agent does not, so
// it is the one most likely to be dropped when the merge is shared.
func TestEngineConfigFileMergesFleetHostsAndFlagsStillWin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "engine.yaml")
	yaml := "" +
		"fleet_hosts: /etc/chokectl.hosts\n" +
		"store: postgres\n" +
		"pg_dsn: postgres://u:p@h/db\n" +
		"throttle_at: 9\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	c := parseEngineFlags([]string{"-config=" + path, "-throttle-at=3"})
	if c.fleetHosts != "/etc/chokectl.hosts" {
		t.Errorf("fleetHosts = %q, want the file's value", c.fleetHosts)
	}
	if c.StoreKind != "postgres" || c.PgDSN != "postgres://u:p@h/db" {
		t.Errorf("store = %q dsn = %q", c.StoreKind, c.PgDSN)
	}
	if c.ThrottleAt != 3 {
		t.Errorf("ThrottleAt = %d — the config file overrode an explicit -throttle-at", c.ThrottleAt)
	}
}
