package hoststack

import (
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/config"
)

func ptrBool(b bool) *bool { return &b }
func ptrInt(i int) *int    { return &i }

// defaultSettings is what a binary holds after flag parsing with no flags set.
// The merge only writes over a field that still equals its default, so this is
// the precondition every "file wins" case below depends on.
func defaultSettings() *Settings {
	return &Settings{
		TetragonAddr: DefaultTetragonAddr,
		DBPath:       DefaultDBPath,
		HTTPAddr:     DefaultHTTPAddr,
		AuthUser:     DefaultAuthUser,
		PoliciesDir:  DefaultPoliciesDir,
		AttacksDir:   DefaultAttacksDir,
		HoneypotsDir: DefaultHoneypotsDir,
		ChokeDir:     DefaultChokeDir,
		ThrottleAt:   DefaultThrottleAt,
		TarpitAt:     DefaultTarpitAt,
		QuarantineAt: DefaultQuarantineAt,
		SeverAt:      DefaultSeverAt,
		CgroupRoot:   DefaultCgroupRoot,
		BPFCgroup:    DefaultBPFCgroup,
		StoreKind:    DefaultStoreKind,
		LogFormat:    DefaultLogFormat,
		LogLevel:     DefaultLogLevel,
	}
}

// The config file exists because 30+ flags on a systemd ExecStart line is
// unmanageable — so a field nobody passed on the command line has to come from
// the file, or the file is decorative.
func TestApplyFileFillsInSettingsLeftAtTheirDefaults(t *testing.T) {
	s := defaultSettings()
	s.ApplyFile(&config.File{
		Tetragon:        "unix:///tmp/tetragon.sock",
		DB:              "/var/lib/agent.db",
		HTTP:            "127.0.0.1:9090",
		User:            "operator",
		Pass:            "Str0ng!Passw0rd",
		PassHash:        "$2a$10$hash",
		SecretPath:      "/etc/ebpf-engine/secret",
		PoliciesDir:     "/etc/policies",
		AttacksDir:      "/etc/attacks",
		HoneypotsDir:    "/srv/honey",
		ChokeDir:        "/etc/choke",
		DryRun:          ptrBool(true),
		Enforce:         ptrBool(true),
		ThrottleAt:      ptrInt(7),
		TarpitAt:        ptrInt(17),
		QuarantineAt:    ptrInt(27),
		SeverAt:         ptrInt(47),
		CgroupRoot:      "/mnt/cgroup2",
		SystemCritical:  "sshd,systemd",
		BPFObj:          "/opt/choke.o",
		BPFCgroup:       "/mnt/cgroup2",
		DevchokeObj:     "/opt/devchoke.o",
		DevchokeIfaces:  "eth0,eth1",
		DevchokeProtect: "aa:bb:cc:dd:ee:01",
		Store:           "postgres",
		PgDSN:           "postgres://u:p@h:5432/db",
		LogFormat:       "json",
		LogLevel:        "debug",
		OTLPEndpoint:    "http://collector:4318",
	})

	checks := []struct {
		name       string
		got, want  string
		skipString bool
	}{
		{name: "TetragonAddr", got: s.TetragonAddr, want: "unix:///tmp/tetragon.sock"},
		{name: "DBPath", got: s.DBPath, want: "/var/lib/agent.db"},
		{name: "HTTPAddr", got: s.HTTPAddr, want: "127.0.0.1:9090"},
		{name: "AuthUser", got: s.AuthUser, want: "operator"},
		{name: "AuthPass", got: s.AuthPass, want: "Str0ng!Passw0rd"},
		{name: "AuthHash", got: s.AuthHash, want: "$2a$10$hash"},
		{name: "SecretPath", got: s.SecretPath, want: "/etc/ebpf-engine/secret"},
		{name: "PoliciesDir", got: s.PoliciesDir, want: "/etc/policies"},
		{name: "AttacksDir", got: s.AttacksDir, want: "/etc/attacks"},
		{name: "HoneypotsDir", got: s.HoneypotsDir, want: "/srv/honey"},
		{name: "ChokeDir", got: s.ChokeDir, want: "/etc/choke"},
		{name: "CgroupRoot", got: s.CgroupRoot, want: "/mnt/cgroup2"},
		{name: "SystemCritical", got: s.SystemCritical, want: "sshd,systemd"},
		{name: "BPFObj", got: s.BPFObj, want: "/opt/choke.o"},
		{name: "BPFCgroup", got: s.BPFCgroup, want: "/mnt/cgroup2"},
		{name: "DevchokeObj", got: s.DevchokeObj, want: "/opt/devchoke.o"},
		{name: "DevchokeIfaces", got: s.DevchokeIfaces, want: "eth0,eth1"},
		{name: "DevchokeProtect", got: s.DevchokeProtect, want: "aa:bb:cc:dd:ee:01"},
		{name: "StoreKind", got: s.StoreKind, want: "postgres"},
		{name: "PgDSN", got: s.PgDSN, want: "postgres://u:p@h:5432/db"},
		{name: "LogFormat", got: s.LogFormat, want: "json"},
		{name: "LogLevel", got: s.LogLevel, want: "debug"},
		{name: "OTLPEndpoint", got: s.OTLPEndpoint, want: "http://collector:4318"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if !s.DryRun || !s.Enforce {
		t.Errorf("DryRun=%v Enforce=%v, want both true", s.DryRun, s.Enforce)
	}
	if s.ThrottleAt != 7 || s.TarpitAt != 17 || s.QuarantineAt != 27 || s.SeverAt != 47 {
		t.Errorf("thresholds = %d/%d/%d/%d, want 7/17/27/47",
			s.ThrottleAt, s.TarpitAt, s.QuarantineAt, s.SeverAt)
	}
}

// Flags always win. These are enforcement thresholds and a storage backend: an
// operator overriding them on the command line to contain an incident must not
// have a stale config file quietly put the old values back.
func TestApplyFileNeverOverridesAValueTheFlagsAlreadySet(t *testing.T) {
	s := defaultSettings()
	s.SeverAt = 99         // as if -sever-at=99 was passed
	s.StoreKind = "sqlite" // still the default, so the file MAY change this
	s.LogLevel = "error"   // as if -log-level=error was passed
	s.Enforce = true       // as if -enforce was passed

	s.ApplyFile(&config.File{
		SeverAt:  ptrInt(40),
		Store:    "postgres",
		LogLevel: "debug",
		Enforce:  ptrBool(false),
	})

	if s.SeverAt != 99 {
		t.Errorf("SeverAt = %d, want the flag's 99 — the config file overrode an explicit threshold", s.SeverAt)
	}
	if s.LogLevel != "error" {
		t.Errorf("LogLevel = %q, want the flag's error", s.LogLevel)
	}
	if !s.Enforce {
		t.Error("Enforce was disarmed by the config file after the flag armed it")
	}
	if s.StoreKind != "postgres" {
		t.Errorf("StoreKind = %q, want postgres — a field still at its default must take the file value", s.StoreKind)
	}
}

// An empty file field means "not configured", never "set it back to empty".
func TestApplyFileIgnoresUnsetFields(t *testing.T) {
	s := defaultSettings()
	s.ApplyFile(&config.File{})
	if s.TetragonAddr != DefaultTetragonAddr || s.SeverAt != DefaultSeverAt || s.StoreKind != DefaultStoreKind {
		t.Errorf("an empty config file changed settings: %+v", s)
	}
}
