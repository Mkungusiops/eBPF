// Package config loads engine settings from a YAML file. Every field
// has a CLI-flag equivalent in main.go; the file is a convenience for
// long-running production deployments where 14+ flags on a systemd
// ExecStart line is unmanageable.
//
// CLI flags always override file values — the file supplies defaults,
// the flags supply overrides. This matches how every operator already
// expects -flag=value to work.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// File mirrors the engine's flag surface in YAML form. Field tags pick
// short, kebab-case keys consistent with the existing flag names so an
// operator can translate -throttle-at 20 -> "throttle_at: 20" trivially.
type File struct {
	Tetragon       string `yaml:"tetragon"`
	DB             string `yaml:"db"`
	HTTP           string `yaml:"http"`
	User           string `yaml:"user"`
	Pass           string `yaml:"pass"`
	// Pre-hashed bcrypt password. When set, takes precedence over Pass
	// (plaintext). Lets operators avoid putting plaintext credentials
	// in /etc/ebpf-engine/engine.yaml. Generate with:
	//   htpasswd -bnBC 10 "" 'your-password' | tr -d ':\n' | sed 's/^[$]2y/$2a/'
	PassHash       string `yaml:"pass_hash"`
	// Path to the HMAC signing secret used for session cookies. Auto-
	// generated 0600 on first start if missing. Empty -> default
	// /etc/ebpf-engine/secret.
	SecretPath     string `yaml:"secret_path"`
	PoliciesDir    string `yaml:"policies"`
	AttacksDir     string `yaml:"attacks"`
	HoneypotsDir   string `yaml:"honeypots"`
	ChokeDir       string `yaml:"choke_policies"`
	DryRun         *bool  `yaml:"dry_run"`
	Enforce        *bool  `yaml:"enforce"`
	ThrottleAt     *int   `yaml:"throttle_at"`
	TarpitAt       *int   `yaml:"tarpit_at"`
	QuarantineAt   *int   `yaml:"quarantine_at"`
	SeverAt        *int   `yaml:"sever_at"`
	CgroupRoot     string `yaml:"cgroup_root"`
	SystemCritical string `yaml:"system_critical"`
	FleetHosts     string `yaml:"fleet_hosts"`
	BPFObj         string `yaml:"bpf_obj"`
	BPFCgroup      string `yaml:"bpf_cgroup"`
	// Storage backend.
	Store          string `yaml:"store"`   // "sqlite" (default) | "postgres"
	PgDSN          string `yaml:"pg_dsn"`  // required when store=postgres
	// Observability.
	LogFormat      string `yaml:"log_format"`     // "text" (dev) | "json" (production)
	LogLevel       string `yaml:"log_level"`      // "debug" | "info" | "warn" | "error"
	OTLPEndpoint   string `yaml:"otlp_endpoint"`  // OTLP/HTTP collector URL, "stdout" for dev, "" disables
}

// Load reads a YAML config from path. Returns (nil, nil) if path is
// empty so callers can use it unconditionally.
func Load(path string) (*File, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var f File
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return &f, nil
}

// ApplyString writes file's value into target only if file value is
// non-empty AND target still holds defaultValue. The "still default"
// check lets a CLI flag override the file because flag parsing happens
// before ApplyString and would have moved target away from the default.
func ApplyString(target *string, fileValue, defaultValue string) {
	if fileValue == "" || *target != defaultValue {
		return
	}
	*target = fileValue
}

// ApplyBool only touches target if file specified the field (non-nil)
// AND target still holds the default. Same flag-wins semantics.
func ApplyBool(target *bool, fileValue *bool, defaultValue bool) {
	if fileValue == nil || *target != defaultValue {
		return
	}
	*target = *fileValue
}

// ApplyInt — same dance for ints.
func ApplyInt(target *int, fileValue *int, defaultValue int) {
	if fileValue == nil || *target != defaultValue {
		return
	}
	*target = *fileValue
}
