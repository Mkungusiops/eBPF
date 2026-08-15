package main

import (
	"flag"
	"log"
	"os"

	"github.com/jeffmk/ebpf-poc-engine/internal/config"
	"github.com/jeffmk/ebpf-poc-engine/internal/hoststack"
)

// agentVersion identifies this build target in logs, metrics resource
// attributes, and /api/system-health. Distinct from the engine's "0.2.0"
// only by the "-agent" suffix so a fleet can tell the two build targets
// apart during the transition without changing metric cardinality.
const agentVersion = "0.2.0-agent"

// agentConfig is the agent's full flag surface: everything it shares with
// cmd/engine, plus the control-plane settings that exist only here.
//
// The shared half lives in hoststack.Settings rather than being redeclared,
// because the two binaries used to carry separate copies of the same 30 flags.
// The help text differs on purpose — the same listener is "the dashboard" on
// the engine and "the local debug/health console" on the agent — but the values
// underneath are one type, so a config file cannot mean two things.
type agentConfig struct {
	hoststack.Settings

	// Control-plane uplink (Phase 1). An EMPTY controlPlane keeps the agent
	// fully standalone — no enrollment, no network, behaviour identical to a
	// pre-Phase-1 agent. When set, the agent enrolls (mTLS) and runs the
	// telemetry/heartbeat/command loops in the background; enforcement never
	// depends on any of them (autonomy).
	controlPlane   string
	bootstrapToken string
	caBundlePath   string
	cpServerName   string
	fleetPubKey    string
	cpStateDir     string
}

// parseAgentFlags builds the agent's configuration from the command line and
// the optional YAML file, in that precedence order.
//
// It takes args and returns the config instead of reading os.Args and writing
// globals so the flag surface, its defaults, and the file-merge precedence are
// reachable from a test — they were unreachable inside main() before, which is
// how a flag default and its merge default could drift apart unnoticed.
func parseAgentFlags(args []string) *agentConfig {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	c := &agentConfig{}
	c.bind(fs)
	// ExitOnError: Parse never returns on a bad flag, it exits 2 with usage.
	_ = fs.Parse(args)
	c.Version = agentVersion
	c.loadFile()
	return c
}

func (c *agentConfig) bind(fs *flag.FlagSet) {
	fs.StringVar(&c.TetragonAddr, "tetragon", hoststack.DefaultTetragonAddr, "Tetragon gRPC address")
	fs.StringVar(&c.DBPath, "db", hoststack.DefaultDBPath, "SQLite database path (agent-local WAL / offline buffer)")
	fs.StringVar(&c.HTTPAddr, "http", hoststack.DefaultHTTPAddr, "HTTP listen address for the local debug/health console; Phase 1 restricts this to localhost")
	fs.StringVar(&c.AuthUser, "user", hoststack.DefaultAuthUser, "local debug console username")
	// SECURITY (Phase 0, deliverable #3): no plaintext credential default.
	// A missing password fails fast at startup rather than silently shipping a
	// known credential. Set -pass, -pass-hash, or pass/pass_hash in config.
	fs.StringVar(&c.AuthPass, "pass", "", "local debug console password (plaintext; bcrypted at startup). REQUIRED unless -pass-hash or config supplies one — there is no built-in default")
	fs.StringVar(&c.AuthHash, "pass-hash", "", "bcrypt-hashed console password; takes precedence over -pass when set")
	fs.StringVar(&c.SecretPath, "secret", "", "path to HMAC signing secret for session cookies; auto-generated 0600 if missing (default: /var/lib/ebpf-engine/secret)")
	fs.StringVar(&c.PoliciesDir, "policies", hoststack.DefaultPoliciesDir, "directory containing TracingPolicy YAMLs (for read-only viewer)")
	fs.StringVar(&c.AttacksDir, "attacks", hoststack.DefaultAttacksDir, "directory containing allowlisted attack scripts (for quick-fire panel)")
	fs.StringVar(&c.HoneypotsDir, "honeypots", hoststack.DefaultHoneypotsDir, "directory where decoy files are seeded; access fires alerts when watched by sensitive-files policy")
	// Choke gateway (process cgroup + BPF map data plane).
	fs.StringVar(&c.ChokeDir, "choke-policies", hoststack.DefaultChokeDir, "directory containing ChokePolicy YAMLs (DSL); empty disables policy-driven choking")
	fs.BoolVar(&c.DryRun, "dry-run", false, "shadow mode: record decisions but do not execute enforcement actions")
	fs.BoolVar(&c.Enforce, "enforce", false, "enable real enforcement (kill/throttle); when false, decisions are logged only")
	fs.IntVar(&c.ThrottleAt, "throttle-at", hoststack.DefaultThrottleAt, "chain score at which to start throttling")
	fs.IntVar(&c.TarpitAt, "tarpit-at", hoststack.DefaultTarpitAt, "chain score at which to tarpit")
	fs.IntVar(&c.QuarantineAt, "quarantine-at", hoststack.DefaultQuarantineAt, "chain score at which to quarantine (sinkhole)")
	fs.IntVar(&c.SeverAt, "sever-at", hoststack.DefaultSeverAt, "chain score at which to sever (SIGKILL)")
	fs.StringVar(&c.CgroupRoot, "cgroup-root", hoststack.DefaultCgroupRoot, "cgroup v2 unified mount; choke-{throttled,tarpit,quarantined} are created under this root")
	fs.StringVar(&c.SystemCritical, "system-critical", "", "comma-separated list of binaries exempt from SCORE-DRIVEN auto-enforce (manual overrides still apply); empty = use the default safe list (sshd, systemd, dockerd, …)")
	// cilium/ebpf process data plane.
	fs.StringVar(&c.BPFObj, "bpf-obj", "", "path to compiled choke.o; empty disables the cilium/ebpf data plane and falls back to the in-memory noop backend")
	fs.StringVar(&c.BPFCgroup, "bpf-cgroup", hoststack.DefaultBPFCgroup, "cgroup v2 root to attach the BPF program to")
	// Network (per-device / MAC) choke data plane.
	fs.StringVar(&c.DevchokeObj, "devchoke-obj", "", "path to compiled devchoke.o; empty disables the network device choke data plane")
	fs.StringVar(&c.DevchokeIfaces, "devchoke-iface", "", "comma-separated LAN/bridge-slave interfaces to attach the device choke to (e.g. eth0,eth1)")
	fs.StringVar(&c.DevchokeProtect, "devchoke-protect", "", "comma-separated MAC allow-list (gateway/uplink/DHCP-DNS/operator) the agent refuses to quarantine/sever; interface MACs are auto-added")
	// Storage backend. -db is the SQLite path; -pg-dsn carries the Postgres
	// connection string when -store=postgres.
	fs.StringVar(&c.StoreKind, "store", hoststack.DefaultStoreKind, "storage backend: sqlite | postgres")
	fs.StringVar(&c.PgDSN, "pg-dsn", "", "Postgres DSN (e.g. postgres://user:pass@host:5432/db?sslmode=disable); required when -store=postgres")
	// Observability.
	fs.StringVar(&c.LogFormat, "log-format", hoststack.DefaultLogFormat, "log handler: text (dev) | json (production — for journald → Vector → Loki/Elastic)")
	fs.StringVar(&c.LogLevel, "log-level", hoststack.DefaultLogLevel, "log level: debug | info | warn | error")
	fs.StringVar(&c.OTLPEndpoint, "otlp-endpoint", "", "OTLP/HTTP metrics endpoint (e.g. http://otel-collector:4318); 'stdout' to print metrics every 30s; empty disables metrics")
	// YAML config file. Any field set in the file is used iff the matching
	// CLI flag is still at its default — flags always win. Shared verbatim
	// with cmd/engine (internal/config), so an operator's engine.yaml drops
	// straight onto the agent.
	fs.StringVar(&c.ConfigPath, "config", "", "path to YAML config file (every field has a CLI-flag equivalent; CLI flags override file values)")
	// Control-plane uplink (Phase 1).
	fs.StringVar(&c.controlPlane, "controlplane", "", "control-plane endpoint host:port; empty runs the agent standalone (no uplink)")
	fs.StringVar(&c.bootstrapToken, "bootstrap-token", "", "one-time enrollment token; needed only for the FIRST enrollment (a persisted -state-dir identity is reused tokenless on restart)")
	fs.StringVar(&c.caBundlePath, "ca-bundle", "", "path to the PEM CA bundle pinned to trust the control plane during enrollment; needed only for the first enrollment")
	fs.StringVar(&c.cpServerName, "controlplane-servername", "", "TLS server name for the control-plane certificate (defaults to the host part of -controlplane)")
	fs.StringVar(&c.fleetPubKey, "fleet-pubkey", "", "path to the fleet command-signing ed25519 public key (hex); required to accept remote commands, otherwise the command channel is disabled")
	fs.StringVar(&c.cpStateDir, "state-dir", "", "directory to persist the enrolled mTLS identity (cert/key/CA) so restarts reuse it instead of consuming a new bootstrap token; enables a durable, reboot-safe agent")
}

// loadFile merges the YAML config. It runs before any flag value gets consumed,
// so nothing downstream can read a setting that the file was still going to
// change. The file format is shared verbatim with cmd/engine, so an operator's
// engine.yaml drops straight onto the agent.
func (c *agentConfig) loadFile() {
	cfg, err := config.Load(c.ConfigPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if cfg == nil {
		return
	}
	c.Settings.ApplyFile(cfg)
	log.Printf("[config] loaded %s", c.ConfigPath)
}
