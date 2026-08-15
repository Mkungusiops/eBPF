package main

import (
	"flag"
	"log"
	"os"

	"github.com/jeffmk/ebpf-poc-engine/internal/config"
	"github.com/jeffmk/ebpf-poc-engine/internal/hoststack"
)

// engineVersion is what this build target reports to /api/system-health. The
// agent build reports the same number with an "-agent" suffix so a fleet can
// tell the two apart without a metric-cardinality change.
const engineVersion = "0.2.0"

// engineConfig is the engine's full flag surface: everything it shares with
// cmd/agent, plus the three settings that belong to the console binary alone.
//
// The shared half lives in hoststack.Settings rather than being redeclared
// here, because the two binaries used to hold separate copies of the same 30
// flags and a value that means one thing on the engine and another on the agent
// is how a fleet ends up enforcing inconsistently from one config file.
type engineConfig struct {
	hoststack.Settings

	// fakeMode synthesizes events instead of connecting to Tetragon. It is a
	// dev/UI convenience of the console binary and deliberately has no
	// counterpart in cmd/agent: an agent is a production sensor, and a build
	// that can fabricate its own telemetry is not one.
	fakeMode bool
	// loginRate is the per-IP login attempt budget guarding the dashboard.
	loginRate int
	// fleetHosts points at a chokectl-format hosts file and turns on the Tier 1
	// Fleet Console fan-out. The multi-host control pattern this implements
	// becomes the control plane's command channel; it is not an agent concern.
	fleetHosts string
}

// parseEngineFlags builds the engine's configuration from the command line and
// the optional YAML file, in that precedence order.
//
// It takes args and returns the config instead of reading os.Args and writing
// globals so the flag surface, its defaults, and the file-merge precedence are
// reachable from a test — they were unreachable inside main() before, which is
// how a flag default and its merge default could drift apart unnoticed.
func parseEngineFlags(args []string) *engineConfig {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	c := &engineConfig{}
	c.bind(fs)
	// ExitOnError: Parse never returns on a bad flag, it exits 2 with usage.
	_ = fs.Parse(args)
	c.Version = engineVersion
	c.loadFile()
	return c
}

func (c *engineConfig) bind(fs *flag.FlagSet) {
	fs.StringVar(&c.TetragonAddr, "tetragon", hoststack.DefaultTetragonAddr, "Tetragon gRPC address")
	fs.StringVar(&c.DBPath, "db", hoststack.DefaultDBPath, "SQLite database path")
	fs.StringVar(&c.HTTPAddr, "http", hoststack.DefaultHTTPAddr, "HTTP listen address")
	fs.BoolVar(&c.fakeMode, "fake", false, "synthesize events instead of connecting to Tetragon (dev/UI mode)")
	fs.StringVar(&c.AuthUser, "user", hoststack.DefaultAuthUser, "dashboard username")
	// SECURITY (Phase 0, deliverable #3): no plaintext credential default.
	// Historically this defaulted to a known demo string, which meant every
	// deployment that forgot to set a password silently shipped the same
	// credential. That default is gone: a missing password now fails fast at
	// startup (see the credential resolution in main). Set -pass, -pass-hash,
	// or pass/pass_hash in the config file; prefer pass_hash for production
	// so plaintext never lands on disk. auth.go's crypto is unchanged.
	fs.StringVar(&c.AuthPass, "pass", "", "dashboard password (plaintext; bcrypted at startup). REQUIRED unless -pass-hash or config supplies one — there is no built-in default; a missing password fails fast")
	fs.StringVar(&c.AuthHash, "pass-hash", "", "bcrypt-hashed dashboard password; takes precedence over -pass when set")
	fs.StringVar(&c.SecretPath, "secret", "", "path to HMAC signing secret for session cookies; auto-generated 0600 if missing (default: /etc/ebpf-engine/secret)")
	fs.IntVar(&c.loginRate, "login-rate", 5, "login attempts per rolling minute per IP (anti-brute-force); 0 disables it for dev/E2E")
	fs.StringVar(&c.PoliciesDir, "policies", hoststack.DefaultPoliciesDir, "directory containing TracingPolicy YAMLs (for read-only viewer)")
	fs.StringVar(&c.AttacksDir, "attacks", hoststack.DefaultAttacksDir, "directory containing allowlisted attack scripts (for quick-fire panel)")
	fs.StringVar(&c.HoneypotsDir, "honeypots", hoststack.DefaultHoneypotsDir, "directory where decoy files are seeded; access fires alerts when watched by sensitive-files policy")
	// Phase 1+2: choke gateway
	fs.StringVar(&c.ChokeDir, "choke-policies", hoststack.DefaultChokeDir, "directory containing ChokePolicy YAMLs (DSL); empty disables policy-driven choking")
	fs.BoolVar(&c.DryRun, "dry-run", false, "shadow mode: record decisions but do not execute enforcement actions")
	fs.BoolVar(&c.Enforce, "enforce", false, "enable real enforcement (kill/throttle); when false, decisions are logged only")
	fs.IntVar(&c.ThrottleAt, "throttle-at", hoststack.DefaultThrottleAt, "chain score at which to start throttling")
	fs.IntVar(&c.TarpitAt, "tarpit-at", hoststack.DefaultTarpitAt, "chain score at which to tarpit")
	fs.IntVar(&c.QuarantineAt, "quarantine-at", hoststack.DefaultQuarantineAt, "chain score at which to quarantine (sinkhole)")
	fs.IntVar(&c.SeverAt, "sever-at", hoststack.DefaultSeverAt, "chain score at which to sever (SIGKILL)")
	fs.StringVar(&c.CgroupRoot, "cgroup-root", hoststack.DefaultCgroupRoot, "cgroup v2 unified mount; choke-{throttled,tarpit,quarantined} are created under this root")
	fs.StringVar(&c.SystemCritical, "system-critical", "", "comma-separated list of binaries exempt from SCORE-DRIVEN auto-enforce (manual overrides still apply); empty = use the default safe list (sshd, systemd, dockerd, …)")
	// Tier 1 fleet console (Fleet Console at /fleet). When this points at
	// a chokectl-format hosts file, /api/fleet/* endpoints fan out to
	// each peer and the embedded UI lets one operator drive N hosts.
	fs.StringVar(&c.fleetHosts, "fleet-hosts", "", "path to chokectl.hosts file; enables the /fleet console and /api/fleet/* fanout endpoints")
	// cilium/ebpf data plane: when -bpf-obj points at a compiled
	// choke.o the engine loads it and attaches cgroup/connect{4,6}
	// programs to -bpf-cgroup. Empty -bpf-obj keeps the noop backend
	// (in-memory mirror only — no kernel enforcement).
	fs.StringVar(&c.BPFObj, "bpf-obj", "", "path to compiled choke.o; empty disables the cilium/ebpf data plane and falls back to the in-memory noop backend")
	fs.StringVar(&c.BPFCgroup, "bpf-cgroup", hoststack.DefaultBPFCgroup, "cgroup v2 root to attach the BPF program to")
	// Network (per-device / MAC) choke data plane. When -devchoke-obj
	// points at a compiled devchoke.o AND -devchoke-iface names one or
	// more LAN/bridge-slave interfaces, the engine loads it and attaches
	// tc ingress+egress so it can throttle/block forwarded traffic by
	// device MAC. Empty -devchoke-iface keeps the in-memory noop backend.
	fs.StringVar(&c.DevchokeObj, "devchoke-obj", "", "path to compiled devchoke.o; empty disables the network device choke data plane")
	fs.StringVar(&c.DevchokeIfaces, "devchoke-iface", "", "comma-separated LAN/bridge-slave interfaces to attach the device choke to (e.g. eth0,eth1)")
	fs.StringVar(&c.DevchokeProtect, "devchoke-protect", "", "comma-separated MAC allow-list (gateway/uplink/DHCP-DNS/operator) the engine refuses to quarantine/sever; interface MACs are auto-added")
	// Storage backend. -db is reused as the SQLite path; -pg-dsn carries
	// the Postgres connection string when -store=postgres.
	fs.StringVar(&c.StoreKind, "store", hoststack.DefaultStoreKind, "storage backend: sqlite | postgres")
	fs.StringVar(&c.PgDSN, "pg-dsn", "", "Postgres DSN (e.g. postgres://user:pass@host:5432/db?sslmode=disable); required when -store=postgres")
	// Observability.
	fs.StringVar(&c.LogFormat, "log-format", hoststack.DefaultLogFormat, "log handler: text (dev) | json (production — for journald → Vector → Loki/Elastic)")
	fs.StringVar(&c.LogLevel, "log-level", hoststack.DefaultLogLevel, "log level: debug | info | warn | error")
	fs.StringVar(&c.OTLPEndpoint, "otlp-endpoint", "", "OTLP/HTTP metrics endpoint (e.g. http://otel-collector:4318); 'stdout' to print metrics every 30s; empty disables metrics")
	// YAML config file. Any field set in the file is used iff the
	// matching CLI flag is still at its default — flags always win.
	fs.StringVar(&c.ConfigPath, "config", "", "path to YAML config file (every field has a CLI-flag equivalent; CLI flags override file values)")
}

// loadFile merges the YAML config. It runs before any flag value gets consumed,
// so nothing downstream can read a setting that the file was still going to
// change.
func (c *engineConfig) loadFile() {
	cfg, err := config.Load(c.ConfigPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if cfg == nil {
		return
	}
	c.Settings.ApplyFile(cfg)
	config.ApplyString(&c.fleetHosts, cfg.FleetHosts, "")
	log.Printf("[config] loaded %s", c.ConfigPath)
}
