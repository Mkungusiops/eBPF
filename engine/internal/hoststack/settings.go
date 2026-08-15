package hoststack

import (
	"github.com/jeffmk/ebpf-poc-engine/internal/config"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/cgroupv2"
)

// Defaults for the settings both build targets share.
//
// They are constants rather than literals repeated at each use because every
// one of them appears TWICE per binary — once as the flag's default, and once
// as the "is this still the default?" test config.Apply* uses to decide whether
// the YAML file may write over it. A pair that drifts apart does not fail
// loudly: it silently makes that one field unconfigurable from the config file
// while every other field keeps working.
const (
	DefaultTetragonAddr = "unix:///var/run/tetragon/tetragon.sock"
	DefaultDBPath       = "events.db"
	DefaultHTTPAddr     = ":8080"
	DefaultAuthUser     = "admin"
	DefaultPoliciesDir  = "policies"
	DefaultAttacksDir   = "attacks"
	DefaultHoneypotsDir = "/var/lib/ebpf-engine/honey"
	DefaultChokeDir     = "policies/choke"
	DefaultThrottleAt   = 5
	DefaultTarpitAt     = 15
	DefaultQuarantineAt = 25
	DefaultSeverAt      = 40
	DefaultBPFCgroup    = "/sys/fs/cgroup"
	DefaultStoreKind    = "sqlite"
	DefaultLogFormat    = "text"
	DefaultLogLevel     = "info"

	// DefaultCgroupRoot re-exports the cgroup package's own constant so the
	// flag default and the merge check cannot be spelled differently.
	DefaultCgroupRoot = cgroupv2.DefaultRoot
)

// Settings is the configuration cmd/engine and cmd/agent share — every flag
// that means the same thing in both binaries, from the Tetragon socket to the
// enforcement thresholds.
//
// Each binary embeds this in its own config struct and binds its own flags
// straight onto these fields. That split is deliberate: the two flag SURFACES
// are legitimately different (the agent has enrollment and uplink flags the
// engine does not, and the same flag is described differently — "dashboard"
// on the engine, "local debug console" on the agent), but the VALUES the shared
// startup path acts on must be one type with one meaning, or the two binaries
// enforce differently from the same config file.
type Settings struct {
	// Version is reported by /api/system-health. cmd/engine reports "0.2.0"
	// and cmd/agent "0.2.0-agent": a fleet has to be able to tell the two
	// build targets apart during the transition without changing metric
	// cardinality. Not a flag.
	Version string

	// ConfigPath is the YAML file whose fields fill in for flags still at
	// their defaults. Empty means flags only.
	ConfigPath string

	// TetragonAddr is the gRPC endpoint of the daemon that supplies every
	// event this host scores.
	TetragonAddr string

	// Local console. HTTPAddr is the listener; AuthPass and AuthHash are the
	// two ways to supply the credential (hash wins); SecretPath holds the HMAC
	// key for session cookies.
	HTTPAddr   string
	AuthUser   string
	AuthPass   string
	AuthHash   string
	SecretPath string

	// Read-only content the console serves: TracingPolicy YAMLs, allowlisted
	// attack scripts, and the directory decoy files are seeded into.
	PoliciesDir  string
	AttacksDir   string
	HoneypotsDir string

	// Storage. DBPath is the SQLite file; PgDSN carries the connection string
	// when StoreKind is "postgres". Both are also reported (DSN redacted) as
	// the system-health store target.
	StoreKind string
	DBPath    string
	PgDSN     string

	// Process choke data plane. An empty BPFObj keeps the in-memory noop
	// backend — a userspace mirror with no kernel enforcement behind it.
	BPFObj    string
	BPFCgroup string

	// CgroupRoot is the cgroup v2 unified mount the choke tiers are created
	// under.
	CgroupRoot string

	// Network (per-device / MAC) choke data plane. It takes BOTH an object
	// file and at least one interface to become real; either one alone leaves
	// the noop backend in place.
	DevchokeObj     string
	DevchokeIfaces  string
	DevchokeProtect string

	// Gateway behaviour. ChokeDir is the ChokePolicy DSL directory; DryRun
	// records decisions without executing them; Enforce picks which enforcer
	// chain is active at boot (both are always built so the mode can be
	// flipped at runtime).
	ChokeDir string
	DryRun   bool
	Enforce  bool

	ThrottleAt   int
	TarpitAt     int
	QuarantineAt int
	SeverAt      int

	// SystemCritical is the comma-separated auto-enforce exemption override.
	// Empty means the package's default safe list (sshd, systemd, dockerd, …).
	SystemCritical string

	// Observability, reported verbatim by /api/system-health.
	OTLPEndpoint string
	LogFormat    string
	LogLevel     string

	// PIDLiveFn, when non-nil, is installed as the gateway's liveness probe —
	// the fallback evidence for a containment target named by PID rather than
	// by an exec_id this host observed. Only cmd/agent sets it, because only
	// the agent answers remote containment commands; leaving it nil keeps
	// cmd/engine's gateway exactly as it was. Not a flag.
	PIDLiveFn func(pid uint32) bool
}

// ApplyFile merges the YAML file into every setting the two build targets
// share. A field is taken from the file only when the matching flag is still at
// its default, so a CLI flag always wins — that is what an operator already
// expects -flag=value to do, and the config file exists because 30+ flags on a
// systemd ExecStart line is unmanageable, not to override the command line.
//
// Fields unique to one binary (the engine's fleet hosts file, the agent's
// enrollment settings) are merged by that binary after this returns.
func (s *Settings) ApplyFile(f *config.File) {
	config.ApplyString(&s.TetragonAddr, f.Tetragon, DefaultTetragonAddr)
	config.ApplyString(&s.DBPath, f.DB, DefaultDBPath)
	config.ApplyString(&s.HTTPAddr, f.HTTP, DefaultHTTPAddr)
	config.ApplyString(&s.AuthUser, f.User, DefaultAuthUser)
	// No default for the password: a missing one has to fail fast rather than
	// fall back to anything, so "" is both the default and the failure case.
	config.ApplyString(&s.AuthPass, f.Pass, "")
	config.ApplyString(&s.AuthHash, f.PassHash, "")
	config.ApplyString(&s.SecretPath, f.SecretPath, "")
	config.ApplyString(&s.PoliciesDir, f.PoliciesDir, DefaultPoliciesDir)
	config.ApplyString(&s.AttacksDir, f.AttacksDir, DefaultAttacksDir)
	config.ApplyString(&s.HoneypotsDir, f.HoneypotsDir, DefaultHoneypotsDir)
	config.ApplyString(&s.ChokeDir, f.ChokeDir, DefaultChokeDir)
	config.ApplyBool(&s.DryRun, f.DryRun, false)
	config.ApplyBool(&s.Enforce, f.Enforce, false)
	config.ApplyInt(&s.ThrottleAt, f.ThrottleAt, DefaultThrottleAt)
	config.ApplyInt(&s.TarpitAt, f.TarpitAt, DefaultTarpitAt)
	config.ApplyInt(&s.QuarantineAt, f.QuarantineAt, DefaultQuarantineAt)
	config.ApplyInt(&s.SeverAt, f.SeverAt, DefaultSeverAt)
	config.ApplyString(&s.CgroupRoot, f.CgroupRoot, DefaultCgroupRoot)
	config.ApplyString(&s.SystemCritical, f.SystemCritical, "")
	config.ApplyString(&s.BPFObj, f.BPFObj, "")
	config.ApplyString(&s.BPFCgroup, f.BPFCgroup, DefaultBPFCgroup)
	config.ApplyString(&s.DevchokeObj, f.DevchokeObj, "")
	config.ApplyString(&s.DevchokeIfaces, f.DevchokeIfaces, "")
	config.ApplyString(&s.DevchokeProtect, f.DevchokeProtect, "")
	config.ApplyString(&s.StoreKind, f.Store, DefaultStoreKind)
	config.ApplyString(&s.PgDSN, f.PgDSN, "")
	config.ApplyString(&s.LogFormat, f.LogFormat, DefaultLogFormat)
	config.ApplyString(&s.LogLevel, f.LogLevel, DefaultLogLevel)
	config.ApplyString(&s.OTLPEndpoint, f.OTLPEndpoint, "")
}
