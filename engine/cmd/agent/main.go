// Command agent is the Choke Agent build target: the per-host, autonomous
// sensing + enforcing core of the platform. It is the first half of the
// agent / control-plane split described in docs/plan/architecture.md §1.
//
// STRANGLER NOTE (Phase 0). This entrypoint is deliberately introduced
// ALONGSIDE cmd/engine, not by refactoring it. Both binaries compile over
// the same internal/ packages (choke, enforce, score, tree, device, origin,
// store, …) — the shared core is untouched. The agent wires the identical
// in-kernel sensing + enforcing path cmd/engine runs today, minus two things
// that architecture.md assigns elsewhere:
//
//   - fake mode  — a dev/UI convenience of the console binary, not part of
//     the sensing+enforcing path; stays in cmd/engine.
//   - fleet fan-out (chokectl) — a client-driven multi-host control pattern
//     that becomes the control plane's command channel in
//     Phase 1 (architecture.md §3.5). Not an agent concern.
//
// The event-handler glue below (handleExec/handleKprobe/…) is duplicated from
// cmd/engine on purpose: extracting it into a shared package is the "hollow
// out cmd/engine" step, which is Phase 1 (roadmap.md "Agent v1"), not Phase 0.
// Until then the duplication is the accepted, temporary cost of the strangler
// pattern — it keeps the live cmd/engine path behaviourally frozen while the
// new build target proves it links cleanly against the shared core.
//
// Autonomy contract (the moat — architecture.md §2/§6): nothing here makes
// in-kernel enforcement depend on a network service. The agent enforces from
// local state; the uplink/enrollment/policy-pull machinery (Phase 1) is layered
// on top without ever becoming a prerequisite for containment.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/api"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/tokens"
	"github.com/jeffmk/ebpf-poc-engine/internal/command"
	"github.com/jeffmk/ebpf-poc-engine/internal/config"
	"github.com/jeffmk/ebpf-poc-engine/internal/cpclient"
	"github.com/jeffmk/ebpf-poc-engine/internal/device"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/bpfmap"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/cgroupv2"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/devbpf"
	"github.com/jeffmk/ebpf-poc-engine/internal/logging"
	"github.com/jeffmk/ebpf-poc-engine/internal/metrics"
	"github.com/jeffmk/ebpf-poc-engine/internal/origin"
	"github.com/jeffmk/ebpf-poc-engine/internal/policy"
	"github.com/jeffmk/ebpf-poc-engine/internal/score"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/sysproc"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
	"github.com/jeffmk/ebpf-poc-engine/internal/uplink"
)

// agentVersion identifies this build target in logs, metrics resource
// attributes, and /api/system-health. Distinct from the engine's "0.2.0"
// only by the "-agent" suffix so a fleet can tell the two build targets
// apart during the transition without changing metric cardinality.
const agentVersion = "0.2.0-agent"

// gw is the global choke gateway. It is created in main() and read by the
// event handlers. nil-safe: handlers check before dispatching. (Same shape
// as cmd/engine — kept identical so the sensing path is byte-for-byte
// equivalent in behaviour.)
var gw *choke.Gateway

// tetragonConnected mirrors the OTel gauge so the /api/system-health
// handler can read live state without reaching into the metrics pipeline.
var tetragonConnected atomic.Bool

// sensors is the Tetragon client, published once the event stream is dialled so
// the heartbeat can ask the daemon what TracingPolicies the kernel actually has.
// It is set after the control-plane config is built, hence the indirection: the
// heartbeat closure runs on a timer and only ever reads it post-startup.
var (
	sensorsMu sync.RWMutex
	sensors   tetragon.FineGuidanceSensorsClient
)

func setSensors(c tetragon.FineGuidanceSensorsClient) {
	sensorsMu.Lock()
	sensors = c
	sensorsMu.Unlock()
}

// kernelPolicies reports Tetragon's TracingPolicies as the KERNEL has them, for
// the heartbeat. This exists because the engine's enforcement mode is only half
// of a host's posture: a `Sigkill` in a loaded policy fires regardless of what
// mode the operator set, with no audit row and no way to reverse it, so a
// console rendering only the engine's mode can report "detect-only" while the
// kernel kills processes (threat-model EN-3).
//
// Read from the daemon rather than from the policy files on disk, because those
// disagree in both directions: a file edited but never reloaded still runs its
// old version, and a policy deleted at runtime comes back on the next restart if
// its file remains. Only the daemon knows what is actually loaded.
//
// Never fatal and never blocking: a nil return degrades the console to the old
// engine-only view, which is exactly the behaviour of an agent predating the
// field. Enforcement must not depend on the reporting path.
func kernelPolicies(ctx context.Context) []*ebpfsocv1.KernelPolicy {
	sensorsMu.RLock()
	c := sensors
	sensorsMu.RUnlock()
	if c == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	resp, err := c.ListTracingPolicies(ctx, &tetragon.ListTracingPoliciesRequest{})
	if err != nil {
		return nil
	}
	out := make([]*ebpfsocv1.KernelPolicy, 0, len(resp.GetPolicies()))
	for _, p := range resp.GetPolicies() {
		kp := &ebpfsocv1.KernelPolicy{
			Name:    p.GetName(),
			Mode:    tracingPolicyMode(p.GetMode()),
			Enabled: p.GetState() == tetragon.TracingPolicyState_TP_STATE_ENABLED,
		}
		// Signal and Override are the actions that kill or divert a syscall.
		// Post is reporting and deliberately not counted here — counting it
		// would make every healthy detection look like enforcement.
		if ac := p.GetStats().GetActionCounters(); ac != nil {
			kp.EnforceActions = ac.GetSignal() + ac.GetOverride()
			kp.SuppressedActions = ac.GetMonitorSignal()
		}
		out = append(out, kp)
	}
	return out
}

// policyVersion fingerprints the policy set this host is ACTUALLY running, so
// the console can spot an agent that has drifted from the rest of the fleet.
//
// The wire contract has carried applied_policy_version since the beginning and
// the control plane already displays it — but nothing ever set it, so every
// agent reported an empty string and drift was invisible. That is not
// hypothetical: `tetra tracingpolicy add` is create-only, so an edited policy
// keeps running the version loaded at start, and a policy deleted at runtime
// returns from a stale file on the next restart. Both leave a host quietly
// running something different from its neighbours.
//
// Derived from the LOADED set (name + mode + enabled), never from files on
// disk, for exactly that reason: what is on disk is what someone intended, and
// the whole class of bug here is the two disagreeing. Mode is included because
// the same policies in enforce rather than monitor mode is a different — and
// much more dangerous — posture, and it should not hash identically.
func policyVersion(pols []*ebpfsocv1.KernelPolicy) string {
	if len(pols) == 0 {
		return ""
	}
	lines := make([]string, 0, len(pols))
	for _, p := range pols {
		lines = append(lines, fmt.Sprintf("%s\x00%s\x00%t", p.GetName(), p.GetMode(), p.GetEnabled()))
	}
	// Tetragon does not promise an order, so sort before hashing or the same
	// fleet-wide policy set would fingerprint differently per host and every
	// agent would look like it had drifted.
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:8])
}

func tracingPolicyMode(m tetragon.TracingPolicyMode) string {
	switch m {
	case tetragon.TracingPolicyMode_TP_MODE_ENFORCE:
		return "enforce"
	case tetragon.TracingPolicyMode_TP_MODE_MONITOR:
		return "monitor"
	default:
		return "unknown"
	}
}

// upBuf is the control-plane telemetry buffer. It is nil unless -controlplane
// is configured; the event handlers enqueue into it only when non-nil, so with
// no control plane the agent's behaviour is exactly as before (autonomy first —
// the uplink is additive and never on the enforcement path).
var upBuf *uplink.Buffer

// enqueueUplink buffers a record for shipment iff the control-plane uplink is
// active. nil-safe and non-blocking.
func enqueueUplink(rec *ebpfsocv1.TelemetryRecord) {
	if upBuf != nil {
		upBuf.Enqueue(rec)
	}
}

func main() {
	var (
		tetragonAddr = flag.String("tetragon", "unix:///var/run/tetragon/tetragon.sock", "Tetragon gRPC address")
		dbPath       = flag.String("db", "events.db", "SQLite database path (agent-local WAL / offline buffer)")
		httpAddr     = flag.String("http", ":8080", "HTTP listen address for the local debug/health console; Phase 1 restricts this to localhost")
		authUser     = flag.String("user", "admin", "local debug console username")
		// SECURITY (Phase 0, deliverable #3): no plaintext credential default.
		// A missing password fails fast below rather than silently shipping a
		// known credential. Set -pass, -pass-hash, or pass/pass_hash in config.
		authPass    = flag.String("pass", "", "local debug console password (plaintext; bcrypted at startup). REQUIRED unless -pass-hash or config supplies one — there is no built-in default")
		authHash    = flag.String("pass-hash", "", "bcrypt-hashed console password; takes precedence over -pass when set")
		secretPath  = flag.String("secret", "", "path to HMAC signing secret for session cookies; auto-generated 0600 if missing (default: /var/lib/ebpf-engine/secret)")
		policiesDir = flag.String("policies", "policies", "directory containing TracingPolicy YAMLs (for read-only viewer)")
		attacksDir  = flag.String("attacks", "attacks", "directory containing allowlisted attack scripts (for quick-fire panel)")
		honeypotDir = flag.String("honeypots", "/var/lib/ebpf-engine/honey", "directory where decoy files are seeded; access fires alerts when watched by sensitive-files policy")
		// Choke gateway (process cgroup + BPF map data plane).
		chokeDir     = flag.String("choke-policies", "policies/choke", "directory containing ChokePolicy YAMLs (DSL); empty disables policy-driven choking")
		dryRun       = flag.Bool("dry-run", false, "shadow mode: record decisions but do not execute enforcement actions")
		enforceFlag  = flag.Bool("enforce", false, "enable real enforcement (kill/throttle); when false, decisions are logged only")
		throttleAt   = flag.Int("throttle-at", 5, "chain score at which to start throttling")
		tarpitAt     = flag.Int("tarpit-at", 15, "chain score at which to tarpit")
		quarantineAt = flag.Int("quarantine-at", 25, "chain score at which to quarantine (sinkhole)")
		severAt      = flag.Int("sever-at", 40, "chain score at which to sever (SIGKILL)")
		cgroupRoot   = flag.String("cgroup-root", cgroupv2.DefaultRoot, "cgroup v2 unified mount; choke-{throttled,tarpit,quarantined} are created under this root")
		critBinsRaw  = flag.String("system-critical", "", "comma-separated list of binaries exempt from SCORE-DRIVEN auto-enforce (manual overrides still apply); empty = use the default safe list (sshd, systemd, dockerd, …)")
		// cilium/ebpf process data plane.
		bpfObj    = flag.String("bpf-obj", "", "path to compiled choke.o; empty disables the cilium/ebpf data plane and falls back to the in-memory noop backend")
		bpfCgroup = flag.String("bpf-cgroup", "/sys/fs/cgroup", "cgroup v2 root to attach the BPF program to")
		// Network (per-device / MAC) choke data plane.
		devchokeObj     = flag.String("devchoke-obj", "", "path to compiled devchoke.o; empty disables the network device choke data plane")
		devchokeIface   = flag.String("devchoke-iface", "", "comma-separated LAN/bridge-slave interfaces to attach the device choke to (e.g. eth0,eth1)")
		devchokeProtect = flag.String("devchoke-protect", "", "comma-separated MAC allow-list (gateway/uplink/DHCP-DNS/operator) the agent refuses to quarantine/sever; interface MACs are auto-added")
		// Storage backend. -db is the SQLite path; -pg-dsn carries the Postgres
		// connection string when -store=postgres.
		storeKind = flag.String("store", "sqlite", "storage backend: sqlite | postgres")
		pgDSN     = flag.String("pg-dsn", "", "Postgres DSN (e.g. postgres://user:pass@host:5432/db?sslmode=disable); required when -store=postgres")
		// Observability.
		logFormat    = flag.String("log-format", "text", "log handler: text (dev) | json (production — for journald → Vector → Loki/Elastic)")
		logLevel     = flag.String("log-level", "info", "log level: debug | info | warn | error")
		otlpEndpoint = flag.String("otlp-endpoint", "", "OTLP/HTTP metrics endpoint (e.g. http://otel-collector:4318); 'stdout' to print metrics every 30s; empty disables metrics")
		// YAML config file. Any field set in the file is used iff the matching
		// CLI flag is still at its default — flags always win. Shared verbatim
		// with cmd/engine (internal/config), so an operator's engine.yaml drops
		// straight onto the agent.
		configPath = flag.String("config", "", "path to YAML config file (every field has a CLI-flag equivalent; CLI flags override file values)")
		// Control-plane uplink (Phase 1). EMPTY -controlplane keeps the agent
		// fully standalone — no enrollment, no network, behaviour identical to a
		// pre-Phase-1 agent. When set, the agent enrolls (mTLS) and runs the
		// telemetry/heartbeat/command loops in the background; enforcement never
		// depends on any of them (autonomy).
		controlPlane   = flag.String("controlplane", "", "control-plane endpoint host:port; empty runs the agent standalone (no uplink)")
		bootstrapToken = flag.String("bootstrap-token", "", "one-time enrollment token; needed only for the FIRST enrollment (a persisted -state-dir identity is reused tokenless on restart)")
		caBundlePath   = flag.String("ca-bundle", "", "path to the PEM CA bundle pinned to trust the control plane during enrollment; needed only for the first enrollment")
		cpServerName   = flag.String("controlplane-servername", "", "TLS server name for the control-plane certificate (defaults to the host part of -controlplane)")
		fleetPubKey    = flag.String("fleet-pubkey", "", "path to the fleet command-signing ed25519 public key (hex); required to accept remote commands, otherwise the command channel is disabled")
		cpStateDir     = flag.String("state-dir", "", "directory to persist the enrolled mTLS identity (cert/key/CA) so restarts reuse it instead of consuming a new bootstrap token; enables a durable, reboot-safe agent")
	)
	flag.Parse()

	// File config: load + merge before any flag value gets consumed. Note the
	// pass default here is "" (not the old demo string) so ApplyString's
	// still-default check works and a config-supplied pass is honoured.
	if cfg, err := config.Load(*configPath); err != nil {
		log.Fatalf("config: %v", err)
	} else if cfg != nil {
		config.ApplyString(tetragonAddr, cfg.Tetragon, "unix:///var/run/tetragon/tetragon.sock")
		config.ApplyString(dbPath, cfg.DB, "events.db")
		config.ApplyString(httpAddr, cfg.HTTP, ":8080")
		config.ApplyString(authUser, cfg.User, "admin")
		config.ApplyString(authPass, cfg.Pass, "")
		config.ApplyString(authHash, cfg.PassHash, "")
		config.ApplyString(secretPath, cfg.SecretPath, "")
		config.ApplyString(policiesDir, cfg.PoliciesDir, "policies")
		config.ApplyString(attacksDir, cfg.AttacksDir, "attacks")
		config.ApplyString(honeypotDir, cfg.HoneypotsDir, "/var/lib/ebpf-engine/honey")
		config.ApplyString(chokeDir, cfg.ChokeDir, "policies/choke")
		config.ApplyBool(dryRun, cfg.DryRun, false)
		config.ApplyBool(enforceFlag, cfg.Enforce, false)
		config.ApplyInt(throttleAt, cfg.ThrottleAt, 5)
		config.ApplyInt(tarpitAt, cfg.TarpitAt, 15)
		config.ApplyInt(quarantineAt, cfg.QuarantineAt, 25)
		config.ApplyInt(severAt, cfg.SeverAt, 40)
		config.ApplyString(cgroupRoot, cfg.CgroupRoot, cgroupv2.DefaultRoot)
		config.ApplyString(critBinsRaw, cfg.SystemCritical, "")
		config.ApplyString(bpfObj, cfg.BPFObj, "")
		config.ApplyString(bpfCgroup, cfg.BPFCgroup, "/sys/fs/cgroup")
		config.ApplyString(devchokeObj, cfg.DevchokeObj, "")
		config.ApplyString(devchokeIface, cfg.DevchokeIfaces, "")
		config.ApplyString(devchokeProtect, cfg.DevchokeProtect, "")
		config.ApplyString(storeKind, cfg.Store, "sqlite")
		config.ApplyString(pgDSN, cfg.PgDSN, "")
		config.ApplyString(logFormat, cfg.LogFormat, "text")
		config.ApplyString(logLevel, cfg.LogLevel, "info")
		config.ApplyString(otlpEndpoint, cfg.OTLPEndpoint, "")
		log.Printf("[config] loaded %s", *configPath)
	}

	// Logging: install slog as the default and bridge stdlib log onto it.
	logging.Setup(*logFormat, *logLevel)
	log.Printf("[agent] choke-agent %s starting (sensing+enforcing build target)", agentVersion)

	// SECURITY fail-fast (Phase 0, deliverable #3): resolve the console
	// credential and refuse to start if none was supplied. Historically -pass
	// defaulted to a known demo string; that default is gone, so a missing
	// password must now be a hard startup error rather than a silent,
	// shipped-everywhere credential. auth.go's crypto is untouched — we simply
	// never hand it an empty password.
	credential := *authPass
	if *authHash != "" {
		credential = *authHash // pre-hashed bcrypt: NewAuth detects $2a$/$2b$/$2y$ prefix
	}
	if credential == "" {
		log.Fatalf("auth: no console credential configured — set -pass, -pass-hash, or pass/pass_hash in the config file; the built-in demo default has been removed so a missing password fails fast instead of shipping a known credential")
	}
	// SECURITY: enforce the password policy on plaintext credentials (mirrors
	// the login page). Pre-hashed bcrypt values can't be checked here.
	if !api.IsBcryptHash(credential) {
		if err := api.ValidatePasswordPolicy(credential); err != nil {
			log.Fatalf("auth: %v — set a compliant -pass/pass, or supply a pre-hashed -pass-hash/pass_hash", err)
		}
	}

	// Metrics: OTel meter provider + instruments. Empty endpoint disables the
	// SDK entirely (instruments stay nil; the safe* helpers no-op).
	hostname, _ := os.Hostname()
	mp, err := metrics.Init(context.Background(), *otlpEndpoint, hostname, agentVersion)
	if err != nil {
		log.Fatalf("metrics: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = mp.Shutdown(ctx)
	}()
	if *otlpEndpoint != "" {
		log.Printf("[metrics] otlp endpoint=%s", *otlpEndpoint)
	}

	api.SetPolicyDir(*policiesDir)
	api.SetAttackDir(*attacksDir)
	if err := api.EnsureHoneypots(*honeypotDir); err != nil {
		log.Printf("honeypots: setup failed (%v) — continuing without decoys", err)
	} else {
		log.Printf("honeypots: seeded at %s", *honeypotDir)
	}

	var st *store.Store
	switch *storeKind {
	case "postgres":
		if *pgDSN == "" {
			log.Fatalf("store: -store=postgres requires -pg-dsn (e.g. postgres://engine:engine@127.0.0.1:5432/ebpf?sslmode=disable)")
		}
		var err error
		st, err = store.NewPostgres(*pgDSN)
		if err != nil {
			log.Fatalf("store: postgres: %v", err)
		}
		log.Printf("[store] postgres connected (%s)", redactDSN(*pgDSN))
	case "sqlite", "":
		var err error
		st, err = store.New(*dbPath)
		if err != nil {
			log.Fatalf("store: sqlite: %v", err)
		}
		log.Printf("[store] sqlite at %s (agent-local offline buffer)", *dbPath)
	default:
		log.Fatalf("store: unknown backend %q (want sqlite or postgres)", *storeKind)
	}
	defer st.Close()

	pt := tree.New(10 * time.Minute)
	broadcast := make(chan api.Broadcast, 1024)

	auth, err := api.NewAuth(*authUser, credential, *secretPath)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	// Local debug/health console. This is the agent's field-diagnostics
	// surface (architecture.md §2 "minimal localhost-only debug/health
	// endpoint"); the multi-tenant console lives in the control plane. No
	// fleet fan-out is wired here — that pattern moves to the control plane's
	// command channel in Phase 1.
	httpSrv := api.NewServer(st, pt, broadcast, auth)
	go func() {
		if err := httpSrv.Start(*httpAddr); err != nil {
			log.Fatalf("http: %v", err)
		}
	}()

	// ---- Choke Gateway (process cgroup + BPF map) -------------------------
	var bpfBackend bpfmap.Backend
	if *bpfObj != "" {
		cilium := bpfmap.NewCiliumEBPFBackend(*bpfObj, *bpfCgroup)
		if err := cilium.Open(); err != nil {
			log.Printf("[bpfmap] cilium backend failed (%v) — falling back to noop", err)
			noop := bpfmap.NewNoopBackend()
			if err := noop.Open(); err != nil {
				log.Fatalf("bpfmap open: %v", err)
			}
			bpfBackend = noop
		} else {
			log.Printf("[bpfmap] cilium/ebpf data plane loaded from %s, attached to %s (%d link(s))",
				*bpfObj, *bpfCgroup, cilium.AttachedLinks())
			metrics.SetBPFAttachedLinks(int64(cilium.AttachedLinks()))
			bpfBackend = cilium
		}
	} else {
		noop := bpfmap.NewNoopBackend()
		if err := noop.Open(); err != nil {
			log.Fatalf("bpfmap open: %v", err)
		}
		log.Printf("[bpfmap] noop backend (no -bpf-obj) — userspace mirror only, no kernel enforcement")
		bpfBackend = noop
	}
	defer bpfBackend.Close()

	// BPF map size: periodic gauge reporter, off the event hot path.
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for range t.C {
			snap, err := bpfBackend.Snapshot()
			if err != nil {
				continue
			}
			metrics.SetBPFEntries(int64(len(snap)))
		}
	}()
	throttleBackend := &enforce.Throttler{Backend: bpfBackend}
	severerBackend := &enforce.Severer{}

	// cgroup v2 backend — real per-PID throttle / tarpit / quarantine on Linux.
	// On non-Linux this is a no-op stub so the agent still compiles and runs in
	// dev mode.
	cgBackend := cgroupv2.NewBackend(*cgroupRoot)
	if cgBackend.Available() {
		if err := cgBackend.Mgr.Setup(); err != nil {
			log.Printf("[cgroupv2] setup failed (%v) — graduated enforcement will fall through to telemetry only", err)
		} else {
			log.Printf("[cgroupv2] choke tiers ready under %s", *cgroupRoot)
			// A limit this kernel refused means enforcement is real but
			// weaker than configured. Say so — the alternative is an
			// operator believing a CPU cap is in force when it is not.
			if d := cgBackend.Mgr.Degraded(); len(d) > 0 {
				log.Printf("[cgroupv2] DEGRADED — kernel refused %d limit(s): %s",
					len(d), strings.Join(d, "; "))
			}
		}
	} else {
		log.Printf("[cgroupv2] not available at %s — graduated enforcement disabled (sever still works via SIGKILL)", *cgroupRoot)
	}

	// Always build BOTH enforcer chains and hand them to the gateway so the
	// operator can flip detect-only ⇄ enforcing at runtime via /api/choke/mode.
	// -enforce only picks which one is active at boot.
	realEnforcer := &enforce.Multi{
		Backends: []enforce.Enforcer{cgBackend, severerBackend, throttleBackend},
	}
	loggerEnforcer := &enforce.Logger{Prefix: "[enforce-disabled]"}
	var enforcer enforce.Enforcer = realEnforcer
	if !*enforceFlag {
		enforcer = loggerEnforcer
	}

	// Policy DSL — load all *.yaml under -choke-policies. Missing dir is not an
	// error; you just get no DSL-driven choking. In Phase 1 this local dir
	// becomes the bootstrap/fallback for signed policy bundles pulled from the
	// control plane (architecture.md §2).
	policySet := policy.NewSet()
	if *chokeDir != "" {
		set, warns, err := policy.LoadDir(*chokeDir)
		if err == nil {
			policySet = set
			for _, w := range warns {
				log.Printf("[policy] warn: %v", w)
			}
			log.Printf("[policy] loaded %d choke policies from %s", set.Len(), *chokeDir)
		} else if !os.IsNotExist(err) {
			log.Printf("[policy] load %s: %v (continuing without DSL)", *chokeDir, err)
		}
	}

	// system-critical exemption list — comma-separated CLI override or the
	// package's safe defaults. Score-driven transitions on these binaries are
	// audited but the enforcer is bypassed; manual overrides still go through.
	var critBins []string
	if *critBinsRaw != "" {
		for _, b := range strings.Split(*critBinsRaw, ",") {
			if t := strings.TrimSpace(b); t != "" {
				critBins = append(critBins, t)
			}
		}
	} else {
		critBins = choke.DefaultSystemCriticalBinaries()
	}
	log.Printf("[gateway] system-critical exemption: %d binaries (auto-enforce bypassed; manual override allowed)", len(critBins))

	gw = choke.NewGateway(choke.Config{
		Store:          st,
		Enforcer:       enforcer,
		RealEnforcer:   realEnforcer,
		LoggerEnforcer: loggerEnforcer,
		Broadcast:      httpSrv,
		Tokens:         tokens.NewManager(),
		Policies:       policySet,
		Tree:           pt,
		BPFMap:         bpfBackend,
		Thresholds: circuit.Config{
			ThrottleAt:   *throttleAt,
			TarpitAt:     *tarpitAt,
			QuarantineAt: *quarantineAt,
			SeverAt:      *severAt,
		},
		DryRun:                 *dryRun,
		Enforcing:              *enforceFlag,
		SystemCriticalBinaries: critBins,
	})
	httpSrv.SetGateway(gw)
	// Liveness probe behind Gateway.Owns — the fallback evidence for a target
	// named by PID rather than by an exec_id this host observed. signal 0 does
	// no work but still runs the kernel's permission check, so EPERM means the
	// process exists and belongs to someone else; only ESRCH means "not here".
	gw.SetPIDLiveFn(func(pid uint32) bool {
		if pid == 0 {
			return false
		}
		err := syscall.Kill(int(pid), 0)
		return err == nil || errors.Is(err, syscall.EPERM)
	})

	// ---- Network Choke Gateway (per-device / MAC) -------------------------
	// A parallel data plane: tc clsact programs keyed by MAC on the LAN /
	// bridge-slave interfaces, independent of the process choke above. Loads
	// only when -devchoke-obj + -devchoke-iface are set; otherwise an in-memory
	// noop backend keeps the /api/choke/device-* endpoints alive.
	devIfaces := splitCSV(*devchokeIface)
	var devBackend devbpf.Backend
	if *devchokeObj != "" && len(devIfaces) > 0 {
		tc := devbpf.NewCiliumTCBackend(*devchokeObj, devIfaces)
		if err := tc.Open(); err != nil {
			log.Printf("[devbpf] tc backend failed (%v) — falling back to noop", err)
			noop := devbpf.NewNoopDeviceBackend()
			_ = noop.Open()
			devBackend = noop
		} else {
			log.Printf("[devbpf] tc data plane loaded from %s on [%s] (%d link(s), tier=%s)",
				*devchokeObj, *devchokeIface, tc.AttachedLinks(), tc.DataPlaneTier())
			devBackend = tc
		}
	} else {
		noop := devbpf.NewNoopDeviceBackend()
		_ = noop.Open()
		log.Printf("[devbpf] network device choke inactive (need -devchoke-obj + -devchoke-iface) — noop backend")
		devBackend = noop
	}
	defer devBackend.Close()

	// Protected MAC allow-list: operator-supplied PLUS the configured
	// interfaces' own hardware addresses, so the box can never quarantine/sever
	// its own bridge ports.
	protected := map[devbpf.MAC]bool{}
	for _, m := range splitCSV(*devchokeProtect) {
		if mac, err := devbpf.ParseMAC(m); err == nil {
			protected[mac] = true
		} else {
			log.Printf("[devgateway] -devchoke-protect: skipping bad MAC %q: %v", m, err)
		}
	}
	for _, ifn := range devIfaces {
		if iface, err := net.InterfaceByName(ifn); err == nil && len(iface.HardwareAddr) == 6 {
			if mac, err := devbpf.ParseMAC(iface.HardwareAddr.String()); err == nil {
				protected[mac] = true
			}
		}
	}
	deviceTable := device.NewTable(time.Hour)
	deviceThrottler := enforce.NewDeviceThrottler(devBackend, protected)
	deviceGW := choke.NewDeviceGateway(choke.DeviceConfig{
		Throttler: deviceThrottler,
		Backend:   devBackend,
		Table:     deviceTable,
		Store:     st,
		Broadcast: httpSrv,
		DryRun:    *dryRun,
		// Device choke starts detect-only just like the process gateway.
		Enforcing: false,
	})
	httpSrv.SetDeviceGateway(deviceGW)
	log.Printf("[devgateway] network device choke ready (ifaces=%q protected=%d dry_run=%v)",
		*devchokeIface, len(protected), *dryRun)

	// Wire cgroup pass-throughs so /api/choke/cgroups + /api/choke/thaw reach
	// the manager without dragging the linux-only package into the choke
	// package itself.
	gw.SetCgroupInhabitorsFn(cgBackend.Mgr.Inhabitants)
	gw.SetThawFn(cgBackend.Mgr.Thaw)
	// Process picker: read /proc on every request and adapt the slice shape
	// into the gateway's choke.SysProcEntry to keep the choke package free of
	// OS-specific imports.
	gw.SetSysProcListFn(func() ([]choke.SysProcEntry, error) {
		raw, err := sysproc.List()
		if err != nil {
			return nil, err
		}
		out := make([]choke.SysProcEntry, 0, len(raw))
		for _, e := range raw {
			out = append(out, choke.SysProcEntry{
				PID: e.PID, PPID: e.PPID, UID: e.UID,
				Comm: e.Comm, Exe: e.Exe, Cmdline: e.Cmdline,
				StartTime: e.StartTime,
			})
		}
		return out, nil
	})
	// Origin tracker — attributes processes to the remote client that
	// triggered them (e.g. an SSH session's source IP + key fingerprint). The
	// journald tailer is the source of SSH attribution on Linux; on other
	// platforms the tracker stays empty and decisions simply carry no origin
	// fields. 30-minute TTL covers typical SSH session lifetimes.
	originTracker := origin.NewTracker(30 * time.Minute)
	httpSrv.SetOriginSnapshotFn(func() map[uint32]map[string]interface{} {
		raw := originTracker.Snapshot()
		out := make(map[uint32]map[string]interface{}, len(raw))
		for pid, o := range raw {
			out[pid] = map[string]interface{}{
				"kind":        string(o.Kind),
				"remote_ip":   o.RemoteIP,
				"remote_port": o.RemotePort,
				"user":        o.User,
				"fingerprint": o.Fingerprint,
				"first_seen":  o.FirstSeen,
			}
		}
		return out
	})
	gw.SetOriginLookupFn(func(pid uint32, execID string) (choke.OriginInfo, bool) {
		// Walk ancestors via the in-memory process tree. The tree holds nodes
		// for ~10 minutes after exit, so short-lived chains still resolve to
		// their per-session sshd parent. /proc would have lost them already.
		ancestors := func(_ uint32) []uint32 {
			if execID == "" {
				return nil
			}
			nodes := pt.Ancestors(execID, 10)
			out := make([]uint32, 0, len(nodes))
			for _, n := range nodes {
				if n.PID != 0 {
					out = append(out, n.PID)
				}
			}
			return out
		}
		o, ok := originTracker.Lookup(pid, ancestors)
		if !ok {
			return choke.OriginInfo{}, false
		}
		return choke.OriginInfo{
			Kind:        string(o.Kind),
			RemoteIP:    o.RemoteIP,
			RemotePort:  o.RemotePort,
			User:        o.User,
			Fingerprint: o.Fingerprint,
		}, true
	})
	gw.SetSysProcDetailFn(func(pid uint32) (choke.SysProcDetail, error) {
		d, err := sysproc.ReadDetail(pid)
		if err != nil {
			return choke.SysProcDetail{PID: pid}, err
		}
		return choke.SysProcDetail{
			PID:         d.PID,
			Status:      d.Status,
			Threads:     d.Threads,
			VmRSSKB:     d.VmRSSKB,
			VmSizeKB:    d.VmSizeKB,
			StartedUnix: d.StartedUnix,
			Cwd:         d.Cwd,
			Root:        d.Root,
			NumFDs:      d.NumFDs,
			FDSamples:   d.FDSamples,
			NumConns:    d.NumConns,
			ConnPeers:   d.ConnPeers,
		}, nil
	})
	mode := "ENFORCING"
	if *dryRun {
		mode = "DRY-RUN"
	} else if !*enforceFlag {
		mode = "DETECT-ONLY"
	}
	log.Printf("[gateway] %s; thresholds throttle=%d tarpit=%d quarantine=%d sever=%d",
		mode, *throttleAt, *tarpitAt, *quarantineAt, *severAt)

	// System health snapshot for /api/system-health. Closures so live values
	// (BPF link count, map size, Tetragon stream state) are re-read on every
	// request.
	bpfBackendKind := "noop"
	bpfLinksFn := func() int { return 0 }
	if cilium, ok := bpfBackend.(*bpfmap.CiliumEBPFBackend); ok {
		bpfBackendKind = "cilium-ebpf"
		bpfLinksFn = func() int { return cilium.AttachedLinks() }
	}
	storeTarget := *dbPath
	if *storeKind == "postgres" {
		storeTarget = redactDSN(*pgDSN)
	}
	httpSrv.SetSystemInfo(api.SystemInfo{
		Version:      agentVersion,
		StartedAt:    time.Now().UTC(),
		StoreBackend: *storeKind,
		StoreTarget:  storeTarget,
		BPFBackend:   bpfBackendKind,
		OTLPEndpoint: *otlpEndpoint,
		LogFormat:    *logFormat,
		LogLevel:     *logLevel,
		BPFLinks:     bpfLinksFn,
		BPFEntries: func() int {
			snap, err := bpfBackend.Snapshot()
			if err != nil {
				return -1
			}
			return len(snap)
		},
		TetragonConnected: func() bool { return tetragonConnected.Load() },
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the sshd journald tailer (Linux only; soft-degrades on macOS dev
	// builds and on hosts without journalctl in PATH).
	if err := origin.NewSSHDTailer(originTracker).Start(ctx); err != nil {
		log.Printf("[origin/sshd] start failed: %v (continuing without SSH attribution)", err)
	}
	// Origin tracker sweeper — evicts entries older than the TTL once a minute.
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				originTracker.Sweep()
			}
		}
	}()

	// Device discovery: passively sniff DHCP on the bridge for
	// MAC<->IP<->hostname, and on a ticker drain the data plane's seen map and
	// poll the neigh table. All feed the one DeviceTable the device gateway
	// reads from.
	device.StartDHCPSniffer(ctx, devIfaces, deviceTable.Record)
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if seen, err := devBackend.SeenSnapshot(); err == nil {
					for mac, sv := range seen {
						deviceTable.Record(device.Device{
							MAC:     mac.String(),
							LastIP:  device.IPv4BEToString(sv.LastSrcIPv4),
							Packets: sv.Packets,
							Source:  device.SourcePassive,
						})
					}
				}
				if neigh, err := device.PollNeigh(); err == nil {
					for _, d := range neigh {
						deviceTable.Record(d)
					}
				}
				deviceTable.Sweep()
			}
		}
	}()

	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigC; log.Println("shutting down"); cancel() }()

	// ---- Control-plane uplink (Phase 1, opt-in) ---------------------------
	// Strictly additive: enforcement above is already fully wired and running.
	// When -controlplane is set the agent enrolls (mTLS) and runs the telemetry
	// drain, heartbeat, and command loops in the background. A down/slow control
	// plane only means telemetry buffers locally and no new commands arrive —
	// the kernel keeps enforcing the last-applied policy (the autonomy moat).
	if *controlPlane != "" {
		// First enrollment needs a one-time token + the pinned CA. A restart
		// with a persisted identity in -state-dir needs neither (it's reused).
		if *cpStateDir == "" && (*bootstrapToken == "" || *caBundlePath == "") {
			log.Fatalf("controlplane: -controlplane requires -state-dir (persisted identity) or -bootstrap-token + -ca-bundle (first enrollment)")
		}
		var caPEM []byte
		if *caBundlePath != "" {
			b, err := os.ReadFile(*caBundlePath)
			if err != nil {
				log.Fatalf("controlplane: read -ca-bundle: %v", err)
			}
			caPEM = b
		}
		upBuf = uplink.NewBuffer()

		// The command channel activates only with a fleet signing key. Commands
		// are applied through the choke gateway with the SAME local
		// system-critical guardrails as score-driven enforcement (critBins), so
		// a remote command can never strip sudo/sshd protection.
		var proc *command.Processor
		if *fleetPubKey != "" {
			raw, err := os.ReadFile(*fleetPubKey)
			if err != nil {
				log.Fatalf("controlplane: read -fleet-pubkey: %v", err)
			}
			pub, err := hex.DecodeString(strings.TrimSpace(string(raw)))
			if err != nil {
				log.Fatalf("controlplane: decode -fleet-pubkey: %v", err)
			}
			verifier, err := signing.VerifierFromPublicKey(pub)
			if err != nil {
				log.Fatalf("controlplane: -fleet-pubkey: %v", err)
			}
			proc = command.NewProcessor(verifier, gatewayApplier{gw: gw, devGW: deviceGW}, critBins)
			log.Printf("[controlplane] command channel enabled (%d protected binaries guardrail)", len(critBins))
		} else {
			log.Printf("[controlplane] command channel DISABLED (no -fleet-pubkey); telemetry + heartbeat only")
		}

		serverName := *cpServerName
		if serverName == "" {
			serverName = hostOnly(*controlPlane)
		}
		agentInfo := func() *ebpfsocv1.AgentInfo {
			return &ebpfsocv1.AgentInfo{Hostname: hostname, AgentVersion: agentVersion, Arch: runtime.GOARCH}
		}
		cfg := cpclient.Config{
			Endpoint:       *controlPlane,
			ServerName:     serverName,
			BootstrapToken: *bootstrapToken,
			CABundlePEM:    caPEM,
			StateDir:       *cpStateDir,
			AgentInfo:      agentInfo(),
			Buffer:         upBuf,
			Processor:      proc,
			Heartbeat: func() *ebpfsocv1.HeartbeatRequest {
				// The uplink buffer sheds its oldest records once the backlog
				// cap is reached (uplink.DefaultMaxRecords). That keeps the
				// agent alive, but it means this host's telemetry has a HOLE,
				// and an operator must be able to find out. Reported every beat
				// while non-zero, not once: a gap that stopped being mentioned
				// reads as a gap that stopped happening.
				if n := upBuf.Dropped(); n > 0 {
					log.Printf("[uplink] TELEMETRY GAP: %d record(s) dropped since start "+
						"(backlog cap %d reached; control plane not acking)", n, uplink.DefaultMaxRecords)
				}
				// Read the kernel's policy set ONCE per heartbeat: the version
				// must fingerprint exactly the set being reported, and a second
				// call could observe a reload in between and disagree with it.
				kpols := kernelPolicies(ctx)
				return &ebpfsocv1.HeartbeatRequest{
					AgentInfo:            agentInfo(),
					AppliedPolicyVersion: policyVersion(kpols),
					DataPlane: &ebpfsocv1.DataPlaneState{
						Mode: gatewayMode(gw),
						// Report the device plane truthfully: the control plane
						// used to assume "active" for any registered agent, which
						// showed a fleet as enforcing on the network plane while
						// every agent was running the noop backend.
						DevicePlane: deviceGW.DataPlaneTier(),
						DeviceLinks: int32(deviceGW.AttachedLinks()),
						// Real frame count, not a placeholder — see frames_seen
						// in common.proto for why the console needs it.
						FramesSeen:  deviceGW.FramesSeen(),
						DevicesSeen: uint32(deviceGW.DevicesSeen()),
						DeviceMode:  deviceGatewayMode(deviceGW),
						// The other enforcement authority on this host. Without
						// it the console reports the engine's mode as if it were
						// the host's posture — see kernelPolicies.
						KernelPolicies: kpols,
					},
					BufferDepth: uint64(upBuf.PendingDepth()),
					Chokes:      chokeSummaries(gw),
					Devices:     deviceSummaries(deviceGW),
					// Drill detail for the console's Choke Gateway page. Without
					// these the multi-tenant console renders those panels empty
					// on every tenant, permanently.
					Buckets:   bucketSummaries(gw),
					Cgroups:   cgroupSummaries(gw),
					Processes: processSummaries(gw),
				}
			},

			Logf: log.Printf,
		}
		go func() {
			if err := cpclient.Run(ctx, cfg); err != nil && ctx.Err() == nil {
				log.Printf("[controlplane] client stopped: %v", err)
			}
		}()
		log.Printf("[controlplane] uplink enabled → %s (tenant bound at enrollment)", *controlPlane)
	}

	// Tetragon subscription — the agent's sole event source. Unlike cmd/engine
	// there is no fake mode here: the agent is a production sensor that runs
	// next to Tetragon. Dev/UI iteration without a kernel uses cmd/engine -fake.
	conn, err := grpc.Dial(*tetragonAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial tetragon: %v", err)
	}
	defer conn.Close()

	client := tetragon.NewFineGuidanceSensorsClient(conn)
	// Publish it for the heartbeat, which asks the daemon what TracingPolicies
	// the kernel really has so the console can show host posture rather than
	// just the engine's half of it.
	setSensors(client)

	stream, err := client.GetEvents(ctx, &tetragon.GetEventsRequest{})
	if err != nil {
		log.Fatalf("get events: %v", err)
	}

	log.Println("subscribed to Tetragon event stream")
	metrics.SetTetragonConnected(true)
	tetragonConnected.Store(true)
	defer func() {
		metrics.SetTetragonConnected(false)
		tetragonConnected.Store(false)
	}()

	for {
		resp, err := stream.Recv()
		if err != nil {
			log.Printf("stream closed: %v", err)
			return
		}
		handleEvent(resp, st, pt, broadcast)
	}
}

// ---------------------------------------------------------------------------
// Event handlers — the sensing path.
//
// Duplicated verbatim (in behaviour) from cmd/engine. See the STRANGLER NOTE
// at the top of this file: sharing this glue means extracting it into a common
// package, which is the Phase 1 "hollow out cmd/engine" step. Keeping it here
// now lets the live cmd/engine path stay frozen while the agent build target
// links against the same scoring/tree/store/gateway core.
// ---------------------------------------------------------------------------

func handleEvent(resp *tetragon.GetEventsResponse, st *store.Store, pt *tree.Tree, broadcast chan<- api.Broadcast) {
	switch ev := resp.Event.(type) {
	case *tetragon.GetEventsResponse_ProcessExec:
		handleExec(ev.ProcessExec, st, pt, broadcast)
	case *tetragon.GetEventsResponse_ProcessKprobe:
		handleKprobe(ev.ProcessKprobe, st, pt, broadcast)
	case *tetragon.GetEventsResponse_ProcessExit:
		handleExit(ev.ProcessExit, broadcast)
	}
}

// handleExit forwards a slim process_exit notification onto the SSE stream so
// the local console can drop the node when it dies. No event-store insert —
// the ring buffer is deliberately tied to telemetry, not lifecycle.
func handleExit(ev *tetragon.ProcessExit, broadcast chan<- api.Broadcast) {
	if ev == nil || ev.Process == nil {
		return
	}
	p := ev.Process
	send(broadcast, api.Broadcast{Type: "process_exit", Payload: map[string]interface{}{
		"exec_id": p.ExecId,
		"pid":     p.Pid.GetValue(),
		"binary":  p.Binary,
	}})
}

func handleExec(ev *tetragon.ProcessExec, st *store.Store, pt *tree.Tree, broadcast chan<- api.Broadcast) {
	if ev == nil || ev.Process == nil {
		return
	}
	p := ev.Process
	parentID := ""
	if ev.Parent != nil {
		parentID = ev.Parent.ExecId
	}
	node := &tree.Node{
		ExecID:    p.ExecId,
		PID:       p.Pid.GetValue(),
		ParentID:  parentID,
		Binary:    p.Binary,
		Args:      p.Arguments,
		UID:       p.Uid.GetValue(),
		StartTime: time.Now(),
	}
	pt.Add(node)

	delta, reason, finding := score.Score("process_exec", p.Binary, p.Arguments, "", p.Uid.GetValue())
	if delta > 0 {
		pt.AddScore(p.ExecId, delta, "process_exec")
	}

	parentPID := uint32(0)
	if ev.Parent != nil {
		parentPID = ev.Parent.Pid.GetValue()
	}

	e := &store.Event{
		Timestamp: time.Now(),
		EventType: "process_exec",
		PID:       p.Pid.GetValue(),
		ParentPID: parentPID,
		ExecID:    p.ExecId,
		Binary:    p.Binary,
		Args:      p.Arguments,
		UID:       p.Uid.GetValue(),
	}
	id, err := st.InsertEvent(e)
	if err != nil {
		log.Printf("insert event: %v", err)
		return
	}
	e.ID = id

	enqueueUplink(uplink.EventRecord(e))
	metrics.IncEvent("process_exec")
	send(broadcast, api.Broadcast{Type: "event", Payload: e})
	checkAlert(p.ExecId, st, pt, broadcast, reason, finding)
}

func handleKprobe(ev *tetragon.ProcessKprobe, st *store.Store, pt *tree.Tree, broadcast chan<- api.Broadcast) {
	if ev == nil || ev.Process == nil {
		return
	}
	p := ev.Process
	policyName := ev.PolicyName

	argStr := extractKprobeArgs(ev.Args)

	delta, reason, finding := score.Score("process_kprobe", p.Binary, argStr, policyName, p.Uid.GetValue())
	if delta > 0 {
		pt.AddScore(p.ExecId, delta, "process_kprobe:"+policyName)
	}

	e := &store.Event{
		Timestamp:  time.Now(),
		EventType:  "process_kprobe",
		PID:        p.Pid.GetValue(),
		ExecID:     p.ExecId,
		Binary:     p.Binary,
		Args:       argStr,
		UID:        p.Uid.GetValue(),
		PolicyName: policyName,
	}
	id, err := st.InsertEvent(e)
	if err != nil {
		log.Printf("insert event: %v", err)
		return
	}
	e.ID = id

	enqueueUplink(uplink.EventRecord(e))
	metrics.IncEvent("process_kprobe")
	send(broadcast, api.Broadcast{Type: "event", Payload: e})
	checkAlert(p.ExecId, st, pt, broadcast, reason, finding)
}

func extractKprobeArgs(args []*tetragon.KprobeArgument) string {
	parts := make([]string, 0, len(args))
	for _, a := range args {
		if a == nil {
			continue
		}
		if f := a.GetFileArg(); f != nil && f.Path != "" {
			parts = append(parts, f.Path)
			continue
		}
		if p := a.GetPathArg(); p != nil && p.Path != "" {
			parts = append(parts, p.Path)
			continue
		}
		if s := a.GetStringArg(); s != "" {
			parts = append(parts, s)
			continue
		}
		// Network arguments (tcp_connect's `sock`, or a `sockaddr`). Without
		// this the destination IP is dropped: an outbound-connections event
		// carries only its policy name, no peer, so the correlation graph can
		// never draw an IP node for it. Rendering the remote endpoint as
		// "daddr:dport" puts it into Args, where the console's IOC/peer
		// extraction picks it up.
		if s := a.GetSockArg(); s != nil && s.GetDaddr() != "" {
			parts = append(parts, joinHostPort(s.GetDaddr(), s.GetDport()))
			continue
		}
		if sa := a.GetSockaddrArg(); sa != nil && sa.GetAddr() != "" {
			parts = append(parts, joinHostPort(sa.GetAddr(), sa.GetPort()))
			continue
		}
		if v := a.GetIntArg(); v != 0 {
			parts = append(parts, fmt.Sprintf("%d", v))
			continue
		}
	}
	return strings.Join(parts, " ")
}

// joinHostPort renders a remote endpoint as ip:port, or just the ip when the
// port is unknown. Kept simple (no net.JoinHostPort) so an IPv6 daddr is left
// as-is rather than bracketed — the console's IP regex matches the bare form.
func joinHostPort(addr string, port uint32) string {
	if port == 0 {
		return addr
	}
	return fmt.Sprintf("%s:%d", addr, port)
}

func checkAlert(execID string, st *store.Store, pt *tree.Tree, broadcast chan<- api.Broadcast, reason, finding string) {
	chainScore := pt.ChainScore(execID)

	// Gateway runs on every event regardless of alert threshold so a process
	// can transition to "throttled" before it ever produces an alert. The
	// gateway is monotonic — repeated calls below threshold are no-ops.
	dispatchGateway(execID, pt, chainScore, reason)

	if chainScore < 10 {
		return
	}
	// Alert on an escalation in severity, or on a finding this chain has not
	// reported before — not on every event. Chain scores are cumulative and
	// never fall, so alerting per-event made 91 of 100 alerts critical on the
	// engine. The agent carries its own copy of this path, so without the same
	// guard every multi-tenant console would still saturate. Enforcement is
	// untouched: dispatchGateway above runs on every event regardless.
	if !pt.EscalateAlert(execID, score.Band(chainScore), finding) {
		return
	}
	severity := score.Severity(chainScore)
	chain := pt.Ancestors(execID, 8)
	binaries := make([]string, 0, len(chain))
	for _, n := range chain {
		binaries = append(binaries, n.Binary)
	}
	title := fmt.Sprintf("Suspicious chain: %s (score %d)", strings.Join(binaries, " → "), chainScore)
	a := &store.Alert{
		Timestamp:   time.Now(),
		Severity:    severity,
		Title:       title,
		Description: reason,
		ExecID:      execID,
		Score:       chainScore,
	}
	id, err := st.InsertAlert(a)
	if err != nil {
		log.Printf("insert alert: %v", err)
		return
	}
	a.ID = id
	enqueueUplink(uplink.AlertRecord(a))
	metrics.IncAlert(severity)
	send(broadcast, api.Broadcast{Type: "alert", Payload: a})
	log.Printf("[ALERT %s] %s", severity, title)
}

// dispatchGateway calls the choke gateway with the latest chain score for an
// exec_id. Looks up the node in the process tree to get the canonical
// PID/binary so the enforcer has a real target. nil-safe.
func dispatchGateway(execID string, pt *tree.Tree, chainScore int, reason string) {
	if gw == nil {
		return
	}
	n, ok := pt.Get(execID)
	if !ok {
		return
	}
	gw.OnEvent(context.Background(), choke.Observation{
		ExecID: execID,
		PID:    n.PID,
		Binary: n.Binary,
		Score:  chainScore,
		Reason: reason,
	})
}

func send(ch chan<- api.Broadcast, b api.Broadcast) {
	select {
	case ch <- b:
	default:
		// drop on overflow rather than block the event loop
	}
}

// splitCSV splits a comma-separated flag value into trimmed, non-empty fields.
// Used for -devchoke-iface and -devchoke-protect.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// redactDSN strips the password from a Postgres DSN before logging it, so
// journald doesn't permanently capture credentials.
func redactDSN(dsn string) string {
	at := strings.LastIndex(dsn, "@")
	if at < 0 {
		return dsn
	}
	scheme := strings.Index(dsn, "://")
	if scheme < 0 || scheme >= at {
		return dsn
	}
	colon := strings.Index(dsn[scheme+3:at], ":")
	if colon < 0 {
		return dsn
	}
	return dsn[:scheme+3+colon+1] + "***" + dsn[at:]
}

// hostOnly returns the host part of a host:port endpoint, used as the default
// TLS server name for control-plane cert verification.
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// gatewayMode maps the choke gateway's runtime mode onto the wire enum for
// heartbeat reporting.
// deviceGatewayMode maps the device gateway's mode string onto the wire enum.
// The device gateway reports "kill-switched" as a mode of its own; on the wire
// that is still detect-only (nothing is being applied), and the kill-switch is
// reported separately.
func deviceGatewayMode(g *choke.DeviceGateway) ebpfsocv1.EnforcementMode {
	if g == nil {
		return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED
	}
	switch g.Mode() {
	case "enforcing":
		return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING
	case "dry-run":
		return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DRY_RUN
	default:
		return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DETECT_ONLY
	}
}

func gatewayMode(g *choke.Gateway) ebpfsocv1.EnforcementMode {
	switch g.Mode() {
	case choke.ModeEnforcing:
		return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING
	case choke.ModeDryRun:
		return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DRY_RUN
	case choke.ModeDetectOnly:
		return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DETECT_ONLY
	default:
		return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED
	}
}

// chokeSummaries builds the compact, capped choke snapshot the agent puts on
// each heartbeat so the central console can render a per-tenant Choke view.
// Highest-score first (the processes an operator cares about); the rich
// interactive surface stays agent-local.
func chokeSummaries(g *choke.Gateway) []*ebpfsocv1.ChokeSummary {
	if g == nil {
		return nil
	}
	snap := g.Snapshot()
	sort.Slice(snap, func(i, j int) bool { return snap[i].Score > snap[j].Score })
	if len(snap) > 100 {
		snap = snap[:100]
	}
	out := make([]*ebpfsocv1.ChokeSummary, 0, len(snap))
	for _, e := range snap {
		out = append(out, &ebpfsocv1.ChokeSummary{
			ExecId: e.ExecID, Pid: e.PID, Binary: e.Binary, State: e.State, Score: int32(e.Score),
		})
	}
	return out
}

// Caps for the drill detail reported on each heartbeat. These panels are a
// fleet SCAN surface — the agent-local API remains authoritative — so they are
// bounded rather than complete. Uncapped, a busy host would ship its entire
// process table to the control plane every 30 seconds, for every agent.
const (
	maxReportedBuckets   = 200
	maxReportedProcesses = 200
)

// bucketSummaries reports the kernel token buckets the choke gateway installed.
//
// This is the evidence that a throttle actually reached the kernel rather than
// only being written as a decision row. Without it the control plane's "Choke
// Map (kernel)" panel is empty on every tenant while the single-host console
// shows hundreds of live buckets.
func bucketSummaries(g *choke.Gateway) []*ebpfsocv1.BucketSummary {
	if g == nil {
		return nil
	}
	snap, err := g.BucketsSnapshot()
	if err != nil || len(snap) == 0 {
		return nil
	}
	out := make([]*ebpfsocv1.BucketSummary, 0, len(snap))
	for pid, b := range snap {
		out = append(out, &ebpfsocv1.BucketSummary{
			Pid: pid, RatePerSec: uint64(b.RatePerSec), Burst: uint64(b.Burst),
			Tokens: uint64(b.Tokens), Flags: b.Flags,
		})
	}
	// Deterministic order before truncating, so the reported subset is stable
	// between heartbeats instead of flickering with Go's map iteration.
	sort.Slice(out, func(i, j int) bool { return out[i].GetPid() < out[j].GetPid() })
	if len(out) > maxReportedBuckets {
		out = out[:maxReportedBuckets]
	}
	return out
}

// cgroupSummaries reports which PIDs the kernel says are inside each choke
// cgroup — what is ACTUALLY confined, as opposed to what a decision row claims.
func cgroupSummaries(g *choke.Gateway) []*ebpfsocv1.CgroupSummary {
	if g == nil {
		return nil
	}
	m, err := g.CgroupInhabitants()
	if err != nil || len(m) == 0 {
		return nil
	}
	tiers := make([]string, 0, len(m))
	for tier := range m {
		tiers = append(tiers, tier)
	}
	sort.Strings(tiers)
	out := make([]*ebpfsocv1.CgroupSummary, 0, len(tiers))
	for _, tier := range tiers {
		out = append(out, &ebpfsocv1.CgroupSummary{Tier: tier, Pids: m[tier]})
	}
	return out
}

// processSummaries reports the live host process table joined with choke state,
// which is what the console's process picker offers an operator. On the control
// plane that picker had nothing to pick from.
func processSummaries(g *choke.Gateway) []*ebpfsocv1.ProcessSummary {
	if g == nil {
		return nil
	}
	procs, err := g.HostProcesses()
	if err != nil || len(procs) == 0 {
		return nil
	}
	// Tracked processes first, then by score: an operator scanning a fleet cares
	// about what the gateway is already acting on, and truncation must not drop
	// exactly those rows.
	sort.Slice(procs, func(i, j int) bool {
		if procs[i].Tracked != procs[j].Tracked {
			return procs[i].Tracked
		}
		if procs[i].Score != procs[j].Score {
			return procs[i].Score > procs[j].Score
		}
		return procs[i].PID < procs[j].PID
	})
	if len(procs) > maxReportedProcesses {
		procs = procs[:maxReportedProcesses]
	}
	out := make([]*ebpfsocv1.ProcessSummary, 0, len(procs))
	for _, p := range procs {
		out = append(out, &ebpfsocv1.ProcessSummary{
			Pid: p.PID, Ppid: p.PPID, Uid: p.UID, Comm: p.Comm, Exe: p.Exe,
			Cmdline: p.Cmdline, Tracked: p.Tracked, State: p.State,
			Score: int32(p.Score), ExecId: p.ExecID,
		})
	}
	return out
}

// deviceSummaries builds the compact device snapshot for the heartbeat (empty
// when the device data plane is inactive, as on a host with no -devchoke-iface).
func deviceSummaries(g *choke.DeviceGateway) []*ebpfsocv1.DeviceSummary {
	if g == nil {
		return nil
	}
	snap := g.Snapshot()
	if len(snap) > 100 {
		snap = snap[:100]
	}
	out := make([]*ebpfsocv1.DeviceSummary, 0, len(snap))
	for _, d := range snap {
		label := d.Hostname
		if label == "" {
			label = d.Vendor
		}
		out = append(out, &ebpfsocv1.DeviceSummary{
			Mac: d.MAC, State: d.State, Label: label,
			LastIp: d.LastIP, Protected: d.Protected,
		})
	}
	return out
}

// gatewayApplier adapts control-plane commands onto the local choke gateway.
// It implements command.Applier. The command.Processor has already verified the
// signature and applied the always-protected guardrail before any method here
// runs, so these are the raw effectors. Actions without a clean, safe gateway
// mapping in Phase 1 return an error, which the processor reports as REJECTED
// (honest — never a silent no-op).
// devGW is the network-plane counterpart of gw. It may be nil on an agent
// built without device choke, in which case device-targeted commands are
// REJECTED with a reason rather than silently applied to the wrong plane.
type gatewayApplier struct {
	gw    *choke.Gateway
	devGW *choke.DeviceGateway
}

// SetMode arms or disarms one plane. PLANE_DEVICE targets the network gateway;
// anything else (including UNSPECIFIED, which is what an older control plane
// sends) targets the process gateway, preserving the previous meaning.
func (a gatewayApplier) SetMode(m ebpfsocv1.EnforcementMode, plane ebpfsocv1.Plane) error {
	enforcing := m == ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING
	if plane == ebpfsocv1.Plane_PLANE_DEVICE {
		if a.devGW == nil {
			return fmt.Errorf("set-mode: device plane requested but no device gateway on this agent")
		}
		a.devGW.SetEnforcing(enforcing, "control-plane", "remote SetMode command")
		return nil
	}
	a.gw.SetEnforcing(enforcing, "control-plane", "remote SetMode command")
	return nil
}

func (a gatewayApplier) KillSwitch(halt bool, _ string, plane ebpfsocv1.Plane) error {
	if plane == ebpfsocv1.Plane_PLANE_DEVICE {
		if a.devGW == nil {
			return fmt.Errorf("kill-switch: device plane requested but no device gateway on this agent")
		}
		a.devGW.SetKillSwitch(halt)
		return nil
	}
	a.gw.SetKillSwitch(halt)
	return nil
}

func (a gatewayApplier) SetThresholds(throttleAt, tarpitAt, quarantineAt, severAt int32) error {
	a.gw.SetThresholds(circuit.Config{
		ThrottleAt:   int(throttleAt),
		TarpitAt:     int(tarpitAt),
		QuarantineAt: int(quarantineAt),
		SeverAt:      int(severAt),
	})
	return nil
}

// OwnsTarget implements command.TargetOwner: it answers whether a Jail/Thaw
// target belongs to THIS host, so the command processor can no-op with a
// STATUS_NOT_TARGET ack instead of enforcing on someone else's process.
//
// The control plane dispatches one containment command to several agents when
// it cannot yet tell which one holds the target. Before this gate, every agent
// applied: on the process plane that means the severer SIGKILLs whatever local
// process happens to hold that PID number (PIDs are per-host and collide across
// a fleet) and then acks APPLIED — so the console reported a threat contained
// while the real process kept running on another host, and an unrelated process
// died on this one. Both halves of that are what this gate removes.
func (a gatewayApplier) OwnsTarget(execID string, pid uint32) ebpfsocv1.CommandAck_TargetMatch {
	if mac, isDevice := strings.CutPrefix(execID, devicePrefix); isDevice {
		// MACs are globally unique, so seeing the device is proof; an agent
		// without a device gateway can never own one.
		if a.devGW != nil && a.devGW.Owns(mac) {
			return ebpfsocv1.CommandAck_TARGET_MATCH_DEVICE
		}
		return ebpfsocv1.CommandAck_TARGET_MATCH_NONE
	}
	switch a.gw.Owns(execID, pid) {
	case choke.MatchExecID:
		return ebpfsocv1.CommandAck_TARGET_MATCH_EXEC_ID
	case choke.MatchPID:
		return ebpfsocv1.CommandAck_TARGET_MATCH_PID
	default:
		return ebpfsocv1.CommandAck_TARGET_MATCH_NONE
	}
}

// devicePrefix marks a command whose target is a LAN device (keyed by MAC)
// rather than a process (keyed by exec_id). The control plane encodes device
// targets as "device:<mac>" because Jail/Thaw carry a single target field for
// both planes; this is the matching decode.
const devicePrefix = "device:"

// tierToAction maps the wire tier name onto a circuit action.
func tierToAction(tier string) (circuit.Action, error) {
	switch tier {
	case "throttle":
		return circuit.ActThrottle, nil
	case "tarpit":
		return circuit.ActTarpit, nil
	case "quarantine":
		return circuit.ActQuarantine, nil
	case "sever":
		return circuit.ActSever, nil
	default:
		return circuit.ActNone, fmt.Errorf("jail: unknown tier %q", tier)
	}
}

// Jail applies a remote enforcement tier to one target. It routes through the
// gateway's Manual path — the same one the agent's local HTTP API uses — so a
// console-dispatched choke behaves exactly like a local operator override,
// including bypassing detect-only mode (a manual override is a deliberate
// decision, not an automatic one) and writing the audit row.
//
// A "device:<mac>" target goes to the DEVICE gateway (network plane). Without
// this branch the MAC would be treated as an exec_id and choked on the PROCESS
// gateway, which silently does nothing to the device and leaves a phantom pid=0
// circuit behind.
func (a gatewayApplier) Jail(execID string, pid uint32, tier string) error {
	action, err := tierToAction(tier)
	if err != nil {
		return err
	}
	if mac, isDevice := strings.CutPrefix(execID, devicePrefix); isDevice {
		if a.devGW == nil {
			return fmt.Errorf("jail: device target %q but no device gateway on this agent", mac)
		}
		_, err := a.devGW.ManualDevice(context.Background(), mac, action,
			"remote jail ("+tier+")", "control-plane")
		return err
	}
	_, err = a.gw.Manual(context.Background(), choke.ManualRequest{
		ExecID: execID, PID: pid, Action: action,
		Reason: "remote jail (" + tier + ")", Actor: "control-plane",
	})
	return err
}

// Thaw releases one target back to pristine — ActNone through the same Manual
// path, matching the per-process release the local API performs. Mirrors Jail's
// device-vs-process routing.
func (a gatewayApplier) Thaw(execID string, pid uint32) error {
	if mac, isDevice := strings.CutPrefix(execID, devicePrefix); isDevice {
		if a.devGW == nil {
			return fmt.Errorf("thaw: device target %q but no device gateway on this agent", mac)
		}
		_, err := a.devGW.ThawDevice(context.Background(), mac, "control-plane", "remote thaw")
		return err
	}
	_, err := a.gw.Manual(context.Background(), choke.ManualRequest{
		ExecID: execID, PID: pid, Action: circuit.ActNone,
		Reason: "remote thaw", Actor: "control-plane",
	})
	return err
}

func (a gatewayApplier) ApplyPreset(name string) error {
	return fmt.Errorf("preset %q: not yet supported via the command channel (Phase 1)", name)
}

func (a gatewayApplier) SetProtectedList([]string, []string) error {
	return fmt.Errorf("protected-list updates: not yet supported via the command channel (Phase 1)")
}
