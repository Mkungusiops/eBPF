// Package hoststack stands up the per-host sensing + enforcing stack that both
// build targets — cmd/engine and cmd/agent — run.
//
// It exists because that wiring was copied rather than shared. The STRANGLER
// NOTE in cmd/agent/main.go called the copy "the accepted, temporary cost…
// until Phase 1"; Phase 1 shipped and the copies drifted. That is not a
// stylistic complaint. A fix landed on deviceGatewayMode and was missed on its
// twin gatewayMode, so a kill-switched host reported
// ENFORCEMENT_MODE_UNSPECIFIED and the console showed no enforcement mode at
// all. Two copies of "attach the BPF program, then set up the cgroup tiers,
// then build the gateway, then wire its seven ports" are two chances to get
// enforcement wrong on one of them, and only one of the two gets tested by hand.
//
// The startup ORDER in New is load-bearing and deliberately frozen: the BPF map
// backend has to exist before the throttler that writes into it, the cgroup
// tiers before the enforcer chain that places PIDs in them, both gateways
// before the HTTP handlers that can be hit the instant the listener is up, and
// the SetX ports before /api/system-health can report a half-wired host as
// healthy. Reordering these is a behaviour change even when everything still
// compiles.
//
// Startup failures call log.Fatalf here rather than returning an error. That is
// deliberate: these are unrecoverable failures of a process with nothing to
// fall back on, and the message text is what operators grep for in journald.
// Converting them to error returns would change both the text and which
// deferred cleanups run on the way out.
package hoststack

import (
	"context"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

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
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/sysproc"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
)

// Stack is the wired, running host stack. Its exported fields are the handles a
// main() still needs after New returns: the two enforcement gateways, and the
// exemption list a remote command channel must be held to.
type Stack struct {
	// Gateway is the process plane (cgroup tiers + per-PID BPF rate buckets).
	Gateway *choke.Gateway
	// DeviceGateway is the network plane (tc clsact programs keyed by MAC).
	// Independent of Gateway: a device sever is a reversible drop rule, a
	// process sever is a SIGKILL.
	DeviceGateway *choke.DeviceGateway
	// SystemCriticalBinaries is the resolved exemption list. cmd/agent hands
	// the same slice to the command processor so a remote command can never
	// strip sshd/sudo protection that local scoring respects.
	SystemCriticalBinaries []string

	bpfBackend    bpfmap.Backend
	devBackend    devbpf.Backend
	deviceTable   *device.Table
	devIfaces     []string
	originTracker *origin.Tracker

	// tetragonConnected mirrors the OTel gauge so the /api/system-health
	// handler can read live stream state without reaching into the metrics
	// pipeline. It was a package-level global in both mains.
	tetragonConnected atomic.Bool
}

// New wires the whole stack and publishes it on srv. Callers must already have
// the store, the process tree, and the HTTP server, because the gateways
// broadcast through the server and record through the store.
//
// The returned Stack owns both data-plane backends; defer Close on it.
func New(s Settings, st *store.Store, pt *tree.Tree, srv *api.Server) *Stack {
	stack := &Stack{}

	// ---- Choke Gateway (process cgroup + BPF map) -------------------------
	// Backends: the throttler writes per-PID rate buckets into the BPF map (via
	// the cilium/ebpf loader when an object file is configured, otherwise the
	// in-memory noop backend); the severer sends SIGKILL on ActSever. Composed
	// via Multi.
	var bpfBackend bpfmap.Backend
	if s.BPFObj != "" {
		cilium := bpfmap.NewCiliumEBPFBackend(s.BPFObj, s.BPFCgroup)
		if err := cilium.Open(); err != nil {
			log.Printf("[bpfmap] cilium backend failed (%v) — falling back to noop", err)
			noop := bpfmap.NewNoopBackend()
			if err := noop.Open(); err != nil {
				log.Fatalf("bpfmap open: %v", err)
			}
			bpfBackend = noop
		} else {
			log.Printf("[bpfmap] cilium/ebpf data plane loaded from %s, attached to %s (%d link(s))",
				s.BPFObj, s.BPFCgroup, cilium.AttachedLinks())
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
	stack.bpfBackend = bpfBackend

	// BPF map size: periodic gauge reporter. Snapshot iterates the hash map;
	// 10s is generous for an SRE-grade gauge and keeps the cost off the event
	// hot path.
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
	// On non-Linux this is a no-op stub (Apply returns ErrUnsupported) so the
	// binary still compiles and runs in dev mode.
	cgBackend := cgroupv2.NewBackend(s.CgroupRoot)
	if cgBackend.Available() {
		if err := cgBackend.Mgr.Setup(); err != nil {
			log.Printf("[cgroupv2] setup failed (%v) — graduated enforcement will fall through to telemetry only", err)
		} else {
			log.Printf("[cgroupv2] choke tiers ready under %s", s.CgroupRoot)
			// A limit this kernel refused means enforcement is real but
			// weaker than configured. Say so — the alternative is an
			// operator believing a CPU cap is in force when it is not.
			if d := cgBackend.Mgr.Degraded(); len(d) > 0 {
				log.Printf("[cgroupv2] DEGRADED — kernel refused %d limit(s): %s",
					len(d), strings.Join(d, "; "))
			}
		}
	} else {
		log.Printf("[cgroupv2] not available at %s — graduated enforcement disabled (sever still works via SIGKILL)", s.CgroupRoot)
	}

	// Order matters: the cgroup backend handles throttle/tarpit/quarantine
	// (real kernel-level choke), the severer handles sever (SIGKILL), and the
	// throttler trails as a telemetry mirror writing to the bpfmap so the UI's
	// "Choke Map (kernel)" panel still populates.
	//
	// Both enforcer chains are always built and handed to the gateway so the
	// operator can flip detect-only ⇄ enforcing at runtime via
	// /api/choke/mode. Enforce only picks which one is active at boot.
	realEnforcer := &enforce.Multi{
		Backends: []enforce.Enforcer{cgBackend, severerBackend, throttleBackend},
	}
	loggerEnforcer := &enforce.Logger{Prefix: "[enforce-disabled]"}
	var enforcer enforce.Enforcer = realEnforcer
	if !s.Enforce {
		enforcer = loggerEnforcer
	}

	// Policy DSL — load all *.yaml under the choke-policy directory. A missing
	// directory is not an error; you just get no DSL-driven choking. This local
	// dir is also the bootstrap/fallback for signed policy bundles pulled from
	// the control plane (architecture.md §2).
	policySet := policy.NewSet()
	if s.ChokeDir != "" {
		set, warns, err := policy.LoadDir(s.ChokeDir)
		if err == nil {
			policySet = set
			for _, w := range warns {
				log.Printf("[policy] warn: %v", w)
			}
			log.Printf("[policy] loaded %d choke policies from %s", set.Len(), s.ChokeDir)
		} else if !os.IsNotExist(err) {
			log.Printf("[policy] load %s: %v (continuing without DSL)", s.ChokeDir, err)
		}
	}

	critBins := systemCriticalBinaries(s.SystemCritical)
	log.Printf("[gateway] system-critical exemption: %d binaries (auto-enforce bypassed; manual override allowed)", len(critBins))
	stack.SystemCriticalBinaries = critBins

	gw := choke.NewGateway(choke.Config{
		Store:          st,
		Enforcer:       enforcer,
		RealEnforcer:   realEnforcer,
		LoggerEnforcer: loggerEnforcer,
		Broadcast:      srv,
		Tokens:         tokens.NewManager(),
		Policies:       policySet,
		Tree:           pt,
		BPFMap:         bpfBackend,
		Thresholds: circuit.Config{
			ThrottleAt:   s.ThrottleAt,
			TarpitAt:     s.TarpitAt,
			QuarantineAt: s.QuarantineAt,
			SeverAt:      s.SeverAt,
		},
		DryRun:                 s.DryRun,
		Enforcing:              s.Enforce,
		SystemCriticalBinaries: critBins,
	})
	stack.Gateway = gw
	srv.SetGateway(gw)
	if s.PIDLiveFn != nil {
		gw.SetPIDLiveFn(s.PIDLiveFn)
	}

	// ---- Network Choke Gateway (per-device / MAC) -------------------------
	// A parallel data plane: tc clsact programs keyed by MAC on the LAN /
	// bridge-slave interfaces, independent of the process choke above. Loads
	// only when an object file AND at least one interface are configured;
	// otherwise an in-memory noop backend keeps the /api/choke/device-*
	// endpoints alive (useful for UI iteration). Operator/manual-driven — no
	// score path.
	devIfaces := config.SplitCSV(s.DevchokeIfaces)
	stack.devIfaces = devIfaces
	var devBackend devbpf.Backend
	if s.DevchokeObj != "" && len(devIfaces) > 0 {
		tc := devbpf.NewCiliumTCBackend(s.DevchokeObj, devIfaces)
		if err := tc.Open(); err != nil {
			log.Printf("[devbpf] tc backend failed (%v) — falling back to noop", err)
			noop := devbpf.NewNoopDeviceBackend()
			_ = noop.Open()
			devBackend = noop
		} else {
			log.Printf("[devbpf] tc data plane loaded from %s on [%s] (%d link(s), tier=%s)",
				s.DevchokeObj, s.DevchokeIfaces, tc.AttachedLinks(), tc.DataPlaneTier())
			devBackend = tc
		}
	} else {
		noop := devbpf.NewNoopDeviceBackend()
		_ = noop.Open()
		log.Printf("[devbpf] network device choke inactive (need -devchoke-obj + -devchoke-iface) — noop backend")
		devBackend = noop
	}
	stack.devBackend = devBackend

	protected := protectedMACs(s.DevchokeProtect, devIfaces)
	deviceTable := device.NewTable(time.Hour)
	stack.deviceTable = deviceTable
	deviceThrottler := enforce.NewDeviceThrottler(devBackend, protected)
	deviceGW := choke.NewDeviceGateway(choke.DeviceConfig{
		Throttler: deviceThrottler,
		Backend:   devBackend,
		Table:     deviceTable,
		Store:     st,
		Broadcast: srv,
		DryRun:    s.DryRun,
		// Device choke starts detect-only just like the process gateway.
		// Operators explicitly flip to enforcing at runtime after confirming
		// protected MACs and data-plane reachability.
		Enforcing: false,
	})
	stack.DeviceGateway = deviceGW
	srv.SetDeviceGateway(deviceGW)
	log.Printf("[devgateway] network device choke ready (ifaces=%q protected=%d dry_run=%v)",
		s.DevchokeIfaces, len(protected), s.DryRun)

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
	// fields. 30-minute TTL covers typical SSH session lifetimes without
	// unbounded growth.
	originTracker := origin.NewTracker(30 * time.Minute)
	stack.originTracker = originTracker
	srv.SetOriginSnapshotFn(func() map[uint32]map[string]interface{} {
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
		// for ~10 minutes after exit, so short-lived chains (SSH MOTD scripts
		// that die in ms) still resolve to their per-session sshd parent.
		// /proc would have lost them already.
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
	log.Printf("[gateway] %s; thresholds throttle=%d tarpit=%d quarantine=%d sever=%d",
		BootModeLabel(s.DryRun, s.Enforce), s.ThrottleAt, s.TarpitAt, s.QuarantineAt, s.SeverAt)

	// System health snapshot for /api/system-health (rendered by the "System
	// Health" panel in the choke console). Closures so live values (BPF link
	// count, map size, Tetragon stream state) are re-read on every request.
	bpfBackendKind := "noop"
	bpfLinksFn := func() int { return 0 }
	if cilium, ok := bpfBackend.(*bpfmap.CiliumEBPFBackend); ok {
		bpfBackendKind = "cilium-ebpf"
		bpfLinksFn = func() int { return cilium.AttachedLinks() }
	}
	storeTarget := s.DBPath
	if s.StoreKind == "postgres" {
		storeTarget = logging.RedactDSN(s.PgDSN)
	}
	srv.SetSystemInfo(api.SystemInfo{
		Version:      s.Version,
		StartedAt:    time.Now().UTC(),
		StoreBackend: s.StoreKind,
		StoreTarget:  storeTarget,
		BPFBackend:   bpfBackendKind,
		OTLPEndpoint: s.OTLPEndpoint,
		LogFormat:    s.LogFormat,
		LogLevel:     s.LogLevel,
		BPFLinks:     bpfLinksFn,
		BPFEntries: func() int {
			snap, err := bpfBackend.Snapshot()
			if err != nil {
				return -1
			}
			return len(snap)
		},
		TetragonConnected: func() bool { return stack.tetragonConnected.Load() },
	})

	return stack
}

// BootModeLabel is the enforcement posture printed on the startup banner.
//
// Dry-run outranks detect-only deliberately: a host with both set is recording
// decisions it will not execute, and calling that "DETECT-ONLY" would hide the
// fact that the enforcer chain is wired and armed behind it.
func BootModeLabel(dryRun, enforcing bool) string {
	mode := "ENFORCING"
	if dryRun {
		mode = "DRY-RUN"
	} else if !enforcing {
		mode = "DETECT-ONLY"
	}
	return mode
}

// systemCriticalBinaries resolves the auto-enforce exemption list: the
// operator's comma-separated override, or the package's safe defaults when the
// override is empty. Score-driven transitions on these binaries are audited but
// the enforcer is bypassed; manual overrides still go through.
//
// An override of only separators and blanks resolves to an EMPTY list, not to
// the defaults — an operator who passed something, however malformed, asked for
// their own list, and silently reinstating sshd/systemd protection they did not
// ask for would misreport what this host will actually enforce on.
func systemCriticalBinaries(raw string) []string {
	if raw == "" {
		return choke.DefaultSystemCriticalBinaries()
	}
	return config.SplitCSV(raw)
}

// protectedMACs builds the device-plane allow-list: the operator-supplied MACs
// (gateway / uplink / DHCP-DNS / operator workstation) PLUS the configured
// interfaces' own hardware addresses, so the box can never quarantine or sever
// its own bridge ports and cut off the operator reaching it.
//
// A malformed entry is logged and skipped rather than fatal: refusing to boot
// over one typo in an allow-list leaves the host with no enforcement at all,
// which is strictly worse than one address going unprotected.
func protectedMACs(csv string, ifaces []string) map[devbpf.MAC]bool {
	protected := map[devbpf.MAC]bool{}
	for _, m := range config.SplitCSV(csv) {
		if mac, err := devbpf.ParseMAC(m); err == nil {
			protected[mac] = true
		} else {
			log.Printf("[devgateway] -devchoke-protect: skipping bad MAC %q: %v", m, err)
		}
	}
	for _, ifn := range ifaces {
		if iface, err := net.InterfaceByName(ifn); err == nil && len(iface.HardwareAddr) == 6 {
			if mac, err := devbpf.ParseMAC(iface.HardwareAddr.String()); err == nil {
				protected[mac] = true
			}
		}
	}
	return protected
}

// StartBackground launches the loops that need a lifetime: SSH attribution and
// the two sweepers that keep the origin and device tables bounded.
//
// Separate from New because the mains own the context — its cancel is what a
// SIGTERM trips, and it must be deferred in main, not here.
func (s *Stack) StartBackground(ctx context.Context) {
	// Start the sshd journald tailer (Linux only; soft-degrades on macOS dev
	// builds and on hosts without journalctl in PATH). Any SSH session that
	// authenticates after this point gets attributed in the tracker.
	if err := origin.NewSSHDTailer(s.originTracker).Start(ctx); err != nil {
		log.Printf("[origin/sshd] start failed: %v (continuing without SSH attribution)", err)
	}
	// Origin tracker sweeper — evicts entries older than the TTL once a minute
	// so the map stays bounded even on busy boxes.
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.originTracker.Sweep()
			}
		}
	}()

	// Device discovery: passively sniff DHCP on the bridge for
	// MAC<->IP<->hostname, and on a ticker drain the data plane's seen map
	// (MAC + last source IP, in-kernel) and poll the neigh table. All feed the
	// one DeviceTable the device gateway reads from.
	device.StartDHCPSniffer(ctx, s.devIfaces, s.deviceTable.Record)
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if seen, err := s.devBackend.SeenSnapshot(); err == nil {
					for mac, sv := range seen {
						s.deviceTable.Record(device.Device{
							MAC:     mac.String(),
							LastIP:  device.IPv4BEToString(sv.LastSrcIPv4),
							Packets: sv.Packets,
							Source:  device.SourcePassive,
						})
					}
				}
				if neigh, err := device.PollNeigh(); err == nil {
					for _, d := range neigh {
						s.deviceTable.Record(d)
					}
				}
				s.deviceTable.Sweep()
			}
		}
	}()
}

// MarkTetragonConnected records the event-stream state in both places that must
// agree about it: the OTel gauge a fleet dashboard scrapes, and the local
// snapshot /api/system-health serves. They were two separate statements in each
// main, which is one statement too many for a fact an operator uses to decide
// whether a host is sensing at all.
func (s *Stack) MarkTetragonConnected(connected bool) {
	metrics.SetTetragonConnected(connected)
	s.tetragonConnected.Store(connected)
}

// Close tears down both data planes. The mains registered these as two separate
// defers, so LIFO ran the device plane down first; that order is kept because
// detach order matters when both planes hold links against the same host.
func (s *Stack) Close() {
	_ = s.devBackend.Close()
	_ = s.bpfBackend.Close()
}
