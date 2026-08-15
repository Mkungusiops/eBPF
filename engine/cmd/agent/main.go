// Command agent is the Choke Agent build target: the per-host, autonomous
// sensing + enforcing core of the platform. It is the first half of the
// agent / control-plane split described in docs/plan/architecture.md §1.
//
// The sensing + enforcing path is not duplicated from cmd/engine any more — it
// is internal/hoststack (data planes, gateways, background loops) and
// internal/eventpipe (Tetragon event → score → store → gateway), which both
// build targets link. That extraction is the "hollow out cmd/engine" step the
// original STRANGLER NOTE deferred to Phase 1. It stopped being optional when
// the copies drifted: a fix landed on deviceGatewayMode and was missed on its
// twin gatewayMode, so a kill-switched host reported
// ENFORCEMENT_MODE_UNSPECIFIED to the console.
//
// What remains here is what is genuinely the agent's own: enrollment, the
// control-plane uplink, and the heartbeat that reports this host's real posture.
// Two things cmd/engine has stay there deliberately —
//
//   - fake mode  — a dev/UI convenience of the console binary, not part of
//     the sensing+enforcing path.
//   - fleet fan-out (chokectl) — a client-driven multi-host control pattern
//     that is the control plane's command channel here (architecture.md §3.5),
//     not an agent concern.
//
// Autonomy contract (the moat — architecture.md §2/§6): nothing here makes
// in-kernel enforcement depend on a network service. The agent enforces from
// local state; the uplink/enrollment/policy-pull machinery is layered on top
// without ever becoming a prerequisite for containment.
package main

import (
	"context"
	"errors"
	"log"
	"os"
	"syscall"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/jeffmk/ebpf-poc-engine/internal/api"
	"github.com/jeffmk/ebpf-poc-engine/internal/eventpipe"
	"github.com/jeffmk/ebpf-poc-engine/internal/hoststack"
	"github.com/jeffmk/ebpf-poc-engine/internal/logging"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
	"github.com/jeffmk/ebpf-poc-engine/internal/uplink"
)

func main() {
	cfg := parseAgentFlags(os.Args[1:])

	// Logging: install slog as the default and bridge stdlib log onto it.
	logging.Setup(cfg.LogFormat, cfg.LogLevel)
	log.Printf("[agent] choke-agent %s starting (sensing+enforcing build target)", agentVersion)

	// Resolved before anything else is stood up: a host with no console
	// credential must fail on the credential, not after it has opened a
	// database and attached BPF programs it is about to abandon.
	credential, err := hoststack.ResolveConsoleCredential(cfg.AuthPass, cfg.AuthHash, "console")
	if err != nil {
		log.Fatal(err)
	}

	hostname, _ := os.Hostname()
	stopMetrics := hoststack.InitMetrics(cfg.OTLPEndpoint, hostname, agentVersion)
	defer stopMetrics()

	hoststack.ConfigureConsoleDirs(cfg.PoliciesDir, cfg.AttacksDir, cfg.HoneypotsDir)

	st := hoststack.OpenStore(cfg.Settings, " (agent-local offline buffer)")
	defer st.Close()

	pt := tree.New(10 * time.Minute)
	broadcast := make(chan api.Broadcast, 1024)

	auth, err := api.NewAuth(cfg.AuthUser, credential, cfg.SecretPath)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	// Local debug/health console. This is the agent's field-diagnostics
	// surface (architecture.md §2 "minimal localhost-only debug/health
	// endpoint"); the multi-tenant console lives in the control plane. No
	// fleet fan-out is wired here — that pattern is the control plane's
	// command channel.
	httpSrv := api.NewServer(st, pt, broadcast, auth)
	go func() {
		if err := httpSrv.Start(cfg.HTTPAddr); err != nil {
			log.Fatalf("http: %v", err)
		}
	}()

	// Only the agent answers remote containment commands, so only the agent
	// needs the gateway's PID liveness probe. See pidLive.
	cfg.PIDLiveFn = pidLive
	stack := hoststack.New(cfg.Settings, st, pt, httpSrv)
	defer stack.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stack.StartBackground(ctx)
	hoststack.NotifyShutdown(cancel)

	// ---- Control-plane uplink (Phase 1, opt-in) ---------------------------
	// Enforcement above is already fully wired and running before this line.
	sensors := &sensorRegistry{}
	upBuf := startControlPlane(ctx, cfg, stack, hostname, sensors)

	pipe := &eventpipe.Pipeline{
		Store:     st,
		Tree:      pt,
		Broadcast: broadcast,
		Gateway:   stack.Gateway,
	}
	if upBuf != nil {
		// Tee telemetry to the control plane. Left nil when standalone, so an
		// agent with no uplink behaves exactly as it did before Phase 1.
		pipe.EventSink = func(e *store.Event) { upBuf.Enqueue(uplink.EventRecord(e)) }
		pipe.AlertSink = func(a *store.Alert) { upBuf.Enqueue(uplink.AlertRecord(a)) }
	}

	// Tetragon subscription — the agent's sole event source. Unlike cmd/engine
	// there is no fake mode here: the agent is a production sensor that runs
	// next to Tetragon. Dev/UI iteration without a kernel uses cmd/engine -fake.
	conn, err := grpc.Dial(cfg.TetragonAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial tetragon: %v", err)
	}
	defer conn.Close()

	client := tetragon.NewFineGuidanceSensorsClient(conn)
	// Publish it for the heartbeat, which asks the daemon what TracingPolicies
	// the kernel really has so the console can show host posture rather than
	// just the engine's half of it.
	sensors.set(client)

	stream, err := client.GetEvents(ctx, &tetragon.GetEventsRequest{})
	if err != nil {
		log.Fatalf("get events: %v", err)
	}

	log.Println("subscribed to Tetragon event stream")
	stack.MarkTetragonConnected(true)
	defer stack.MarkTetragonConnected(false)

	pipe.Consume(stream)
}

// pidLive is the liveness probe behind Gateway.Owns — the fallback evidence for
// a containment target named by PID rather than by an exec_id this host
// observed. signal 0 does no work but still runs the kernel's permission check,
// so EPERM means the process exists and belongs to someone else; only ESRCH
// means "not here".
func pidLive(pid uint32) bool {
	if pid == 0 {
		return false
	}
	err := syscall.Kill(int(pid), 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
