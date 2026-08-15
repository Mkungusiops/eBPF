// Command engine is the single-host build target: the sensing + enforcing core
// plus the full operator console and the Tier 1 fleet fan-out.
//
// It shares the entire host stack with cmd/agent through internal/hoststack and
// internal/eventpipe — the two binaries differ only in what surrounds that
// stack. The engine adds the dashboard's rate-limited login, the /fleet console,
// and fake mode; the agent adds enrollment and the control-plane uplink. The
// wiring in between used to be copied into both mains, and the copies drifted.
package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/jeffmk/ebpf-poc-engine/internal/api"
	"github.com/jeffmk/ebpf-poc-engine/internal/eventpipe"
	"github.com/jeffmk/ebpf-poc-engine/internal/hoststack"
	"github.com/jeffmk/ebpf-poc-engine/internal/logging"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
)

func main() {
	cfg := parseEngineFlags(os.Args[1:])

	// Logging: install slog as the default and bridge stdlib log onto it.
	// Existing log.Printf("…") calls keep working but emit structured records.
	logging.Setup(cfg.LogFormat, cfg.LogLevel)

	hostname, _ := os.Hostname()
	stopMetrics := hoststack.InitMetrics(cfg.OTLPEndpoint, hostname, engineVersion)
	defer stopMetrics()

	hoststack.ConfigureConsoleDirs(cfg.PoliciesDir, cfg.AttacksDir, cfg.HoneypotsDir)

	st := hoststack.OpenStore(cfg.Settings, "")
	defer st.Close()

	pt := tree.New(10 * time.Minute)
	broadcast := make(chan api.Broadcast, 1024)

	credential, err := hoststack.ResolveConsoleCredential(cfg.AuthPass, cfg.AuthHash, "dashboard")
	if err != nil {
		log.Fatal(err)
	}
	auth, err := api.NewAuth(cfg.AuthUser, credential, cfg.SecretPath)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	auth.SetLoginRateLimit(cfg.loginRate)
	httpSrv := api.NewServer(st, pt, broadcast, auth)
	if cfg.fleetHosts != "" {
		// Same credentials chokectl uses by default; the engine itself acts
		// as the operator presenting them to peers. Per-peer audit chains
		// remain the tamper-evident record.
		httpSrv.SetFleet(api.NewFleet(cfg.fleetHosts, cfg.AuthUser, cfg.AuthPass))
		log.Printf("[fleet] console enabled at /fleet (hosts=%s)", cfg.fleetHosts)
	}
	go func() {
		if err := httpSrv.Start(cfg.HTTPAddr); err != nil {
			log.Fatalf("http: %v", err)
		}
	}()

	stack := hoststack.New(cfg.Settings, st, pt, httpSrv)
	defer stack.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stack.StartBackground(ctx)
	hoststack.NotifyShutdown(cancel)

	// The gateway is captured here rather than read from a global on every
	// event: by this point it is fully wired, and a pipeline that cannot
	// observe a half-built gateway cannot dispatch enforcement through one.
	pipe := &eventpipe.Pipeline{
		Store:     st,
		Tree:      pt,
		Broadcast: broadcast,
		Gateway:   stack.Gateway,
	}

	if cfg.fakeMode {
		log.Println("fake mode: synthesizing events (no Tetragon required)")
		runFake(ctx, pipe)
		return
	}

	// NewClient, not the deprecated Dial: Dial's implicit connect-on-create and
	// WithBlock semantics are gone in the 1.x successor API.
	conn, err := grpc.NewClient(cfg.TetragonAddr,
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
	stack.MarkTetragonConnected(true)
	defer stack.MarkTetragonConnected(false)

	pipe.Consume(stream)
}
