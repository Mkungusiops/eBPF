package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
	"github.com/jeffmk/ebpf-poc-engine/internal/command"
	"github.com/jeffmk/ebpf-poc-engine/internal/cpclient"
	"github.com/jeffmk/ebpf-poc-engine/internal/enrollment"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
	"github.com/jeffmk/ebpf-poc-engine/internal/mtls"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/uplink"
)

// harness stands up one gRPC server hosting all agent-facing services over TLS.
// VerifyClientCertIfGiven lets the bootstrap Enroll call (no client cert) through
// while every other channel presents a cert that TLS verifies against the CA
// before a handler reads its subject. Production splits enroll (server-auth)
// from the mTLS channels; the security property is identical.
type harness struct {
	ca            *mtls.CA
	addr          string
	tokens        *enrollment.TokenStore
	dispatcher    *command.Dispatcher
	registry      *heartbeat.Registry
	fleetVerifier signing.Verifier
}

// newHarness stands up the full control-plane server with the given telemetry
// sink (a MemSink for assertion-by-count, or a centralstore for the tenant-
// scoped-storage integration).
func newHarness(t *testing.T, sink ingest.Sink) *harness {
	t.Helper()
	ca, err := mtls.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	serverCertPEM, serverKeyPEM, err := ca.IssueServer("127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    ca.Pool(),
		MinVersion:   tls.VersionTLS13,
	}

	tokens := enrollment.NewTokenStore()
	fleetSigner, fleetVerifier, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := command.NewDispatcher(fleetSigner, time.Minute)
	registry := heartbeat.NewRegistry()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	ebpfsocv1.RegisterEnrollmentServiceServer(gs, enrollment.NewServer(ca, tokens, time.Hour, "127.0.0.1:uplink", "127.0.0.1:cmd"))
	ebpfsocv1.RegisterTelemetryServiceServer(gs, ingest.NewServer(sink))
	ebpfsocv1.RegisterCommandServiceServer(gs, dispatcher)
	ebpfsocv1.RegisterHeartbeatServiceServer(gs, heartbeat.NewServer(registry, 30*time.Second))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	return &harness{
		ca: ca, addr: lis.Addr().String(), tokens: tokens,
		dispatcher: dispatcher, registry: registry, fleetVerifier: fleetVerifier,
	}
}

func (h *harness) enroll(t *testing.T, ctx context.Context, tenant string) *enrollment.Enrolled {
	t.Helper()
	tok, err := h.tokens.Mint(tenant, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := grpc.NewClient(h.addr, grpc.WithTransportCredentials(
		credentials.NewTLS(mtls.BootstrapTLSConfig(h.ca.Pool(), "127.0.0.1"))))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	en, err := enrollment.Enroll(ctx, cc, tok, &ebpfsocv1.AgentInfo{Hostname: "h-" + tenant})
	if err != nil {
		t.Fatalf("enroll %s: %v", tenant, err)
	}
	return en
}

func (h *harness) mtlsConn(t *testing.T, en *enrollment.Enrolled) *grpc.ClientConn {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(en.CABundlePEM) {
		t.Fatal("bad CA bundle")
	}
	cfg, err := mtls.ClientTLSConfig(en.CertPEM, en.KeyPEM, pool, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	cc, err := grpc.NewClient(h.addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

// --- telemetry: tenant stamping, resume/dedup, cross-tenant isolation -------

func TestTelemetryStampAndIsolation(t *testing.T) {
	sink := ingest.NewMemSink()
	h := newHarness(t, sink)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	mkEvent := func(id int) *ebpfsocv1.TelemetryRecord {
		return uplink.EventRecord(&store.Event{
			ID: int64(id), Timestamp: time.Unix(int64(id), 0),
			EventType: "process_exec", ExecID: fmt.Sprintf("exec-%d", id), Binary: "/bin/sh",
		})
	}

	// Agent A buffers 3 records while "offline", then drains over mTLS.
	agentA := h.enroll(t, ctx, "tenant-a")
	bufA := uplink.NewBuffer()
	for i := 1; i <= 3; i++ {
		bufA.Enqueue(mkEvent(i))
	}
	if bufA.PendingDepth() != 3 {
		t.Fatalf("offline buffer depth = %d, want 3", bufA.PendingDepth())
	}
	clA := ebpfsocv1.NewTelemetryServiceClient(h.mtlsConn(t, agentA))
	if err := uplink.DrainOnce(ctx, clA, bufA, 2); err != nil {
		t.Fatalf("drain A: %v", err)
	}
	if bufA.PendingDepth() != 0 || sink.Count("tenant-a") != 3 {
		t.Fatalf("after drain: depth=%d sink=%d, want 0/3", bufA.PendingDepth(), sink.Count("tenant-a"))
	}

	// Idempotent replay: re-send evt:1..3 + new evt:4,5 → collector dedups.
	for i := 1; i <= 5; i++ {
		bufA.Enqueue(mkEvent(i))
	}
	if err := uplink.DrainOnce(ctx, clA, bufA, 3); err != nil {
		t.Fatalf("drain A replay: %v", err)
	}
	if got := sink.Count("tenant-a"); got != 5 {
		t.Fatalf("after replay tenant-a = %d, want 5 (dedup)", got)
	}

	// Agent B: identical record keys → separate partition, no contamination.
	agentB := h.enroll(t, ctx, "tenant-b")
	bufB := uplink.NewBuffer()
	bufB.Enqueue(mkEvent(1))
	bufB.Enqueue(mkEvent(2))
	clB := ebpfsocv1.NewTelemetryServiceClient(h.mtlsConn(t, agentB))
	if err := uplink.DrainOnce(ctx, clB, bufB, 10); err != nil {
		t.Fatalf("drain B: %v", err)
	}
	if sink.Count("tenant-b") != 2 || sink.Count("tenant-a") != 5 {
		t.Fatalf("isolation breach: a=%d b=%d, want 5/2", sink.Count("tenant-a"), sink.Count("tenant-b"))
	}
}

// --- command channel: signed command round-trip over mTLS -------------------

type fakeApplier struct{ mode ebpfsocv1.EnforcementMode }

func (f *fakeApplier) SetMode(m ebpfsocv1.EnforcementMode) error { f.mode = m; return nil }
func (f *fakeApplier) Jail(string, uint32, string) error         { return nil }
func (f *fakeApplier) Thaw(string, uint32) error                 { return nil }
func (f *fakeApplier) SetThresholds(_, _, _, _ int32) error      { return nil }
func (f *fakeApplier) ApplyPreset(string) error                  { return nil }
func (f *fakeApplier) KillSwitch(bool, string) error             { return nil }
func (f *fakeApplier) SetProtectedList([]string, []string) error { return nil }

func TestCommandRoundTrip(t *testing.T) {
	h := newHarness(t, ingest.NewMemSink())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	agent := h.enroll(t, ctx, "tenant-a")

	// Control plane enqueues a signed SetMode(ENFORCING) for this agent.
	id := h.dispatcher.Enqueue(agent.AgentID, &ebpfsocv1.Command{
		Action: &ebpfsocv1.Command_SetMode{SetMode: &ebpfsocv1.SetMode{Mode: ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING}},
	})

	// Agent runs the command channel: verify (fleet key) → apply → ack.
	fa := &fakeApplier{}
	proc := command.NewProcessor(h.fleetVerifier, fa, []string{"sudo", "sshd"})
	cc := ebpfsocv1.NewCommandServiceClient(h.mtlsConn(t, agent))
	if err := command.RunCommands(ctx, cc, proc); err != nil {
		t.Fatalf("RunCommands: %v", err)
	}

	// Applied on the agent, and the ack made it back to the control plane.
	if fa.mode != ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING {
		t.Fatalf("command not applied on agent: mode=%v", fa.mode)
	}
	ack, ok := h.dispatcher.Ack(id)
	if !ok || ack.GetStatus() != ebpfsocv1.CommandAck_STATUS_APPLIED {
		t.Fatalf("dispatcher ack = (%v, ok=%v), want APPLIED", ack.GetStatus(), ok)
	}
}

// --- heartbeat: recorded under the cert-derived tenant ----------------------

func TestHeartbeatRecorded(t *testing.T) {
	h := newHarness(t, ingest.NewMemSink())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	agent := h.enroll(t, ctx, "tenant-a")
	hc := ebpfsocv1.NewHeartbeatServiceClient(h.mtlsConn(t, agent))
	if _, err := hc.Heartbeat(ctx, &ebpfsocv1.HeartbeatRequest{
		AgentInfo:   &ebpfsocv1.AgentInfo{AgentVersion: "0.2.0-agent", Kernel: "6.8.0"},
		DataPlane:   &ebpfsocv1.DataPlaneState{Mode: ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DETECT_ONLY},
		BufferDepth: 7,
	}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}

	rec, ok := h.registry.Get("tenant-a", agent.AgentID)
	if !ok {
		t.Fatal("heartbeat not recorded under cert-derived tenant")
	}
	if rec.Version != "0.2.0-agent" || rec.BufferDepth != 7 {
		t.Fatalf("heartbeat record fields wrong: %+v", rec)
	}
}

// --- cpclient: the agent orchestrator enrolls, drains, and heartbeats -------

func TestCPClientDrainsAndHeartbeats(t *testing.T) {
	sink := ingest.NewMemSink()
	h := newHarness(t, sink)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tok, err := h.tokens.Mint("tenant-a", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	buf := uplink.NewBuffer()
	for i := 1; i <= 3; i++ {
		buf.Enqueue(uplink.EventRecord(&store.Event{ID: int64(i), Timestamp: time.Unix(int64(i), 0), EventType: "process_exec", ExecID: fmt.Sprintf("e-%d", i)}))
	}

	enrolled := make(chan *enrollment.Enrolled, 1)
	cfg := cpclient.Config{
		Endpoint: h.addr, ServerName: "127.0.0.1",
		BootstrapToken: tok, CABundlePEM: h.ca.CertPEM(),
		AgentInfo: &ebpfsocv1.AgentInfo{Hostname: "agent-x", AgentVersion: "0.2.0-agent"},
		Buffer:    buf,
		Processor: command.NewProcessor(h.fleetVerifier, &fakeApplier{}, nil),
		Heartbeat: func() *ebpfsocv1.HeartbeatRequest {
			return &ebpfsocv1.HeartbeatRequest{AgentInfo: &ebpfsocv1.AgentInfo{AgentVersion: "0.2.0-agent"}, BufferDepth: uint64(buf.PendingDepth())}
		},
		DrainInterval: 100 * time.Millisecond, HeartbeatInterval: 100 * time.Millisecond, Backoff: 100 * time.Millisecond,
		OnEnrolled: func(en *enrollment.Enrolled) { enrolled <- en },
	}
	runErr := make(chan error, 1)
	go func() { runErr <- cpclient.Run(ctx, cfg) }()

	var en *enrollment.Enrolled
	select {
	case en = <-enrolled:
	case <-time.After(5 * time.Second):
		t.Fatal("cpclient did not enroll in time")
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sink.Count("tenant-a") >= 3 {
			if _, ok := h.registry.Get("tenant-a", en.AgentID); ok {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if sink.Count("tenant-a") != 3 {
		t.Fatalf("cpclient drained %d records, want 3", sink.Count("tenant-a"))
	}
	if _, ok := h.registry.Get("tenant-a", en.AgentID); !ok {
		t.Fatal("cpclient did not heartbeat under the cert-derived tenant")
	}

	cancel()
	select {
	case <-runErr:
	case <-time.After(5 * time.Second):
		t.Fatal("cpclient did not shut down on ctx cancel")
	}
}

// --- Layers 1→2→3: cert identity → ingest stamp → tenant-scoped store -------

// TestIngestToCentralStoreIsolation drives telemetry from two enrolled agents
// through the real ingest collector into the tenant-partitioned central store,
// then proves a tenant-scoped read returns ONLY that tenant's rows — the full
// isolation invariant chain (mTLS identity → ingest stamp → storage filter)
// end to end over the wire, with identical record keys across tenants.
func TestIngestToCentralStoreIsolation(t *testing.T) {
	cs, err := centralstore.Open(filepath.Join(t.TempDir(), "central.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	h := newHarness(t, cs) // the collector sinks straight into the central store
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	mkEvent := func(id int) *ebpfsocv1.TelemetryRecord {
		return uplink.EventRecord(&store.Event{ID: int64(id), Timestamp: time.Unix(int64(id), 0), EventType: "process_exec", ExecID: fmt.Sprintf("exec-%d", id)})
	}
	stream := func(tenant string, ids ...int) {
		en := h.enroll(t, ctx, tenant)
		buf := uplink.NewBuffer()
		for _, id := range ids {
			buf.Enqueue(mkEvent(id))
		}
		if err := uplink.DrainOnce(ctx, ebpfsocv1.NewTelemetryServiceClient(h.mtlsConn(t, en)), buf, 10); err != nil {
			t.Fatalf("drain %s: %v", tenant, err)
		}
	}

	stream("tenant-a", 1, 2, 3)
	stream("tenant-b", 1, 2) // identical keys evt:1, evt:2

	// Scoped reads see only their own tenant.
	if n, _ := cs.Count(centralstore.Scope{TenantID: "tenant-a"}); n != 3 {
		t.Fatalf("central store tenant-a count = %d, want 3", n)
	}
	rowsB, err := cs.Query(centralstore.Scope{TenantID: "tenant-b"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rowsB) != 2 {
		t.Fatalf("tenant-b rows = %d, want 2", len(rowsB))
	}
	for _, r := range rowsB {
		if r.TenantID != "tenant-b" {
			t.Fatalf("tenant-b scoped read returned a %q row — end-to-end cross-tenant LEAK", r.TenantID)
		}
	}
	// An unscoped read is impossible (fails closed).
	if _, err := cs.Query(centralstore.Scope{}, 100); err != centralstore.ErrNoScope {
		t.Fatalf("unscoped read err = %v, want ErrNoScope", err)
	}
}
