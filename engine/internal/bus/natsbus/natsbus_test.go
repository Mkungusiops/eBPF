package natsbus

import (
	"path/filepath"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/bus"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
)

// runEmbeddedNATS starts an in-process JetStream-enabled NATS server so the
// adapter is exercised against the REAL bus, no external infra.
func runEmbeddedNATS(t *testing.T) (url string, shutdown func()) {
	t.Helper()
	ns, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(10 * time.Second) {
		t.Fatal("embedded NATS did not become ready")
	}
	return ns.ClientURL(), ns.Shutdown
}

func eventRec(dedup, execID string) *ebpfsocv1.TelemetryRecord {
	return &ebpfsocv1.TelemetryRecord{
		DedupKey: dedup,
		Payload:  &ebpfsocv1.TelemetryRecord_Event{Event: &ebpfsocv1.ProcessEvent{ExecId: execID}},
	}
}

// TestNATSJetStreamPipelineIsolation drives records through a real JetStream
// stream into the tenant-scoped central store and proves isolation survives the
// durable bus hop — with identical dedup keys across tenants.
func TestNATSJetStreamPipelineIsolation(t *testing.T) {
	url, shutdown := runEmbeddedNATS(t)
	defer shutdown()

	b, err := Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	cs, err := centralstore.Open(filepath.Join(t.TempDir(), "central.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	stop, err := bus.Consume(b, cs) // JetStream -> central store
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	sink := bus.NewSink(b) // ingest.Sink -> JetStream
	put := func(tenant, agent, dedup string) {
		if err := sink.Put(ingest.StampedRecord{TenantID: tenant, AgentID: agent, Record: eventRec(dedup, "e")}); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}
	put("tenant-a", "aa", "evt:1")
	put("tenant-a", "aa", "evt:2")
	put("tenant-b", "bb", "evt:1") // identical dedup key, other tenant

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		na, _ := cs.Count(centralstore.Scope{TenantID: "tenant-a"})
		nb, _ := cs.Count(centralstore.Scope{TenantID: "tenant-b"})
		if na == 2 && nb == 1 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	if na, _ := cs.Count(centralstore.Scope{TenantID: "tenant-a"}); na != 2 {
		t.Fatalf("tenant-a via JetStream = %d, want 2", na)
	}
	rowsB, _ := cs.Query(centralstore.Scope{TenantID: "tenant-b"}, 100)
	if len(rowsB) != 1 || rowsB[0].TenantID != "tenant-b" {
		t.Fatalf("tenant-b via JetStream = %d rows — isolation breach across the bus", len(rowsB))
	}
}
