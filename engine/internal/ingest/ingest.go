// Package ingest is the control-plane collector: it terminates agent mTLS,
// derives the tenant from the verified client certificate, stamps every record
// with that tenant, and hands it to a Sink. It is the enforcement point for
// Layer 2 of the tenant isolation invariant (tenant-isolation-invariant.md):
// the tenant is taken from the cert, NEVER from the payload, so a record can
// never be attributed to a tenant the presenting agent was not issued for.
package ingest

import (
	"errors"
	"io"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/mtls"
)

// StampedRecord is a telemetry record with the (tenant_id, agent_id) the
// collector derived from the agent's mTLS certificate. Everything downstream
// (bus, storage) partitions by this tenant.
type StampedRecord struct {
	TenantID string
	AgentID  string
	Record   *ebpfsocv1.TelemetryRecord
}

// Sink receives stamped records. In Phase 1 this is the message bus; the
// in-memory MemSink here is used by tests and the Phase 0 control-plane stub.
type Sink interface {
	Put(StampedRecord) error
}

// Server implements ebpfsocv1.TelemetryServiceServer. It dedups on
// (agent_id, dedup_key) so a replay after an agent reconnect is idempotent
// (wire-contract.md §4), and ACKs cumulatively so the agent can free its WAL.
type Server struct {
	ebpfsocv1.UnimplementedTelemetryServiceServer

	sink Sink

	mu   sync.Mutex
	seen map[string]struct{} // agent_id \x00 dedup_key
}

func NewServer(sink Sink) *Server {
	return &Server{sink: sink, seen: make(map[string]struct{})}
}

// StreamTelemetry receives batches, stamps + dedups + sinks their records, and
// acks each batch cumulatively by its agent_seq.
func (s *Server) StreamTelemetry(stream ebpfsocv1.TelemetryService_StreamTelemetryServer) error {
	tenant, agent, err := mtls.PeerTenant(stream.Context())
	if err != nil {
		// No trusted tenant ⇒ refuse the stream. This is the invariant's
		// fail-closed behaviour at the edge.
		return status.Error(codes.Unauthenticated, err.Error())
	}
	for {
		batch, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, rec := range batch.GetRecords() {
			if s.duplicate(agent, rec.GetDedupKey()) {
				continue // already ingested — idempotent replay
			}
			if err := s.sink.Put(StampedRecord{TenantID: tenant, AgentID: agent, Record: rec}); err != nil {
				return status.Errorf(codes.Internal, "sink: %v", err)
			}
		}
		if err := stream.Send(&ebpfsocv1.TelemetryAck{AckedThroughSeq: batch.GetAgentSeq()}); err != nil {
			return err
		}
	}
}

// duplicate records (agent, key) as seen and reports whether it already was.
func (s *Server) duplicate(agent, key string) bool {
	k := agent + "\x00" + key
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[k]; ok {
		return true
	}
	s.seen[k] = struct{}{}
	return false
}
