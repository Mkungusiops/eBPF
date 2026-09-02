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
	// Synthetic marks telemetry produced by cmd/simagent rather than a real
	// host, so a fabricated containment decision can never be read as evidence.
	//
	// Stamped at INGEST rather than derived at read time: the agent that
	// produced a record may be long gone by the time anyone reads it — the 431
	// synthetic decisions on the live estate came from two simulators that
	// stopped reporting on 2026-08-15 and never returned, leaving nothing to
	// join against.
	Synthetic bool
}

// SyntheticFn reports whether an agent is a simulator. Injected so the ingest
// path does not depend on the heartbeat package, and so a deployment with no
// registry simply marks nothing.
type SyntheticFn func(tenant, agent string) bool

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
	// synthetic reports whether an agent is a simulator. nil means "assume
	// real", which is the safe direction: a real agent must never be
	// mislabelled as demo data.
	synthetic SyntheticFn

	mu sync.Mutex
	// Two-generation dedup set, keyed tenant \x00 agent \x00 dedup_key.
	//
	// This was ONE unbounded map with no TTL, cap or eviction, holding an entry
	// for every record ever ingested for the life of the process. Measured
	// production ingest is ~400k records/day, so the control plane leaked memory
	// on a timescale of weeks — the same failure class already bounded twice in
	// this codebase (the uplink buffer and the connection pool), one layer down.
	//
	// Rotation rather than a TTL: when `cur` fills, it becomes `prev` and a new
	// `cur` starts. A key is a duplicate if it is in either generation, so the
	// effective dedup window is between one and two full generations — always at
	// least dedupGenSize recent records, with memory bounded at 2x that.
	//
	// The key now includes the tenant. It was (agent, key) while the storage
	// primary key is (tenant_id, agent_id, dedup_key), so two tenants whose
	// agents shared an agent_id would silently drop one tenant's record as a
	// replay.
	cur  map[string]struct{}
	prev map[string]struct{}
}

// dedupGenSize bounds one generation. ~200k keys is a few tens of MB at these
// key lengths and covers roughly half a day of measured production ingest.
const dedupGenSize = 200_000

func NewServer(sink Sink) *Server {
	return &Server{sink: sink, cur: make(map[string]struct{}), prev: make(map[string]struct{})}
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
			if s.duplicate(tenant, agent, rec.GetDedupKey()) {
				continue // already ingested — idempotent replay
			}
			if err := s.sink.Put(StampedRecord{
				TenantID: tenant, AgentID: agent, Record: rec,
				Synthetic: s.synthetic != nil && s.synthetic(tenant, agent),
			}); err != nil {
				return status.Errorf(codes.Internal, "sink: %v", err)
			}
		}
		if err := stream.Send(&ebpfsocv1.TelemetryAck{AckedThroughSeq: batch.GetAgentSeq()}); err != nil {
			return err
		}
	}
}

// duplicate records (tenant, agent, key) as seen and reports whether it already
// was, across the two live generations.
func (s *Server) duplicate(tenant, agent, key string) bool {
	k := tenant + "\x00" + agent + "\x00" + key
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.cur[k]; ok {
		return true
	}
	if _, ok := s.prev[k]; ok {
		return true
	}
	if len(s.cur) >= dedupGenSize {
		s.prev = s.cur
		s.cur = make(map[string]struct{}, dedupGenSize)
	}
	s.cur[k] = struct{}{}
	return false
}

// SetSyntheticFn wires the simulator predicate after construction, the way the
// control plane wires its other late dependencies.
func (s *Server) SetSyntheticFn(fn SyntheticFn) { s.synthetic = fn }
