// Package heartbeat is the agent liveness/health channel (wire-contract.md §2).
// Agents periodically report version, kernel, data-plane state, enforcement
// mode, and buffer depth; the control plane records the latest per agent to
// build its fleet registry (architecture.md §3.5). Tenant/agent are derived
// from the mTLS certificate, never the request. A missed heartbeat never stops
// enforcement (autonomy).
package heartbeat

import (
	"context"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/mtls"
)

// Record is the last-known state of one agent.
type Record struct {
	TenantID             string
	AgentID              string
	LastSeen             time.Time
	Version              string
	Kernel               string
	Mode                 ebpfsocv1.EnforcementMode
	BufferDepth          uint64
	AppliedPolicyVersion string
}

// Registry holds the latest Record per (tenant, agent). Safe for concurrent use.
type Registry struct {
	now func() time.Time

	mu     sync.Mutex
	agents map[string]Record // key: tenant \x00 agent
}

func NewRegistry() *Registry {
	return &Registry{now: time.Now, agents: make(map[string]Record)}
}

func key(tenant, agent string) string { return tenant + "\x00" + agent }

// Record updates the registry from a heartbeat request. tenant/agent come from
// the verified cert (the caller), not the request body.
func (r *Registry) Record(tenant, agent string, req *ebpfsocv1.HeartbeatRequest) {
	rec := Record{
		TenantID:             tenant,
		AgentID:              agent,
		LastSeen:             r.now(),
		BufferDepth:          req.GetBufferDepth(),
		AppliedPolicyVersion: req.GetAppliedPolicyVersion(),
	}
	if info := req.GetAgentInfo(); info != nil {
		rec.Version = info.GetAgentVersion()
		rec.Kernel = info.GetKernel()
	}
	if dp := req.GetDataPlane(); dp != nil {
		rec.Mode = dp.GetMode()
	}
	r.mu.Lock()
	r.agents[key(tenant, agent)] = rec
	r.mu.Unlock()
}

// Get returns the record for (tenant, agent).
func (r *Registry) Get(tenant, agent string) (Record, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.agents[key(tenant, agent)]
	return rec, ok
}

// Count returns how many agents have reported.
func (r *Registry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.agents)
}

// Server implements ebpfsocv1.HeartbeatServiceServer.
type Server struct {
	ebpfsocv1.UnimplementedHeartbeatServiceServer
	reg      *Registry
	interval time.Duration
}

func NewServer(reg *Registry, interval time.Duration) *Server {
	return &Server{reg: reg, interval: interval}
}

func (s *Server) Heartbeat(ctx context.Context, req *ebpfsocv1.HeartbeatRequest) (*ebpfsocv1.HeartbeatResponse, error) {
	tenant, agent, err := mtls.PeerTenant(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	s.reg.Record(tenant, agent, req)
	return &ebpfsocv1.HeartbeatResponse{
		ServerTime:                timestamppb.Now(),
		DesiredHeartbeatIntervalS: uint32(s.interval / time.Second),
	}, nil
}
