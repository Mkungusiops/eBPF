// Package heartbeat is the agent liveness/health channel (wire-contract.md §2).
// Agents periodically report version, kernel, data-plane state, enforcement
// mode, and buffer depth; the control plane records the latest per agent to
// build its fleet registry (architecture.md §3.5). Tenant/agent are derived
// from the mTLS certificate, never the request. A missed heartbeat never stops
// enforcement (autonomy).
package heartbeat

import (
	"context"
	"sort"
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
	// DevicePlane is the network-plane backend the agent reports ("tc" | "noop";
	// empty from an agent predating the field). DeviceLinks is how many
	// interfaces it is attached to. Kept so the fleet view can distinguish an
	// agent that CAN enforce on the network plane from one only recording
	// decisions, instead of assuming any online agent is enforcing.
	DevicePlane string
	DeviceLinks int32
	// DeviceMode is the DEVICE plane's own enforcement mode. Mode above is the
	// process plane's; the two arm independently.
	DeviceMode ebpfsocv1.EnforcementMode
	// KernelPolicies is the host's OTHER enforcement authority: Tetragon
	// TracingPolicies as the kernel currently has them. A Sigkill in one fires
	// regardless of Mode above, so without this the console reports the engine's
	// mode as though it were the host's posture (threat-model EN-3). Empty from
	// an agent predating the field, or one that could not reach Tetragon.
	KernelPolicies []*ebpfsocv1.KernelPolicy
	// Latest data-plane snapshot the agent reported (compact; may be empty).
	Chokes  []*ebpfsocv1.ChokeSummary
	Devices []*ebpfsocv1.DeviceSummary
}

// KernelEnforcing reports whether this host has a kernel-level enforcement
// authority armed — a loaded TracingPolicy in Tetragon's `enforce` mode.
//
// It answers "can the kernel kill without the engine", which is the question
// that makes the console's mode honest. Policies in `monitor` mode do not count:
// Tetragon suppresses their enforcing actions in-kernel, verified on v1.6.1.
func (r Record) KernelEnforcing() bool {
	for _, p := range r.KernelPolicies {
		if p.GetEnabled() && p.GetMode() == "enforce" {
			return true
		}
	}
	return false
}

// KernelEnforceActions totals enforcing actions that have ACTUALLY fired across
// this host's policies. Non-zero is evidence rather than risk: something was
// killed or diverted with no engine decision, so no audit row exists for it.
func (r Record) KernelEnforceActions() uint64 {
	var n uint64
	for _, p := range r.KernelPolicies {
		n += p.GetEnforceActions()
	}
	return n
}

// Diverged reports the condition EN-3 names: the operator has been told the
// host is detect-only while a kernel authority is armed to kill. This is the
// single fact worth alerting on — the rest is detail.
func (r Record) Diverged() bool {
	engineEnforcing := r.Mode == ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING
	return !engineEnforcing && r.KernelEnforcing()
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
		Chokes:               req.GetChokes(),
		Devices:              req.GetDevices(),
	}
	if info := req.GetAgentInfo(); info != nil {
		rec.Version = info.GetAgentVersion()
		rec.Kernel = info.GetKernel()
	}
	if dp := req.GetDataPlane(); dp != nil {
		rec.Mode = dp.GetMode()
		rec.DevicePlane = dp.GetDevicePlane()
		rec.DeviceLinks = dp.GetDeviceLinks()
		rec.DeviceMode = dp.GetDeviceMode()
		rec.KernelPolicies = dp.GetKernelPolicies()
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

// ListTenant returns every agent record for a tenant, newest-seen first. The
// tenant scoping is the caller's authz boundary; this only filters by the
// tenant already stamped on each record at heartbeat time.
func (r *Registry) ListTenant(tenant string) []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Record, 0, len(r.agents))
	for _, rec := range r.agents {
		if rec.TenantID == tenant {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
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
