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
	"strings"
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
	// FramesSeen is forwarded frames this agent's data plane has actually
	// observed. The control plane has no data plane of its own, so without
	// this it reported zero and the console's bridge-master warning fired on
	// every deployment.
	FramesSeen uint64
	// DevicesSeen is devices the data plane observed, not devices known.
	DevicesSeen uint32
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
	// Drill detail behind the Choke Gateway page. Only the agent can see these
	// — they are kernel and /proc state — so a control plane without them can
	// only render those panels empty. Capped by the agent; empty from an agent
	// predating the fields.
	Buckets   []*ebpfsocv1.BucketSummary
	Cgroups   []*ebpfsocv1.CgroupSummary
	Processes []*ebpfsocv1.ProcessSummary
	// ProcessPlane / ProcessLinks are the PROCESS choke data plane, the
	// counterpart of DevicePlane / DeviceLinks above. Both wire fields existed
	// from the start and neither was ever populated by the agent, so a control
	// plane could not tell a live cgroup/BPF data plane from the noop fallback.
	ProcessPlane string
	ProcessLinks int32
	// Thresholds is the score ladder the agent is ACTUALLY running. Nil from an
	// agent predating the field — callers must fall back rather than render a
	// zero ladder, since 0/0/0/0 reads as "contains everything immediately".
	Thresholds *ebpfsocv1.ChokeThresholds
	// DroppedRecords is telemetry this agent has PERMANENTLY lost to the uplink
	// buffer cap — evidence that will never arrive, as distinct from
	// BufferDepth, which is a backlog that still will. DroppedBroadcast is the
	// agent's local console missing live frames, which is not an evidence gap.
	DroppedRecords   uint64
	DroppedBroadcast uint64
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
	// roster persists agent identity beyond this process. nil keeps the
	// memory-only behaviour. See SetRosterSink.
	roster RosterSink
}

func NewRegistry() *Registry {
	return &Registry{now: time.Now, agents: make(map[string]Record)}
}

func key(tenant, agent string) string { return tenant + "\x00" + agent }

// Record updates the registry from a heartbeat request. tenant/agent come from
// the verified cert (the caller), not the request body.
// Simulated reports whether this record came from cmd/simagent rather than a
// real host.
//
// The simulator has always identified itself — AgentVersion "sim-0.1", Kernel
// "6.8.0-sim" — and nothing ever read it. So its telemetry landed in the same
// tenant ledger as real containment, indistinguishable: on the live estate,
// 431 fabricated decisions sat beside real ones with nothing to tell them
// apart. An audit trail that cannot separate demo data from evidence is not an
// audit trail.
//
// Matched on the version PREFIX and the kernel SUFFIX rather than an exact
// string, so a simulator that bumps its own version does not silently start
// passing as real.
func (rec Record) Simulated() bool {
	return strings.HasPrefix(rec.Version, "sim-") || strings.HasSuffix(rec.Kernel, "-sim")
}

// IsSimulated answers for one agent, for the ingest path to stamp its records.
//
// An agent the registry has not heard from yet answers false. That is the
// right way round: a real agent must never be mislabelled as synthetic, and a
// simulator is mislabelled only in the seconds between control-plane start and
// its first heartbeat.
func (r *Registry) IsSimulated(tenant, agent string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.agents[key(tenant, agent)]
	return ok && rec.Simulated()
}

// RosterSink persists an agent's identity so it survives a restart.
//
// Injected rather than imported, so this package keeps no dependency on the
// central store and a deployment without one behaves exactly as before.
type RosterSink func(tenant, agent, hostname, version, arch, mode string, bufferDepth int64)

// SetRosterSink wires durable roster persistence.
func (r *Registry) SetRosterSink(fn RosterSink) {
	r.mu.Lock()
	r.roster = fn
	r.mu.Unlock()
}

func (r *Registry) Record(tenant, agent string, req *ebpfsocv1.HeartbeatRequest) {
	rec := Record{
		TenantID:             tenant,
		AgentID:              agent,
		LastSeen:             r.now(),
		BufferDepth:          req.GetBufferDepth(),
		AppliedPolicyVersion: req.GetAppliedPolicyVersion(),
		Chokes:               req.GetChokes(),
		Devices:              req.GetDevices(),
		Buckets:              req.GetBuckets(),
		Cgroups:              req.GetCgroups(),
		Processes:            req.GetProcesses(),
	}
	if info := req.GetAgentInfo(); info != nil {
		rec.Version = info.GetAgentVersion()
		rec.Kernel = info.GetKernel()
	}
	if dp := req.GetDataPlane(); dp != nil {
		rec.Mode = dp.GetMode()
		rec.DevicePlane = dp.GetDevicePlane()
		rec.DeviceLinks = dp.GetDeviceLinks()
		rec.FramesSeen = dp.GetFramesSeen()
		rec.DevicesSeen = dp.GetDevicesSeen()
		rec.DeviceMode = dp.GetDeviceMode()
		rec.KernelPolicies = dp.GetKernelPolicies()
		rec.ProcessPlane = dp.GetProcessPlane()
		rec.ProcessLinks = dp.GetProcessLinks()
		rec.Thresholds = dp.GetThresholds()
	}
	rec.DroppedRecords = req.GetDroppedRecords()
	rec.DroppedBroadcast = req.GetDroppedBroadcast()
	r.mu.Lock()
	r.agents[key(tenant, agent)] = rec
	roster := r.roster
	r.mu.Unlock()
	// Outside the lock: the sink writes to a database, and holding the
	// registry mutex across that would serialise every agent's heartbeat
	// behind one slow query.
	if roster != nil {
		info := req.GetAgentInfo()
		roster(tenant, agent, info.GetHostname(), rec.Version, info.GetArch(),
			rec.Mode.String(), int64(rec.BufferDepth))
	}
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
// Tenants lists the tenants that currently have a reporting agent.
//
// Derived from live records rather than a configured list: a control plane's
// idea of "which tenants exist" should come from who is actually reporting,
// not from a roster that can drift.
func (r *Registry) Tenants() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := map[string]bool{}
	out := []string{}
	for _, rec := range r.agents {
		if !seen[rec.TenantID] {
			seen[rec.TenantID] = true
			out = append(out, rec.TenantID)
		}
	}
	sort.Strings(out)
	return out
}

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
