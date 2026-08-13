// Package fleet is the control-plane fleet/policy service (architecture.md
// §3.5): it holds signed policy bundles per tenant, assigns agents to rollout
// rings, and serves each agent the bundle version appropriate for its ring
// during a staged rollout (canary → limited → fleet). It reuses internal/signing
// + internal/policypull so the bundles it serves verify with the agent's
// existing policy-pull client.
//
// TENANCY: bundles and ring assignments are keyed by tenant, and the policy
// server derives (tenant, agent) from the mTLS certificate — an agent can only
// ever receive its own tenant's bundle (isolation invariant, Layer 1→3).
package fleet

import (
	"context"
	"errors"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/mtls"
	"github.com/jeffmk/ebpf-poc-engine/internal/policypull"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
)

// Ring is a staged-rollout ring. Rollout promotes in this order.
type Ring string

const (
	RingCanary  Ring = "canary"
	RingLimited Ring = "limited"
	RingFleet   Ring = "fleet"
)

// ringOrder is the promotion order: a lower number is reached earlier.
var ringOrder = map[Ring]int{RingCanary: 0, RingLimited: 1, RingFleet: 2}

// ErrNoBundle is returned when a tenant has no published bundle.
var ErrNoBundle = errors.New("fleet: tenant has no published policy bundle")

type rollout struct {
	version string
	reached Ring // highest ring the rollout version has reached
}

type tenantState struct {
	bundles map[string][]byte // version → content
	stable  string            // fleet-wide stable version
	roll    *rollout          // in-progress rollout, or nil
	rings   map[string]Ring   // agent_id → ring (default RingFleet)
}

// Service manages per-tenant signed bundles + staged rollouts.
type Service struct {
	signer signing.Signer
	keyID  string

	mu      sync.Mutex
	tenants map[string]*tenantState
}

func NewService(signer signing.Signer, keyID string) *Service {
	return &Service{signer: signer, keyID: keyID, tenants: make(map[string]*tenantState)}
}

func (s *Service) state(tenant string) *tenantState {
	ts := s.tenants[tenant]
	if ts == nil {
		ts = &tenantState{bundles: map[string][]byte{}, rings: map[string]Ring{}}
		s.tenants[tenant] = ts
	}
	return ts
}

// Publish stores a signed bundle version for a tenant. The first version becomes
// stable immediately; a later version begins a staged rollout at the canary ring.
func (s *Service) Publish(tenant, version string, content []byte) error {
	if tenant == "" || version == "" {
		return errors.New("fleet: tenant and version required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := s.state(tenant)
	ts.bundles[version] = content
	if ts.stable == "" {
		ts.stable = version
		return nil
	}
	if version != ts.stable {
		ts.roll = &rollout{version: version, reached: RingCanary}
	}
	return nil
}

// Promote advances the tenant's in-progress rollout to the next ring. Reaching
// the fleet ring commits the rollout version as the new stable and ends it.
func (s *Service) Promote(tenant string) (Ring, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := s.tenants[tenant]
	if ts == nil || ts.roll == nil {
		return "", errors.New("fleet: no rollout in progress")
	}
	switch ts.roll.reached {
	case RingCanary:
		ts.roll.reached = RingLimited
	case RingLimited:
		ts.roll.reached = RingFleet
		ts.stable = ts.roll.version
		ts.roll = nil
		return RingFleet, nil
	}
	return ts.roll.reached, nil
}

// SetAgentRing assigns an agent to a ring (defaults to fleet if never set).
func (s *Service) SetAgentRing(tenant, agent string, ring Ring) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state(tenant).rings[agent] = ring
}

// versionForAgent computes which version an agent's ring should currently run.
func versionForAgent(ts *tenantState, agent string) string {
	ring := ts.rings[agent]
	if ring == "" {
		ring = RingFleet
	}
	if ts.roll != nil && ringOrder[ring] <= ringOrder[ts.roll.reached] {
		return ts.roll.version
	}
	return ts.stable
}

// BundleForAgent returns the signed bundle the agent should apply. If the agent
// already has the right version (currentEtag == version) it returns
// not_modified; if the tenant has no bundle, it returns (nil, ErrNoBundle).
func (s *Service) BundleForAgent(tenant, agent, currentEtag string) (*ebpfsocv1.PolicyBundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := s.tenants[tenant]
	if ts == nil || ts.stable == "" {
		return nil, ErrNoBundle
	}
	version := versionForAgent(ts, agent)
	if version == currentEtag {
		return &ebpfsocv1.PolicyBundle{NotModified: true}, nil
	}
	// etag == version: content is deterministic per version.
	return policypull.SignedBundle(s.signer, s.keyID, version, version, ts.bundles[version]), nil
}

// RolloutStatus reports the stable version and any in-progress rollout for a
// tenant (for the console/fleet UI).
type RolloutStatus struct {
	Stable         string
	RolloutVersion string
	ReachedRing    Ring
}

func (s *Service) RolloutStatus(tenant string) RolloutStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := s.tenants[tenant]
	if ts == nil {
		return RolloutStatus{}
	}
	st := RolloutStatus{Stable: ts.stable}
	if ts.roll != nil {
		st.RolloutVersion = ts.roll.version
		st.ReachedRing = ts.roll.reached
	}
	return st
}

// PolicyServer implements ebpfsocv1.PolicyServiceServer backed by the fleet
// Service. It derives (tenant, agent) from the mTLS certificate — never a
// request field — so an agent only ever receives its own tenant's bundle.
type PolicyServer struct {
	ebpfsocv1.UnimplementedPolicyServiceServer
	svc *Service
}

func NewPolicyServer(svc *Service) *PolicyServer { return &PolicyServer{svc: svc} }

func (p *PolicyServer) GetBundle(ctx context.Context, req *ebpfsocv1.PolicyPullRequest) (*ebpfsocv1.PolicyBundle, error) {
	tenant, agent, err := mtls.PeerTenant(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	b, err := p.svc.BundleForAgent(tenant, agent, req.GetCurrentEtag())
	if errors.Is(err, ErrNoBundle) {
		// No bundle yet is a valid "nothing to apply" state, not an error.
		return &ebpfsocv1.PolicyBundle{NotModified: true}, nil
	}
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return b, nil
}
