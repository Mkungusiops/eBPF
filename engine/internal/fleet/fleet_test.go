package fleet

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/policypull"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
)

// fakePolicyClient lets us drive the agent's policypull.Client with a fleet
// bundle, proving the fleet-signed bundle verifies on the agent side.
type fakePolicyClient struct{ resp *ebpfsocv1.PolicyBundle }

func (f *fakePolicyClient) GetBundle(_ context.Context, _ *ebpfsocv1.PolicyPullRequest, _ ...grpc.CallOption) (*ebpfsocv1.PolicyBundle, error) {
	return f.resp, nil
}

func versionFor(t *testing.T, s *Service, tenant, agent string) string {
	t.Helper()
	b, err := s.BundleForAgent(tenant, agent, "")
	if err != nil {
		t.Fatalf("BundleForAgent(%s,%s): %v", tenant, agent, err)
	}
	return b.GetVersion()
}

// TestStagedRollout: a new version reaches rings in order canary→limited→fleet,
// and only commits as stable once it reaches the fleet ring.
func TestStagedRollout(t *testing.T) {
	signer, _, _ := signing.GenerateKey()
	s := NewService(signer, "key-1")
	s.SetAgentRing("t", "canaryAgent", RingCanary)
	s.SetAgentRing("t", "limitedAgent", RingLimited)
	// fleetAgent left default → fleet ring.

	// v1 is the first bundle → stable for everyone.
	if err := s.Publish("t", "v1", []byte("p1")); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"canaryAgent", "limitedAgent", "fleetAgent"} {
		if v := versionFor(t, s, "t", a); v != "v1" {
			t.Fatalf("%s = %s, want v1", a, v)
		}
	}

	// v2 starts a rollout at canary.
	if err := s.Publish("t", "v2", []byte("p2")); err != nil {
		t.Fatal(err)
	}
	if v := versionFor(t, s, "t", "canaryAgent"); v != "v2" {
		t.Fatalf("canary after publish = %s, want v2", v)
	}
	if v := versionFor(t, s, "t", "limitedAgent"); v != "v1" {
		t.Fatalf("limited before promote = %s, want v1", v)
	}
	if v := versionFor(t, s, "t", "fleetAgent"); v != "v1" {
		t.Fatalf("fleet before promote = %s, want v1", v)
	}

	// Promote to limited.
	if r, err := s.Promote("t"); err != nil || r != RingLimited {
		t.Fatalf("promote1 = (%v,%v), want limited", r, err)
	}
	if v := versionFor(t, s, "t", "limitedAgent"); v != "v2" {
		t.Fatalf("limited after promote = %s, want v2", v)
	}
	if v := versionFor(t, s, "t", "fleetAgent"); v != "v1" {
		t.Fatalf("fleet still rolling = %s, want v1", v)
	}

	// Promote to fleet → commits stable.
	if r, err := s.Promote("t"); err != nil || r != RingFleet {
		t.Fatalf("promote2 = (%v,%v), want fleet", r, err)
	}
	if v := versionFor(t, s, "t", "fleetAgent"); v != "v2" {
		t.Fatalf("fleet after full rollout = %s, want v2", v)
	}
	if st := s.RolloutStatus("t"); st.Stable != "v2" || st.RolloutVersion != "" {
		t.Fatalf("status = %+v, want stable v2 no rollout", st)
	}
	if _, err := s.Promote("t"); err == nil {
		t.Fatal("promote with no rollout should error")
	}
}

// TestTenantIsolation: an agent only ever gets its own tenant's bundle.
func TestTenantIsolation(t *testing.T) {
	signer, _, _ := signing.GenerateKey()
	s := NewService(signer, "key-1")
	s.Publish("tenant-a", "va", []byte("policy-A"))
	s.Publish("tenant-b", "vb", []byte("policy-B"))

	ba, _ := s.BundleForAgent("tenant-a", "agent-a", "")
	bb, _ := s.BundleForAgent("tenant-b", "agent-b", "")
	if string(ba.GetContent()) != "policy-A" {
		t.Fatalf("tenant-a bundle = %q, want policy-A", ba.GetContent())
	}
	if string(bb.GetContent()) != "policy-B" {
		t.Fatalf("tenant-b bundle = %q, want policy-B", bb.GetContent())
	}
	// A tenant with no bundle yields ErrNoBundle.
	if _, err := s.BundleForAgent("tenant-c", "agent-c", ""); err != ErrNoBundle {
		t.Fatalf("unknown tenant err = %v, want ErrNoBundle", err)
	}
}

// TestFleetBundleVerifiesOnAgent: the fleet-signed bundle passes the agent's
// policy-pull verification, and a matching etag yields not-modified.
func TestFleetBundleVerifiesOnAgent(t *testing.T) {
	signer, verifier, _ := signing.GenerateKey()
	s := NewService(signer, "key-1")
	s.Publish("t", "v1", []byte("policy-v1"))

	b, _ := s.BundleForAgent("t", "a", "")
	client := policypull.NewClient(verifier)
	applied, changed, err := client.Pull(context.Background(), &fakePolicyClient{resp: b})
	if err != nil || !changed || applied == nil || applied.Version != "v1" {
		t.Fatalf("agent verify = (%v,%v,%v), want applied v1", applied, changed, err)
	}

	// Agent already on v1 → not modified.
	nm, _ := s.BundleForAgent("t", "a", "v1")
	if !nm.GetNotModified() {
		t.Fatalf("expected not_modified for current etag, got %+v", nm)
	}
}

// TestTamperedFleetBundleRejected: altering fleet content breaks the signature.
func TestTamperedFleetBundleRejected(t *testing.T) {
	signer, verifier, _ := signing.GenerateKey()
	s := NewService(signer, "key-1")
	s.Publish("t", "v1", []byte("good"))
	b, _ := s.BundleForAgent("t", "a", "")
	b.Content = []byte("evil") // tamper after signing

	client := policypull.NewClient(verifier)
	if _, changed, err := client.Pull(context.Background(), &fakePolicyClient{resp: b}); err == nil || changed {
		t.Fatal("tampered fleet bundle must be rejected by the agent")
	}
}
