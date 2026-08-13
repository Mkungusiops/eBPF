package policypull

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
)

// fakePolicyClient returns a canned bundle, standing in for the gRPC client.
type fakePolicyClient struct{ resp *ebpfsocv1.PolicyBundle }

func (f *fakePolicyClient) GetBundle(_ context.Context, _ *ebpfsocv1.PolicyPullRequest, _ ...grpc.CallOption) (*ebpfsocv1.PolicyBundle, error) {
	return f.resp, nil
}

func TestPullVerifiesAndApplies(t *testing.T) {
	signer, verifier, _ := signing.GenerateKey()
	store := NewStore(signer, "key-1")
	store.Set("v1", "etag-1", []byte("policy-content"))

	c := NewClient(verifier)
	applied, changed, err := c.Pull(context.Background(), &fakePolicyClient{resp: store.forEtag("")})
	if err != nil || !changed || applied == nil {
		t.Fatalf("Pull = (%v, %v, %v), want applied bundle", applied, changed, err)
	}
	if applied.Etag != "etag-1" || string(applied.Content) != "policy-content" {
		t.Fatalf("applied wrong bundle: %+v", applied)
	}
	if c.AppliedEtag() != "etag-1" {
		t.Fatalf("applied etag = %q", c.AppliedEtag())
	}
}

// TestTamperedBundleRejectedRetainsLastGood: a bundle whose content was altered
// after signing must fail verification, and the client must keep its last-good.
func TestTamperedBundleRejectedRetainsLastGood(t *testing.T) {
	signer, verifier, _ := signing.GenerateKey()
	store := NewStore(signer, "key-1")
	store.Set("v1", "etag-1", []byte("good-content"))

	c := NewClient(verifier)
	if _, _, err := c.Pull(context.Background(), &fakePolicyClient{resp: store.forEtag("")}); err != nil {
		t.Fatalf("first pull: %v", err)
	}

	good := store.forEtag("")
	tampered := &ebpfsocv1.PolicyBundle{
		Version:     good.GetVersion(),
		Etag:        "etag-2",
		Content:     []byte("evil-content"), // altered → signature no longer matches
		Signature:   good.GetSignature(),
		SignerKeyId: good.GetSignerKeyId(),
	}
	if _, changed, err := c.Pull(context.Background(), &fakePolicyClient{resp: tampered}); err == nil || changed {
		t.Fatal("tampered bundle must be rejected")
	}
	if c.AppliedEtag() != "etag-1" {
		t.Fatalf("last-good not retained: applied etag = %q, want etag-1", c.AppliedEtag())
	}
}

func TestNotModified(t *testing.T) {
	_, verifier, _ := signing.GenerateKey()
	c := NewClient(verifier)
	applied, changed, err := c.Pull(context.Background(), &fakePolicyClient{resp: &ebpfsocv1.PolicyBundle{NotModified: true}})
	if err != nil || changed || applied != nil {
		t.Fatalf("not-modified Pull = (%v, %v, %v), want (nil,false,nil)", applied, changed, err)
	}
}
