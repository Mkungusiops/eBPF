// Package policypull is the signed policy-bundle channel (wire-contract.md §5).
// The control plane serves a signed bundle by etag; the agent VERIFIES the
// signature before applying and, on any verification failure, retains its
// last-good bundle rather than applying unverified policy (threat-model.md
// SC-4). Bundle CONTENT (TracingPolicies + ChokePolicy DSL + thresholds +
// protected lists) is opaque here — this package only fetches and verifies;
// the agent's policy loader applies it.
package policypull

import (
	"context"
	"errors"
	"sync"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
)

// canonicalBundle is the byte sequence that is signed and verified. Binding
// version + etag + content prevents metadata swapping. Both sides must agree.
func canonicalBundle(version, etag string, content []byte) []byte {
	b := make([]byte, 0, len(version)+len(etag)+len(content)+2)
	b = append(b, version...)
	b = append(b, '\n')
	b = append(b, etag...)
	b = append(b, '\n')
	b = append(b, content...)
	return b
}

// Store holds the current signed bundle on the control plane and serves it by
// etag. Minimal Phase 1 form; the fleet service owns bundle composition later.
type Store struct {
	signer signing.Signer
	keyID  string

	mu  sync.Mutex
	cur *ebpfsocv1.PolicyBundle
}

func NewStore(signer signing.Signer, keyID string) *Store {
	return &Store{signer: signer, keyID: keyID}
}

// Set signs (version, etag, content) and makes it the current bundle.
func (s *Store) Set(version, etag string, content []byte) {
	sig := s.signer.Sign(canonicalBundle(version, etag, content))
	s.mu.Lock()
	s.cur = &ebpfsocv1.PolicyBundle{
		Version:     version,
		Etag:        etag,
		Content:     content,
		Signature:   sig,
		SignerKeyId: s.keyID,
	}
	s.mu.Unlock()
}

// forEtag returns the current bundle, or a not_modified response when the
// caller already has it (or nothing is set yet).
func (s *Store) forEtag(currentEtag string) *ebpfsocv1.PolicyBundle {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil || (currentEtag != "" && currentEtag == s.cur.GetEtag()) {
		return &ebpfsocv1.PolicyBundle{NotModified: true}
	}
	return s.cur
}

// Server implements ebpfsocv1.PolicyServiceServer.
type Server struct {
	ebpfsocv1.UnimplementedPolicyServiceServer
	store *Store
}

func NewServer(store *Store) *Server { return &Server{store: store} }

func (srv *Server) GetBundle(_ context.Context, req *ebpfsocv1.PolicyPullRequest) (*ebpfsocv1.PolicyBundle, error) {
	return srv.store.forEtag(req.GetCurrentEtag()), nil
}

// Applied is a verified bundle the agent may apply.
type Applied struct {
	Version string
	Etag    string
	Content []byte
}

// Client is the agent side: it pulls, verifies, and tracks the last-good etag.
type Client struct {
	verify signing.Verifier

	mu          sync.Mutex
	appliedEtag string
	lastGood    *Applied
}

func NewClient(verify signing.Verifier) *Client { return &Client{verify: verify} }

// AppliedEtag is the etag of the last successfully-verified bundle.
func (c *Client) AppliedEtag() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.appliedEtag
}

// LastGood returns the last verified bundle (nil if none).
func (c *Client) LastGood() *Applied {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastGood
}

// Pull fetches the bundle for the agent's current etag and verifies it.
//   - not modified            → (nil, false, nil)
//   - new + valid signature   → (bundle, true, nil), last-good updated
//   - signature invalid       → (nil, false, error), LAST-GOOD RETAINED
//
// The caller applies the returned bundle; a verification error means the agent
// keeps enforcing its previous, verified policy (autonomy + SC-4).
func (c *Client) Pull(ctx context.Context, pc ebpfsocv1.PolicyServiceClient) (*Applied, bool, error) {
	c.mu.Lock()
	etag := c.appliedEtag
	c.mu.Unlock()

	resp, err := pc.GetBundle(ctx, &ebpfsocv1.PolicyPullRequest{CurrentEtag: etag})
	if err != nil {
		return nil, false, err
	}
	if resp.GetNotModified() {
		return nil, false, nil
	}
	if !c.verify.Verify(canonicalBundle(resp.GetVersion(), resp.GetEtag(), resp.GetContent()), resp.GetSignature()) {
		return nil, false, errors.New("policypull: bundle signature verification failed; retaining last-good bundle")
	}
	applied := &Applied{Version: resp.GetVersion(), Etag: resp.GetEtag(), Content: resp.GetContent()}
	c.mu.Lock()
	c.appliedEtag = applied.Etag
	c.lastGood = applied
	c.mu.Unlock()
	return applied, true, nil
}
