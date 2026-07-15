package enrollment

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/mtls"
)

// Server implements ebpfsocv1.EnrollmentServiceServer: it verifies a one-time
// bootstrap token, then issues a client certificate binding the token's tenant.
// The tenant is taken from the token (server-side), never from the request —
// an agent cannot self-assign a tenant (isolation invariant R1/R4).
type Server struct {
	ebpfsocv1.UnimplementedEnrollmentServiceServer

	ca              *mtls.CA
	tokens          *TokenStore
	certTTL         time.Duration
	uplinkEndpoint  string
	commandEndpoint string
}

func NewServer(ca *mtls.CA, tokens *TokenStore, certTTL time.Duration, uplinkEndpoint, commandEndpoint string) *Server {
	return &Server{
		ca:              ca,
		tokens:          tokens,
		certTTL:         certTTL,
		uplinkEndpoint:  uplinkEndpoint,
		commandEndpoint: commandEndpoint,
	}
}

func (s *Server) Enroll(ctx context.Context, req *ebpfsocv1.EnrollRequest) (*ebpfsocv1.EnrollResponse, error) {
	tenant, ok := s.tokens.Redeem(req.GetBootstrapToken())
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "invalid, expired, or already-used bootstrap token")
	}
	agentID := newAgentID()
	certPEM, err := s.ca.IssueClient(req.GetCsrPem(), tenant, agentID, s.certTTL)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "issue certificate: %v", err)
	}
	return &ebpfsocv1.EnrollResponse{
		CertificatePem:  certPEM,
		CaBundlePem:     s.ca.CertPEM(),
		AgentId:         agentID,
		CertNotAfter:    timestamppb.New(time.Now().Add(s.certTTL)),
		UplinkEndpoint:  s.uplinkEndpoint,
		CommandEndpoint: s.commandEndpoint,
	}, nil
}

// Renew re-issues a certificate for an already-enrolled agent. The identity is
// taken from the caller's VERIFIED mTLS client cert (mtls.PeerTenant), never
// the request, so an agent keeps exactly its tenant_id + agent_id across
// rotations and cannot self-assign a new tenant (isolation invariant R4). No
// bootstrap token is involved — possession of a valid, unexpired client cert is
// the authorization.
func (s *Server) Renew(ctx context.Context, req *ebpfsocv1.RenewRequest) (*ebpfsocv1.EnrollResponse, error) {
	tenant, agentID, err := mtls.PeerTenant(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "renew requires a currently-enrolled mTLS client certificate")
	}
	certPEM, err := s.ca.IssueClient(req.GetCsrPem(), tenant, agentID, s.certTTL)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "issue certificate: %v", err)
	}
	return &ebpfsocv1.EnrollResponse{
		CertificatePem:  certPEM,
		CaBundlePem:     s.ca.CertPEM(),
		AgentId:         agentID,
		CertNotAfter:    timestamppb.New(time.Now().Add(s.certTTL)),
		UplinkEndpoint:  s.uplinkEndpoint,
		CommandEndpoint: s.commandEndpoint,
	}, nil
}

// newAgentID mints a random, opaque agent identifier. It is authoritative only
// once encoded into the issued cert's subject.
func newAgentID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "agent-" + hex.EncodeToString(b)
}
