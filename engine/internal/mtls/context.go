package mtls

import (
	"context"
	"errors"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// PeerTenant derives (tenant_id, agent_id) from the VERIFIED mTLS client
// certificate on a gRPC request/stream context. gRPC/TLS has already validated
// the chain to our CA (RequireAndVerifyClientCert / VerifyClientCertIfGiven)
// before this runs; we only read the subject. It is the single derivation used
// by every tenant-aware control-plane handler (ingest, heartbeat, command) so
// the isolation invariant (R1) has exactly one implementation.
func PeerTenant(ctx context.Context) (tenantID, agentID string, err error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", "", errors.New("mtls: no peer information on context")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", "", errors.New("mtls: connection is not mTLS")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", "", errors.New("mtls: no verified client certificate")
	}
	return TenantFromCert(tlsInfo.State.VerifiedChains[0][0])
}
