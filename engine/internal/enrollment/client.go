package enrollment

import (
	"context"

	"google.golang.org/grpc"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/mtls"
)

// Enrolled is everything an agent needs after a successful enrollment to open
// the mTLS channels. The private key is generated locally and never leaves the
// host.
type Enrolled struct {
	CertPEM         []byte
	KeyPEM          []byte
	CABundlePEM     []byte
	AgentID         string
	UplinkEndpoint  string
	CommandEndpoint string
}

// Enroll runs the agent side of the handshake over cc — a bootstrap,
// server-auth TLS connection that already trusts the control plane's CA. It
// generates the keypair + CSR locally, exchanges the one-time token for a cert,
// and returns the issued identity.
func Enroll(ctx context.Context, cc *grpc.ClientConn, bootstrapToken string, info *ebpfsocv1.AgentInfo) (*Enrolled, error) {
	keyPEM, csrDER, err := mtls.GenerateKeyAndCSR()
	if err != nil {
		return nil, err
	}
	resp, err := ebpfsocv1.NewEnrollmentServiceClient(cc).Enroll(ctx, &ebpfsocv1.EnrollRequest{
		BootstrapToken: bootstrapToken,
		CsrPem:         csrDER,
		AgentInfo:      info,
	})
	if err != nil {
		return nil, err
	}
	return &Enrolled{
		CertPEM:         resp.GetCertificatePem(),
		KeyPEM:          keyPEM,
		CABundlePEM:     resp.GetCaBundlePem(),
		AgentID:         resp.GetAgentId(),
		UplinkEndpoint:  resp.GetUplinkEndpoint(),
		CommandEndpoint: resp.GetCommandEndpoint(),
	}, nil
}

// Renew rotates an already-enrolled identity over the agent's EXISTING mTLS
// connection cc (authenticated by the current client cert). It mints a fresh
// keypair + CSR locally and exchanges it for a new cert bound to the same
// tenant/agent — the server derives those from the peer cert, not the request.
func Renew(ctx context.Context, cc *grpc.ClientConn, info *ebpfsocv1.AgentInfo) (*Enrolled, error) {
	keyPEM, csrDER, err := mtls.GenerateKeyAndCSR()
	if err != nil {
		return nil, err
	}
	resp, err := ebpfsocv1.NewEnrollmentServiceClient(cc).Renew(ctx, &ebpfsocv1.RenewRequest{
		CsrPem:    csrDER,
		AgentInfo: info,
	})
	if err != nil {
		return nil, err
	}
	return &Enrolled{
		CertPEM:         resp.GetCertificatePem(),
		KeyPEM:          keyPEM,
		CABundlePEM:     resp.GetCaBundlePem(),
		AgentID:         resp.GetAgentId(),
		UplinkEndpoint:  resp.GetUplinkEndpoint(),
		CommandEndpoint: resp.GetCommandEndpoint(),
	}, nil
}
