package enrollment

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/mtls"
)

func leaf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("issued cert is not PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// peerCtx fakes the gRPC context a verified mTLS request would carry, so the
// Renew handler can read the identity out of VerifiedChains.
func peerCtx(cert *x509.Certificate) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{cert}},
		}},
	})
}

func TestRenewKeepsIdentityIssuesNewCert(t *testing.T) {
	ca, err := mtls.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	ts := NewTokenStore()
	tok, _ := ts.Mint("tenant-alpha", time.Hour)
	srv := NewServer(ca, ts, time.Hour, "uplink:9443", "command:9443")

	_, csr1, _ := mtls.GenerateKeyAndCSR()
	enrolled, err := srv.Enroll(context.Background(), &ebpfsocv1.EnrollRequest{BootstrapToken: tok, CsrPem: csr1})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	orig := leaf(t, enrolled.GetCertificatePem())

	// Renew over the (faked) mTLS identity — no token, a fresh CSR.
	_, csr2, _ := mtls.GenerateKeyAndCSR()
	renewed, err := srv.Renew(peerCtx(orig), &ebpfsocv1.RenewRequest{CsrPem: csr2})
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	next := leaf(t, renewed.GetCertificatePem())

	// Same tenant + same agent id (identity carried by the peer cert, not the request).
	if got := next.Subject.Organization[0]; got != "tenant-alpha" {
		t.Errorf("renewed tenant = %q, want tenant-alpha", got)
	}
	if next.Subject.CommonName != orig.Subject.CommonName {
		t.Errorf("renewed agent id = %q, want %q (must not change)", next.Subject.CommonName, orig.Subject.CommonName)
	}
	if renewed.GetAgentId() != enrolled.GetAgentId() {
		t.Errorf("renewed agent_id = %q, want %q", renewed.GetAgentId(), enrolled.GetAgentId())
	}
	// A genuinely new certificate (different serial), not the same bytes.
	if next.SerialNumber.Cmp(orig.SerialNumber) == 0 {
		t.Error("renewed cert has the same serial as the original — not a fresh cert")
	}
}

func TestRenewRejectsWithoutClientCert(t *testing.T) {
	ca, _ := mtls.NewCA()
	srv := NewServer(ca, NewTokenStore(), time.Hour, "u:9443", "c:9443")
	_, csr, _ := mtls.GenerateKeyAndCSR()

	// No peer / no mTLS cert on the context → must be refused, not issued.
	_, err := srv.Renew(context.Background(), &ebpfsocv1.RenewRequest{CsrPem: csr})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Renew without client cert = %v, want Unauthenticated", err)
	}
}
