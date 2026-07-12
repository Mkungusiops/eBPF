package enrollment

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/mtls"
)

func TestTokenOneTime(t *testing.T) {
	ts := NewTokenStore()
	tok, err := ts.Mint("tenant-x", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if tenant, ok := ts.Redeem(tok); !ok || tenant != "tenant-x" {
		t.Fatalf("first redeem = (%q,%v), want (tenant-x,true)", tenant, ok)
	}
	if _, ok := ts.Redeem(tok); ok {
		t.Fatal("second redeem of a one-time token must fail")
	}
}

func TestTokenExpiry(t *testing.T) {
	ts := NewTokenStore()
	tok, _ := ts.Mint("tenant-x", -time.Second) // already expired
	if _, ok := ts.Redeem(tok); ok {
		t.Fatal("expired token must not redeem")
	}
}

func TestEnrollIssuesTenantCert(t *testing.T) {
	ca, err := mtls.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	ts := NewTokenStore()
	tok, _ := ts.Mint("tenant-alpha", time.Hour)
	srv := NewServer(ca, ts, time.Hour, "uplink:9443", "command:9443")

	_, csrDER, _ := mtls.GenerateKeyAndCSR()
	resp, err := srv.Enroll(context.Background(), &ebpfsocv1.EnrollRequest{
		BootstrapToken: tok,
		CsrPem:         csrDER,
		AgentInfo:      &ebpfsocv1.AgentInfo{Hostname: "h1", AgentVersion: "0.2.0-agent"},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if resp.GetAgentId() == "" {
		t.Fatal("no agent id issued")
	}
	if len(resp.GetCaBundlePem()) == 0 {
		t.Fatal("no CA bundle returned")
	}

	blk, _ := pem.Decode(resp.GetCertificatePem())
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	tenant, agent, err := mtls.TenantFromCert(cert)
	if err != nil {
		t.Fatal(err)
	}
	if tenant != "tenant-alpha" || agent != resp.GetAgentId() {
		t.Fatalf("cert binds tenant=%q agent=%q, want tenant-alpha/%s", tenant, agent, resp.GetAgentId())
	}
}

func TestEnrollRejectsBadToken(t *testing.T) {
	ca, _ := mtls.NewCA()
	srv := NewServer(ca, NewTokenStore(), time.Hour, "", "")
	_, csrDER, _ := mtls.GenerateKeyAndCSR()
	if _, err := srv.Enroll(context.Background(), &ebpfsocv1.EnrollRequest{BootstrapToken: "bogus", CsrPem: csrDER}); err == nil {
		t.Fatal("enrollment with a bad token must fail")
	}
}
