package controlplane_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
	"github.com/jeffmk/ebpf-poc-engine/internal/controlplane"
	"github.com/jeffmk/ebpf-poc-engine/internal/enrollment"
	"github.com/jeffmk/ebpf-poc-engine/internal/mtls"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
)

// TestRenewOverMTLS proves cert rotation end-to-end over a real mTLS gRPC
// connection: an enrolled agent calls Renew (no bootstrap token) authenticated
// only by its current client cert, and gets a fresh cert bound to the SAME
// tenant + agent id — the identity the server reads out of the TLS peer chain.
func TestRenewOverMTLS(t *testing.T) {
	ca, err := mtls.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	signer, _, _ := signing.GenerateKey()
	cs, err := centralstore.Open(filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	cp, err := controlplane.New(controlplane.Config{
		CA: ca, ServerName: "127.0.0.1", FleetSigner: signer, FleetKeyID: "k",
		Store: cs, AdminToken: "admin-secret", CertTTL: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	grpcLis, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = cp.GRPC().Serve(grpcLis) }()
	t.Cleanup(cp.GRPC().Stop)
	httpLis, _ := net.Listen("tcp", "127.0.0.1:0")
	httpSrv := &http.Server{Handler: cp.HTTP()}
	go func() { _ = httpSrv.Serve(httpLis) }()
	t.Cleanup(func() { _ = httpSrv.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Bootstrap enroll (token) → get the first identity.
	body := adminReq(t, "POST", "http://"+httpLis.Addr().String()+"/api/admin/enroll-token", "admin-secret", map[string]any{"tenant": "tenant-alpha"})
	token, _ := body["token"].(string)
	caPEM, _ := body["ca_bundle_pem"].(string)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(caPEM))

	boot, err := grpc.NewClient(grpcLis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(mtls.BootstrapTLSConfig(pool, "127.0.0.1"))))
	if err != nil {
		t.Fatal(err)
	}
	en, err := enrollment.Enroll(ctx, boot, token, &ebpfsocv1.AgentInfo{Hostname: "h1"})
	boot.Close()
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	// Reconnect using the ISSUED cert (real mTLS) and renew — no token.
	cfg, _ := mtls.ClientTLSConfig(en.CertPEM, en.KeyPEM, pool, "127.0.0.1")
	mcc, err := grpc.NewClient(grpcLis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	defer mcc.Close()

	renewed, err := enrollment.Renew(ctx, mcc, &ebpfsocv1.AgentInfo{Hostname: "h1", AgentVersion: "0.2.0"})
	if err != nil {
		t.Fatalf("renew over mTLS: %v", err)
	}

	if renewed.AgentID != en.AgentID {
		t.Errorf("renewed agent_id = %q, want %q (must not change)", renewed.AgentID, en.AgentID)
	}
	// Same tenant, and a genuinely different cert + key.
	nleaf := parseLeaf(t, renewed.CertPEM)
	if org := nleaf.Subject.Organization; len(org) == 0 || org[0] != "tenant-alpha" {
		t.Errorf("renewed tenant = %v, want tenant-alpha", org)
	}
	if string(renewed.CertPEM) == string(en.CertPEM) {
		t.Error("renewed cert is byte-identical to the original")
	}
	if string(renewed.KeyPEM) == string(en.KeyPEM) {
		t.Error("renew reused the old private key — a fresh keypair is expected")
	}

	// The renewed cert must actually authenticate a subsequent mTLS call.
	cfg2, _ := mtls.ClientTLSConfig(renewed.CertPEM, renewed.KeyPEM, pool, "127.0.0.1")
	cc2, err := grpc.NewClient(grpcLis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(cfg2)))
	if err != nil {
		t.Fatal(err)
	}
	defer cc2.Close()
	if _, err := enrollment.Renew(ctx, cc2, &ebpfsocv1.AgentInfo{Hostname: "h1"}); err != nil {
		t.Fatalf("renewed identity could not re-authenticate: %v", err)
	}
}

func parseLeaf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("cert is not PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
