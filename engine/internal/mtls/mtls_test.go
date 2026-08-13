package mtls

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func parseCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		t.Fatal("no PEM block")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c
}

// TestIssueBindsTenantAndChains is the security-critical test: the issued cert
// encodes the tenant/agent the CA was told (NOT anything in the CSR), it chains
// to the CA, and TenantFromCert reads the binding back.
func TestIssueBindsTenantAndChains(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	_, csrDER, err := GenerateKeyAndCSR() // CSR subject is "pending-enrollment"
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := ca.IssueClient(csrDER, "tenant-a", "agent-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert := parseCert(t, certPEM)

	tenant, agent, err := TenantFromCert(cert)
	if err != nil {
		t.Fatalf("TenantFromCert: %v", err)
	}
	if tenant != "tenant-a" || agent != "agent-1" {
		t.Fatalf("got tenant=%q agent=%q, want tenant-a/agent-1 (CA binding, not CSR)", tenant, agent)
	}

	// Chains to the CA with client-auth usage.
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     ca.Pool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("issued cert does not chain to CA: %v", err)
	}
}

// TestDistinctTenantsAreDistinct: two agents enrolled under different tenants
// carry different, non-forgeable tenant bindings (the fixture the isolation
// invariant needs — identical-looking agents, different tenants).
func TestDistinctTenantsAreDistinct(t *testing.T) {
	ca, _ := NewCA()
	_, csrA, _ := GenerateKeyAndCSR()
	_, csrB, _ := GenerateKeyAndCSR()
	aPEM, _ := ca.IssueClient(csrA, "tenant-a", "agent-1", time.Hour)
	bPEM, _ := ca.IssueClient(csrB, "tenant-b", "agent-1", time.Hour) // same agent id, different tenant

	ta, _, _ := TenantFromCert(parseCert(t, aPEM))
	tb, _, _ := TenantFromCert(parseCert(t, bPEM))
	if ta == tb {
		t.Fatalf("tenants must differ: %q == %q", ta, tb)
	}
}

func TestTenantFromCertRejectsMissing(t *testing.T) {
	if _, _, err := TenantFromCert(nil); err == nil {
		t.Fatal("nil cert must error")
	}
	// A cert with no Organization must be rejected (no ambient tenant, R3).
	ca, _ := NewCA()
	_, csr, _ := GenerateKeyAndCSR()
	if _, err := ca.IssueClient(csr, "", "agent-1", time.Hour); err == nil {
		t.Fatal("issuing with empty tenant must error")
	}
}

func TestServerCertChains(t *testing.T) {
	ca, _ := NewCA()
	certPEM, _, err := ca.IssueServer("127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert := parseCert(t, certPEM)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     ca.Pool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("server cert does not chain: %v", err)
	}
}
