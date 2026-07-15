package mtls

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLoadOrCreateCARestartKeepsTrust: a second LoadOrCreateCA from the same
// paths loads the SAME CA, and a cert the restarted CA issues still chains to
// the bundle an agent pinned on the first start.
func TestLoadOrCreateCARestartKeepsTrust(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")

	ca1, err := LoadOrCreateCA(certPath, keyPath) // generates + persists
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := LoadOrCreateCA(certPath, keyPath) // loads the persisted CA
	if err != nil {
		t.Fatal(err)
	}
	if string(ca1.CertPEM()) != string(ca2.CertPEM()) {
		t.Fatal("CA bundle changed across restart — agents would lose trust")
	}

	_, csr, err := GenerateKeyAndCSR()
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, err := ca2.IssueClient(csr, "tenant-a", "agent-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := parseCert(t, leafPEM)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     ca1.Pool(), // the pool an agent pinned from start #1
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("cert from restarted CA does not chain to the pinned CA: %v", err)
	}

	if fi, err := os.Stat(keyPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("CA key perms = %v (err %v), want 0600", fi.Mode().Perm(), err)
	}
}
