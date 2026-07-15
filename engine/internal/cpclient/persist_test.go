package cpclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/enrollment"
)

// certPEM mints a self-signed leaf with the given validity, for exercising the
// load-time expiry gate without standing up a real CA.
func certPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agent-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func sampleIdentity(cert []byte) *enrollment.Enrolled {
	return &enrollment.Enrolled{
		CertPEM:         cert,
		KeyPEM:          []byte("-----BEGIN EC PRIVATE KEY-----\nsecret\n-----END EC PRIVATE KEY-----\n"),
		CABundlePEM:     []byte("-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n"),
		AgentID:         "agent-abc123",
		UplinkEndpoint:  "cp:9443",
		CommandEndpoint: "cp:9443",
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	orig := sampleIdentity(certPEM(t, time.Now().Add(90*24*time.Hour)))

	if err := SaveIdentity(dir, orig); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, ok, err := LoadIdentity(dir)
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if got.AgentID != orig.AgentID || string(got.KeyPEM) != string(orig.KeyPEM) ||
		string(got.CABundlePEM) != string(orig.CABundlePEM) || got.UplinkEndpoint != orig.UplinkEndpoint {
		t.Fatalf("round-trip mismatch: got %+v", got)
	}

	// The private key must be owner-only; the rest world-readable.
	if fi, _ := os.Stat(filepath.Join(dir, fileKey)); fi.Mode().Perm() != 0o600 {
		t.Errorf("key perms = %v, want 0600", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(filepath.Join(dir, fileCert)); fi.Mode().Perm() != 0o644 {
		t.Errorf("cert perms = %v, want 0644", fi.Mode().Perm())
	}
}

func TestLoadMissingIsNotFound(t *testing.T) {
	_, ok, err := LoadIdentity(t.TempDir())
	if ok || err != nil {
		t.Fatalf("empty dir: ok=%v err=%v, want false/nil", ok, err)
	}
	if _, ok, err := LoadIdentity(""); ok || err != nil {
		t.Fatalf("empty path: ok=%v err=%v, want false/nil", ok, err)
	}
}

func TestLoadExpiredIsNotReused(t *testing.T) {
	dir := t.TempDir()
	// Inside the renewal window (expires in 2 days < 7-day window) → not reusable.
	if err := SaveIdentity(dir, sampleIdentity(certPEM(t, time.Now().Add(2*24*time.Hour)))); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := LoadIdentity(dir); ok || err != nil {
		t.Fatalf("near-expiry cert: ok=%v err=%v, want false/nil (forces re-enroll)", ok, err)
	}
}

func TestLoadCorruptCertErrors(t *testing.T) {
	dir := t.TempDir()
	if err := SaveIdentity(dir, sampleIdentity([]byte("not a pem cert"))); err != nil {
		t.Fatal(err)
	}
	// A present-but-corrupt identity must surface an error, not be silently
	// treated as "never enrolled" (which would re-enroll over real state).
	if _, ok, err := LoadIdentity(dir); ok || err == nil {
		t.Fatalf("corrupt cert: ok=%v err=%v, want false/non-nil", ok, err)
	}
}
