package signing

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadOrCreateSignerRestartKeepsKey: a reload yields the SAME key, so a
// signature made before a restart still verifies after — agents that pinned the
// public key keep trusting fleet commands + policy bundles.
func TestLoadOrCreateSignerRestartKeepsKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.key")

	s1, err := LoadOrCreateSigner(path) // generates + persists
	if err != nil {
		t.Fatal(err)
	}
	s2, err := LoadOrCreateSigner(path) // loads the persisted key
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("v1\netag-1\npolicy-content")
	if !s2.Verifier().Verify(msg, s1.Sign(msg)) {
		t.Fatal("fleet signing key changed across restart")
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key perms = %v (err %v), want 0600", fi.Mode().Perm(), err)
	}
	if _, err := SignerFromPrivateKey([]byte("too-short")); err == nil {
		t.Fatal("a malformed private key must be rejected")
	}
}
