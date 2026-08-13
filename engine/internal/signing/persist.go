package signing

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"strings"
)

// PrivateKey returns the raw ed25519 private-key bytes. Sensitive — persist 0600
// (KMS/Vault in production).
func (s Signer) PrivateKey() []byte { return append([]byte(nil), s.priv...) }

// SignerFromPrivateKey rebuilds a Signer from private-key bytes.
func SignerFromPrivateKey(priv []byte) (Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Signer{}, errors.New("signing: invalid private key length")
	}
	return Signer{priv: ed25519.PrivateKey(append([]byte(nil), priv...))}, nil
}

// LoadOrCreateSigner loads the ed25519 signing key (hex) from path, or generates
// one and writes it 0600 when absent. This gives the fleet a STABLE signing key
// across restarts, so agents that pinned its public key keep verifying commands
// and policy bundles.
func LoadOrCreateSigner(path string) (Signer, error) {
	if raw, err := os.ReadFile(path); err == nil {
		priv, derr := hex.DecodeString(strings.TrimSpace(string(raw)))
		if derr != nil {
			return Signer{}, derr
		}
		return SignerFromPrivateKey(priv)
	}
	s, _, err := GenerateKey()
	if err != nil {
		return Signer{}, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(s.PrivateKey())), 0o600); err != nil {
		return Signer{}, err
	}
	return s, nil
}
