// Package signing is the ed25519 sign/verify primitive behind the
// "signed-everything-downstream" rule of the wire contract: the fleet service
// signs commands and policy bundles, and the agent verifies them before acting
// (docs/plan/wire-contract.md §5; threat-model.md CH-5, SC-4). The private key
// lives in the control plane (KMS in production, SC-6); the agent holds only the
// public key.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
)

// Signer holds the fleet private key and signs canonical bytes.
type Signer struct{ priv ed25519.PrivateKey }

// Verifier holds a public key and checks signatures. The agent is given the
// fleet's Verifier out-of-band / at enrollment.
type Verifier struct{ pub ed25519.PublicKey }

// GenerateKey produces a fresh signing keypair.
func GenerateKey() (Signer, Verifier, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Signer{}, Verifier{}, err
	}
	return Signer{priv: priv}, Verifier{pub: pub}, nil
}

// Sign returns the detached signature over msg.
func (s Signer) Sign(msg []byte) []byte { return ed25519.Sign(s.priv, msg) }

// PublicKey returns the verifier's public key bytes (to distribute to agents).
func (s Signer) Verifier() Verifier { return Verifier{pub: s.priv.Public().(ed25519.PublicKey)} }

// Verify reports whether sig is a valid signature over msg. A zero Verifier
// (no key) always returns false — fail closed.
func (v Verifier) Verify(msg, sig []byte) bool {
	if len(v.pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(v.pub, msg, sig)
}

// PublicKey returns a copy of the public key bytes.
func (v Verifier) PublicKey() []byte { return append([]byte(nil), v.pub...) }

// VerifierFromPublicKey rebuilds a Verifier from distributed public-key bytes.
func VerifierFromPublicKey(pub []byte) (Verifier, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Verifier{}, errors.New("signing: invalid public key length")
	}
	return Verifier{pub: ed25519.PublicKey(append([]byte(nil), pub...))}, nil
}
