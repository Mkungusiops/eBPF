package mtls

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

// KeyPEM exports the CA private key as PEM (EC PRIVATE KEY). It is sensitive —
// persist it 0600, and in production keep it in KMS/Vault (threat-model SC-6).
func (ca *CA) KeyPEM() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return nil, err
	}
	return pemBlock("EC PRIVATE KEY", der), nil
}

// LoadCA reconstructs a CA from its certificate + private-key PEM.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, errors.New("mtls: invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("mtls: invalid CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, certPEM: append([]byte(nil), certPEM...)}, nil
}

// LoadOrCreateCA loads the CA from certPath+keyPath, or generates a fresh CA and
// writes it (key 0600) when they are absent. This gives the control plane a
// STABLE trust anchor across restarts, so agents that pinned the CA bundle keep
// trusting the same authority.
func LoadOrCreateCA(certPath, keyPath string) (*CA, error) {
	if certPEM, err := os.ReadFile(certPath); err == nil {
		if keyPEM, err := os.ReadFile(keyPath); err == nil {
			return LoadCA(certPEM, keyPEM)
		}
	}
	ca, err := NewCA()
	if err != nil {
		return nil, err
	}
	keyPEM, err := ca.KeyPEM()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, ca.CertPEM(), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return ca, nil
}
