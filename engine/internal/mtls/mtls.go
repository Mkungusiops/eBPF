// Package mtls is the self-managed certificate authority and mTLS identity
// layer for agent enrollment (docs/plan/wire-contract.md §1, §3).
//
// Self-managed (not cloud PKI) is a deliberate choice: it keeps the agent a
// single static binary with no cloud-PKI runtime dependency and preserves the
// single-tenant on-prem/residency packaging variant a telco needs (plan.md §1).
//
// ROOT OF THE ISOLATION INVARIANT: an agent's tenant_id is encoded into the
// Subject of its client certificate at issue time and read back with
// TenantFromCert. That is the ONLY authoritative source of tenant identity —
// no wire payload is ever trusted for it (tenant-isolation-invariant.md R1).
package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// Subject encoding: tenant_id in Organization, agent_id in CommonName. Simple,
// standard, and verifiable; a SPIFFE-style URI SAN is a later hardening.
//
// TenantFromCert extracts (tenantID, agentID) from a verified peer certificate.
// This is the sole authoritative derivation of tenant identity.
func TenantFromCert(cert *x509.Certificate) (tenantID, agentID string, err error) {
	if cert == nil {
		return "", "", errors.New("mtls: no client certificate presented")
	}
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] == "" {
		return "", "", errors.New("mtls: certificate carries no tenant (Subject.Organization)")
	}
	if cert.Subject.CommonName == "" {
		return "", "", errors.New("mtls: certificate carries no agent id (Subject.CommonName)")
	}
	return cert.Subject.Organization[0], cert.Subject.CommonName, nil
}

// CA is a minimal ECDSA P-256 certificate authority.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

// NewCA generates a fresh self-signed CA. In production the CA key lives in
// Vault/KMS (threat-model.md SC-6); this in-process form is what the control
// plane and tests use to bootstrap.
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: "ebpf-soc-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, certPEM: pemBlock("CERTIFICATE", der)}, nil
}

// CertPEM is the CA certificate — the trust anchor agents pin.
func (ca *CA) CertPEM() []byte { return append([]byte(nil), ca.certPEM...) }

// Pool returns a cert pool containing the CA for verifying peers.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}

// IssueClient signs an agent CSR into a client certificate binding tenantID
// (Organization) and agentID (CommonName). The tenant/agent in the CSR itself
// are ignored — the CA sets them authoritatively from the (verified) bootstrap
// token, so an agent cannot self-assign a tenant (isolation invariant R1/R4).
func (ca *CA) IssueClient(csrDER []byte, tenantID, agentID string, ttl time.Duration) ([]byte, error) {
	if tenantID == "" || agentID == "" {
		return nil, errors.New("mtls: tenant and agent id required to issue")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("mtls: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("mtls: CSR signature: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{Organization: []string{tenantID}, CommonName: agentID},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	return pemBlock("CERTIFICATE", der), nil
}

// IssueServer mints a control-plane server certificate + key (PEM) signed by
// the CA, with host as CN/SAN, so agents can authenticate the control plane.
func (ca *CA) IssueServer(host string, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	}
	// Signed by the CA (parent), so the signer is the CA key, not the leaf key.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pemBlock("CERTIFICATE", der), pemBlock("EC PRIVATE KEY", keyDER), nil
}

// GenerateKeyAndCSR creates an agent keypair and a CSR. The private key never
// leaves the host. The CSR subject is advisory only; the CA authoritatively
// sets tenant/agent from the bootstrap token.
func GenerateKeyAndCSR() (keyPEM, csrDER []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err = x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "pending-enrollment"}}, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pemBlock("EC PRIVATE KEY", keyDER), csrDER, nil
}

// ServerTLSConfig presents the server cert and REQUIRES + verifies client certs
// against the CA (mutual TLS). This is what makes tenant-from-cert trustworthy:
// the gRPC layer has already verified the client cert chains to our CA before a
// handler ever reads its Subject.
func ServerTLSConfig(serverCertPEM, serverKeyPEM []byte, clientCAs *x509.CertPool) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientTLSConfig presents the agent cert and verifies the control plane
// against the CA pool (full mTLS, for every channel after enrollment).
func ClientTLSConfig(clientCertPEM, clientKeyPEM []byte, caPool *x509.CertPool, serverName string) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// BootstrapTLSConfig is server-auth only — used for the single Enroll call
// before the agent holds a client cert. The agent still verifies the control
// plane against the pinned CA.
func BootstrapTLSConfig(caPool *x509.CertPool, serverName string) *tls.Config {
	return &tls.Config{RootCAs: caPool, ServerName: serverName, MinVersion: tls.VersionTLS13}
}

func newSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(fmt.Sprintf("mtls: serial: %v", err)) // crypto/rand failure is fatal
	}
	return n
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}
