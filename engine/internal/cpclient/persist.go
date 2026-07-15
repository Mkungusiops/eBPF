package cpclient

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/enrollment"
)

// Persisted-identity file names within the state dir. The private key is the
// only secret; the cert, CA bundle, and metadata are not sensitive.
const (
	fileCert = "agent-cert.pem"
	fileKey  = "agent-key.pem"
	fileCA   = "ca-bundle.pem"
	fileMeta = "identity.json"
)

// renewWindow: a persisted cert with less than this remaining is treated as
// unusable, forcing re-enrollment (which needs a fresh bootstrap token). Certs
// are issued with a 90-day TTL by default, so a week of slack lets an operator
// re-enroll before hard expiry rather than at the moment of it.
const renewWindow = 7 * 24 * time.Hour

// identityMeta is the non-PEM part of a persisted identity.
type identityMeta struct {
	AgentID         string `json:"agent_id"`
	UplinkEndpoint  string `json:"uplink_endpoint"`
	CommandEndpoint string `json:"command_endpoint"`
}

// LoadIdentity reads a previously persisted enrollment identity from dir.
//
// It returns (identity, true, nil) only when a complete, currently-valid
// identity is present; (nil, false, nil) when there is nothing usable — dir
// empty, no saved identity, or the cert is expired/within renewWindow; and an
// error only on unexpected IO/parse failures (a corrupt-but-present identity),
// which the caller should surface rather than silently re-enroll over.
func LoadIdentity(dir string) (*enrollment.Enrolled, bool, error) {
	if dir == "" {
		return nil, false, nil
	}
	cert, err := os.ReadFile(filepath.Join(dir, fileCert))
	if os.IsNotExist(err) {
		return nil, false, nil // never enrolled here yet
	} else if err != nil {
		return nil, false, err
	}
	key, err := os.ReadFile(filepath.Join(dir, fileKey))
	if err != nil {
		return nil, false, err
	}
	ca, err := os.ReadFile(filepath.Join(dir, fileCA))
	if err != nil {
		return nil, false, err
	}
	metaRaw, err := os.ReadFile(filepath.Join(dir, fileMeta))
	if err != nil {
		return nil, false, err
	}
	var meta identityMeta
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		return nil, false, fmt.Errorf("cpclient: parse %s: %w", fileMeta, err)
	}

	// The leaf must parse and have comfortable life left; a cert past the
	// renewal window can't be reused (re-enrollment needs a bootstrap token).
	leaf, err := leafFromPEM(cert)
	if err != nil {
		return nil, false, err
	}
	if time.Now().Add(renewWindow).After(leaf.NotAfter) {
		return nil, false, nil
	}

	return &enrollment.Enrolled{
		CertPEM:         cert,
		KeyPEM:          key,
		CABundlePEM:     ca,
		AgentID:         meta.AgentID,
		UplinkEndpoint:  meta.UplinkEndpoint,
		CommandEndpoint: meta.CommandEndpoint,
	}, true, nil
}

// SaveIdentity persists an enrollment identity under dir with least-privilege
// modes — private key 0600, everything else 0644, dir 0700. Each file is
// written atomically (temp + rename) so a crash mid-write cannot leave a torn
// identity that LoadIdentity would then reject as corrupt.
func SaveIdentity(dir string, en *enrollment.Enrolled) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	meta, err := json.MarshalIndent(identityMeta{
		AgentID:         en.AgentID,
		UplinkEndpoint:  en.UplinkEndpoint,
		CommandEndpoint: en.CommandEndpoint,
	}, "", "  ")
	if err != nil {
		return err
	}
	writes := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{fileKey, en.KeyPEM, 0o600}, // the only secret
		{fileCert, en.CertPEM, 0o644},
		{fileCA, en.CABundlePEM, 0o644},
		{fileMeta, meta, 0o644},
	}
	for _, w := range writes {
		if err := atomicWrite(filepath.Join(dir, w.name), w.data, w.mode); err != nil {
			return err
		}
	}
	return nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func leafFromPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("cpclient: stored cert is not valid PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
