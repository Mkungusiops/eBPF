package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Honeypot files: realistic-looking decoys placed in a known directory.
// They have no real value, but accessing them via the sensitive-files
// kprobe (configured to also watch the honeypot prefix) is a strong signal
// of malicious intent. The path prefix is exposed so the dashboard can
// badge alerts that touched it.
type honeypot struct {
	Path        string `json:"path"`
	Description string `json:"description"`
	Bytes       int    `json:"bytes"`
}

const honeypotPrefixDefault = "/var/lib/ebpf-engine/honey/"

var (
	honeypotMu     sync.RWMutex
	honeypotPrefix = honeypotPrefixDefault
	honeypotFiles  []honeypot
)

// EnsureHoneypots is called from main on startup. It creates the directory
// (if missing) and writes a small set of decoy files. Idempotent — files
// that already exist are left alone. Returns the dir prefix so it can be
// surfaced via /api/honeypots.
func EnsureHoneypots(dir string) error {
	if dir == "" {
		dir = honeypotPrefixDefault
	}
	if !strings.HasSuffix(dir, "/") {
		dir += "/"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	decoys := []struct {
		name string
		desc string
		body string
	}{
		{"_passwd", "decoy /etc/passwd-style file", "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\n"},
		{"_shadow", "decoy credential hashes", "root:$6$lXAqHfn3$decoynothashed:19000:0:99999:7:::\nadmin:$6$placeholder$decoyonly:19000:0:99999:7:::\n"},
		{"_id_rsa", "decoy private key", "-----BEGIN OPENSSH PRIVATE KEY-----\nThisIsNotARealKeyAccessToThisFileShouldFireAnAlert\n-----END OPENSSH PRIVATE KEY-----\n"},
		{"_aws_credentials", "decoy AWS credentials", "[default]\naws_access_key_id = AKIA0000000000000000\naws_secret_access_key = decoy/notreal/donotuse\n"},
		{"_db_backup.sql", "decoy DB dump", "-- decoy backup; access fires an alert\nSELECT 'this is bait';\n"},
	}

	files := make([]honeypot, 0, len(decoys))
	for _, d := range decoys {
		full := filepath.Join(dir, d.name)
		// Idempotent: only write if missing
		if _, err := os.Stat(full); os.IsNotExist(err) {
			if err := os.WriteFile(full, []byte(d.body), 0o644); err != nil {
				return err
			}
		}
		st, err := os.Stat(full)
		size := 0
		if err == nil {
			size = int(st.Size())
		}
		files = append(files, honeypot{Path: full, Description: d.desc, Bytes: size})
	}

	honeypotMu.Lock()
	honeypotPrefix = dir
	honeypotFiles = files
	honeypotMu.Unlock()
	return nil
}

// HoneypotPrefix returns the configured prefix (always trailing slash).
func HoneypotPrefix() string {
	honeypotMu.RLock()
	defer honeypotMu.RUnlock()
	return honeypotPrefix
}

func (s *Server) handleHoneypots(w http.ResponseWriter, r *http.Request) {
	honeypotMu.RLock()
	defer honeypotMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"prefix": honeypotPrefix,
		"files":  honeypotFiles,
	})
}
