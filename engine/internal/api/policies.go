package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Policy metadata that the dashboard uses to annotate the embedded YAMLs.
// The map keys match the `metadata.name` field inside each YAML and what
// `tetra tracingpolicy list` reports.
var policyMeta = map[string]struct {
	File        string
	Description string
	MITRE       string
}{
	"outbound-connections": {
		File:        "network-watch.yaml",
		Description: "tcp_connect kprobe filtered to bash/sh/nc/socat — catches shells calling out",
		MITRE:       "T1071 Command & Control",
	},
	"privilege-escalation": {
		File:        "privilege-escalation.yaml",
		Description: "setuid hooks — catches gain-of-root events",
		MITRE:       "T1548 Abuse Elevation Control Mechanism",
	},
	"sensitive-file-access": {
		File:        "sensitive-files.yaml",
		Description: "security_file_permission kprobe on /etc/shadow, /etc/passwd, /etc/sudoers, /root/.ssh",
		MITRE:       "T1003 OS Credential Dumping",
	},
}

type policyEntry struct {
	Name        string `json:"name"`
	File        string `json:"file"`
	YAML        string `json:"yaml"`
	Description string `json:"description"`
	MITRE       string `json:"mitre"`
}

// PolicyDir is set from main via the -policies flag. When unset, the handler
// returns metadata only with empty YAML bodies.
var (
	policyDirMu sync.RWMutex
	policyDir   string
)

func SetPolicyDir(dir string) {
	policyDirMu.Lock()
	policyDir = dir
	policyDirMu.Unlock()
}

func readPolicyFile(name string) string {
	policyDirMu.RLock()
	dir := policyDir
	policyDirMu.RUnlock()
	if dir == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return string(b)
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	out := make([]policyEntry, 0, len(policyMeta))
	for name, meta := range policyMeta {
		out = append(out, policyEntry{
			Name:        name,
			File:        meta.File,
			YAML:        readPolicyFile(meta.File),
			Description: meta.Description,
			MITRE:       meta.MITRE,
		})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
