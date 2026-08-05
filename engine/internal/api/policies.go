package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/jeffmk/ebpf-poc-engine/internal/mitre"
)

// Policy metadata comes from internal/mitre, which the multi-tenant control
// plane serves from the same table — one map, so the two consoles cannot drift
// apart on what a policy detects.

type policyEntry struct {
	Name        string `json:"name"`
	File        string `json:"file"`
	YAML        string `json:"yaml"`
	Description string `json:"description"`
	MITRE       string `json:"mitre"`
	Tactic      string `json:"tactic"`
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
	names := mitre.Policies()
	out := make([]policyEntry, 0, len(names))
	for _, name := range names {
		meta, _ := mitre.Lookup(name)
		out = append(out, policyEntry{
			Name:        name,
			File:        meta.File,
			YAML:        readPolicyFile(meta.File),
			Description: meta.Description,
			MITRE:       meta.Technique,
			Tactic:      meta.Tactic,
		})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
