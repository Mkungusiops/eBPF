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
	"github.com/jeffmk/ebpf-poc-engine/internal/policyapply"
)

// Policy metadata comes from internal/mitre, which the multi-tenant control
// plane serves from the same table — one map, so the two consoles cannot drift
// apart on what a policy detects.

type policyEntry struct {
	Name string `json:"name"`
	File string `json:"file"`
	YAML string `json:"yaml"`
	// YAMLSource names where that body came from, matching the control plane's
	// field of the same name so one console can label both. Here it is "host":
	// the engine runs ON the monitored machine and reads the file that machine
	// was provisioned with. The control plane, which runs off-host and can only
	// serve the source its own build ships, says "shipped" instead. The two are
	// usually the same bytes and are not the same claim.
	YAMLSource  string `json:"yaml_source,omitempty"`
	Description string `json:"description"`
	MITRE       string `json:"mitre"`
	Tactic      string `json:"tactic"`
	// LoadedAgents and KernelMode describe what the KERNEL has, matching the
	// control plane's fields of the same name so one console renders both.
	//
	// The engine is a single host, so LoadedAgents is 0 or 1. It is a POINTER
	// because absent and zero are different facts: nil means "this deployment
	// could not ask Tetragon", zero means "asked, and it is not loaded". The
	// console raises an alarm on the second and says "unknown" for the first —
	// which is the distinction that matters, since a console claiming zero
	// detection coverage on a fully-covered host is worse than one that admits
	// it does not know.
	LoadedAgents *int   `json:"loaded_agents,omitempty"`
	KernelMode   string `json:"kernel_mode,omitempty"`
	// Expected marks a policy this build SHIPS and therefore expects a host to
	// be running. Only an expected policy that is absent is a coverage gap.
	//
	// Without it the console flagged a deliberately-REMOVED policy as a missing
	// detection: the control plane's list unions kernel-loaded names with names
	// merely seen in recent telemetry, so a policy that fired and was then
	// removed lingers there at zero and looked like a hole in coverage.
	Expected bool `json:"expected"`
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
	// Ask Tetragon what is actually loaded. Best-effort: a failure leaves every
	// LoadedAgents nil, which the console renders as "unknown" rather than as a
	// false claim in either direction.
	loaded := map[string]policyStat{}
	kernelReadable := false
	// "The command exited 0" is not "I understood the answer". A tetra whose
	// output this build cannot parse yields no rows, and treating that as an
	// empty kernel reports every shipped detection as NOT LOADED — a fabricated
	// coverage gap. Only a RECOGNISED table counts as having read the kernel.
	stats, ok, _ := kernelPolicies(r.Context())
	for _, st := range stats {
		loaded[st.Name] = st
	}
	kernelReadable = ok

	// UNION of the shipped catalogue with what the kernel actually has.
	//
	// The catalogue alone was right only while policies could not be authored.
	// Now that an operator can write one, the catalogue misses it: they push a
	// detection, get "applied: 1, ok", hit refresh and see nothing new — the
	// feature looks broken at the exact moment it worked. The control plane
	// already unions for the same reason (controlplane/http.go).
	//
	// The union is one-directional in what it CLAIMS: a catalogue policy is
	// Expected (this build ships it, so its absence is a coverage gap), and a
	// kernel-only policy is not (it is someone's own detection, and nothing
	// says it ought to be there).
	names := unionPolicyNames(mitre.Policies(), loaded)
	out := make([]policyEntry, 0, len(names))
	for _, name := range names {
		meta, expected := mitre.Lookup(name)
		// An unreadable policy directory yields no body and no source claim,
		// rather than an empty body the console cannot distinguish from a
		// policy whose file is genuinely empty.
		body := readPolicyFile(meta.File)
		source := ""
		if body != "" {
			source = "host"
		}
		e := policyEntry{
			Name:        name,
			File:        meta.File,
			YAML:        body,
			YAMLSource:  source,
			Description: meta.Description,
			MITRE:       meta.Technique,
			Tactic:      meta.Tactic,
			Expected:    expected,
		}
		// A policy the kernel has but the catalogue does not is one the
		// operator wrote. Its body lives in Tetragon's load directory, not in
		// the shipped policy directory, so say where it came from rather than
		// showing it as body-less.
		if !expected && e.YAML == "" {
			if b, err := os.ReadFile(policyapply.DurablePath(currentDurableDir(), name)); err == nil {
				e.YAML, e.YAMLSource, e.File = string(b), "host", name+".yaml"
			}
		}
		if kernelReadable {
			n := 0
			if st, ok := loaded[name]; ok && strings.EqualFold(st.State, "enabled") {
				n = 1
				e.KernelMode = st.Mode
			}
			e.LoadedAgents = &n
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// unionPolicyNames merges the shipped catalogue with what the kernel reports.
//
// Extracted so it can be tested: handlePolicies reaches Tetragon by shelling
// out, which a unit test cannot drive, and the union is the part that was
// actually wrong. Sorted here so the handler's own sort is a no-op and the
// order is deterministic for callers either way.
func unionPolicyNames(catalogue []string, loaded map[string]policyStat) []string {
	seen := make(map[string]bool, len(catalogue)+len(loaded))
	out := make([]string, 0, len(catalogue)+len(loaded))
	add := func(n string) {
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, n := range catalogue {
		add(n)
	}
	for n := range loaded {
		add(n)
	}
	sort.Strings(out)
	return out
}
