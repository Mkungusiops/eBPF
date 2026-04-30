// Package policy is the choke-policy DSL.
//
// A choke policy declares, for a class of process (matched by binary path
// prefix or basename), what gets choked when its circuit transitions
// out of pristine. Policies are pure data — the gateway and enforcer
// backends translate them into runtime token buckets, seccomp filters,
// and BPF map updates.
//
// Example:
//
//	apiVersion: chokegw/v1
//	kind: ChokePolicy
//	metadata:
//	  name: shell-egress-throttle
//	  description: cap shells to 5 outbound connects/s when throttled
//	match:
//	  binaries:
//	    - /bin/bash
//	    - /usr/bin/sh
//	    - /bin/sh
//	  states:
//	    - throttled
//	    - tarpit
//	buckets:
//	  - dimension: egress.connect
//	    rate_per_sec: 5
//	    burst: 10
//	  - dimension: dns.query
//	    rate_per_sec: 20
//	    burst: 40
//	deny_syscalls:
//	  - ptrace
//	  - mount
//	deny_paths:
//	  - /etc/shadow
//	  - /root/.ssh/
package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

const (
	APIVersion = "chokegw/v1"
	Kind       = "ChokePolicy"
)

// Bucket declares a token bucket dimension. Rate and Burst are floats so
// fractional rates ("0.5/s = one every 2s") are expressible.
type Bucket struct {
	Dimension  string  `yaml:"dimension"`
	RatePerSec float64 `yaml:"rate_per_sec"`
	Burst      float64 `yaml:"burst"`
}

// Match selects which processes (and circuit states) the policy applies to.
type Match struct {
	Binaries []string `yaml:"binaries"`
	// States is the set of circuit state names ("throttled", "tarpit",
	// "quarantined", "severed") at which this policy activates. Empty
	// means "all non-pristine states".
	States []string `yaml:"states"`
}

// Metadata mirrors Kubernetes-style metadata so the DSL feels familiar.
type Metadata struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

// Policy is the top-level DSL document.
type Policy struct {
	APIVersion   string   `yaml:"apiVersion"`
	Kind         string   `yaml:"kind"`
	Metadata     Metadata `yaml:"metadata"`
	Match        Match    `yaml:"match"`
	Buckets      []Bucket `yaml:"buckets"`
	DenySyscalls []string `yaml:"deny_syscalls"`
	DenyPaths    []string `yaml:"deny_paths"`
}

// Validate sanity-checks a policy. Returns the first problem found.
func (p *Policy) Validate() error {
	if p.APIVersion != APIVersion {
		return fmt.Errorf("apiVersion=%q want %q", p.APIVersion, APIVersion)
	}
	if p.Kind != Kind {
		return fmt.Errorf("kind=%q want %q", p.Kind, Kind)
	}
	if p.Metadata.Name == "" {
		return errors.New("metadata.name is required")
	}
	if len(p.Match.Binaries) == 0 {
		return errors.New("match.binaries: at least one binary required")
	}
	for i, b := range p.Buckets {
		if b.Dimension == "" {
			return fmt.Errorf("buckets[%d].dimension required", i)
		}
		if b.RatePerSec <= 0 {
			return fmt.Errorf("buckets[%d].rate_per_sec must be > 0", i)
		}
	}
	for _, s := range p.Match.States {
		switch s {
		case "throttled", "tarpit", "quarantined", "severed":
		default:
			return fmt.Errorf("match.states: %q is not a valid state name", s)
		}
	}
	return nil
}

// matchesBinary reports whether the policy applies to the given binary.
// Match rules: exact path equality, or path prefix when the policy entry
// ends with '/', or basename equality otherwise.
func (p *Policy) matchesBinary(binary string) bool {
	for _, want := range p.Match.Binaries {
		if want == binary {
			return true
		}
		if strings.HasSuffix(want, "/") && strings.HasPrefix(binary, want) {
			return true
		}
		if !strings.Contains(want, "/") && filepath.Base(binary) == want {
			return true
		}
	}
	return false
}

// MatchesState reports whether the policy is active in the given circuit
// state name.
func (p *Policy) MatchesState(state string) bool {
	if len(p.Match.States) == 0 {
		return state != "pristine"
	}
	for _, s := range p.Match.States {
		if s == state {
			return true
		}
	}
	return false
}

// Set is a thread-safe collection of policies, indexed for fast lookup.
type Set struct {
	mu       sync.RWMutex
	policies []Policy
}

// NewSet returns an empty Set.
func NewSet() *Set { return &Set{} }

// Add appends a policy to the set after validation.
func (s *Set) Add(p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	s.policies = append(s.policies, p)
	s.mu.Unlock()
	return nil
}

// Match returns every policy that applies to the given binary. Order
// preserved (file/insertion order); callers may layer them.
func (s *Set) Match(binary string) []Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Policy, 0, len(s.policies))
	for _, p := range s.policies {
		if p.matchesBinary(binary) {
			out = append(out, p)
		}
	}
	return out
}

// All returns a snapshot of every policy in the set.
func (s *Set) All() []Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Policy, len(s.policies))
	copy(out, s.policies)
	return out
}

// Len returns the number of policies in the set.
func (s *Set) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.policies)
}

// LoadFile parses a single YAML file into a Policy.
func LoadFile(path string) (Policy, error) {
	var p Policy
	b, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	if err := yaml.Unmarshal(b, &p); err != nil {
		return p, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return p, fmt.Errorf("validate %s: %w", path, err)
	}
	return p, nil
}

// LoadDir loads every *.yaml/*.yml file under dir into a fresh Set. Files
// that fail to parse are skipped with a non-fatal error in the returned
// slice; the Set contains the policies that did parse.
func LoadDir(dir string) (*Set, []error, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, nil, err
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("%s is not a directory", dir)
	}
	set := NewSet()
	var nonFatal []error
	walk := func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		p, err := LoadFile(path)
		if err != nil {
			nonFatal = append(nonFatal, err)
			return nil
		}
		if err := set.Add(p); err != nil {
			nonFatal = append(nonFatal, fmt.Errorf("add %s: %w", path, err))
		}
		return nil
	}
	if err := filepath.WalkDir(dir, walk); err != nil {
		return nil, nonFatal, err
	}
	return set, nonFatal, nil
}
