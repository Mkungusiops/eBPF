package policy

import (
	"os"
	"path/filepath"
	"testing"
)

const validYAML = `
apiVersion: chokegw/v1
kind: ChokePolicy
metadata:
  name: shell-egress-throttle
  description: limit shells when score crosses throttle threshold
match:
  binaries:
    - /bin/bash
    - /usr/bin/sh
    - bash
    - /usr/bin/python/
  states:
    - throttled
    - tarpit
buckets:
  - dimension: egress.connect
    rate_per_sec: 5
    burst: 10
  - dimension: dns.query
    rate_per_sec: 20
    burst: 40
deny_syscalls:
  - ptrace
  - mount
deny_paths:
  - /etc/shadow
  - /root/.ssh/
`

func TestLoadAndValidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, []byte(validYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := LoadFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if p.Metadata.Name != "shell-egress-throttle" {
		t.Errorf("name=%q", p.Metadata.Name)
	}
	if len(p.Buckets) != 2 {
		t.Errorf("buckets=%d want 2", len(p.Buckets))
	}
}

func TestValidateRejectsBadAPIVersion(t *testing.T) {
	p := Policy{APIVersion: "bogus", Kind: Kind, Metadata: Metadata{Name: "x"},
		Match: Match{Binaries: []string{"/bin/x"}}}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error on bad apiVersion")
	}
}

func TestValidateRejectsZeroRate(t *testing.T) {
	p := Policy{APIVersion: APIVersion, Kind: Kind, Metadata: Metadata{Name: "x"},
		Match:   Match{Binaries: []string{"/bin/x"}},
		Buckets: []Bucket{{Dimension: "egress", RatePerSec: 0}}}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error on zero rate")
	}
}

func TestMatchesBinaryRules(t *testing.T) {
	p := Policy{Match: Match{Binaries: []string{"/bin/bash", "python", "/opt/app/"}}}
	cases := []struct {
		bin  string
		want bool
	}{
		{"/bin/bash", true},          // exact
		{"/usr/bin/python", true},    // basename match
		{"/opt/app/main.py", true},   // prefix match (trailing slash)
		{"/usr/bin/sh", false},       // no match
		{"/bin/python", true},        // basename
		{"/etc/passwd", false},
	}
	for _, tc := range cases {
		if got := p.matchesBinary(tc.bin); got != tc.want {
			t.Errorf("matchesBinary(%q)=%v want %v", tc.bin, got, tc.want)
		}
	}
}

func TestMatchesStateDefault(t *testing.T) {
	p := Policy{} // empty States
	if !p.MatchesState("throttled") {
		t.Errorf("empty States should match throttled")
	}
	if p.MatchesState("pristine") {
		t.Errorf("empty States must not match pristine")
	}
}

func TestSetMatchPreservesOrder(t *testing.T) {
	s := NewSet()
	for i, name := range []string{"a", "b", "c"} {
		_ = s.Add(Policy{
			APIVersion: APIVersion, Kind: Kind,
			Metadata:   Metadata{Name: name},
			Match:      Match{Binaries: []string{"/bin/x"}},
			Buckets:    []Bucket{{Dimension: "d", RatePerSec: float64(i + 1)}},
		})
	}
	got := s.Match("/bin/x")
	if len(got) != 3 {
		t.Fatalf("got %d, want 3", len(got))
	}
	if got[0].Metadata.Name != "a" || got[2].Metadata.Name != "c" {
		t.Errorf("order not preserved: %v %v %v", got[0].Metadata.Name, got[1].Metadata.Name, got[2].Metadata.Name)
	}
}

func TestLoadDirSkipsBadFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.yaml"), []byte(validYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("this is not valid yaml: ::"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignored.txt"), []byte("not a policy"), 0o644); err != nil {
		t.Fatal(err)
	}
	set, nonFatal, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("loaddir: %v", err)
	}
	if set.Len() != 1 {
		t.Errorf("set.Len()=%d want 1", set.Len())
	}
	if len(nonFatal) == 0 {
		t.Errorf("expected non-fatal error for bad.yaml")
	}
}
