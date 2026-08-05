// Package buildinfo reports which source revision a running binary was built
// from.
//
// Before this existed there was no way to ask a deployed box what code it was
// running. The control plane's /api/version returned a hardcoded constant
// ("0.3.0-controlplane") that had never changed, and the engine's returned a
// hash of its EMBEDDED FRONTEND ASSETS — so a Go-only fix shipped without
// moving the reported version at all. During the 2026-08-05 outage the only way
// to confirm which build was live was to compare served asset filename hashes
// against a local build, which answers a different question and only by luck.
//
// The revision comes from Go's own VCS stamping (`go build` records
// vcs.revision, vcs.time and vcs.modified automatically when building inside a
// git work tree), so this works with no Makefile changes and cannot drift from
// the commit that produced the binary. An -ldflags override is honoured for
// release builds where VCS stamping is unavailable — for example
// `-buildvcs=false`, or building from an exported tarball.
package buildinfo

import (
	"runtime/debug"
	"sync"
	"time"
)

// revision may be set at link time:
//
//	go build -ldflags "-X github.com/jeffmk/ebpf-poc-engine/internal/buildinfo.revision=$(git rev-parse HEAD)"
//
// When empty, it is read from the binary's embedded VCS stamp.
var revision string

// Info describes the build. Dirty means the work tree had uncommitted changes
// when the binary was built — worth surfacing, because deploying an uncommitted
// tree is exactly how a production box ends up running code that exists nowhere
// else.
type Info struct {
	Revision string // full commit sha, or "unknown"
	Short    string // first 12 chars of Revision, or "unknown"
	Dirty    bool   // work tree had uncommitted changes at build time
	BuiltAt  string // RFC3339 commit timestamp, or "" when unknown
}

var (
	once   sync.Once
	cached Info
)

// Get returns the build's identity. Safe for concurrent use; computed once.
func Get() Info {
	once.Do(func() { cached = read() })
	return cached
}

func read() Info {
	out := Info{Revision: "unknown", Short: "unknown"}
	if revision != "" {
		out.Revision = revision
		out.Short = short(revision)
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return out
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			// An explicit -ldflags value wins: it is the deliberate one.
			if revision == "" && s.Value != "" {
				out.Revision = s.Value
				out.Short = short(s.Value)
			}
		case "vcs.modified":
			out.Dirty = s.Value == "true"
		case "vcs.time":
			if t, err := time.Parse(time.RFC3339, s.Value); err == nil {
				out.BuiltAt = t.UTC().Format(time.RFC3339)
			}
		}
	}
	return out
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// String renders the revision for logs: "a1b2c3d4e5f6" or "a1b2c3d4e5f6-dirty".
func (i Info) String() string {
	if i.Dirty {
		return i.Short + "-dirty"
	}
	return i.Short
}
