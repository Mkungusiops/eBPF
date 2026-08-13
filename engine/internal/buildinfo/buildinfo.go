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
	"strings"
	"sync"
	"time"
)

// revision may be set at link time:
//
//	go build -ldflags "-X github.com/jeffmk/ebpf-poc-engine/internal/buildinfo.revision=$(git rev-parse HEAD)"
//
// When empty, it is read from the binary's embedded VCS stamp.
var revision string

// version is the release name — the annotated tag this binary was cut from,
// as `git describe --tags --dirty` renders it (e.g. "v1.0.0", or
// "v1.0.0-3-gabc1234-dirty" off-tag). Set at link time:
//
//	go build -ldflags "-X github.com/jeffmk/ebpf-poc-engine/internal/buildinfo.version=$(git describe --tags --dirty --always)"
//
// A revision alone answers "which commit"; a customer asks "which VERSION", and
// only a tag answers that. Empty when built outside a release, which is itself
// the honest answer.
var version string

// Info describes the build. Dirty means the work tree had uncommitted changes
// when the binary was built — worth surfacing, because deploying an uncommitted
// tree is exactly how a production box ends up running code that exists nowhere
// else.
type Info struct {
	Version  string // release tag from `git describe`, or "" when not a release build
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
	out := Info{Version: version, Revision: "unknown", Short: "unknown"}
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

// String renders the build for logs. A release build names its tag, because
// "v1.0.0" is what a customer can act on; an untagged build falls back to the
// revision so the output is never empty.
func (i Info) String() string {
	name := i.Short
	if i.Version != "" {
		name = i.Version
	}
	if i.Dirty && !strings.HasSuffix(name, "-dirty") {
		return name + "-dirty"
	}
	return name
}

// Released reports whether this binary was cut from a clean tag. Deploy tooling
// gates on it: a box running an uncommitted tree is running code that exists
// nowhere else, which is unsupportable for a customer.
func (i Info) Released() bool { return i.Version != "" && !i.Dirty }
