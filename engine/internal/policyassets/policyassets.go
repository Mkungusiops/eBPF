// Package policyassets carries the detection policies this build ships, as
// source, inside the binary.
//
// # Why the control plane needs this at all
//
// The single-tenant engine runs ON the monitored host, so it answers "show me
// this policy" by reading the host's own policy directory. The control plane
// runs somewhere else entirely and has no such directory — so every policy it
// listed came back with an empty body. That is fine for a read-only viewer and
// useless the moment the console lets an operator AUTHOR a policy: the most
// useful starting point for writing a detection is a detection that already
// works, and on the control plane there was nothing to copy from.
//
// # Provenance, and why it is reported rather than assumed
//
// What this returns is the source THIS BUILD SHIPS for a policy name. It is not
// a dump of what a particular kernel has loaded — an agent running an older
// build could carry an older revision of the same file. The distance is small
// and the honest thing is to say so rather than to imply the console is showing
// live kernel state, so the API tags these bodies as shipped source and the
// console labels them that way. Reading a policy body out of the kernel would
// need the agent to return it over the command channel, which is a real
// feature, not a rename of this one.
//
// Staging follows the same convention as the embedded web bundle: a committed
// .keep keeps the directory embeddable for a direct `go build`, the Makefile
// copies the canonical policies/ in, and a build without that step degrades to
// no bodies rather than to a wrong one.
package policyassets

import (
	"embed"
	"io/fs"
	"path"
	"sort"
	"strings"
)

//go:embed all:embedded
var assets embed.FS

// Lookup returns the shipped source for a policy, by policy NAME.
//
// The name is the policy's metadata.name, which is what telemetry, the kernel
// and the console all key on; the filename is an implementation detail that
// happens to match today. Matching on the parsed name rather than on
// "name + .yaml" means a file whose name field disagrees with its filename is
// still found under the name everything else uses for it.
func Lookup(name string) (string, bool) {
	body, ok := index()[name]
	return body, ok
}

// Names lists every policy this build ships source for, sorted.
func Names() []string {
	idx := index()
	out := make([]string, 0, len(idx))
	for n := range idx {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

var cached map[string]string

func index() map[string]string {
	if cached != nil {
		return cached
	}
	cached = map[string]string{}
	_ = fs.WalkDir(assets, "embedded", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(path.Ext(p))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		b, readErr := assets.ReadFile(p)
		if readErr != nil {
			return nil
		}
		body := string(b)
		if n := metadataName(body); n != "" {
			cached[n] = body
		}
		return nil
	})
	return cached
}

// metadataName pulls metadata.name out of a TracingPolicy without a YAML
// parser.
//
// A parser would be the obvious choice and is the wrong one here: `name:`
// appears several times in a TracingPolicy — under options as
// `name: "policy-mode"`, and inside selectors — so what matters is finding the
// one at metadata's indentation level, immediately under a top-level
// `metadata:`. Scanning for exactly that is both smaller than a schema and
// harder to get subtly wrong than a map traversal that silently accepts the
// first `name` key it meets.
func metadataName(body string) string {
	inMetadata := false
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimRight(line, "\r")
		if trimmed == "" || strings.HasPrefix(strings.TrimSpace(trimmed), "#") {
			continue
		}
		indented := strings.HasPrefix(trimmed, " ") || strings.HasPrefix(trimmed, "\t")
		if !indented {
			// A new top-level key ends the metadata block, so a `name:` under
			// spec never gets mistaken for the policy's own name.
			inMetadata = strings.HasPrefix(trimmed, "metadata:")
			continue
		}
		if !inMetadata {
			continue
		}
		field := strings.TrimSpace(trimmed)
		if !strings.HasPrefix(field, "name:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(field, "name:"))
		v = strings.Trim(v, `"'`)
		if v != "" {
			return v
		}
	}
	return ""
}
