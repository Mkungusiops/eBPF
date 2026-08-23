// Package policyapply loads and unloads TracingPolicies on the local host's
// Tetragon.
//
// # Why this is shared rather than the agent's private business
//
// This logic began inside cmd/agent, which is `package main` and therefore
// unimportable. That was fine while the agent was the only thing that changed
// detection policy: the multi-tenant control plane dispatches a signed command
// and the agent on each host applies it.
//
// The single-tenant engine has the same job and no way to do it. It runs ON the
// monitored host, already dials the same Tetragon socket for its event stream
// (cmd/engine/main.go), and shows the operator exactly which policies the
// kernel has — but could not change one, so its console had to hide the
// authoring surface and tell the customer to go and use a control plane they
// may not have deployed. A single-host customer had no way to write a detection
// at all except SSH.
//
// Lifting the applier here gives both callers ONE implementation. That matters
// more than the duplication saved: the rules encoded below — delete-then-add,
// mode applied explicitly, durability reported separately from liveness — are
// each the residue of a specific way this went wrong, and a second copy is a
// second chance to lose one of them.
//
// # What a caller still owns
//
// Authorisation, the reason for the change, and the refusal of enforce mode are
// deliberately NOT here. They differ by plane: the control plane authenticates
// an OIDC principal and signs a command across a network; the engine
// authenticates a console session on the machine itself. This package is the
// effector, and an effector that silently second-guesses its callers is harder
// to reason about than one that does exactly what it is told.
package policyapply

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
)

// Client is the slice of Tetragon's API this package needs.
//
// Narrowed to three methods rather than taking FineGuidanceSensorsClient whole:
// both real callers already hold the full client, and the narrow interface is
// what lets the tests drive every branch — including the failure branches that
// matter most here — without a live daemon.
type Client interface {
	AddTracingPolicy(ctx context.Context, in *tetragon.AddTracingPolicyRequest, opts ...grpc.CallOption) (*tetragon.AddTracingPolicyResponse, error)
	DeleteTracingPolicy(ctx context.Context, in *tetragon.DeleteTracingPolicyRequest, opts ...grpc.CallOption) (*tetragon.DeleteTracingPolicyResponse, error)
	ConfigureTracingPolicy(ctx context.Context, in *tetragon.ConfigureTracingPolicyRequest, opts ...grpc.CallOption) (*tetragon.ConfigureTracingPolicyResponse, error)
	ListTracingPolicies(ctx context.Context, in *tetragon.ListTracingPoliciesRequest, opts ...grpc.CallOption) (*tetragon.ListTracingPoliciesResponse, error)
}

// Status is one policy as the kernel reports it.
//
// Everything the CLI table carried is here EXCEPT NENFORCE and NMONITOR, which
// are aggregates `tetra` computes from seven raw action counters using a
// summation not vendored in this tree. They are absent rather than
// approximated; nothing reads them. Enforces below is signal+override, which is
// a different and defensible number, not a stand-in for either.
type Status struct {
	ID       uint64
	Name     string
	Enabled  bool
	Mode     string
	Sensors  []string
	MemBytes uint64
	Posts    uint64
	Enforces uint64
}

// List reads the loaded policy set over gRPC.
//
// # Why this exists next to the write path
//
// The engine WROTE policy over this connection and READ it by shelling out:
// `docker exec tetragon tetra tracingpolicy list`, with no context, no timeout,
// a hardcoded runtime and container name, and a text table scraped by a
// heuristic parser. One host, two mechanisms, one of which needs the docker
// socket — root-on-host — for a read the open gRPC connection already answers.
//
// The agent has always done it this way (cmd/agent/controlplane.go). This puts
// the mapping in the package that owns the policy rules so both binaries share
// one definition of what the kernel said.
func List(ctx context.Context, c Client) ([]Status, error) {
	resp, err := c.ListTracingPolicies(ctx, &tetragon.ListTracingPoliciesRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]Status, 0, len(resp.GetPolicies()))
	for _, p := range resp.GetPolicies() {
		st := Status{
			ID:      p.GetId(),
			Name:    p.GetName(),
			Enabled: p.GetState() == tetragon.TracingPolicyState_TP_STATE_ENABLED,
			Mode:    modeString(p.GetMode()),
			Sensors: p.GetSensors(),
			// The CLI prints this pre-formatted ("4.70 MB"); the API gives
			// bytes. Carried raw so the caller decides how to render it, and so
			// the gRPC path loses nothing the scrape provided.
			MemBytes: p.GetKernelMemoryBytes(),
		}
		if ac := p.GetStats().GetActionCounters(); ac != nil {
			st.Posts = ac.GetPost()
			// Signal and Override are the actions that kill or divert. Post is
			// reporting and is deliberately not counted as enforcement — doing
			// so would make every healthy detection look like it was killing.
			st.Enforces = ac.GetSignal() + ac.GetOverride()
		}
		out = append(out, st)
	}
	return out, nil
}

func modeString(m tetragon.TracingPolicyMode) string {
	switch m {
	case tetragon.TracingPolicyMode_TP_MODE_ENFORCE:
		return "enforce"
	case tetragon.TracingPolicyMode_TP_MODE_MONITOR:
		return "monitor"
	default:
		return ""
	}
}

// Doc is one policy to apply: its name, its body, and the mode to set after it
// loads. Mirrors the wire type without importing it, so a caller that has no
// protobuf in hand (the engine, which is handed YAML straight from an HTTP
// body) does not have to build one.
type Doc struct {
	Name string
	YAML string
	Mode string
}

// Outcome codes. Callers render these; the console distinguishes them, so they
// are values rather than free prose.
const (
	// OK means loaded into the kernel AND persisted to disk.
	OK = "ok"
	// NotDurable means the policy IS running right now but will be lost when
	// Tetragon next restarts. Reported separately rather than folded into
	// either success or failure, because it is genuinely both: useful now, at
	// risk later, and the operator can only act on it if told.
	NotDurable = "live, but NOT durable — lost on the next Tetragon restart: "
	// Removed means the policy was unloaded and its durable copy deleted.
	Removed = "removed"
	// FailedAndLost means a replace destroyed a working detection and could not
	// put it back. Distinct from an ordinary failure because the consequence is
	// the opposite: an ordinary failure changes nothing, this one leaves the
	// host less protected than before it was asked.
	FailedAndLost = "FAILED AND THE PREVIOUS VERSION IS LOST: "
)

// Succeeded reports whether an outcome code means the operation did what was
// asked. It exists because "success" is not a single string.
//
// The control plane's command processor decides APPLIED versus REJECTED by
// testing the outcome, and it originally tested `outcome != "ok"`. When
// removals began reporting "removed" instead of "ok" — a strictly better thing
// to show an operator — every SUCCESSFUL removal started acking as REJECTED:
// the console would tell the operator their removal had failed while the policy
// was in fact gone from the kernel. One exported predicate, used by every
// caller, is what stops that from being rediscovered a third time.
//
// NotDurable is deliberately NOT a success: the policy is live but will vanish
// on the next restart, and an ack that calls that "applied" hides the one fact
// the operator has to act on.
func Succeeded(outcome string) bool {
	return outcome == OK || outcome == Removed
}

// Apply loads each doc and removes each named policy, returning a per-policy
// outcome keyed by name.
//
// Every step reports rather than aborts: one policy Tetragon rejects must not
// prevent the other four from loading, and the operator needs to know which of
// the five it was.
func Apply(ctx context.Context, c Client, durableDir string, docs []Doc, remove []string) map[string]string {
	out := make(map[string]string, len(docs)+len(remove))

	for _, d := range docs {
		if d.Name == "" || d.YAML == "" {
			out[d.Name] = "rejected: a policy needs both a name and a body"
			continue
		}
		// ROLLBACK COPY, taken before anything is destroyed.
		//
		// The replace below is delete-then-add, and Tetragon's add can fail:
		// a kprobe symbol this kernel lacks, a selector it rejects, BPF memory
		// exhausted. Without this, that sequence DELETES A WORKING DETECTION
		// and leaves nothing in its place — the host silently stops watching
		// something it was watching a second ago, and the operator is told only
		// that their new policy "failed", which reads like nothing happened.
		//
		// Benign while pushes were mostly new policies (the delete no-ops, the
		// add creates). Editing an existing detection makes replace the normal
		// path, so every typo becomes a destroyed detection.
		//
		// The durable file is the best available previous version. It can be
		// stale relative to the kernel if someone loaded a policy out of band,
		// which is why a restore is REPORTED rather than assumed to be a
		// perfect undo.
		var prior string
		if b, err := os.ReadFile(DurablePath(durableDir, d.Name)); err == nil {
			prior = string(b)
		}

		// Delete-then-add. Tetragon's AddTracingPolicy is CREATE-ONLY, so
		// without the delete a policy whose content changed keeps running the
		// version loaded when the daemon started: the file and the kernel
		// diverge silently, and a fix deploys with no effect. The delete's
		// failure is expected and ignored — the usual case is a policy that is
		// not there yet.
		_, _ = c.DeleteTracingPolicy(ctx, &tetragon.DeleteTracingPolicyRequest{Name: d.Name})

		if _, err := c.AddTracingPolicy(ctx, &tetragon.AddTracingPolicyRequest{Yaml: d.YAML}); err != nil {
			// Verbatim, not paraphrased: a rejected kprobe symbol or an
			// exhausted BPF map is something the operator can only act on in
			// the daemon's own words.
			out[d.Name] = rollback(ctx, c, d.Name, prior, err)
			continue
		}
		// Mode is set explicitly and separately because it decides whether the
		// policy can KILL. An enforcing TracingPolicy fires independently of
		// the choke ladder, with no audit row and no kill-switch.
		if d.Mode != "" {
			if err := ConfigureMode(ctx, c, d.Name, d.Mode); err != nil {
				out[d.Name] = "loaded, but mode not set: " + err.Error()
				continue
			}
		}
		if err := WriteDurable(durableDir, d.Name, d.YAML); err != nil {
			out[d.Name] = NotDurable + err.Error()
			continue
		}
		out[d.Name] = OK
	}

	for _, name := range remove {
		// The durable copy goes FIRST. If the file survives a successful
		// unload, Tetragon reloads the policy at its next restart and the
		// operator's removal silently undoes itself.
		_ = os.Remove(DurablePath(durableDir, name))
		if _, err := c.DeleteTracingPolicy(ctx, &tetragon.DeleteTracingPolicyRequest{Name: name}); err != nil {
			out[name] = "remove failed: " + err.Error()
			continue
		}
		out[name] = Removed
	}
	return out
}

// rollback restores the previous version of a policy after a failed replace,
// and describes what actually happened to the host.
//
// Three genuinely different outcomes, none of which may be collapsed:
//   - restored: the host is watching what it was watching before. Annoying, safe.
//   - could not restore: the host has LOST a detection it had. Urgent.
//   - nothing to restore: there was no previous version, so nothing was lost.
//
// The middle case is the one that must never be reported as a plain "failed".
func rollback(ctx context.Context, c Client, name, prior string, cause error) string {
	if prior == "" {
		return "failed: " + cause.Error() + " (no previous version existed, so nothing was lost)"
	}
	if _, err := c.AddTracingPolicy(ctx, &tetragon.AddTracingPolicyRequest{Yaml: prior}); err != nil {
		return FailedAndLost + cause.Error() + " — and the previous version could NOT be restored (" +
			err.Error() + "). This host is no longer watching what this detection covered."
	}
	return "failed: " + cause.Error() + " — the previous version was restored, so this host is still covered"
}

// ConfigureMode flips a loaded policy between monitor and enforce without
// reloading it. Anything other than those two words is refused rather than
// guessed — "enforce" is the difference between a detection and a kill.
func ConfigureMode(ctx context.Context, c Client, name, mode string) error {
	var m tetragon.TracingPolicyMode
	switch mode {
	case "monitor":
		m = tetragon.TracingPolicyMode_TP_MODE_MONITOR
	case "enforce":
		m = tetragon.TracingPolicyMode_TP_MODE_ENFORCE
	default:
		return fmt.Errorf("unknown policy mode %q (want monitor or enforce)", mode)
	}
	_, err := c.ConfigureTracingPolicy(ctx, &tetragon.ConfigureTracingPolicyRequest{Name: name, Mode: &m})
	return err
}

// DefaultDurableDir is where Tetragon loads TracingPolicies from at startup.
// The deploy bind-mounts it from the host on both agent and engine boxes, so
// the process can write here directly as root — no docker socket, which would
// be root-on-host and a serious privilege expansion just to persist a YAML.
const DefaultDurableDir = "/etc/tetragon/tetragon.tp.d"

// DurablePath is the on-disk location of one policy.
func DurablePath(dir, name string) string {
	return filepath.Join(dir, name+".yaml")
}

// WriteDurable persists a policy so it survives a Tetragon restart.
//
// Atomic via write-to-temp-and-rename: a torn file in this directory is a
// policy the daemon refuses at its next startup, which would turn a routine
// restart into the silent loss of one detection.
//
// Fails rather than creating the directory. Its absence means the bind mount is
// missing, and creating it would produce a file inside this process's own
// filesystem that Tetragon never reads — persisted, unreadable, and reported as
// success. Better to say the policy is live but not durable.
func WriteDurable(dir, name, yaml string) error {
	if dir == "" {
		return fmt.Errorf("no durable policy directory configured")
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return fmt.Errorf("%s is not present (is it bind-mounted into the Tetragon container?)", dir)
	}
	// A name is a filename here, so a name containing a separator would escape
	// the directory. Refused rather than sanitised: a policy whose name does
	// not round-trip is not the policy the operator asked for.
	if strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return fmt.Errorf("refusing a policy name that is a path: %q", name)
	}
	final := DurablePath(dir, name)
	tmp, err := os.CreateTemp(dir, ".tmp-"+name+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(yaml); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), final)
}
