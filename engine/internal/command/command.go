// Package command is the agent side of the control-plane command channel
// (docs/plan/wire-contract.md §5). It verifies a signed command, checks
// expiry, applies CONSERVATIVE LOCAL GUARDRAILS, and only then effects it via
// an Applier — returning an ack for the control plane.
//
// The guardrails are the crux of the enforcement-blast-radius defense
// (threat-model.md EN-1/EN-4, the sudo-lockout trap): a validly-signed command
// can never remove the always-protected binaries (sudo/sshd/systemd/…) from the
// protected set, and while the kill-switch is engaged no command may re-arm
// enforcement. Local safety overrides remote intent, always.
package command

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
)

// Applier is the agent's local effector. The real agent wires it to the choke
// gateway; tests use a fake. Methods should be idempotent where possible.
// The agent runs two independent enforcement planes, so mode and kill-switch
// carry the plane they act on. Sending them plane-agnostically meant an operator
// arming the DEVICE plane silently armed the PROCESS plane instead — where a
// sever is a SIGKILL rather than a reversible drop rule.
type Applier interface {
	SetMode(mode ebpfsocv1.EnforcementMode, plane ebpfsocv1.Plane) error
	Jail(execID string, pid uint32, tier string) error
	Thaw(execID string, pid uint32) error
	SetThresholds(throttleAt, tarpitAt, quarantineAt, severAt int32) error
	ApplyPreset(name string) error
	KillSwitch(halt bool, reason string, plane ebpfsocv1.Plane) error
	SetProtectedList(binaries, macs []string) error
}

// TargetOwner is the optional half of Applier that answers "is this Jail/Thaw
// target actually mine?".
//
// It exists because the control plane cannot always tell which agent in a
// tenant is running a given process, so one containment command may be
// dispatched to several of them. Every agent that is not running the target
// must no-op AND SAY SO: an agent that no-ops but acks APPLIED tells the
// operator a threat is contained while it is still running, which is the exact
// failure this product exists to prevent. Worse on the process plane, applying
// blind means SIGKILLing whatever local process happens to hold that PID
// number — PIDs are per-host and collide across a fleet.
//
// An Applier that does not implement this keeps the old, trusting behavior, so
// simulators and tests are unaffected.
type TargetOwner interface {
	// OwnsTarget grades this host's claim on (execID, pid). The grades are
	// ordered: EXEC_ID (this host observed it) beats PID (a live process of
	// that number is here, which is a guess) beats NONE.
	OwnsTarget(execID string, pid uint32) ebpfsocv1.CommandAck_TargetMatch
}

// Processor verifies and applies signed commands. It is safe for concurrent use.
type Processor struct {
	verify          signing.Verifier
	applier         Applier
	alwaysProtected []string // local minimum; never removable by a command

	mu     sync.Mutex
	halted bool // kill-switch engaged
}

// NewProcessor builds a processor. alwaysProtected is the local minimum set of
// protected binaries (e.g. choke.DefaultSystemCriticalBinaries()) that no
// command may strip — passed in so this package does not depend on choke.
func NewProcessor(verify signing.Verifier, applier Applier, alwaysProtected []string) *Processor {
	return &Processor{verify: verify, applier: applier, alwaysProtected: alwaysProtected}
}

// Handle verifies, guardrail-checks, and applies a single command, returning the
// ack the agent sends back on the command stream.
func (p *Processor) Handle(c *ebpfsocv1.Command) *ebpfsocv1.CommandAck {
	id := c.GetCommandId()

	// 1. Expiry — reject stale commands before doing any work.
	if exp := c.GetExpiresAt(); exp != nil && time.Now().After(exp.AsTime()) {
		return ack(id, ebpfsocv1.CommandAck_STATUS_EXPIRED, "command expired")
	}

	// 2. Signature — the fleet signer must have authorized these exact bytes.
	if !p.verify.Verify(Canonical(c), c.GetSignature()) {
		return ack(id, ebpfsocv1.CommandAck_STATUS_REJECTED, "invalid or missing signature")
	}

	// 3. Kill-switch is always honored, even while halted (it is the unhalt path).
	if ks, ok := c.GetAction().(*ebpfsocv1.Command_KillSwitch); ok {
		if err := p.applier.KillSwitch(ks.KillSwitch.GetHaltAllEnforcement(), ks.KillSwitch.GetReason(), ks.KillSwitch.GetPlane()); err != nil {
			return ack(id, ebpfsocv1.CommandAck_STATUS_REJECTED, err.Error())
		}
		// Only a PROCESS-plane halt gates further commands. A device-plane
		// kill-switch stops network enforcement without freezing the whole
		// command channel, so process containment stays reachable.
		if ks.KillSwitch.GetPlane() != ebpfsocv1.Plane_PLANE_DEVICE {
			p.mu.Lock()
			p.halted = ks.KillSwitch.GetHaltAllEnforcement()
			p.mu.Unlock()
		}
		return ack(id, ebpfsocv1.CommandAck_STATUS_APPLIED, "")
	}

	// 4. While halted, refuse anything that could re-arm enforcement.
	p.mu.Lock()
	halted := p.halted
	p.mu.Unlock()
	if halted {
		return ack(id, ebpfsocv1.CommandAck_STATUS_REJECTED, "kill-switch engaged; enforcement halted")
	}

	// 5. Effect the action.
	//
	// The targeted actions (Jail/Thaw) are gated on ownership FIRST. Deciding
	// after the fact is not good enough: on the process plane the enforcer would
	// already have SIGKILLed a same-numbered local PID before anyone asked whose
	// process it was.
	var err error
	match := ebpfsocv1.CommandAck_TARGET_MATCH_UNSPECIFIED
	switch a := c.GetAction().(type) {
	case *ebpfsocv1.Command_SetMode:
		err = p.applier.SetMode(a.SetMode.GetMode(), a.SetMode.GetPlane())
	case *ebpfsocv1.Command_Jail:
		if match = p.ownership(a.Jail.GetExecId(), a.Jail.GetPid()); match == ebpfsocv1.CommandAck_TARGET_MATCH_NONE {
			return ackMatch(id, ebpfsocv1.CommandAck_STATUS_NOT_TARGET, notTargetDetail, match)
		}
		err = p.applier.Jail(a.Jail.GetExecId(), a.Jail.GetPid(), a.Jail.GetTier())
	case *ebpfsocv1.Command_Thaw:
		if match = p.ownership(a.Thaw.GetExecId(), a.Thaw.GetPid()); match == ebpfsocv1.CommandAck_TARGET_MATCH_NONE {
			return ackMatch(id, ebpfsocv1.CommandAck_STATUS_NOT_TARGET, notTargetDetail, match)
		}
		err = p.applier.Thaw(a.Thaw.GetExecId(), a.Thaw.GetPid())
	case *ebpfsocv1.Command_SetThresholds:
		t := a.SetThresholds
		err = p.applier.SetThresholds(t.GetThrottleAt(), t.GetTarpitAt(), t.GetQuarantineAt(), t.GetSeverAt())
	case *ebpfsocv1.Command_ApplyPreset:
		err = p.applier.ApplyPreset(a.ApplyPreset.GetPreset())
	case *ebpfsocv1.Command_UpdateProtectedList:
		u := a.UpdateProtectedList
		// GUARDRAIL: union the command's list with the always-protected
		// minimum so sudo/sshd/systemd can never be stripped, even by a valid
		// signature (the sudo-lockout defense).
		err = p.applier.SetProtectedList(unionProtected(u.GetProtectedBinaries(), p.alwaysProtected), u.GetProtectedMacs())
	default:
		return ack(id, ebpfsocv1.CommandAck_STATUS_REJECTED, "unknown or empty command action")
	}
	if err != nil {
		return ackMatch(id, ebpfsocv1.CommandAck_STATUS_REJECTED, err.Error(), match)
	}
	return ackMatch(id, ebpfsocv1.CommandAck_STATUS_APPLIED, "", match)
}

// notTargetDetail is what the operator ends up reading when a command reached
// an agent that is not running the target. It has to be plain, because it will
// appear in the console next to a containment they asked for.
const notTargetDetail = "this agent is not running that target; nothing was done"

// ownership asks the applier whether the target is this host's. An applier that
// does not implement TargetOwner cannot answer, so it keeps the pre-existing
// behavior of applying whatever it is told — reported as UNSPECIFIED so the
// control plane can see the claim is ungraded rather than mistaking it for
// proof of ownership.
func (p *Processor) ownership(execID string, pid uint32) ebpfsocv1.CommandAck_TargetMatch {
	owner, ok := p.applier.(TargetOwner)
	if !ok {
		return ebpfsocv1.CommandAck_TARGET_MATCH_UNSPECIFIED
	}
	return owner.OwnsTarget(execID, pid)
}

// Halted reports whether the kill-switch is currently engaged.
func (p *Processor) Halted() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.halted
}

// Canonical is the deterministic byte encoding of a command that the fleet
// signs and the agent verifies. Both sides MUST agree on it. It covers the
// command id, expiry, and the action-specific fields.
func Canonical(c *ebpfsocv1.Command) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "id=%s;exp=%d;", c.GetCommandId(), c.GetExpiresAt().GetSeconds())
	switch a := c.GetAction().(type) {
	case *ebpfsocv1.Command_SetMode:
		fmt.Fprintf(&b, "set_mode=%d", a.SetMode.GetMode())
	case *ebpfsocv1.Command_Jail:
		fmt.Fprintf(&b, "jail=%s,%d,%s", a.Jail.GetExecId(), a.Jail.GetPid(), a.Jail.GetTier())
	case *ebpfsocv1.Command_Thaw:
		fmt.Fprintf(&b, "thaw=%s,%d", a.Thaw.GetExecId(), a.Thaw.GetPid())
	case *ebpfsocv1.Command_SetThresholds:
		t := a.SetThresholds
		fmt.Fprintf(&b, "thresholds=%d,%d,%d,%d", t.GetThrottleAt(), t.GetTarpitAt(), t.GetQuarantineAt(), t.GetSeverAt())
	case *ebpfsocv1.Command_ApplyPreset:
		fmt.Fprintf(&b, "preset=%s", a.ApplyPreset.GetPreset())
	case *ebpfsocv1.Command_KillSwitch:
		fmt.Fprintf(&b, "killswitch=%v,%s", a.KillSwitch.GetHaltAllEnforcement(), a.KillSwitch.GetReason())
	case *ebpfsocv1.Command_UpdateProtectedList:
		u := a.UpdateProtectedList
		fmt.Fprintf(&b, "protected=%s|%s", strings.Join(u.GetProtectedBinaries(), ","), strings.Join(u.GetProtectedMacs(), ","))
	}
	return []byte(b.String())
}

// unionProtected returns the deduplicated union of the requested binaries and
// the always-protected minimum, preserving that the minimum is a subset.
func unionProtected(requested, always []string) []string {
	seen := make(map[string]struct{}, len(requested)+len(always))
	out := make([]string, 0, len(requested)+len(always))
	for _, s := range append(append([]string{}, requested...), always...) {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func ack(id string, st ebpfsocv1.CommandAck_Status, detail string) *ebpfsocv1.CommandAck {
	return ackMatch(id, st, detail, ebpfsocv1.CommandAck_TARGET_MATCH_UNSPECIFIED)
}

func ackMatch(id string, st ebpfsocv1.CommandAck_Status, detail string, match ebpfsocv1.CommandAck_TargetMatch) *ebpfsocv1.CommandAck {
	return &ebpfsocv1.CommandAck{
		CommandId:   id,
		Status:      st,
		Detail:      detail,
		AppliedAt:   timestamppb.Now(),
		TargetMatch: match,
	}
}
