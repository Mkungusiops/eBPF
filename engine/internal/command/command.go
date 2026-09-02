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
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/policyapply"
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
	// Jail contains a target. revertAfter of 0 means the containment stands
	// until an operator thaws it.
	Jail(execID string, pid uint32, tier string, revertAfter time.Duration) error
	Thaw(execID string, pid uint32) error
	SetThresholds(throttleAt, tarpitAt, quarantineAt, severAt int32) error
	ApplyPreset(name string) error
	KillSwitch(halt bool, reason string, plane ebpfsocv1.Plane) error
	SetProtectedList(binaries, macs []string) error
}

// DecisionResender is implemented by an agent that can re-queue decisions it
// has already sent, so the control plane can close a gap in the audit chain.
//
// Optional: an agent with no local decision store cannot replay, and must
// answer "I cannot" rather than acking a command it silently ignored — the
// distinction an operator watching a fleet needs.
type DecisionResender interface {
	// ResendDecisions re-queues up to limit decisions with id >= fromID and
	// reports how many were queued.
	ResendDecisions(fromID int64, limit int) (int, error)
}

// ConfigAuditor is implemented by an agent that can record a signed
// configuration change in its tamper-evident decision ledger.
//
// # Why this exists as its own interface
//
// Containment commands (Jail, Thaw) already produce an audit row, because they
// go through the gateway's decision path. Configuration commands did not
// produce one at all — not on any of the six that change how enforcement
// BEHAVES fleet-wide: mode, kill-switch, thresholds, preset, protect-list,
// suppressions. An operator could arm every host in a tenant, drop the
// thresholds so ordinary activity reaches a sever, or switch detection off,
// and the ledger those hosts keep would show nothing.
//
// That was invisible because the single-tenant engine DOES audit all six from
// its HTTP handlers. The same action was recorded on one plane and silent on
// the other, and the silent one is the multi-tenant plane.
//
// Optional, like TargetOwner: an applier that cannot audit is not refused, it
// simply records nothing — which is what the simulator and the tests want.
type ConfigAuditor interface {
	// AuditConfigCommand records one applied configuration change. detail is
	// the human-readable new value; actor is the operator named in the signed
	// command, empty when the platform acted on its own.
	AuditConfigCommand(action, detail, actor string)
}

// SuppressionApplier is implemented by an agent that can withhold scores for
// operator-defined patterns. Separate from Applier for the same reason
// PolicyApplier is: an agent that cannot do it must say so rather than ack a
// command it silently ignored.
type SuppressionApplier interface {
	SetSuppressions([]*ebpfsocv1.Suppression) error
}

// PolicyApplier is the OPTIONAL half of Applier that changes detection policy.
//
// Optional so an agent build without a Tetragon connection — or a test fake —
// simply reports the action unsupported rather than failing to compile. The
// Processor checks for it and answers STATUS_REJECTED when it is absent, which
// is the honest reply: this agent cannot do that, as distinct from it tried and
// failed.
type PolicyApplier interface {
	// ApplyPolicies loads or replaces each document and removes each name.
	// Returns a per-policy outcome map so a PARTIAL application is reportable:
	// an aggregate boolean over four policies where two loaded would leave the
	// operator believing all four did.
	ApplyPolicies(docs []*ebpfsocv1.PolicyDoc, remove []string) (map[string]string, error)
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
	//
	// A nil canonical form means this build cannot represent the action, so it
	// cannot check what it would be agreeing to. Verifying against nil would
	// compare a signature over EMPTY bytes and could accept it; refusing is the
	// only safe reading of "I do not understand this command".
	canon := Canonical(c)
	if canon == nil {
		return ack(id, ebpfsocv1.CommandAck_STATUS_REJECTED,
			"unsupported action: this agent cannot canonicalise it, so its signature cannot be checked")
	}
	if !p.verify.Verify(canon, c.GetSignature()) {
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
		// Audited on this path too. The kill-switch returns early — it must
		// work while halted, since it is also the unhalt path — so the audit
		// at the end of Handle never sees it. Missing that would have left the
		// single most consequential control in the product as the one
		// configuration change with no record: stopping all enforcement across
		// a tenant, and nothing anywhere saying who did it or when.
		p.auditConfig(c)
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
		err = p.applier.Jail(a.Jail.GetExecId(), a.Jail.GetPid(), a.Jail.GetTier(),
			time.Duration(a.Jail.GetRevertAfterSeconds())*time.Second)
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
	case *ebpfsocv1.Command_ApplyPolicy:
		// Detection policy. Rejected outright when this agent has no policy
		// applier — "I cannot" is a different answer from "I tried and failed",
		// and an operator watching a fleet needs to tell them apart.
		pa, ok := p.applier.(PolicyApplier)
		if !ok {
			return ack(id, ebpfsocv1.CommandAck_STATUS_REJECTED,
				"this agent cannot apply detection policy (no Tetragon connection)")
		}
		ap := a.ApplyPolicy
		var outcomes map[string]string
		outcomes, err = pa.ApplyPolicies(ap.GetPolicies(), ap.GetRemove())
		// A PARTIAL application must not ack as applied. Four policies where
		// two loaded leaves the host in a state matching neither the old set
		// nor the requested one, and an aggregate "applied" would hide it.
		if err == nil {
			var failed []string
			for name, outcome := range outcomes {
				// policyapply.Succeeded, not a literal: a removal reports
				// "removed" rather than "ok", and testing the literal acked
				// every successful removal as REJECTED.
				if !policyapply.Succeeded(outcome) {
					failed = append(failed, name+": "+outcome)
				}
			}
			if len(failed) > 0 {
				sort.Strings(failed)
				return ack(id, ebpfsocv1.CommandAck_STATUS_REJECTED,
					"partially applied — "+strings.Join(failed, "; "))
			}
		}
	case *ebpfsocv1.Command_ResendDecisions:
		rs, ok := p.applier.(DecisionResender)
		if !ok {
			return ack(id, ebpfsocv1.CommandAck_STATUS_REJECTED,
				"this agent cannot replay decisions (no local decision store)")
		}
		rd := a.ResendDecisions
		var n int
		n, err = rs.ResendDecisions(rd.GetFromId(), int(rd.GetLimit()))
		if err == nil {
			// The COUNT is the answer. "Applied" alone would leave the control
			// plane unable to tell a gap that was filled from one the agent no
			// longer has the records for.
			return ack(id, ebpfsocv1.CommandAck_STATUS_APPLIED,
				fmt.Sprintf("re-queued %d decision(s)", n))
		}
	case *ebpfsocv1.Command_UpdateSuppressions:
		// Suppressions can only REDUCE what is scored, so unlike a policy push
		// there is no capability to refuse on and no partial-application
		// hazard: the agent replaces its whole set or fails.
		sa, ok := p.applier.(SuppressionApplier)
		if !ok {
			return ack(id, ebpfsocv1.CommandAck_STATUS_REJECTED,
				"this agent cannot apply scoring suppressions")
		}
		err = sa.SetSuppressions(a.UpdateSuppressions.GetSuppressions())

	default:
		return ack(id, ebpfsocv1.CommandAck_STATUS_REJECTED, "unknown or empty command action")
	}
	if err != nil {
		return ackMatch(id, ebpfsocv1.CommandAck_STATUS_REJECTED, err.Error(), match)
	}
	// Audited AFTER the apply succeeded, in one place rather than in each of
	// the six appliers. A row written before the apply would claim a change
	// that a validating applier then refused — and SetThresholds refuses a
	// ladder that would sever everything, so that is a live case, not a
	// hypothetical.
	p.auditConfig(c)
	return ackMatch(id, ebpfsocv1.CommandAck_STATUS_APPLIED, "", match)
}

// auditConfig records a configuration change in the agent's decision ledger.
//
// Only the actions that change how enforcement BEHAVES. Jail and Thaw are
// deliberately absent: they already produce a decision row through the
// gateway, and recording them twice would double-count containment in the
// audit an incident review reads.
func (p *Processor) auditConfig(c *ebpfsocv1.Command) {
	auditor, ok := p.applier.(ConfigAuditor)
	if !ok {
		return
	}
	var action, detail string
	switch a := c.GetAction().(type) {
	case *ebpfsocv1.Command_SetMode:
		action, detail = "set-mode", fmt.Sprintf("%s plane=%s", a.SetMode.GetMode(), a.SetMode.GetPlane())
	case *ebpfsocv1.Command_KillSwitch:
		action = "kill-switch"
		detail = fmt.Sprintf("halt=%v plane=%s %s",
			a.KillSwitch.GetHaltAllEnforcement(), a.KillSwitch.GetPlane(), a.KillSwitch.GetReason())
	case *ebpfsocv1.Command_SetThresholds:
		t := a.SetThresholds
		action = "set-thresholds"
		detail = fmt.Sprintf("%d/%d/%d/%d", t.GetThrottleAt(), t.GetTarpitAt(), t.GetQuarantineAt(), t.GetSeverAt())
	case *ebpfsocv1.Command_ApplyPreset:
		action, detail = "apply-preset", a.ApplyPreset.GetPreset()
	case *ebpfsocv1.Command_UpdateProtectedList:
		u := a.UpdateProtectedList
		action = "protect-list"
		detail = fmt.Sprintf("%d binaries, %d addresses",
			len(u.GetProtectedBinaries()), len(u.GetProtectedMacs()))
	case *ebpfsocv1.Command_UpdateSuppressions:
		action = "set-suppressions"
		detail = fmt.Sprintf("%d rules", len(a.UpdateSuppressions.GetSuppressions()))
	default:
		return // containment and policy audit themselves elsewhere
	}
	auditor.AuditConfigCommand(action, detail, c.GetActor())
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
	// Actor is bound, because it ends up in a tamper-evident audit row as
	// verified fact. Left unbound, anyone on the path could rename the operator
	// on a validly-signed command and the chain would attest to it — an
	// attributable action whose attribution can be rewritten is worse than an
	// anonymous one, because it accuses a specific person.
	//
	// Included ONLY when non-empty, so a command carrying no actor produces
	// byte-for-byte what it produced before this field existed. That keeps an
	// agent from before this change verifying commands from a control plane
	// from before it. The remaining window is a NEW control plane sending an
	// actor to an OLD agent mid-deploy: those are rejected on signature, which
	// is visible and retryable rather than silent.
	if actor := c.GetActor(); actor != "" {
		fmt.Fprintf(&b, "actor=%s;", actor)
	}
	switch a := c.GetAction().(type) {
	case *ebpfsocv1.Command_SetMode:
		// Plane is IN the signature. It was not, and the agent acts on it
		// (Handle -> applier.SetMode(mode, plane)), so anyone able to modify
		// the stream could retarget a validly-signed mode change at the other
		// enforcement plane and the signature would still verify.
		fmt.Fprintf(&b, "set_mode=%d,plane=%d", a.SetMode.GetMode(), a.SetMode.GetPlane())
	case *ebpfsocv1.Command_Jail:
		// revert_after_seconds is bound here because it changes what the
		// command DOES: the same jail with and without it is a temporary
		// containment versus a permanent one. Leaving it out of the canonical
		// form would let anything between the control plane and the agent strip
		// the auto-revert from a validly signed command and turn a
		// thirty-minute hold into an indefinite one, with the signature still
		// verifying.
		fmt.Fprintf(&b, "jail=%s,%d,%s", a.Jail.GetExecId(), a.Jail.GetPid(), a.Jail.GetTier())
		if secs := a.Jail.GetRevertAfterSeconds(); secs > 0 {
			// Appended only when set, so every command signed before this field
			// existed still canonicalises to the same bytes it was signed with.
			fmt.Fprintf(&b, ",revert=%d", secs)
		}
	case *ebpfsocv1.Command_Thaw:
		fmt.Fprintf(&b, "thaw=%s,%d", a.Thaw.GetExecId(), a.Thaw.GetPid())
	case *ebpfsocv1.Command_SetThresholds:
		t := a.SetThresholds
		fmt.Fprintf(&b, "thresholds=%d,%d,%d,%d", t.GetThrottleAt(), t.GetTarpitAt(), t.GetQuarantineAt(), t.GetSeverAt())
	case *ebpfsocv1.Command_ApplyPreset:
		fmt.Fprintf(&b, "preset=%s", a.ApplyPreset.GetPreset())
	case *ebpfsocv1.Command_KillSwitch:
		// Same omission, on the one control that exists to stop everything: a
		// signed process-plane halt could be flipped to the device plane, so
		// the operator's emergency stop lands on the wrong plane while process
		// enforcement keeps killing. threat-model EN-2/CH-5.
		fmt.Fprintf(&b, "killswitch=%v,%s,plane=%d",
			a.KillSwitch.GetHaltAllEnforcement(), a.KillSwitch.GetReason(), a.KillSwitch.GetPlane())
	case *ebpfsocv1.Command_UpdateProtectedList:
		u := a.UpdateProtectedList
		fmt.Fprintf(&b, "protected=%s|%s", strings.Join(u.GetProtectedBinaries(), ","), strings.Join(u.GetProtectedMacs(), ","))
	case *ebpfsocv1.Command_ResendDecisions:
		// Bounds are IN the signature: they decide how much an agent replays,
		// and an unbound rewrite of the limit could be used to flood a fleet's
		// outbound buffers and evict live telemetry behind the replay.
		rd := a.ResendDecisions
		fmt.Fprintf(&b, "resend=%d,%d", rd.GetFromId(), rd.GetLimit())
	case *ebpfsocv1.Command_ApplyPolicy:
		// The policy BODIES are hashed, not inlined: a 10 KB YAML in the signed
		// string would make every signature verification allocate the whole
		// bundle, and the hash binds the content just as tightly. Name, mode
		// and the removal list are inlined because they are short and each one
		// changes what the command DOES — mode especially, since "enforce"
		// decides whether the policy can kill.
		ap := a.ApplyPolicy
		fmt.Fprintf(&b, "applypolicy=")
		for _, d := range ap.GetPolicies() {
			sum := sha256.Sum256([]byte(d.GetYaml()))
			fmt.Fprintf(&b, "%s:%s:%x,", d.GetName(), d.GetMode(), sum[:8])
		}
		fmt.Fprintf(&b, "|remove=%s|reason=%s", strings.Join(ap.GetRemove(), ","), ap.GetReason())
	case *ebpfsocv1.Command_UpdateSuppressions:
		// Every field is inlined: they are all short, and each one changes WHAT
		// IS SILENCED. A signature that did not bind the policy or parent
		// narrowing would let an attacker widen a legitimate suppression from
		// "this binary under this detection" to "this binary always" without
		// breaking the signature.
		us := a.UpdateSuppressions
		fmt.Fprintf(&b, "suppressions=")
		for _, r := range us.GetSuppressions() {
			fmt.Fprintf(&b, "%s:%s:%s,", r.GetBinary(), r.GetPolicy(), r.GetParent())
		}
		fmt.Fprintf(&b, "|reason=%s", us.GetReason())
	default:
		// An action this build does not know how to canonicalise must NOT be
		// signable. Falling through left the signature covering only
		// "id=…;exp=…", so any two commands of an unhandled kind sharing an id
		// and expiry had identical signatures — and a future action added to
		// the proto without a case here would ship unsigned in all but name.
		// Returning nil makes Sign/Verify fail closed instead.
		return nil
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
