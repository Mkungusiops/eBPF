package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
)

// gatewayApplier adapts control-plane commands onto the local choke gateway.
// It implements command.Applier. The command.Processor has already verified the
// signature and applied the always-protected guardrail before any method here
// runs, so these are the raw effectors. Actions without a clean, safe gateway
// mapping in Phase 1 return an error, which the processor reports as REJECTED
// (honest — never a silent no-op).
// devGW is the network-plane counterpart of gw. It may be nil on an agent
// built without device choke, in which case device-targeted commands are
// REJECTED with a reason rather than silently applied to the wrong plane.
type gatewayApplier struct {
	gw    *choke.Gateway
	devGW *choke.DeviceGateway
}

// SetMode arms or disarms one plane. PLANE_DEVICE targets the network gateway;
// anything else (including UNSPECIFIED, which is what an older control plane
// sends) targets the process gateway, preserving the previous meaning.
func (a gatewayApplier) SetMode(m ebpfsocv1.EnforcementMode, plane ebpfsocv1.Plane) error {
	enforcing := m == ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING
	if plane == ebpfsocv1.Plane_PLANE_DEVICE {
		if a.devGW == nil {
			return fmt.Errorf("set-mode: device plane requested but no device gateway on this agent")
		}
		a.devGW.SetEnforcing(enforcing, "control-plane", "remote SetMode command")
		return nil
	}
	a.gw.SetEnforcing(enforcing, "control-plane", "remote SetMode command")
	return nil
}

func (a gatewayApplier) KillSwitch(halt bool, _ string, plane ebpfsocv1.Plane) error {
	if plane == ebpfsocv1.Plane_PLANE_DEVICE {
		if a.devGW == nil {
			return fmt.Errorf("kill-switch: device plane requested but no device gateway on this agent")
		}
		a.devGW.SetKillSwitch(halt)
		return nil
	}
	a.gw.SetKillSwitch(halt)
	return nil
}

func (a gatewayApplier) SetThresholds(throttleAt, tarpitAt, quarantineAt, severAt int32) error {
	a.gw.SetThresholds(circuit.Config{
		ThrottleAt:   int(throttleAt),
		TarpitAt:     int(tarpitAt),
		QuarantineAt: int(quarantineAt),
		SeverAt:      int(severAt),
	})
	return nil
}

// OwnsTarget implements command.TargetOwner: it answers whether a Jail/Thaw
// target belongs to THIS host, so the command processor can no-op with a
// STATUS_NOT_TARGET ack instead of enforcing on someone else's process.
//
// The control plane dispatches one containment command to several agents when
// it cannot yet tell which one holds the target. Before this gate, every agent
// applied: on the process plane that means the severer SIGKILLs whatever local
// process happens to hold that PID number (PIDs are per-host and collide across
// a fleet) and then acks APPLIED — so the console reported a threat contained
// while the real process kept running on another host, and an unrelated process
// died on this one. Both halves of that are what this gate removes.
func (a gatewayApplier) OwnsTarget(execID string, pid uint32) ebpfsocv1.CommandAck_TargetMatch {
	if mac, isDevice := strings.CutPrefix(execID, devicePrefix); isDevice {
		// MACs are globally unique, so seeing the device is proof; an agent
		// without a device gateway can never own one.
		if a.devGW != nil && a.devGW.Owns(mac) {
			return ebpfsocv1.CommandAck_TARGET_MATCH_DEVICE
		}
		return ebpfsocv1.CommandAck_TARGET_MATCH_NONE
	}
	switch a.gw.Owns(execID, pid) {
	case choke.MatchExecID:
		return ebpfsocv1.CommandAck_TARGET_MATCH_EXEC_ID
	case choke.MatchPID:
		return ebpfsocv1.CommandAck_TARGET_MATCH_PID
	default:
		return ebpfsocv1.CommandAck_TARGET_MATCH_NONE
	}
}

// devicePrefix marks a command whose target is a LAN device (keyed by MAC)
// rather than a process (keyed by exec_id). The control plane encodes device
// targets as "device:<mac>" because Jail/Thaw carry a single target field for
// both planes; this is the matching decode.
const devicePrefix = "device:"

// tierToAction maps the wire tier name onto a circuit action.
func tierToAction(tier string) (circuit.Action, error) {
	switch tier {
	case "throttle":
		return circuit.ActThrottle, nil
	case "tarpit":
		return circuit.ActTarpit, nil
	case "quarantine":
		return circuit.ActQuarantine, nil
	case "sever":
		return circuit.ActSever, nil
	default:
		return circuit.ActNone, fmt.Errorf("jail: unknown tier %q", tier)
	}
}

// Jail applies a remote enforcement tier to one target. It routes through the
// gateway's Manual path — the same one the agent's local HTTP API uses — so a
// console-dispatched choke behaves exactly like a local operator override,
// including bypassing detect-only mode (a manual override is a deliberate
// decision, not an automatic one) and writing the audit row.
//
// A "device:<mac>" target goes to the DEVICE gateway (network plane). Without
// this branch the MAC would be treated as an exec_id and choked on the PROCESS
// gateway, which silently does nothing to the device and leaves a phantom pid=0
// circuit behind.
func (a gatewayApplier) Jail(execID string, pid uint32, tier string) error {
	action, err := tierToAction(tier)
	if err != nil {
		return err
	}
	if mac, isDevice := strings.CutPrefix(execID, devicePrefix); isDevice {
		if a.devGW == nil {
			return fmt.Errorf("jail: device target %q but no device gateway on this agent", mac)
		}
		_, err := a.devGW.ManualDevice(context.Background(), mac, action,
			"remote jail ("+tier+")", "control-plane")
		return err
	}
	_, err = a.gw.Manual(context.Background(), choke.ManualRequest{
		ExecID: execID, PID: pid, Action: action,
		Reason: "remote jail (" + tier + ")", Actor: "control-plane",
	})
	return err
}

// Thaw releases one target back to pristine — ActNone through the same Manual
// path, matching the per-process release the local API performs. Mirrors Jail's
// device-vs-process routing.
func (a gatewayApplier) Thaw(execID string, pid uint32) error {
	if mac, isDevice := strings.CutPrefix(execID, devicePrefix); isDevice {
		if a.devGW == nil {
			return fmt.Errorf("thaw: device target %q but no device gateway on this agent", mac)
		}
		_, err := a.devGW.ThawDevice(context.Background(), mac, "control-plane", "remote thaw")
		return err
	}
	_, err := a.gw.Manual(context.Background(), choke.ManualRequest{
		ExecID: execID, PID: pid, Action: circuit.ActNone,
		Reason: "remote thaw", Actor: "control-plane",
	})
	return err
}

// ApplyPreset switches the gateway's posture from a fleet-wide command.
//
// This returned "not yet supported (Phase 1)" long after Phase 1 shipped, so
// two operators could complete a dual-control approval for a fleet containment
// preset and every agent would ack REJECTED — a change-control flow that ran to
// completion and applied nothing. The gateway's preset machinery was fully
// implemented the whole time; nothing connected it to the command channel.
func (a gatewayApplier) ApplyPreset(name string) error {
	if a.gw == nil {
		return errors.New("preset: no choke gateway on this agent")
	}
	prev, err := a.gw.ApplyPreset(choke.Preset(strings.TrimSpace(name)), "control-plane",
		"fleet preset via command channel")
	if err != nil {
		return err // unknown preset — the gateway validates the name
	}
	log.Printf("[applier] preset=%s applied (previous: thresholds=%+v kill_switch=%v dry_run=%v)",
		name, prev.Thresholds, prev.KillSwitched, prev.DryRun)
	return nil
}

// SetProtectedList widens the enforcement exemption lists on both planes.
//
// Both underlying setters are deliberately additive against a safe minimum:
// Gateway.SetSystemCritical always unions the default list (sshd, sudo,
// systemd, the login path) and DeviceGateway.SetProtectedMACs only ever adds.
// So a signed command can widen protection and cannot narrow it — the
// sudo-lockout defense in threat-model EN-1. command.Processor also unions
// before calling here; the guarantee is enforced at both ends on purpose,
// because one call site is one call site away from being forgotten.
func (a gatewayApplier) SetProtectedList(binaries, macs []string) error {
	if a.gw == nil {
		return errors.New("protected-list: no choke gateway on this agent")
	}
	effective := a.gw.SetSystemCritical(binaries)
	log.Printf("[applier] system-critical exemption list set: %d binaries", len(effective))

	if a.devGW != nil && len(macs) > 0 {
		added, skipped := a.devGW.SetProtectedMACs(macs)
		log.Printf("[applier] device protect-list: %d MAC(s) protected", len(added))
		if len(skipped) > 0 {
			// Reported, not swallowed: a MAC the operator believes is
			// protected but which never parsed is exactly the gap that gets
			// a gateway severed.
			return fmt.Errorf("protected-list applied, but %d MAC(s) were unparseable and are NOT protected: %s",
				len(skipped), strings.Join(skipped, ", "))
		}
	}
	return nil
}
