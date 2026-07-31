package main

import (
	"path/filepath"
	"testing"
	"time"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/tokens"
	"github.com/jeffmk/ebpf-poc-engine/internal/device"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/bpfmap"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/devbpf"
	"github.com/jeffmk/ebpf-poc-engine/internal/policy"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
)

// newTestApplier wires a gatewayApplier over real process + device gateways
// (noop kernel backends) — the same pair main() hands the command processor.
func newTestApplier(t *testing.T) (gatewayApplier, *choke.Gateway, *choke.DeviceGateway) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.New(filepath.Join(dir, "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	be := bpfmap.NewNoopBackend()
	_ = be.Open()
	gw := choke.NewGateway(choke.Config{
		Store: st, Broadcast: nil, Tokens: tokens.NewManager(),
		Tree: tree.New(time.Hour), BPFMap: be, Policies: policy.NewSet(),
		Enforcer:  &enforce.Multi{Backends: []enforce.Enforcer{&enforce.Throttler{Backend: be}}},
		Enforcing: true,
	})

	devBE := devbpf.NewNoopDeviceBackend()
	_ = devBE.Open()
	devGW := choke.NewDeviceGateway(choke.DeviceConfig{
		Throttler: enforce.NewDeviceThrottler(devBE, map[devbpf.MAC]bool{}),
		Backend:   devBE,
		Table:     device.NewTable(time.Hour),
		Store:     st,
		Enforcing: true,
	})
	return gatewayApplier{gw: gw, devGW: devGW}, gw, devGW
}

func deviceState(t *testing.T, g *choke.DeviceGateway, mac string) string {
	t.Helper()
	for _, d := range g.Snapshot() {
		if d.MAC == mac {
			return d.State
		}
	}
	return "MISSING"
}

// A "device:<mac>" command must reach the DEVICE gateway. It used to fall
// through to the process gateway, which left the device untouched (enforcement
// silently did nothing) and created a phantom pid=0 process circuit.
func TestJailRoutesDeviceTargetToDeviceGateway(t *testing.T) {
	a, gw, devGW := newTestApplier(t)
	const mac = "aa:bb:cc:dd:ee:01"

	if err := a.Jail(devicePrefix+mac, 0, "quarantine"); err != nil {
		t.Fatalf("Jail device: %v", err)
	}
	if got := deviceState(t, devGW, mac); got != circuit.Quarantined.String() {
		t.Errorf("device state = %q, want %q", got, circuit.Quarantined)
	}
	for _, c := range gw.Snapshot() {
		if c.ExecID == devicePrefix+mac {
			t.Errorf("device target leaked into the PROCESS gateway as circuit %q (pid=%d)", c.ExecID, c.PID)
		}
	}
}

func TestThawRoutesDeviceTargetToDeviceGateway(t *testing.T) {
	a, gw, devGW := newTestApplier(t)
	const mac = "aa:bb:cc:dd:ee:02"

	if err := a.Jail(devicePrefix+mac, 0, "sever"); err != nil {
		t.Fatalf("Jail device: %v", err)
	}
	if got := deviceState(t, devGW, mac); got != circuit.Severed.String() {
		t.Fatalf("device state after sever = %q, want %q", got, circuit.Severed)
	}
	// A device sever is a reversible drop rule, unlike a process SIGKILL.
	if err := a.Thaw(devicePrefix+mac, 0); err != nil {
		t.Fatalf("Thaw device: %v", err)
	}
	if got := deviceState(t, devGW, mac); got != circuit.Pristine.String() {
		t.Errorf("device state after thaw = %q, want %q", got, circuit.Pristine)
	}
	for _, c := range gw.Snapshot() {
		if c.ExecID == devicePrefix+mac {
			t.Errorf("device target leaked into the PROCESS gateway as circuit %q", c.ExecID)
		}
	}
}

// The process path must be unaffected by the device branch.
func TestJailStillRoutesProcessTargetToProcessGateway(t *testing.T) {
	a, gw, devGW := newTestApplier(t)
	const execID = "exec-abc"

	if err := a.Jail(execID, 4242, "throttle"); err != nil {
		t.Fatalf("Jail process: %v", err)
	}
	var found bool
	for _, c := range gw.Snapshot() {
		if c.ExecID == execID {
			found = true
			if c.State != circuit.Throttled.String() {
				t.Errorf("process state = %q, want %q", c.State, circuit.Throttled)
			}
		}
	}
	if !found {
		t.Errorf("process target %q never reached the process gateway", execID)
	}
	if n := len(devGW.Snapshot()); n != 0 {
		t.Errorf("process target touched the device gateway (%d devices)", n)
	}
}

// Without a device gateway the command must be REJECTED with a reason, never
// silently applied to the wrong plane.
func TestJailDeviceTargetWithoutDeviceGatewayErrors(t *testing.T) {
	a, _, _ := newTestApplier(t)
	a.devGW = nil
	if err := a.Jail(devicePrefix+"aa:bb:cc:dd:ee:03", 0, "throttle"); err == nil {
		t.Error("Jail with no device gateway returned nil, want an error")
	}
	if err := a.Thaw(devicePrefix+"aa:bb:cc:dd:ee:03", 0); err == nil {
		t.Error("Thaw with no device gateway returned nil, want an error")
	}
}

// SetMode and KillSwitch used to be plane-agnostic, so arming the DEVICE plane
// from the console armed the PROCESS gateway instead — where a sever is a
// SIGKILL rather than a reversible drop rule.
func TestSetModeTargetsTheRequestedPlane(t *testing.T) {
	a, gw, devGW := newTestApplier(t)
	// Start both disarmed so an arm on one plane is unambiguous.
	gw.SetEnforcing(false, "test", "reset")
	devGW.SetEnforcing(false, "test", "reset")

	if err := a.SetMode(ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING, ebpfsocv1.Plane_PLANE_DEVICE); err != nil {
		t.Fatalf("SetMode device: %v", err)
	}
	if got := devGW.Mode(); got != "enforcing" {
		t.Errorf("device gateway mode = %q, want enforcing", got)
	}
	if got := gw.Mode(); got != choke.ModeDetectOnly {
		t.Errorf("device SetMode leaked onto the PROCESS gateway (mode=%v)", got)
	}
}

func TestSetModeDefaultsToTheProcessPlane(t *testing.T) {
	a, gw, devGW := newTestApplier(t)
	gw.SetEnforcing(false, "test", "reset")
	devGW.SetEnforcing(false, "test", "reset")

	// UNSPECIFIED is what a control plane predating the plane field sends.
	if err := a.SetMode(ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING, ebpfsocv1.Plane_PLANE_UNSPECIFIED); err != nil {
		t.Fatalf("SetMode unspecified: %v", err)
	}
	if got := gw.Mode(); got != choke.ModeEnforcing {
		t.Errorf("process gateway mode = %v, want enforcing", got)
	}
	if got := devGW.Mode(); got != "detect-only" {
		t.Errorf("unspecified SetMode leaked onto the DEVICE gateway (mode=%q)", got)
	}
}

func TestKillSwitchTargetsTheRequestedPlane(t *testing.T) {
	a, gw, devGW := newTestApplier(t)

	if err := a.KillSwitch(true, "e2e", ebpfsocv1.Plane_PLANE_DEVICE); err != nil {
		t.Fatalf("KillSwitch device: %v", err)
	}
	if !devGW.KillSwitched() {
		t.Error("device kill-switch not engaged")
	}
	if gw.KillSwitched() {
		t.Error("device kill-switch leaked onto the PROCESS gateway")
	}

	if err := a.KillSwitch(true, "e2e", ebpfsocv1.Plane_PLANE_PROCESS); err != nil {
		t.Fatalf("KillSwitch process: %v", err)
	}
	if !gw.KillSwitched() {
		t.Error("process kill-switch not engaged")
	}
}
