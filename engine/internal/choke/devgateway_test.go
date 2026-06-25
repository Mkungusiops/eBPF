package choke

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/device"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/devbpf"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

func newTestDeviceGateway(t *testing.T, protected ...string) (*DeviceGateway, devbpf.Backend, *store.Store) {
	t.Helper()
	st, err := store.New(filepath.Join(t.TempDir(), "dev.db"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	backend := devbpf.NewNoopDeviceBackend()
	if err := backend.Open(); err != nil {
		t.Fatalf("backend.Open: %v", err)
	}
	prot := map[devbpf.MAC]bool{}
	for _, m := range protected {
		mac, err := devbpf.ParseMAC(m)
		if err != nil {
			t.Fatalf("bad protected MAC %q: %v", m, err)
		}
		prot[mac] = true
	}
	thr := enforce.NewDeviceThrottler(backend, prot)
	gw := NewDeviceGateway(DeviceConfig{
		Throttler: thr,
		Backend:   backend,
		Table:     device.NewTable(time.Hour),
		Store:     st,
		Enforcing: true,
	})
	return gw, backend, st
}

func hasMAC(t *testing.T, b devbpf.Backend, macStr string) (devbpf.DeviceBucket, bool) {
	t.Helper()
	m, _ := devbpf.ParseMAC(macStr)
	snap, err := b.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	v, ok := snap[m]
	return v, ok
}

func TestDeviceGatewayJailWritesBucketAndState(t *testing.T) {
	gw, backend, st := newTestDeviceGateway(t)
	const mac = "aa:bb:cc:dd:ee:01"

	d, err := gw.ManualDevice(context.Background(), mac, circuit.ActTarpit, "lab test", "tester")
	if err != nil {
		t.Fatalf("ManualDevice: %v", err)
	}
	if d.To != circuit.Tarpit {
		t.Fatalf("decision To = %v, want tarpit", d.To)
	}
	b, ok := hasMAC(t, backend, mac)
	if !ok {
		t.Fatal("expected a kernel bucket for the jailed device")
	}
	if b.Flags != devbpf.FlagTarpit {
		t.Fatalf("bucket flags = %d, want FlagTarpit", b.Flags)
	}

	// State + counts reflect the transition.
	if got := gw.StateCounts()["tarpit"]; got != 1 {
		t.Fatalf("tarpit count = %d, want 1", got)
	}
	// Audit chain holds the decision with device attribution and verifies.
	res, err := st.VerifyDecisionChain()
	if err != nil || !res.OK {
		t.Fatalf("verify chain: ok=%v err=%v badAt=%d", res.OK, err, res.BadAt)
	}
	decs, _ := st.RecentDecisions(10)
	if len(decs) == 0 || decs[0].DeviceMAC != mac || decs[0].DeviceID != "dev:aabbccddee01" {
		t.Fatalf("audit row missing device attribution: %+v", decs)
	}
}

func TestDeviceGatewayThawClearsBucket(t *testing.T) {
	gw, backend, _ := newTestDeviceGateway(t)
	const mac = "aa:bb:cc:dd:ee:02"

	if _, err := gw.ManualDevice(context.Background(), mac, circuit.ActSever, "block it", "tester"); err != nil {
		t.Fatalf("jail: %v", err)
	}
	if _, ok := hasMAC(t, backend, mac); !ok {
		t.Fatal("expected bucket after sever")
	}
	if _, err := gw.ThawDevice(context.Background(), mac, "tester", "investigated"); err != nil {
		t.Fatalf("thaw: %v", err)
	}
	if _, ok := hasMAC(t, backend, mac); ok {
		t.Fatal("bucket should be gone after thaw")
	}
}

func TestDeviceGatewayDetectOnlyDoesNotEnforce(t *testing.T) {
	gw, backend, st := newTestDeviceGateway(t)
	const mac = "aa:bb:cc:dd:ee:0d"

	if gw.Mode() != "enforcing" {
		t.Fatalf("default Mode = %q, want enforcing", gw.Mode())
	}
	gw.SetEnforcing(false, "tester", "stage policy")
	if gw.Mode() != "detect-only" {
		t.Fatalf("after SetEnforcing(false) Mode = %q, want detect-only", gw.Mode())
	}

	// Jail in detect-only: circuit advances, audit row written, but the
	// kernel data plane is NOT touched.
	d, err := gw.ManualDevice(context.Background(), mac, circuit.ActSever, "would-be block", "tester")
	if err != nil {
		t.Fatalf("ManualDevice: %v", err)
	}
	if d.To != circuit.Severed {
		t.Fatalf("circuit To = %v, want severed (state still advances in detect-only)", d.To)
	}
	if _, ok := hasMAC(t, backend, mac); ok {
		t.Fatal("detect-only must NOT write a kernel bucket")
	}
	decs, _ := st.RecentDecisions(5)
	if len(decs) == 0 || decs[0].Outcome != "skipped: detect-only" {
		t.Fatalf("expected 'skipped: detect-only' audit outcome, got %q", decs[0].Outcome)
	}

	// Back to enforcing: now it writes.
	gw.SetEnforcing(true, "tester", "go live")
	if _, err := gw.ManualDevice(context.Background(), mac, circuit.ActSever, "block", "tester"); err != nil {
		t.Fatalf("ManualDevice enforcing: %v", err)
	}
	if _, ok := hasMAC(t, backend, mac); !ok {
		t.Fatal("enforcing mode must write the kernel bucket")
	}
}

func TestDeviceGatewayProtectedMACRefused(t *testing.T) {
	const mac = "aa:bb:cc:dd:ee:03"
	gw, backend, st := newTestDeviceGateway(t, mac)

	// Sever on a protected MAC: the call succeeds (it always audits) but the
	// data plane is NOT written — the allow-list guard refuses it.
	if _, err := gw.ManualDevice(context.Background(), mac, circuit.ActSever, "oops", "tester"); err != nil {
		t.Fatalf("ManualDevice returned error (should record refusal, not fail): %v", err)
	}
	if _, ok := hasMAC(t, backend, mac); ok {
		t.Fatal("protected MAC must NOT get a sever bucket")
	}
	decs, _ := st.RecentDecisions(10)
	if len(decs) == 0 || decs[0].Outcome == "ok" {
		t.Fatalf("expected a refusal outcome in the audit row, got: %+v", decs[0])
	}

	// Throttle on a protected MAC IS allowed (recoverable, not a lockout).
	if _, err := gw.ManualDevice(context.Background(), mac, circuit.ActThrottle, "rate-limit", "tester"); err != nil {
		t.Fatalf("throttle protected: %v", err)
	}
	if b, ok := hasMAC(t, backend, mac); !ok || b.Flags != devbpf.FlagThrottle {
		t.Fatalf("protected MAC should accept throttle, got ok=%v flags=%d", ok, b.Flags)
	}
}
