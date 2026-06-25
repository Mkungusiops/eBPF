package enforce

import (
	"fmt"
	"sync"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/devbpf"
)

// DeviceThrottler turns a circuit Action into a per-device BPF map update
// that the tc data plane reads — the network-layer sibling of Throttler.
// It is keyed by MAC, not PID, and so does NOT implement the Enforcer
// interface; the DeviceGateway calls it directly.
//
// Rate/burst tiers reuse ThrottlerConfig verbatim so a device and a process
// at the same tier are shaped identically:
//
//	throttle  -> rate=50/s, burst=100
//	tarpit    -> rate=5/s,  burst=10
//	quarantine-> rate=1/s,  burst=2
//	sever     -> unconditional drop (no bucket)
type DeviceThrottler struct {
	Backend devbpf.Backend
	Config  ThrottlerConfig

	// mu guards Protected so the allow-list can be updated at runtime (e.g.
	// the operator adds the uplink MAC after discovering it).
	mu sync.RWMutex
	// Protected is the device analog of the gateway's SystemCriticalBinaries
	// exemption: the engine REFUSES to write a quarantine/sever bucket for
	// any MAC in this set — the gateway, the uplink, the DHCP/DNS server,
	// the operator's workstation — so an enforcement mistake can't blackhole
	// the control plane. Throttle/tarpit are still allowed (recoverable).
	Protected map[devbpf.MAC]bool
}

// NewDeviceThrottler builds a throttler with the default rate tiers.
func NewDeviceThrottler(backend devbpf.Backend, protected map[devbpf.MAC]bool) *DeviceThrottler {
	if protected == nil {
		protected = map[devbpf.MAC]bool{}
	}
	return &DeviceThrottler{Backend: backend, Config: DefaultThrottlerConfig(), Protected: protected}
}

// IsProtected reports whether a MAC is on the lockout allow-list.
func (t *DeviceThrottler) IsProtected(mac devbpf.MAC) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.Protected[mac]
}

// Protect adds a MAC to the allow-list. Idempotent.
func (t *DeviceThrottler) Protect(mac devbpf.MAC) {
	t.mu.Lock()
	if t.Protected == nil {
		t.Protected = map[devbpf.MAC]bool{}
	}
	t.Protected[mac] = true
	t.mu.Unlock()
}

// Apply writes (or clears) the device's bucket for the requested action.
// ActNone clears the bucket (thaw). Quarantine/sever on a protected MAC is
// refused with an error — the caller still records the audited "would-have"
// decision so the refusal is visible in the chain.
func (t *DeviceThrottler) Apply(mac devbpf.MAC, action circuit.Action) error {
	if t.Backend == nil {
		return ErrUnsupported
	}
	if (action == circuit.ActQuarantine || action == circuit.ActSever) && t.IsProtected(mac) {
		return fmt.Errorf("devthrottler: refusing to %s protected MAC %s (allow-list)", action, mac)
	}

	cfg := t.Config
	if cfg == (ThrottlerConfig{}) {
		cfg = DefaultThrottlerConfig()
	}

	var b devbpf.DeviceBucket
	switch action {
	case circuit.ActNone:
		return t.Backend.Delete(mac) // thaw: remove from the map -> pass
	case circuit.ActThrottle:
		b = devbpf.DeviceBucket{RatePerSec: cfg.ThrottleRate, Burst: cfg.ThrottleBurst, Flags: devbpf.FlagThrottle}
	case circuit.ActTarpit:
		b = devbpf.DeviceBucket{RatePerSec: cfg.TarpitRate, Burst: cfg.TarpitBurst, Flags: devbpf.FlagTarpit}
	case circuit.ActQuarantine:
		b = devbpf.DeviceBucket{RatePerSec: cfg.QuarantineRate, Burst: cfg.QuarantineBurst, Flags: devbpf.FlagQuarantine}
	case circuit.ActSever:
		b = devbpf.DeviceBucket{Flags: devbpf.FlagSever}
	default:
		return ErrUnsupported
	}
	return t.Backend.Update(mac, b)
}

// Forget removes a device from the choke map. Called on thaw / eviction.
func (t *DeviceThrottler) Forget(mac devbpf.MAC) error {
	if t.Backend == nil {
		return nil
	}
	return t.Backend.Delete(mac)
}
