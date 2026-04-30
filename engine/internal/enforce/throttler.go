package enforce

import (
	"context"
	"fmt"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/bpfmap"
)

// Throttler turns ActThrottle/Tarpit/Quarantine into BPF map updates that
// the kernel data plane reads. It does NOT handle ActSever — chain that
// to a Severer in a Multi.
//
// Defaults applied per action (overridable via Config):
//
//	throttle  -> rate=50/s, burst=100   (gentle nudge, exfil-rate)
//	tarpit    -> rate=5/s,  burst=10    (slow them way down)
//	quarantine-> rate=1/s,  burst=2     (effectively offline)
type Throttler struct {
	Backend bpfmap.Backend
	Config  ThrottlerConfig
}

// ThrottlerConfig overrides the per-action default rate/burst.
type ThrottlerConfig struct {
	ThrottleRate, ThrottleBurst     uint32
	TarpitRate, TarpitBurst         uint32
	QuarantineRate, QuarantineBurst uint32
}

// DefaultThrottlerConfig returns the production defaults. Documented in
// the package doc — change with care, these flow through to the kernel.
func DefaultThrottlerConfig() ThrottlerConfig {
	return ThrottlerConfig{
		ThrottleRate: 50, ThrottleBurst: 100,
		TarpitRate: 5, TarpitBurst: 10,
		QuarantineRate: 1, QuarantineBurst: 2,
	}
}

func (t *Throttler) Name() string { return "throttler" }

func (t *Throttler) Apply(_ context.Context, target Target, action circuit.Action, _ string) error {
	if t.Backend == nil {
		return ErrUnsupported
	}
	if target.PID == 0 {
		return fmt.Errorf("throttler: refusing to write PID 0 entry")
	}
	cfg := t.Config
	if cfg == (ThrottlerConfig{}) {
		cfg = DefaultThrottlerConfig()
	}

	var bk bpfmap.PIDBucket
	switch action {
	case circuit.ActThrottle:
		bk = bpfmap.PIDBucket{RatePerSec: cfg.ThrottleRate, Burst: cfg.ThrottleBurst, Flags: bpfmap.FlagThrottle}
	case circuit.ActTarpit:
		bk = bpfmap.PIDBucket{RatePerSec: cfg.TarpitRate, Burst: cfg.TarpitBurst, Flags: bpfmap.FlagTarpit}
	case circuit.ActQuarantine:
		bk = bpfmap.PIDBucket{RatePerSec: cfg.QuarantineRate, Burst: cfg.QuarantineBurst, Flags: bpfmap.FlagQuarantine}
	default:
		return ErrUnsupported
	}
	return t.Backend.Update(target.PID, bk)
}

// ForgetPID removes a process from the throttle map. Called by the
// gateway on process_exit.
func (t *Throttler) ForgetPID(pid uint32) error {
	if t.Backend == nil {
		return nil
	}
	return t.Backend.Delete(pid)
}
