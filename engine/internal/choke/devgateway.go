package choke

import (
	"context"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/device"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/devbpf"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// DeviceGateway is the network-layer sibling of Gateway. Where Gateway
// chokes processes (keyed by exec_id/PID) via cgroup/connect hooks, the
// DeviceGateway chokes LAN devices (keyed by MAC) via the tc data plane.
//
// It reuses circuit.Circuit verbatim — the circuit's state map is keyed by
// an opaque string, so the canonical MAC string slots straight in and the
// monotonic ladder / Force / thresholds all work unchanged. Device choke is
// operator/manual-driven for v1 (a forwarding box has no per-device
// telemetry to feed score-based transitions), so there is no OnEvent path.
type DeviceGateway struct {
	circuit *circuit.Circuit
	thr     *enforce.DeviceThrottler
	backend devbpf.Backend
	table   *device.Table
	store   *store.Store
	bcast   Broadcaster

	dryRun     bool
	enforcing  atomic.Bool // runtime mode: true=enforcing, false=detect-only
	killSwitch atomic.Bool

	revMu   sync.Mutex
	reverts map[string]devPendingRevert
}

type devPendingRevert struct {
	prev   circuit.State
	cancel chan struct{}
}

// DeviceConfig bundles the inputs to NewDeviceGateway. Store and Throttler
// are required; the rest fall back to safe defaults.
type DeviceConfig struct {
	Throttler *enforce.DeviceThrottler
	Backend   devbpf.Backend
	Table     *device.Table
	Store     *store.Store
	Broadcast Broadcaster
	DryRun    bool
	// Enforcing is the initial runtime mode. When false the gateway starts
	// in DETECT-ONLY: device-jail decisions are audited but the kernel data
	// plane is not written (a shadow mode for staging policy / watching flows
	// without dropping traffic). Flip at runtime via SetEnforcing.
	Enforcing bool
}

func NewDeviceGateway(cfg DeviceConfig) *DeviceGateway {
	if cfg.Store == nil {
		panic("choke.NewDeviceGateway: Store is required")
	}
	if cfg.Throttler == nil {
		panic("choke.NewDeviceGateway: Throttler is required")
	}
	tbl := cfg.Table
	if tbl == nil {
		tbl = device.NewTable(time.Hour)
	}
	g := &DeviceGateway{
		circuit: circuit.New(circuit.DefaultConfig()),
		thr:     cfg.Throttler,
		backend: cfg.Backend,
		table:   tbl,
		store:   cfg.Store,
		bcast:   cfg.Broadcast,
		dryRun:  cfg.DryRun,
		reverts: make(map[string]devPendingRevert),
	}
	// Dry-run forces detect-only regardless of the Enforcing flag.
	g.enforcing.Store(cfg.Enforcing && !cfg.DryRun)
	return g
}

// Table exposes the device table so the discovery sources (seen-map drain,
// neigh poller, DHCP sniffer) can Record into the same instance the gateway
// reads from.
func (g *DeviceGateway) Table() *device.Table { return g.table }

// ManualDevice applies an enforcement action to a device by MAC. It is the
// device analog of Gateway.Manual: the circuit is forced to the target
// state, the data plane is updated (unless dry-run / kill-switch), and a
// hash-chained audit row is written and broadcast — always, even when the
// enforcer is skipped, so the audit trail captures *why*.
//
// action == ActNone clears the choke (thaw). Returns the synthesised
// Decision for echoing back to the UI.
func (g *DeviceGateway) ManualDevice(ctx context.Context, macStr string, action circuit.Action, reason, actor string) (*circuit.Decision, error) {
	mac, err := devbpf.ParseMAC(macStr)
	if err != nil {
		return nil, err
	}
	canon := mac.String()

	target := actionToState(action)
	prev, _ := g.circuit.Force(canon, target)

	outcome := "ok"
	backendName := g.thr.Backend.DataPlaneTier()
	// applyErr is the enforcement refusal (e.g. a protected MAC). It must reach
	// the caller: reporting a device as contained when the data plane refused is
	// the worst failure mode a containment product has — the operator believes a
	// threat is cut off and stops responding. The audit row is still written, so
	// the refused ATTEMPT stays in the chain.
	var applyErr error
	switch {
	case g.killSwitch.Load():
		outcome = "skipped: kill-switch engaged"
		backendName = "kill-switch"
	case g.dryRun:
		outcome = "skipped: dry-run"
		backendName = "dry-run(" + backendName + ")"
	case !g.enforcing.Load():
		// DETECT-ONLY: record the would-be decision, don't touch the kernel.
		outcome = "skipped: detect-only"
		backendName = "detect-only(" + backendName + ")"
	default:
		if err := g.thr.Apply(mac, action); err != nil {
			outcome = "error: " + err.Error()
			log.Printf("[devgateway] enforce action=%s mac=%s: %v", action, canon, err)
			applyErr = err
		}
	}

	// Identity for the audit row + broadcast.
	dev, _ := g.table.Lookup(canon)
	binary := dev.Hostname
	if binary == "" {
		binary = dev.LastIP
	}

	d := &circuit.Decision{
		ExecID:    "device:" + canon,
		Binary:    binary,
		From:      prev,
		To:        target,
		Action:    action,
		Reason:    reason + " (by " + actor + ")",
		Timestamp: time.Now().UTC(),
	}

	rec := &store.Decision{
		Timestamp: d.Timestamp,
		ExecID:    d.ExecID,
		Binary:    d.Binary,
		Action:    d.Action.String(),
		FromState: d.From.String(),
		ToState:   d.To.String(),
		Reason:    "[manual] " + d.Reason,
		DryRun:    g.dryRun,
		Backend:   backendName,
		Outcome:   outcome,
		DeviceMAC: canon,
		DeviceID:  mac.DeviceID(),
	}
	if _, err := g.store.InsertDecision(rec); err != nil {
		log.Printf("[devgateway] insert decision: %v", err)
	} else if g.bcast != nil {
		g.bcast.Broadcast("decision", rec)
	}

	// The data plane refused, so the device is NOT in the state we optimistically
	// forced above. Roll the circuit back and surface the error. Without this the
	// table shows a protected gateway as "severed" while it keeps routing — the
	// operator is told the containment landed when nothing was applied.
	if applyErr != nil {
		g.circuit.Force(canon, prev)
		d.To = prev
		return d, applyErr
	}
	return d, nil
}

// ThawDevice clears all enforcement for a device: removes its bucket from
// the data plane and forces the circuit back to pristine. Audited.
func (g *DeviceGateway) ThawDevice(ctx context.Context, macStr, actor, reason string) (*circuit.Decision, error) {
	return g.ManualDevice(ctx, macStr, circuit.ActNone, "thaw: "+reason, actor)
}

// ─────────── Operator-facing read surface ───────────────────────────────

// DeviceBucketView is the JSON shape for a device's live kernel bucket.
type DeviceBucketView struct {
	RatePerSec uint32 `json:"rate_per_sec"`
	Burst      uint32 `json:"burst"`
	Tokens     uint32 `json:"tokens"`
	Flags      uint32 `json:"flags"`
}

// DeviceEntry is one row of the device snapshot — the device table joined
// with its circuit state and current kernel bucket. Sorted most-dangerous
// first so the UI renders the worst offenders at the top.
type DeviceEntry struct {
	MAC           string            `json:"mac"`
	DeviceID      string            `json:"device_id"`
	LastIP        string            `json:"last_ip,omitempty"`
	Hostname      string            `json:"hostname,omitempty"`
	Vendor        string            `json:"vendor,omitempty"`
	State         string            `json:"state"`
	Protected     bool              `json:"protected"`
	Packets       uint64            `json:"packets,omitempty"`
	Source        string            `json:"source,omitempty"`
	FirstSeen     time.Time         `json:"first_seen,omitempty"`
	LastSeen      time.Time         `json:"last_seen,omitempty"`
	Bucket        *DeviceBucketView `json:"bucket,omitempty"`
	Flows         int               `json:"flows,omitempty"`
	RevertPending bool              `json:"revert_pending,omitempty"`
}

// DeviceFlow is one (device -> destination) flow for the per-device drill-in:
// what the device is talking to, so an operator can judge maliciousness
// before choking.
type DeviceFlow struct {
	DestIP   string `json:"dest_ip"`
	DestPort uint16 `json:"dest_port"`
	Proto    string `json:"proto"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
}

// DeviceFlows returns the destinations a device is contacting, busiest first
// (top `limit`, or all if limit<=0). Sourced from the data plane's choke_flows
// map. Empty when the backend has no kernel side (noop).
func (g *DeviceGateway) DeviceFlows(macStr string, limit int) ([]DeviceFlow, error) {
	mac, err := devbpf.ParseMAC(macStr)
	if err != nil {
		return nil, err
	}
	if g.backend == nil {
		return nil, nil
	}
	flows, err := g.backend.FlowsSnapshot()
	if err != nil {
		return nil, err
	}
	out := make([]DeviceFlow, 0)
	for k, v := range flows {
		if k.MAC != mac {
			continue
		}
		out = append(out, DeviceFlow{
			DestIP:   k.DestIP(),
			DestPort: k.DestPort(),
			Proto:    devbpf.ProtoName(k.Proto),
			Packets:  v.Packets,
			Bytes:    v.Bytes,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Packets != out[j].Packets {
			return out[i].Packets > out[j].Packets
		}
		return out[i].Bytes > out[j].Bytes
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Snapshot returns one DeviceEntry per known device (and any choked MAC the
// table hasn't seen yet), joined with circuit state + kernel bucket.
func (g *DeviceGateway) Snapshot() []DeviceEntry {
	buckets, _ := g.BucketsSnapshot()
	pending := map[string]bool{}
	for _, m := range g.PendingReverts() {
		pending[m] = true
	}
	// Per-device count of distinct destinations seen, for the row affordance.
	flowCount := map[string]int{}
	if g.backend != nil {
		if fs, err := g.backend.FlowsSnapshot(); err == nil {
			for k := range fs {
				flowCount[k.MAC.String()]++
			}
		}
	}

	seen := map[string]bool{}
	out := make([]DeviceEntry, 0)
	add := func(mac string, dev device.Device, haveDev bool) {
		if seen[mac] {
			return
		}
		seen[mac] = true
		e := DeviceEntry{
			MAC:      mac,
			State:    g.circuit.State(mac).String(),
			DeviceID: "dev:" + nonColon(mac),
		}
		if haveDev {
			e.DeviceID = dev.DeviceID
			e.LastIP = dev.LastIP
			e.Hostname = dev.Hostname
			e.Vendor = dev.Vendor
			e.Packets = dev.Packets
			e.Source = string(dev.Source)
			e.FirstSeen = dev.FirstSeen
			e.LastSeen = dev.LastSeen
		}
		if m, err := devbpf.ParseMAC(mac); err == nil {
			e.Protected = g.thr.IsProtected(m)
			if b, ok := buckets[m]; ok {
				e.Bucket = &DeviceBucketView{RatePerSec: b.RatePerSec, Burst: b.Burst, Tokens: b.Tokens, Flags: b.Flags}
			}
		}
		e.Flows = flowCount[mac]
		e.RevertPending = pending[mac]
		out = append(out, e)
	}

	for _, dev := range g.table.Snapshot() {
		add(dev.MAC, dev, true)
	}
	// Include any choked MAC not (yet) in the discovery table so it's never
	// invisible in the console.
	for m := range buckets {
		add(m.String(), device.Device{}, false)
	}
	for _, ts := range g.circuit.Snapshot() {
		add(ts.ExecID, device.Device{}, false)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].State != out[j].State {
			return stateOrder(out[i].State) > stateOrder(out[j].State)
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

// StateCounts returns how many devices sit on each rung of the ladder.
func (g *DeviceGateway) StateCounts() map[string]int {
	out := map[string]int{"pristine": 0, "throttled": 0, "tarpit": 0, "quarantined": 0, "severed": 0}
	for _, ts := range g.circuit.Snapshot() {
		out[ts.State.String()]++
	}
	return out
}

// BucketsSnapshot returns the kernel-side per-device choke map.
func (g *DeviceGateway) BucketsSnapshot() (map[devbpf.MAC]devbpf.DeviceBucket, error) {
	if g.backend == nil {
		return nil, nil
	}
	return g.backend.Snapshot()
}

// DataPlaneState reports the active actuator tier and attach status — the
// operator's confirmation that the box is actually enforcing.
// DataPlaneTier names the backend actually enforcing device choke ("tc" when a
// compiled program is attached, "noop" otherwise). Reported to the control
// plane so a fleet operator can tell an agent that *can* enforce from one that
// is only recording decisions.
func (g *DeviceGateway) DataPlaneTier() string {
	if g == nil || g.backend == nil {
		return "noop"
	}
	return g.backend.DataPlaneTier()
}

// AttachedLinks is the number of interfaces the device data plane is attached
// to. Zero with a "tc" tier means the program loaded but is attached nowhere —
// the case that looks healthy and enforces nothing.
func (g *DeviceGateway) AttachedLinks() int {
	if g == nil || g.backend == nil {
		return 0
	}
	return g.backend.AttachedLinks()
}

func (g *DeviceGateway) DataPlaneState() map[string]interface{} {
	tier := "noop"
	links := 0
	// frames_seen is the count of forwarded frames the data plane has
	// observed (summed from choke_devs_seen). It is the operator's "is the
	// program actually seeing transit traffic?" signal — the detector for
	// the classic bridge-master-instead-of-slave mistake, where the program
	// attaches fine (links>0) but sees zero forwarded frames.
	var framesSeen uint64
	devicesSeen := 0
	if g.backend != nil {
		tier = g.backend.DataPlaneTier()
		links = g.backend.AttachedLinks()
		if seen, err := g.backend.SeenSnapshot(); err == nil {
			devicesSeen = len(seen)
			for _, s := range seen {
				framesSeen += s.Packets
			}
		}
	}
	return map[string]interface{}{
		"data_plane":     tier,
		"links_attached": links,
		"frames_seen":    framesSeen,
		"devices_seen":   devicesSeen,
		"mode":           g.Mode(),
		"enforcing":      g.enforcing.Load(),
		"dry_run":        g.dryRun,
		"kill_switched":  g.killSwitch.Load(),
		"tracked":        g.circuit.Tracked(),
		"devices_known":  g.table.Len(),
		"counts":         g.StateCounts(),
	}
}

// Tracked returns the number of devices with a non-pristine circuit entry.
func (g *DeviceGateway) Tracked() int { return g.circuit.Tracked() }

// DryRun reports whether device decisions are shadow-only.
func (g *DeviceGateway) DryRun() bool { return g.dryRun }

// Mode returns the current enforcement posture string, mirroring the process
// console: "kill-switched" > "dry-run" > "detect-only" > "enforcing".
func (g *DeviceGateway) Mode() string {
	if g.killSwitch.Load() {
		return "kill-switched"
	}
	if g.dryRun {
		return "dry-run"
	}
	if !g.enforcing.Load() {
		return "detect-only"
	}
	return "enforcing"
}

// Enforcing reports whether device decisions reach the kernel data plane.
func (g *DeviceGateway) Enforcing() bool { return g.enforcing.Load() }

// SetEnforcing flips between ENFORCING and DETECT-ONLY at runtime. In
// detect-only, device-jail decisions are still audited but the kernel data
// plane is untouched (a shadow mode for staging policy / watching flows).
// Dry-run (a boot flag) and the kill-switch remain independent global stops.
// Returns the prior mode string for the audit/UI.
func (g *DeviceGateway) SetEnforcing(on bool, actor, reason string) string {
	prev := g.Mode()
	g.enforcing.Store(on)
	log.Printf("[devgateway] mode %s → %s (actor=%s reason=%q)", prev, g.Mode(), actor, reason)
	return prev
}

// KillSwitched reports whether the device kill-switch is engaged.
func (g *DeviceGateway) KillSwitched() bool { return g.killSwitch.Load() }

// SetKillSwitch toggles the global device-enforcement bypass. Returns the
// prior value.
func (g *DeviceGateway) SetKillSwitch(on bool) bool {
	prev := g.killSwitch.Swap(on)
	state := "DISENGAGED"
	if on {
		state = "ENGAGED"
	}
	log.Printf("[devgateway] kill-switch %s (prev=%v)", state, prev)
	return prev
}

// ─────────── Time-bound auto-revert (mirrors Gateway.ScheduleRevert) ─────

// ScheduleRevert sets up an auto-revert for a device MAC after `after`.
// Cancels any prior revert for the same MAC. `after` <= 0 just cancels.
func (g *DeviceGateway) ScheduleRevert(macStr string, prev circuit.State, after time.Duration, actor string) {
	mac, err := devbpf.ParseMAC(macStr)
	if err != nil {
		return
	}
	canon := mac.String()
	g.revMu.Lock()
	if existing, ok := g.reverts[canon]; ok {
		close(existing.cancel)
		delete(g.reverts, canon)
	}
	if after <= 0 {
		g.revMu.Unlock()
		return
	}
	cancel := make(chan struct{})
	g.reverts[canon] = devPendingRevert{prev: prev, cancel: cancel}
	g.revMu.Unlock()

	go func() {
		select {
		case <-cancel:
			return
		case <-time.After(after):
		}
		g.revMu.Lock()
		cur, ok := g.reverts[canon]
		if !ok || cur.cancel != cancel {
			g.revMu.Unlock()
			return
		}
		delete(g.reverts, canon)
		g.revMu.Unlock()

		action := stateToAction(prev)
		_, _ = g.ManualDevice(context.Background(), canon, action,
			"auto-revert (scheduled by "+actor+")", actor)
	}()
}

// PendingReverts returns the MACs with a scheduled auto-revert.
func (g *DeviceGateway) PendingReverts() []string {
	g.revMu.Lock()
	defer g.revMu.Unlock()
	out := make([]string, 0, len(g.reverts))
	for k := range g.reverts {
		out = append(out, k)
	}
	return out
}

// stateToAction maps a circuit state back to the action that produces it —
// used by auto-revert to re-apply the prior rung's enforcement.
func stateToAction(s circuit.State) circuit.Action {
	switch s {
	case circuit.Throttled:
		return circuit.ActThrottle
	case circuit.Tarpit:
		return circuit.ActTarpit
	case circuit.Quarantined:
		return circuit.ActQuarantine
	case circuit.Severed:
		return circuit.ActSever
	}
	return circuit.ActNone
}

// nonColon strips colons from a MAC for the synthetic DeviceID fallback.
func nonColon(mac string) string {
	out := make([]byte, 0, len(mac))
	for i := 0; i < len(mac); i++ {
		if mac[i] != ':' {
			out = append(out, mac[i])
		}
	}
	return string(out)
}
