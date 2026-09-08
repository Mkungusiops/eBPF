package choke

import (
	"context"
	"log"
	"sort"
	"strings"
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
	// decisionSink tees recorded decisions to the control-plane uplink. See
	// Config.DecisionSink on the process gateway; the device plane needs its
	// own because it is a separate type with its own store handle.
	decisionSink func(*store.Decision)

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
	// DecisionSink tees every device-plane decision to the uplink. nil on a
	// standalone host.
	DecisionSink func(*store.Decision)
	DryRun       bool
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
		circuit:      circuit.New(circuit.DefaultConfig()),
		thr:          cfg.Throttler,
		backend:      cfg.Backend,
		table:        tbl,
		store:        cfg.Store,
		bcast:        cfg.Broadcast,
		decisionSink: cfg.DecisionSink,
		dryRun:       cfg.DryRun,
		reverts:      make(map[string]devPendingRevert),
	}
	// Dry-run forces detect-only regardless of the Enforcing flag.
	g.enforcing.Store(cfg.Enforcing && !cfg.DryRun)
	return g
}

// Table exposes the device table so the discovery sources (seen-map drain,
// neigh poller, DHCP sniffer) can Record into the same instance the gateway
// reads from.
func (g *DeviceGateway) Table() *device.Table { return g.table }

// Owns reports whether this agent has actually seen the MAC on its own LAN.
//
// The device analog of Gateway.Owns, and the same defense: a fleet-wide device
// jail reaches every agent in the tenant, but only the one whose segment the
// device is on can contain it. An agent that has never seen the MAC writes a tc
// rule that matches nothing — so if it acked "applied", the console would show
// a device as cut off while it keeps talking on someone else's segment.
//
// MACs are globally unique (unlike PIDs), so unlike the process side there is
// no weak grade here: the device is either in this host's table or it is not.
func (g *DeviceGateway) Owns(macStr string) bool {
	mac, err := devbpf.ParseMAC(macStr)
	if err != nil {
		return false
	}
	_, ok := g.table.Lookup(mac.String())
	return ok
}

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
	// Through the process gateway's recorder so the device plane reaches the
	// control-plane audit by the same path as the process plane. A second
	// insert-and-broadcast here is how one of the two planes ends up missing
	// from the uplink.
	g.recordDecision(rec, "insert decision")

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
// recordDecision persists one device-plane decision, then fans it out to the
// console and the control-plane uplink.
//
// Deliberately the same shape as the process gateway's: the two planes are
// separate types with separate stores, and a device sever that never reached
// the tenant's audit while a process sever did would be the worst kind of
// half-working — the console would look complete and be missing exactly the
// plane an operator reaches for when a host is unreachable.
//
// Insert first: InsertDecision stamps the id and the chain hashes, and a
// record sunk before that carries neither.
func (g *DeviceGateway) recordDecision(rec *store.Decision, what string) bool {
	if _, err := g.store.InsertDecision(rec); err != nil {
		log.Printf("[devgateway] %s: %v", what, err)
		return false
	}
	if g.decisionSink != nil {
		g.decisionSink(rec)
	}
	if g.bcast != nil {
		g.bcast.Broadcast("decision", rec)
	}
	return true
}

// SetDecisionSink wires the control-plane uplink after construction. See the
// process gateway's equivalent for why this is late-wired.
func (g *DeviceGateway) SetDecisionSink(fn func(*store.Decision)) { g.decisionSink = fn }

// SetProtectedMACs adds MACs to the device-plane lockout allow-list.
//
// ADD-ONLY, deliberately. The list is what stops the engine quarantining or
// severing the default gateway, the uplink, the DHCP/DNS server or the control
// plane itself — blackholing the very path an operator would use to undo the
// mistake. Allowing a remote command to REMOVE an entry would hand that
// self-inflicted outage to anyone who could sign one, so protection may be
// widened from the control plane but never narrowed. Narrowing is a local
// decision, made in the agent's config, by someone with a shell on the box.
//
// Unparseable MACs are skipped and returned so the caller can report them
// rather than silently protecting nothing.
func (g *DeviceGateway) SetProtectedMACs(macs []string) (added []string, skipped []string) {
	for _, raw := range macs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		m, err := devbpf.ParseMAC(raw)
		if err != nil {
			skipped = append(skipped, raw)
			continue
		}
		g.thr.Protect(m)
		added = append(added, m.String())
	}
	sort.Strings(added)
	sort.Strings(skipped)
	return added, skipped
}

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
// FramesSeen is the total forwarded frames the data plane has observed, summed
// across every device it knows about. Exposed separately from DataPlaneState so
// the agent can put a real number on the heartbeat: the control plane has no
// data plane of its own, and previously reported a hardcoded zero, which made
// the console's bridge-master warning fire on every multi-tenant deployment.
func (g *DeviceGateway) FramesSeen() uint64 {
	if g == nil || g.backend == nil {
		return 0
	}
	seen, err := g.backend.SeenSnapshot()
	if err != nil {
		return 0
	}
	var total uint64
	for _, s := range seen {
		total += s.Packets
	}
	return total
}

// DevicesSeen is how many distinct devices the data plane has actually
// observed — not how many the agent knows about. See devices_seen in
// common.proto for why the two must not be conflated.
func (g *DeviceGateway) DevicesSeen() int {
	if g == nil || g.backend == nil {
		return 0
	}
	seen, err := g.backend.SeenSnapshot()
	if err != nil {
		return 0
	}
	return len(seen)
}

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
//
// The transition is written to the hash-chained ledger, the way the process
// gateway's SetEnforcing writes its "set-mode" row. Disarming a host's whole
// network plane used to leave a log line and nothing else: every subsequent
// device decision became an audited no-op, and nothing an incident review can
// reach said who ordered that, or why.
//
// Recorded inside the setter rather than at the handler because actor and
// reason are already parameters here, so BOTH callers — the operator's HTTP
// toggle and the agent applier acting on a signed SetMode — leave a row.
func (g *DeviceGateway) SetEnforcing(on bool, actor, reason string) string {
	prevMode := g.Mode()
	// Swap, so the flag's own prior value is known: a no-op flip must write no
	// row, because rows for changes that did not happen are how a ledger stops
	// being evidence.
	prev := g.enforcing.Swap(on)
	log.Printf("[devgateway] mode %s → %s (actor=%s reason=%q)", prevMode, g.Mode(), actor, reason)
	if prev != on {
		g.auditConfigChange("device-set-mode", g.enforcementWord(prev), g.enforcementWord(on), actor, reason)
	}
	return prevMode
}

// enforcementWord names the posture the ENFORCING FLAG alone selects, and says
// which wider stop is overriding it when one is in force.
//
// Not Mode(): Mode folds the stops in, so a flip made while the kill-switch is
// engaged or dry-run is set reads "kill-switched → kill-switched" — an audit
// row that records an arming as though nothing happened. Naming the flag alone
// would have the opposite fault, reading as though the host now enforces when a
// global stop says it does not, so the row carries both.
func (g *DeviceGateway) enforcementWord(on bool) string {
	word := "detect-only"
	if on {
		word = "enforcing"
	}
	switch {
	case g.killSwitch.Load():
		return word + " (kill-switch engaged)"
	case g.dryRun:
		return word + " (dry-run)"
	}
	return word
}

// KillSwitched reports whether the device kill-switch is engaged.
func (g *DeviceGateway) KillSwitched() bool { return g.killSwitch.Load() }

// SetKillSwitch toggles the global device-enforcement bypass with no operator
// named. Returns the prior value.
//
// The caller that lands here is the agent's applier, acting on a signed
// KillSwitch command that carries no operator down to this level. The row it
// writes is therefore unattributed, which is the honest record — inventing a
// name for a caller that gave none would put words in an operator's mouth in an
// audit chain. An operator-driven toggle goes through SetKillSwitchBy.
func (g *DeviceGateway) SetKillSwitch(on bool) bool {
	return g.SetKillSwitchBy(on, "", "")
}

// SetKillSwitchBy is SetKillSwitch with the operator and their justification,
// and it is the one that writes the tamper-evident row.
//
// This is the device plane's widest toggle: it halts ALL device enforcement,
// including a sever an operator pressed themselves. It used to write a
// log.Printf and nothing else, while the process plane's identical toggle wrote
// a hash-chained row through Gateway.AuditConfigChange — so the question an
// incident review asks first, "who bypassed the network plane, and when", had
// no answer on this half of the product.
//
// Only a real transition is recorded: re-engaging a switch that is already
// engaged changed nothing.
func (g *DeviceGateway) SetKillSwitchBy(on bool, actor, reason string) bool {
	prev := g.killSwitch.Swap(on)
	state := "DISENGAGED"
	if on {
		state = "ENGAGED"
	}
	log.Printf("[devgateway] kill-switch %s (prev=%v actor=%s reason=%q)", state, prev, actor, reason)
	if prev != on {
		g.auditConfigChange("device-kill-switch", killSwitchWord(prev), killSwitchWord(on), actor, reason)
	}
	return prev
}

// killSwitchWord renders a kill-switch position for the audit row. "engaged"
// and "released" rather than true/false: a from/to pair a reviewer can read
// without having to know which way the boolean points.
func killSwitchWord(on bool) string {
	if on {
		return "engaged"
	}
	return "released"
}

// auditConfigChange records a change to how DEVICE enforcement BEHAVES as a
// hash-chained decision row — the device plane's copy of
// Gateway.auditConfigChange, and it exists for the same reason.
//
// Jailing one device wrote a tamper-evident row from the start. Halting the
// plane and disarming it wrote nothing, so on this plane the two widest actions
// were the two /api/verify-chain could not cover: there was no row to verify.
//
// Unexported, unlike the process gateway's: every device config change this
// engine has runs through the two setters above, which already hold the actor
// and the reason, so there is nothing for a handler to call. The day a device
// config command needs its own row (the agent audits signed commands against
// the PROCESS gateway today, whichever plane they name), this grows an exported
// wrapper the way Gateway did.
//
// ExecID is "config:<action>" rather than a device MAC, because this is a
// change to the gateway and not to a device; each action is device-prefixed so
// a review can tell a network-plane halt from a process-plane one at a glance.
// Reason and Actor are hashed into the chain (store.Decision.canonicalAt), so
// the justification is evidence rather than decoration.
func (g *DeviceGateway) auditConfigChange(action, from, to, actor, reason string) {
	rec := &store.Decision{
		Timestamp: time.Now().UTC(),
		ExecID:    "config:" + action,
		Action:    action,
		FromState: from,
		ToState:   to,
		Reason:    reason,
		DryRun:    g.dryRun,
		Backend:   "device-gateway",
		Outcome:   "ok",
		Actor:     actor,
	}
	// Through recordDecision, so a config change reaches the console and the
	// control-plane uplink by the same path a containment does. A row that only
	// ever lands in the local SQLite is invisible to the tenant whose network
	// plane was just halted.
	g.recordDecision(rec, action+" audit insert")
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

// ProtectedMACs returns the device-plane lockout allow-list, sorted.
//
// Read-back for SetProtectedMACs, which is add-only. An operator arming the
// device plane needs to confirm the uplink and the control plane are on this
// list BEFORE arming, not discover afterwards that a typo left them exposed.
func (g *DeviceGateway) ProtectedMACs() []string {
	if g == nil || g.thr == nil {
		return nil
	}
	return g.thr.ProtectedList()
}
