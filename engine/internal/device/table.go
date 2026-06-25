// Package device tracks the LAN devices the network choke gateway can see,
// binding a stable identity (MAC) to its current IP and hostname.
//
// It is the network-layer analog of internal/origin: a thin concurrent map
// with TTL eviction and field-wise merge, so a DHCP observation can refine
// {IP, hostname} without wiping an earlier passive sighting. Identity is the
// MAC (survives DHCP/IP churn); DeviceID = "dev:" + colonless MAC.
//
// Discovery sources live in sibling files and call Record:
//   - the data plane's choke_devs_seen map (passive, drained in main.go)
//   - neigh_linux.go   (ip neigh / RTM_GETNEIGH — MAC<->IP)
//   - dhcp_linux.go    (passive DHCP sniff on the bridge — MAC<->IP<->hostname)
package device

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Source labels where a sighting came from, so the UI can show how strong
// the binding is and the operator can tell a hostname-bearing DHCP lease
// from a bare passive MAC.
type Source string

const (
	SourcePassive Source = "passive" // seen by the data plane (MAC, maybe IP)
	SourceNeigh   Source = "neigh"   // kernel neighbour table (MAC<->IP)
	SourceDHCP    Source = "dhcp"    // sniffed DHCP (MAC<->IP<->hostname)
)

// Device is the merged view of one LAN device.
type Device struct {
	MAC       string    `json:"mac"`
	DeviceID  string    `json:"device_id"`
	LastIP    string    `json:"last_ip,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	Vendor    string    `json:"vendor,omitempty"`
	Packets   uint64    `json:"packets,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Source    Source    `json:"source"`
}

// Table is the in-memory device store. Safe for concurrent use. Entries are
// evicted after TTL since LastSeen.
type Table struct {
	mu    sync.RWMutex
	byMAC map[string]Device
	ttl   time.Duration
	now   func() time.Time // overridable for tests
}

// NewTable returns a Table with the given idle TTL. Zero/negative TTL
// defaults to 1h — long enough that an idle but still-present device isn't
// dropped between active periods, short enough to bound the map.
func NewTable(ttl time.Duration) *Table {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Table{byMAC: make(map[string]Device), ttl: ttl, now: time.Now}
}

// canonMAC lowercases and validates a MAC string. Returns "" if unparseable
// so callers can skip junk without polluting the table.
func canonMAC(s string) string {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(hw) != 6 {
		return ""
	}
	return hw.String()
}

// deviceID returns the stable id for a canonical MAC.
func deviceID(mac string) string { return "dev:" + strings.ReplaceAll(mac, ":", "") }

// Record merges an observation into the table, keyed by MAC. Non-empty new
// fields win (so a DHCP hostname refines a passive MAC sighting); LastSeen
// always advances. The MAC is canonicalised; junk is dropped.
func (t *Table) Record(d Device) {
	mac := canonMAC(d.MAC)
	if mac == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	cur, ok := t.byMAC[mac]
	if !ok {
		cur = Device{MAC: mac, DeviceID: deviceID(mac), FirstSeen: now}
	}
	if ip := strings.TrimSpace(d.LastIP); ip != "" {
		cur.LastIP = ip
	}
	if h := strings.TrimSpace(d.Hostname); h != "" {
		cur.Hostname = h
	}
	if v := strings.TrimSpace(d.Vendor); v != "" {
		cur.Vendor = v
	}
	if d.Packets > cur.Packets {
		cur.Packets = d.Packets
	}
	if d.Source != "" {
		cur.Source = d.Source
	}
	cur.LastSeen = now
	t.byMAC[mac] = cur
}

// Lookup returns the Device for a MAC string (canonicalised) if present.
func (t *Table) Lookup(mac string) (Device, bool) {
	cm := canonMAC(mac)
	if cm == "" {
		return Device{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	d, ok := t.byMAC[cm]
	return d, ok
}

// Snapshot returns every known device, sorted most-recently-seen first.
func (t *Table) Snapshot() []Device {
	t.mu.RLock()
	out := make([]Device, 0, len(t.byMAC))
	for _, d := range t.byMAC {
		out = append(out, d)
	}
	t.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// Forget drops a device. Idempotent.
func (t *Table) Forget(mac string) {
	cm := canonMAC(mac)
	if cm == "" {
		return
	}
	t.mu.Lock()
	delete(t.byMAC, cm)
	t.mu.Unlock()
}

// Sweep evicts devices idle longer than TTL. Returns how many were dropped.
// Cheap O(n) walk under the write lock; call from a ticker.
func (t *Table) Sweep() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := t.now().Add(-t.ttl)
	n := 0
	for mac, d := range t.byMAC {
		if d.LastSeen.Before(cutoff) {
			delete(t.byMAC, mac)
			n++
		}
	}
	return n
}

// Len returns the number of tracked devices.
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.byMAC)
}

// IPv4BEToString converts a big-endian (network-order) uint32 IPv4 — as
// stored by the data plane's choke_devs_seen map — to dotted-quad. Returns
// "" for the zero address.
func IPv4BEToString(be uint32) string {
	if be == 0 {
		return ""
	}
	// be is in network byte order as read from the packet; bytes are
	// [b0 b1 b2 b3] = a.b.c.d already in memory order on the wire.
	ip := net.IPv4(byte(be), byte(be>>8), byte(be>>16), byte(be>>24))
	return ip.String()
}
