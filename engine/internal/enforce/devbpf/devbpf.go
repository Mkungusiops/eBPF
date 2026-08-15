// Package devbpf is the userspace contract for the per-DEVICE (MAC) choke
// map — the network-layer sibling of internal/enforce/bpfmap.
//
// The data plane that actually shapes traffic lives in a small BPF program
// (devchoke.c, a tc clsact classifier) that:
//
//  1. reads the Ethernet header of every forwarded frame,
//  2. keys a BPF_MAP_TYPE_HASH on the device MAC (src on ingress, dst on
//     egress),
//  3. consumes a token from the per-device bucket; on empty -> TC_ACT_SHOT.
//
// The userspace gateway updates this map: on a device choke it calls
// Backend.Update(mac, bucket); on thaw it calls Delete(mac).
//
// This file defines the interface and a NoopDeviceBackend used during dev
// and in tests. The real loader (cilium/ebpf based) is linux-only and lives
// in cilium_linux.go; the engine stays pure-Go (no CGO) on every platform.
package devbpf

import (
	"errors"
	"fmt"
	"math/bits"
	"net"
	"strings"
	"sync"
)

// DeviceBucket is the kernel-side struct laid out exactly as devchoke.c
// reads it — and byte-for-byte identical to bpfmap.PIDBucket (24 bytes).
// Field order and types must not change without also bumping the matching
// struct dev_bucket in bpf/devchoke.c.
type DeviceBucket struct {
	LastNs     uint64 // last refill timestamp (ns since boot)
	RatePerSec uint32 // tokens added per second
	Burst      uint32 // max accumulated tokens
	Tokens     uint32 // current token count (kernel-side, written by BPF)
	Flags      uint32 // bit 0: throttle, 1: tarpit, 2: quarantine, 3: sever
}

// Action flags carried in DeviceBucket.Flags. Same bit layout as bpfmap.
const (
	FlagThrottle   uint32 = 1 << 0
	FlagTarpit     uint32 = 1 << 1
	FlagQuarantine uint32 = 1 << 2
	FlagSever      uint32 = 1 << 3
)

// Seen mirrors devchoke.c's `struct seen` (24 bytes): passive-discovery
// telemetry written by the data plane on every forwarded frame.
type Seen struct {
	LastNs      uint64 // last time a frame from/to this MAC was seen (ns since boot)
	Packets     uint64 // cumulative frame count
	LastSrcIPv4 uint32 // last observed source IPv4 (big-endian / network order)
	Pad         uint32 // keeps the struct at 24 bytes; matches the C _pad
}

// FlowKey identifies one (device -> destination) flow. Must match struct
// flow_key in devchoke.c byte-for-byte (16 bytes). DAddr/DPort are in network
// byte order as read from the packet.
type FlowKey struct {
	MAC   MAC
	Pad   [2]byte
	DAddr uint32 // destination IPv4, network order
	DPort uint16 // destination port, network order
	Proto uint8
	Pad2  uint8
}

// FlowStat counts a flow. Matches struct flow_stat (24 bytes).
type FlowStat struct {
	Packets uint64
	Bytes   uint64
	LastNs  uint64
}

// DestIP renders the destination as dotted-quad. DAddr is network order read
// back as a native-endian uint32, so its bytes are already in octet order.
func (k FlowKey) DestIP() string {
	be := k.DAddr
	return net.IPv4(byte(be), byte(be>>8), byte(be>>16), byte(be>>24)).String()
}

// DestPort returns the destination port in host order.
func (k FlowKey) DestPort() uint16 { return bits.ReverseBytes16(k.DPort) }

// ProtoName maps the IP protocol number to a short name.
func ProtoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("ip/%d", p)
	}
}

// MAC is a 6-byte hardware address used as the map key's identity portion.
type MAC [6]byte

// devKey is the 8-byte kernel key: MAC + 2 zero pad bytes. Must match
// `struct dev_key` in devchoke.c byte-for-byte.
type devKey struct {
	MAC [6]byte
	Pad [2]byte
}

// keyFor builds the kernel map key for a MAC.
//
// Only cilium_linux.go calls this, and that file is behind `//go:build linux`.
// golangci-lint's `unused` check does not analyse Linux-tagged files when run on
// darwin, so it reports this function as dead and a macOS-only verification loop
// (build, vet, test, lint) agrees — every one of those steps passes with it
// deleted. It is not dead: removing it breaks `GOOS=linux go build`, which is
// the only build that ships. Confirm with a cross-build before touching it.
//
//nolint:unused // used by cilium_linux.go; invisible to the linter on darwin.
func keyFor(m MAC) devKey { return devKey{MAC: m} }

// ParseMAC parses a colon/dash MAC string into a MAC. Rejects anything that
// isn't a 6-byte EUI-48.
func ParseMAC(s string) (MAC, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil {
		return MAC{}, fmt.Errorf("devbpf: bad MAC %q: %w", s, err)
	}
	if len(hw) != 6 {
		return MAC{}, fmt.Errorf("devbpf: %q is not a 6-byte MAC", s)
	}
	var m MAC
	copy(m[:], hw)
	return m, nil
}

// String renders the canonical lowercased colon form, e.g. "aa:bb:cc:dd:ee:ff".
func (m MAC) String() string { return net.HardwareAddr(m[:]).String() }

// DeviceID returns the stable operator-facing identity for the device:
// "dev:" + the colonless lowercased MAC. Deterministic across IP changes
// and reboots — this is what the audit chain and UI key on.
func (m MAC) DeviceID() string {
	return "dev:" + strings.ReplaceAll(m.String(), ":", "")
}

// ErrClosed is returned when an operation is attempted on a closed backend.
var ErrClosed = errors.New("devbpf: backend closed")

// Backend abstracts the kernel-side per-device map. Implementations:
//
//   - NoopDeviceBackend (this file): in-memory mirror, used by tests/dev/non-linux
//   - CiliumTCBackend   (linux only): loads devchoke.o and attaches it to tc clsact
//
// Update and Delete must be safe to call from many goroutines.
type Backend interface {
	Open() error
	Close() error
	Update(mac MAC, b DeviceBucket) error
	Delete(mac MAC) error
	// Snapshot returns a copy of the enforcement map (choke_devs).
	Snapshot() (map[MAC]DeviceBucket, error)
	// SeenSnapshot returns a copy of the passive-discovery map
	// (choke_devs_seen). Nil (no error) when the backend has no kernel side.
	SeenSnapshot() (map[MAC]Seen, error)
	// FlowsSnapshot returns a copy of the per-device flow map (choke_flows):
	// which destinations each device is contacting. Nil (no error) for the
	// noop backend.
	FlowsSnapshot() (map[FlowKey]FlowStat, error)
	// AttachedLinks reports how many tc programs are live (0 for noop).
	AttachedLinks() int
	// DataPlaneTier names the active actuator: "tc", "noop" (later "xdp"/"nftables").
	DataPlaneTier() string
}

// NoopDeviceBackend is a fully-functional in-memory backend with no kernel
// side. Mirrors bpfmap.NoopBackend. The engine wires it in by default;
// production deployments on a gateway swap it for the real loader.
type NoopDeviceBackend struct {
	mu    sync.RWMutex
	open  bool
	state map[MAC]DeviceBucket
}

func NewNoopDeviceBackend() *NoopDeviceBackend {
	return &NoopDeviceBackend{state: make(map[MAC]DeviceBucket)}
}

func (n *NoopDeviceBackend) Open() error {
	n.mu.Lock()
	n.open = true
	if n.state == nil {
		n.state = make(map[MAC]DeviceBucket)
	}
	n.mu.Unlock()
	return nil
}

func (n *NoopDeviceBackend) Close() error {
	n.mu.Lock()
	n.open = false
	n.mu.Unlock()
	return nil
}

func (n *NoopDeviceBackend) Update(mac MAC, b DeviceBucket) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.open {
		return ErrClosed
	}
	n.state[mac] = b
	return nil
}

func (n *NoopDeviceBackend) Delete(mac MAC) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.open {
		return ErrClosed
	}
	delete(n.state, mac)
	return nil
}

func (n *NoopDeviceBackend) Snapshot() (map[MAC]DeviceBucket, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if !n.open {
		return nil, ErrClosed
	}
	out := make(map[MAC]DeviceBucket, len(n.state))
	for k, v := range n.state {
		out[k] = v
	}
	return out, nil
}

func (n *NoopDeviceBackend) SeenSnapshot() (map[MAC]Seen, error)          { return nil, nil }
func (n *NoopDeviceBackend) FlowsSnapshot() (map[FlowKey]FlowStat, error) { return nil, nil }
func (n *NoopDeviceBackend) AttachedLinks() int                           { return 0 }
func (n *NoopDeviceBackend) DataPlaneTier() string                        { return "noop" }
