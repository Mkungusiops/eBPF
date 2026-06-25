//go:build linux

package devbpf

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// CiliumTCBackend is the real network data plane. It loads devchoke.o
// (built from bpf/devchoke.c by setup.sh on the target gateway), attaches
// the devchoke_ingress/devchoke_egress classifier programs to the tc clsact
// qdisc of each configured interface via TCX, and exposes the choke_devs
// hash map through the Backend interface.
//
// Attach to bridge SLAVE ports (or routed LAN ifaces), never the bridge
// master — the master only sees locally-terminated traffic, so attaching
// there enforces nothing while reporting "attached". The loader is
// intentionally permissive on attach failure (mirrors bpfmap): if a TCX
// attach fails the map updates still go through as a kernel-side audit
// trail, and AttachedLinks() lets the operator see the box isn't actually
// enforcing.
type CiliumTCBackend struct {
	objPath string
	ifaces  []string

	mu      sync.RWMutex
	open    bool
	coll     *ebpf.Collection
	links    []link.Link
	devMap   *ebpf.Map
	seenMap  *ebpf.Map
	flowsMap *ebpf.Map
}

// NewCiliumTCBackend builds the backend without loading. Call Open() to
// actually load the programs and attach them.
//
//	objPath: path to a compiled devchoke.o (BPF ELF)
//	ifaces:  LAN/bridge-slave interface names to attach ingress+egress to
func NewCiliumTCBackend(objPath string, ifaces []string) *CiliumTCBackend {
	return &CiliumTCBackend{objPath: objPath, ifaces: ifaces}
}

func (c *CiliumTCBackend) Open() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open {
		return nil
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("devbpf: remove memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(c.objPath)
	if err != nil {
		return fmt.Errorf("devbpf: load %s: %w", c.objPath, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("devbpf: new collection: %w", err)
	}
	c.coll = coll

	devMap, ok := coll.Maps["choke_devs"]
	if !ok {
		c.coll.Close()
		c.coll = nil
		return errors.New("devbpf: choke_devs map not found in object")
	}
	c.devMap = devMap
	c.seenMap = coll.Maps["choke_devs_seen"] // optional; nil-tolerant below
	c.flowsMap = coll.Maps["choke_flows"]    // optional; nil-tolerant below

	if len(c.ifaces) == 0 {
		fmt.Fprintf(os.Stderr, "[devbpf] no -devchoke-iface configured: map usable but nothing attached (no enforcement)\n")
	}
	for _, ifn := range c.ifaces {
		iface, err := net.InterfaceByName(ifn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[devbpf] interface %q: %v (skipped)\n", ifn, err)
			continue
		}
		for _, a := range []struct {
			prog   string
			attach ebpf.AttachType
		}{
			{"devchoke_ingress", ebpf.AttachTCXIngress},
			{"devchoke_egress", ebpf.AttachTCXEgress},
		} {
			prog, ok := coll.Programs[a.prog]
			if !ok {
				continue
			}
			l, err := link.AttachTCX(link.TCXOptions{
				Interface: iface.Index,
				Program:   prog,
				Attach:    a.attach,
			})
			if err != nil {
				// non-fatal: keep the map for telemetry, surface the failure
				// via AttachedLinks() and the boot log.
				fmt.Fprintf(os.Stderr, "[devbpf] attach %s to %s: %v (map remains usable)\n",
					a.prog, ifn, err)
				continue
			}
			c.links = append(c.links, l)
		}
	}

	c.open = true
	return nil
}

func (c *CiliumTCBackend) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.open {
		return nil
	}
	for _, l := range c.links {
		_ = l.Close()
	}
	c.links = nil
	if c.coll != nil {
		c.coll.Close()
		c.coll = nil
	}
	c.devMap = nil
	c.seenMap = nil
	c.flowsMap = nil
	c.open = false
	return nil
}

func (c *CiliumTCBackend) Update(mac MAC, b DeviceBucket) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.open || c.devMap == nil {
		return ErrClosed
	}
	key := keyFor(mac)
	return c.devMap.Update(&key, &b, ebpf.UpdateAny)
}

func (c *CiliumTCBackend) Delete(mac MAC) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.open || c.devMap == nil {
		return ErrClosed
	}
	key := keyFor(mac)
	if err := c.devMap.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

func (c *CiliumTCBackend) Snapshot() (map[MAC]DeviceBucket, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.open || c.devMap == nil {
		return nil, ErrClosed
	}
	out := make(map[MAC]DeviceBucket)
	var (
		key devKey
		val DeviceBucket
	)
	it := c.devMap.Iterate()
	for it.Next(&key, &val) {
		out[key.MAC] = val
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *CiliumTCBackend) SeenSnapshot() (map[MAC]Seen, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.open || c.seenMap == nil {
		return nil, nil
	}
	out := make(map[MAC]Seen)
	var (
		key devKey
		val Seen
	)
	it := c.seenMap.Iterate()
	for it.Next(&key, &val) {
		out[key.MAC] = val
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *CiliumTCBackend) FlowsSnapshot() (map[FlowKey]FlowStat, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.open || c.flowsMap == nil {
		return nil, nil
	}
	out := make(map[FlowKey]FlowStat)
	var (
		key FlowKey
		val FlowStat
	)
	it := c.flowsMap.Iterate()
	for it.Next(&key, &val) {
		out[key] = val
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// AttachedLinks returns how many tc programs are live. Useful for the
// startup log and the /api/choke/device-state payload — if this is 0 the
// box is NOT enforcing even though the map is writable.
func (c *CiliumTCBackend) AttachedLinks() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.links)
}

func (c *CiliumTCBackend) DataPlaneTier() string { return "tc" }
