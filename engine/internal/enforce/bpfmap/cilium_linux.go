//go:build linux

package bpfmap

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// CiliumEBPFBackend is the real kernel data plane. It loads choke.o
// (built from bpf/choke.c by setup.sh on the target VM), attaches the
// connect4/connect6 programs to the system cgroup root, and exposes
// the choke_pids hash map through the Backend interface.
//
// Sever-only for now: when a PID's bucket has FlagSever or
// FlagQuarantine set, the kernel returns 0 from cgroup/connect{4,6},
// which the kernel translates into EPERM on connect(2). Throttle and
// tarpit still flow through the cgroup v2 backend.
//
// The loader is intentionally permissive on attach failure — if the
// kernel doesn't support cgroup attach, the map updates still go
// through and serve as a kernel-side audit trail. The engine logs the
// failure and keeps running. Sever via SIGKILL (the Severer backend)
// remains the hard kill path.
type CiliumEBPFBackend struct {
	objPath   string
	cgroupDir string

	mu     sync.RWMutex
	open   bool
	coll   *ebpf.Collection
	links  []link.Link
	pidMap *ebpf.Map
}

// NewCiliumEBPFBackend builds the backend without loading. Call Open()
// to actually load the program and attach it.
//
//	objPath:   path to a compiled choke.o (BPF ELF)
//	cgroupDir: cgroup v2 root to attach to (e.g. /sys/fs/cgroup)
func NewCiliumEBPFBackend(objPath, cgroupDir string) *CiliumEBPFBackend {
	return &CiliumEBPFBackend{objPath: objPath, cgroupDir: cgroupDir}
}

func (c *CiliumEBPFBackend) Open() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open {
		return nil
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("bpfmap: remove memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(c.objPath)
	if err != nil {
		return fmt.Errorf("bpfmap: load %s: %w", c.objPath, err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("bpfmap: new collection: %w", err)
	}
	c.coll = coll

	pidMap, ok := coll.Maps["choke_pids"]
	if !ok {
		c.coll.Close()
		c.coll = nil
		return errors.New("bpfmap: choke_pids map not found in object")
	}
	c.pidMap = pidMap

	for _, attach := range []struct {
		name string
		typ  ebpf.AttachType
	}{
		{"choke_connect4", ebpf.AttachCGroupInet4Connect},
		{"choke_connect6", ebpf.AttachCGroupInet6Connect},
		{"choke_sendmsg4", ebpf.AttachCGroupUDP4Sendmsg},
		{"choke_sendmsg6", ebpf.AttachCGroupUDP6Sendmsg},
	} {
		prog, ok := coll.Programs[attach.name]
		if !ok {
			continue
		}
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    c.cgroupDir,
			Attach:  attach.typ,
			Program: prog,
		})
		if err != nil {
			// non-fatal: keep the map for telemetry, log the failure
			// upstream by returning a sentinel the caller can choose
			// to ignore.
			fmt.Fprintf(os.Stderr, "[bpfmap] attach %s to %s: %v (map remains usable)\n",
				attach.name, c.cgroupDir, err)
			continue
		}
		c.links = append(c.links, l)
	}

	c.open = true
	return nil
}

func (c *CiliumEBPFBackend) Close() error {
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
	c.pidMap = nil
	c.open = false
	return nil
}

func (c *CiliumEBPFBackend) Update(pid uint32, b PIDBucket) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.open || c.pidMap == nil {
		return ErrClosed
	}
	return c.pidMap.Update(&pid, &b, ebpf.UpdateAny)
}

func (c *CiliumEBPFBackend) Delete(pid uint32) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.open || c.pidMap == nil {
		return ErrClosed
	}
	if err := c.pidMap.Delete(&pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

func (c *CiliumEBPFBackend) Snapshot() (map[uint32]PIDBucket, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.open || c.pidMap == nil {
		return nil, ErrClosed
	}
	out := make(map[uint32]PIDBucket)
	var (
		key uint32
		val PIDBucket
	)
	it := c.pidMap.Iterate()
	for it.Next(&key, &val) {
		out[key] = val
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// AttachedLinks returns how many cgroup attach links are live. Useful
// for the engine startup log and the /api/choke/state debug payload.
func (c *CiliumEBPFBackend) AttachedLinks() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.links)
}
