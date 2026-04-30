// Package bpfmap is the userspace contract for the per-PID choke map.
//
// The data plane that actually shapes traffic lives in a small CO-RE BPF
// program (cgroup_skb / cgroup/connect4 / lsm hooks) that:
//
//   1. reads bpf_get_current_pid_tgid() on every syscall/packet,
//   2. looks up that PID in a BPF_MAP_TYPE_HASH keyed by u32 pid,
//   3. consumes a token from the per-PID bucket; on empty -> drop/EPERM.
//
// The userspace gateway updates this map: on circuit transitions it calls
// Backend.Update(pid, bucket); on process exit it calls Delete(pid).
//
// This file defines the interface and a NoopBackend used during dev and
// in tests. The real loader (cilium/ebpf based) is intentionally NOT a
// build dependency of the engine — wire it in via dependency-inversion
// when/if the operator wants the kernel data plane. That keeps the engine
// pure-Go (no CGO) on every platform.
package bpfmap

import (
	"errors"
	"sync"
)

// PIDBucket is the kernel-side struct laid out exactly as the BPF program
// reads it. Field order and types must not change without also bumping
// the BPF program's matching struct.
type PIDBucket struct {
	RatePerSec uint32 // tokens added per second
	Burst      uint32 // max accumulated tokens
	Tokens     uint32 // current token count (kernel-side, written by BPF)
	LastNs     uint64 // last refill timestamp (ns since boot)
	Flags      uint32 // bit 0: throttle, 1: tarpit, 2: quarantine, 3: sever
}

// Action flags carried in PIDBucket.Flags. The kernel program switches on
// these to pick its drop/delay/redirect behaviour.
const (
	FlagThrottle   uint32 = 1 << 0
	FlagTarpit     uint32 = 1 << 1
	FlagQuarantine uint32 = 1 << 2
	FlagSever      uint32 = 1 << 3
)

// Backend abstracts the kernel-side per-PID map. Implementations:
//
//   - NoopBackend         (this file): no-op + in-memory mirror, used by tests
//   - CiliumEBPFBackend   (linux only, optional): loads a real BPF program
//
// Update and Delete must be safe to call from many goroutines.
type Backend interface {
	Open() error
	Close() error
	Update(pid uint32, b PIDBucket) error
	Delete(pid uint32) error
	// Snapshot returns a copy of the current map contents. Useful for the
	// /api/choke-state endpoint and for debugging.
	Snapshot() (map[uint32]PIDBucket, error)
}

// ErrClosed is returned when an operation is attempted on a closed backend.
var ErrClosed = errors.New("bpfmap: backend closed")

// NoopBackend is a fully-functional in-memory backend with no kernel side.
// Useful for tests, dry-run, and dev hosts. The engine wires it in by
// default; production deployments swap it for the real loader.
type NoopBackend struct {
	mu     sync.RWMutex
	open   bool
	state  map[uint32]PIDBucket
}

func NewNoopBackend() *NoopBackend {
	return &NoopBackend{state: make(map[uint32]PIDBucket)}
}

func (n *NoopBackend) Open() error {
	n.mu.Lock()
	n.open = true
	if n.state == nil {
		n.state = make(map[uint32]PIDBucket)
	}
	n.mu.Unlock()
	return nil
}

func (n *NoopBackend) Close() error {
	n.mu.Lock()
	n.open = false
	n.mu.Unlock()
	return nil
}

func (n *NoopBackend) Update(pid uint32, b PIDBucket) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.open {
		return ErrClosed
	}
	n.state[pid] = b
	return nil
}

func (n *NoopBackend) Delete(pid uint32) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.open {
		return ErrClosed
	}
	delete(n.state, pid)
	return nil
}

func (n *NoopBackend) Snapshot() (map[uint32]PIDBucket, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if !n.open {
		return nil, ErrClosed
	}
	out := make(map[uint32]PIDBucket, len(n.state))
	for k, v := range n.state {
		out[k] = v
	}
	return out, nil
}
