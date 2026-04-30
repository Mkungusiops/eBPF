// Package tokens implements per-process token-bucket rate limiting.
//
// Each bucket is keyed on (pid, dimension) where dimension is a free-form
// string from the policy DSL — e.g. "egress.bytes", "dns.queries",
// "syscall.connect". The userspace BPF backend periodically syncs these
// buckets to a kernel BPF map; on a non-Linux dev environment the buckets
// are still authoritative for "would the kernel allow this?" decisions.
//
// The implementation is lazy: buckets refill on Allow() rather than from a
// timer, so an idle bucket consumes zero CPU.
package tokens

import (
	"sync"
	"time"
)

// Key identifies a bucket. Dimension is policy-defined; the gateway
// installs the same Key for every policy that mentions that dimension on
// that PID.
type Key struct {
	PID       uint32
	Dimension string
}

// Bucket is a single token bucket. Concurrency-safe.
type Bucket struct {
	mu         sync.Mutex
	capacity   float64
	ratePerSec float64
	tokens     float64
	last       time.Time

	// stats — read-only after AllowN; not authoritative, just for telemetry.
	allowed uint64
	denied  uint64
}

// NewBucket builds a Bucket starting full. ratePerSec is the steady-state
// refill rate; burst is the max tokens that can accumulate (also the
// instantaneous capacity).
func NewBucket(ratePerSec, burst float64) *Bucket {
	if burst <= 0 {
		burst = ratePerSec
	}
	return &Bucket{
		capacity:   burst,
		ratePerSec: ratePerSec,
		tokens:     burst,
		last:       time.Now(),
	}
}

// AllowN attempts to consume n tokens. Returns true if the bucket had
// enough; false otherwise. Lazy refill: the elapsed time since the last
// call is converted to tokens at ratePerSec.
func (b *Bucket) AllowN(n float64) bool {
	if n <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.ratePerSec
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
	if b.tokens >= n {
		b.tokens -= n
		b.allowed++
		return true
	}
	b.denied++
	return false
}

// Allow is shorthand for AllowN(1).
func (b *Bucket) Allow() bool { return b.AllowN(1) }

// Stats returns (allowed, denied) counters for telemetry.
func (b *Bucket) Stats() (uint64, uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.allowed, b.denied
}

// Manager is a thread-safe map from Key to Bucket. The gateway calls
// Install when a circuit transition fires; the BPF/seccomp backend (or a
// userspace decision point) calls Allow when the kernel asks "is this
// packet/syscall ok?".
type Manager struct {
	mu      sync.RWMutex
	buckets map[Key]*Bucket
}

func NewManager() *Manager {
	return &Manager{buckets: make(map[Key]*Bucket)}
}

// Install puts a bucket under the given key, replacing any existing bucket.
// Replacement is intentional: a re-evaluation of the policy may carry new
// rate values, and we want them to take effect immediately.
func (m *Manager) Install(k Key, ratePerSec, burst float64) {
	m.mu.Lock()
	m.buckets[k] = NewBucket(ratePerSec, burst)
	m.mu.Unlock()
}

// Allow consumes 1 token. If the key has no bucket installed the call
// returns true (no policy → no choke). This makes the data-plane fail-open
// when no policy applies.
func (m *Manager) Allow(k Key) bool {
	return m.AllowN(k, 1)
}

// AllowN consumes n tokens. Same fail-open semantics as Allow.
func (m *Manager) AllowN(k Key, n float64) bool {
	m.mu.RLock()
	b, ok := m.buckets[k]
	m.mu.RUnlock()
	if !ok {
		return true
	}
	return b.AllowN(n)
}

// ForgetPID drops every bucket whose key has the given pid. Wire to
// process exit events to keep memory bounded.
func (m *Manager) ForgetPID(pid uint32) {
	m.mu.Lock()
	for k := range m.buckets {
		if k.PID == pid {
			delete(m.buckets, k)
		}
	}
	m.mu.Unlock()
}

// Snapshot returns a copy of every key currently installed. Use for
// metrics or for syncing to a kernel BPF map.
func (m *Manager) Snapshot() []Key {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Key, 0, len(m.buckets))
	for k := range m.buckets {
		out = append(out, k)
	}
	return out
}

// Tracked returns the number of installed buckets.
func (m *Manager) Tracked() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.buckets)
}
