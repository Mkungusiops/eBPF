// Package cgroupv2 is the real per-process choke backend for Linux.
//
// It uses the kernel's cgroup v2 unified hierarchy to actually enforce
// throttle / tarpit / quarantine actions:
//
//	throttled   → 5%  CPU,   200 max pids, low IO weight
//	tarpit      → 1%  CPU,   50  max pids, lower IO weight
//	quarantined → cgroup.freeze=1 — process is paused entirely
//	severed     → handled by the Severer (SIGKILL); not this backend
//
// On engine startup the backend creates three sibling cgroups under the
// configured root (default /sys/fs/cgroup) and writes their resource
// limits. A Decision then translates to writing the target PID into the
// cgroup's cgroup.procs and (for quarantine) freezing that cgroup.
//
// The Manager itself is platform-neutral (just file I/O) so it builds and
// unit-tests on any OS. The Apply method that wires it to the enforce
// interface is split across backend_linux.go / backend_other.go so the
// macOS dev environment compiles cleanly without trying to touch /sys.
package cgroupv2

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
)

const (
	// DefaultRoot is the conventional cgroup v2 unified mount.
	DefaultRoot = "/sys/fs/cgroup"

	// Names of the per-state cgroups we create. Sibling-of-system, owned
	// by the engine — operators can `cat /sys/fs/cgroup/choke-*/cgroup.procs`
	// to see who's currently choked.
	NameThrottled   = "choke-throttled"
	NameTarpit      = "choke-tarpit"
	NameQuarantined = "choke-quarantined"
)

// Limits is the resource budget for a single tier. CPUMax follows
// cgroup v2's "<quota> <period>" syntax in microseconds. PidsMax is a
// hard cap on the descendant pid count. IOWeight is 1..10000 (lower =
// less IO). MemoryHigh is in bytes; 0 = unlimited.
type Limits struct {
	CPUMax     string
	PidsMax    string
	IOWeight   string
	MemoryHigh string
}

// DefaultLimits returns the production-ish presets. Tuned for a single
// VM where the OS itself stays responsive even when 100 procs land in
// "tarpit". Override per-tier via SetLimits().
func DefaultLimits() map[circuit.Action]Limits {
	return map[circuit.Action]Limits{
		circuit.ActThrottle: {
			CPUMax:     "5000 100000", // 5% of one core
			PidsMax:    "200",
			IOWeight:   "10",
			MemoryHigh: "536870912", // 512 MiB soft cap
		},
		circuit.ActTarpit: {
			CPUMax:     "1000 100000", // 1% of one core
			PidsMax:    "50",
			IOWeight:   "1",
			MemoryHigh: "134217728", // 128 MiB soft cap
		},
		circuit.ActQuarantine: {
			// Quarantine uses cgroup.freeze rather than CPU caps; the
			// limits below take effect only briefly between move and
			// freeze, but we set them anyway so a freeze failure still
			// produces a heavily-restricted process.
			CPUMax:     "100 100000", // 0.1% of one core
			PidsMax:    "10",
			IOWeight:   "1",
			MemoryHigh: "67108864", // 64 MiB soft cap
		},
	}
}

// Manager owns the per-state cgroups. Concurrency-safe.
type Manager struct {
	root string
	mu   sync.Mutex
	limits map[circuit.Action]Limits
	paths  map[circuit.Action]string
}

// NewManager builds an unconfigured manager. Call Setup() before Apply.
func NewManager(root string) *Manager {
	if root == "" {
		root = DefaultRoot
	}
	return &Manager{
		root:   root,
		limits: DefaultLimits(),
		paths: map[circuit.Action]string{
			circuit.ActThrottle:   filepath.Join(root, NameThrottled),
			circuit.ActTarpit:     filepath.Join(root, NameTarpit),
			circuit.ActQuarantine: filepath.Join(root, NameQuarantined),
		},
	}
}

// Root returns the cgroup root path the manager was constructed with.
func (m *Manager) Root() string { return m.root }

// PathFor returns the absolute path of the cgroup for a given action,
// or empty string for actions that have no cgroup (sever, none).
func (m *Manager) PathFor(a circuit.Action) string { return m.paths[a] }

// SetLimits replaces the limits map. Call before Setup.
func (m *Manager) SetLimits(l map[circuit.Action]Limits) {
	m.mu.Lock()
	m.limits = l
	m.mu.Unlock()
}

// IsCgroupV2 reports whether root looks like a cgroup v2 unified mount.
// Heuristic: cgroup v2 has a cgroup.controllers file at the root.
func IsCgroupV2(root string) bool {
	_, err := os.Stat(filepath.Join(root, "cgroup.controllers"))
	return err == nil
}

// Setup verifies cgroup v2, enables the controllers we need on the
// parent, and creates the per-tier cgroups with their limits applied.
// Idempotent: running it again is safe — existing cgroups are kept and
// limits are re-written (so a config change picks up on engine restart).
func (m *Manager) Setup() error {
	if !IsCgroupV2(m.root) {
		return fmt.Errorf("cgroup v2 not detected at %s (no cgroup.controllers file)", m.root)
	}
	// Enable controllers in the parent's subtree so child cgroups can
	// use them. Best-effort — they may already be enabled, in which case
	// the kernel returns -EBUSY/-EINVAL and we ignore.
	_ = os.WriteFile(filepath.Join(m.root, "cgroup.subtree_control"),
		[]byte("+cpu +memory +io +pids"), 0o644)

	for a, path := range m.paths {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", path, err)
		}
		l := m.limits[a]
		if err := writeIfNotEmpty(filepath.Join(path, "cpu.max"), l.CPUMax); err != nil {
			return err
		}
		if err := writeIfNotEmpty(filepath.Join(path, "pids.max"), l.PidsMax); err != nil {
			return err
		}
		if err := writeIfNotEmpty(filepath.Join(path, "io.weight"), l.IOWeight); err != nil {
			// io.weight is only available when the io controller is
			// enabled with weight tracking; failure is non-fatal.
		}
		if err := writeIfNotEmpty(filepath.Join(path, "memory.high"), l.MemoryHigh); err != nil {
			// memory.high may be unavailable in unprivileged containers;
			// non-fatal.
		}
	}
	return nil
}

func writeIfNotEmpty(path, value string) error {
	if value == "" {
		return nil
	}
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// MoveTo writes pid into the cgroup matching action. For quarantine the
// cgroup.freeze flag is then raised, which immediately suspends the
// process (the kernel sends a synchronous freeze signal to every task in
// the cgroup).
//
// Returns nil even if the PID is already gone — the goal is "this PID is
// in the right cgroup or doesn't exist", which is satisfied either way.
func (m *Manager) MoveTo(pid uint32, a circuit.Action) error {
	if pid == 0 {
		return errors.New("cgroupv2: refuse to move PID 0")
	}
	path, ok := m.paths[a]
	if !ok {
		return ErrUnsupported
	}
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"),
		[]byte(strconv.Itoa(int(pid))), 0o644); err != nil {
		// ESRCH means the process exited — treat as success.
		if isESRCH(err) {
			return nil
		}
		return fmt.Errorf("cgroupv2: move pid=%d → %s: %w", pid, path, err)
	}
	if a == circuit.ActQuarantine {
		_ = os.WriteFile(filepath.Join(path, "cgroup.freeze"), []byte("1"), 0o644)
	}
	return nil
}

// Thaw releases a quarantined cgroup so its members can run again. Used
// when an operator de-escalates a process out of quarantine. It is a
// per-cgroup operation, not per-pid: every member of the quarantine
// cgroup unfreezes simultaneously.
func (m *Manager) Thaw() error {
	path := m.paths[circuit.ActQuarantine]
	if path == "" {
		return nil
	}
	return os.WriteFile(filepath.Join(path, "cgroup.freeze"), []byte("0"), 0o644)
}

// Inhabitants reads cgroup.procs from each tier and returns the per-tier
// PID lists. Used by /api/choke/cgroups for the UI's tier inspector.
func (m *Manager) Inhabitants() (map[string][]uint32, error) {
	out := map[string][]uint32{
		NameThrottled: {}, NameTarpit: {}, NameQuarantined: {},
	}
	for a, path := range m.paths {
		name := filepath.Base(path)
		b, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
		if err != nil {
			if os.IsNotExist(err) {
				continue // Setup may not have run yet; not fatal
			}
			return out, err
		}
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if line == "" {
				continue
			}
			pid, err := strconv.ParseUint(line, 10, 32)
			if err != nil {
				continue
			}
			out[name] = append(out[name], uint32(pid))
		}
		_ = a
	}
	return out, nil
}

// ErrUnsupported is returned when the action isn't owned by this backend.
// Mirrors enforce.ErrUnsupported but defined here to avoid importing the
// enforce package (cycle). The two are checked as text by Multi() — see
// backend_linux.go where we wrap to enforce.ErrUnsupported explicitly.
var ErrUnsupported = errors.New("cgroupv2: action not supported (not throttle/tarpit/quarantine)")
