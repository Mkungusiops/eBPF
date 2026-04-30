// Package sysproc returns a snapshot of every process on the host so an
// operator can pick one (or many) in the choke console and act on them
// directly — even when the gateway hasn't seen them yet via Tetragon.
//
// The Linux implementation reads /proc; the non-Linux build returns an
// empty list so the engine still compiles for macOS dev. Wired into the
// gateway via SetSysProcFn — the gateway exposes it via /api/choke/processes.
package sysproc

// Entry is one row in the process list. Fields are kept minimal; the UI
// joins this with the gateway's circuit state to add (state, score) per row.
type Entry struct {
	PID       uint32 `json:"pid"`
	PPID      uint32 `json:"ppid"`
	UID       uint32 `json:"uid"`
	Comm      string `json:"comm"`         // 16-char short name (kernel comm)
	Exe       string `json:"exe"`          // /proc/<pid>/exe symlink target
	Cmdline   string `json:"cmdline"`      // null-separated argv joined by space
	StartTime uint64 `json:"start_time"`   // jiffies since boot — stable across re-reads
}

// ListFn is the platform-agnostic entry point. Linux returns the live list;
// other platforms return an empty slice.
type ListFn func() ([]Entry, error)

// Detail is a richer per-PID snapshot, used by the choke console's inspect
// drawer. Fields are best-effort — anything the caller can't read (EACCES
// on /proc/<pid>/cwd, missing /proc/uptime, etc.) stays at its zero value.
type Detail struct {
	PID         uint32   `json:"pid"`
	Status      string   `json:"status,omitempty"`        // "R","S","D","Z","T","I"
	Threads     int      `json:"threads,omitempty"`
	VmRSSKB     uint64   `json:"vm_rss_kb,omitempty"`
	VmSizeKB    uint64   `json:"vm_size_kb,omitempty"`
	StartedUnix int64    `json:"started_unix,omitempty"`  // wall-clock seconds since epoch
	Cwd         string   `json:"cwd,omitempty"`
	Root        string   `json:"root,omitempty"`
	NumFDs      int      `json:"num_fds,omitempty"`
	FDSamples   []string `json:"fd_samples,omitempty"`    // up to 10 readlink targets
	NumConns    int      `json:"num_conns,omitempty"`     // tcp+tcp6+udp+udp6 owned by this PID
	ConnPeers   []string `json:"conn_peers,omitempty"`    // up to 5 sample peer "ip:port"
}

// Descendants walks the PPID tree to collect every PID transitively
// descended from root. Excludes root itself unless includeRoot=true.
// Cycle-safe (a malicious or buggy parent loop is detected via the
// visited map). Order is BFS so the closest descendants come first.
func Descendants(all []Entry, root uint32, includeRoot bool) []uint32 {
	if len(all) == 0 || root == 0 {
		return nil
	}
	// Index children-of: ppid -> []pid
	kids := make(map[uint32][]uint32, len(all))
	for _, e := range all {
		kids[e.PPID] = append(kids[e.PPID], e.PID)
	}
	out := make([]uint32, 0, 16)
	if includeRoot {
		out = append(out, root)
	}
	visited := map[uint32]bool{root: true}
	queue := []uint32{root}
	for len(queue) > 0 {
		head := queue[0]
		queue = queue[1:]
		for _, c := range kids[head] {
			if visited[c] {
				continue
			}
			visited[c] = true
			out = append(out, c)
			queue = append(queue, c)
		}
	}
	return out
}
