//go:build linux

package sysproc

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ReadDetail returns a richer /proc/<pid> snapshot for the inspect drawer.
// Best-effort: missing data shows up as zero/empty fields rather than an
// error, since the operator's UID may not be allowed to read every link.
func ReadDetail(pid uint32) (Detail, error) {
	base := filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10))
	if _, err := os.Stat(base); err != nil {
		return Detail{PID: pid}, err
	}
	d := Detail{PID: pid}

	// /proc/<pid>/status — text key/value, easy to parse.
	if f, err := os.Open(filepath.Join(base, "status")); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "State:"):
				if fs := strings.Fields(line); len(fs) >= 2 {
					d.Status = fs[1]
				}
			case strings.HasPrefix(line, "Threads:"):
				if fs := strings.Fields(line); len(fs) >= 2 {
					if n, err := strconv.Atoi(fs[1]); err == nil {
						d.Threads = n
					}
				}
			case strings.HasPrefix(line, "VmRSS:"):
				if fs := strings.Fields(line); len(fs) >= 2 {
					if n, err := strconv.ParseUint(fs[1], 10, 64); err == nil {
						d.VmRSSKB = n
					}
				}
			case strings.HasPrefix(line, "VmSize:"):
				if fs := strings.Fields(line); len(fs) >= 2 {
					if n, err := strconv.ParseUint(fs[1], 10, 64); err == nil {
						d.VmSizeKB = n
					}
				}
			}
		}
		f.Close()
	}

	if started, ok := computeStartedUnix(base); ok {
		d.StartedUnix = started
	}
	if v, err := os.Readlink(filepath.Join(base, "cwd")); err == nil {
		d.Cwd = v
	}
	if v, err := os.Readlink(filepath.Join(base, "root")); err == nil {
		d.Root = v
	}

	inodes, count, samples := readFDs(base)
	d.NumFDs = count
	d.FDSamples = samples

	if len(inodes) > 0 {
		d.NumConns, d.ConnPeers = countConns(base, inodes)
	}
	return d, nil
}

// computeStartedUnix converts the process's start_time (clock ticks since
// boot, /proc/<pid>/stat field 22) into a wall-clock unix timestamp via
// /proc/uptime. CLK_TCK is hardcoded to 100 — virtually universal on
// Linux/x86_64; reading it from sysconf would require CGO.
func computeStartedUnix(base string) (int64, bool) {
	statBytes, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return 0, false
	}
	s := string(statBytes)
	end := strings.LastIndex(s, ")")
	if end < 0 || end+1 >= len(s) {
		return 0, false
	}
	fields := strings.Fields(s[end+1:])
	if len(fields) <= 19 {
		return 0, false
	}
	starttime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, false
	}
	upBytes, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, false
	}
	upFields := strings.Fields(string(upBytes))
	if len(upFields) == 0 {
		return 0, false
	}
	uptimeSec, err := strconv.ParseFloat(upFields[0], 64)
	if err != nil {
		return 0, false
	}
	const clkTck = 100.0
	procAgeSec := uptimeSec - float64(starttime)/clkTck
	if procAgeSec < 0 {
		return 0, false
	}
	return time.Now().Unix() - int64(procAgeSec), true
}

// readFDs walks /proc/<pid>/fd, returning the set of socket inodes (used
// to cross-reference net/tcp + net/udp), the total fd count, and up to
// ten sample readlink targets ("socket:[NNN]", "/var/log/foo", …).
func readFDs(base string) (inodes map[uint64]bool, count int, samples []string) {
	inodes = make(map[uint64]bool)
	fdDir := filepath.Join(base, "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return inodes, 0, nil
	}
	count = len(entries)
	samples = make([]string, 0, 10)
	for _, e := range entries {
		link, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
			inum := link[len("socket:[") : len(link)-1]
			if v, err := strconv.ParseUint(inum, 10, 64); err == nil {
				inodes[v] = true
			}
		}
		if len(samples) < 10 {
			samples = append(samples, link)
		}
	}
	return
}

// countConns scans /proc/<pid>/net/{tcp,tcp6,udp,udp6} for entries whose
// inode matches one of this PID's socket fds. Returns the count plus up
// to five sample peer addresses parsed from the rem_address column.
func countConns(base string, inodes map[uint64]bool) (count int, peers []string) {
	files := []string{"tcp", "tcp6", "udp", "udp6"}
	for _, name := range files {
		f, err := os.Open(filepath.Join(base, "net", name))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		first := true
		for sc.Scan() {
			if first {
				first = false
				continue
			}
			fs := strings.Fields(sc.Text())
			// Standard layout: sl local rem state tx rx tr tm rt uid timeout inode
			// Inode is index 9.
			if len(fs) < 10 {
				continue
			}
			inum, err := strconv.ParseUint(fs[9], 10, 64)
			if err != nil {
				continue
			}
			if !inodes[inum] {
				continue
			}
			count++
			if len(peers) < 5 {
				if peer := parseHexAddr(fs[2], strings.HasSuffix(name, "6")); peer != "" {
					peers = append(peers, peer)
				}
			}
		}
		f.Close()
	}
	return
}

// parseHexAddr decodes /proc/net/{tcp,udp}'s "AABBCCDD:PPPP" form into
// "ip:port". Each 4-byte word in the address is little-endian on x86_64.
func parseHexAddr(hexAddr string, isV6 bool) string {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return ""
	}
	portU, err := strconv.ParseUint(parts[1], 16, 32)
	if err != nil {
		return ""
	}
	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	if isV6 {
		if len(raw) != 16 {
			return ""
		}
		for w := 0; w < 4; w++ {
			i := w * 4
			raw[i], raw[i+3] = raw[i+3], raw[i]
			raw[i+1], raw[i+2] = raw[i+2], raw[i+1]
		}
		return fmt.Sprintf("[%s]:%d", net.IP(raw).String(), portU)
	}
	if len(raw) != 4 {
		return ""
	}
	raw[0], raw[3] = raw[3], raw[0]
	raw[1], raw[2] = raw[2], raw[1]
	return fmt.Sprintf("%s:%d", net.IP(raw).String(), portU)
}
