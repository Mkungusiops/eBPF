//go:build linux

package sysproc

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// List reads /proc and returns one Entry per running PID. Best-effort —
// PIDs that disappear mid-read are silently skipped (the typical
// pid_max_age race against fork/exit). Sorted by PID ascending so the UI
// has stable ordering.
func List() ([]Entry, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		ent, err := readOne(uint32(pid64))
		if err != nil {
			continue // PID exited mid-read — skip
		}
		out = append(out, ent)
	}
	return out, nil
}

func readOne(pid uint32) (Entry, error) {
	base := filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10))

	comm := strings.TrimSpace(readSmall(filepath.Join(base, "comm")))
	exe, _ := os.Readlink(filepath.Join(base, "exe"))
	cmd := readCmdline(filepath.Join(base, "cmdline"))
	ppid, uid, starttime := readStatusAndStat(base)

	return Entry{
		PID: pid, PPID: ppid, UID: uid,
		Comm: comm, Exe: exe, Cmdline: cmd, StartTime: starttime,
	}, nil
}

func readSmall(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// readCmdline reads /proc/<pid>/cmdline (null-separated argv) and joins
// with single spaces. Trailing nulls are trimmed. Returns the comm in
// brackets if cmdline is empty (kernel threads have empty cmdline).
func readCmdline(path string) string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return ""
	}
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	for i, c := range b {
		if c == 0 {
			b[i] = ' '
		}
	}
	return string(b)
}

// readStatusAndStat extracts PPid + UID from /proc/<pid>/status (text
// format, easy parsing) and the starttime field (#22) from /proc/<pid>/stat
// (space-separated, after a parenthesized comm field that may itself
// contain spaces — so we slice from the *last* ')' to be safe).
func readStatusAndStat(base string) (ppid, uid uint32, starttime uint64) {
	if b, err := os.ReadFile(filepath.Join(base, "status")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			switch {
			case strings.HasPrefix(line, "PPid:"):
				if v, err := strconv.ParseUint(strings.TrimSpace(line[5:]), 10, 32); err == nil {
					ppid = uint32(v)
				}
			case strings.HasPrefix(line, "Uid:"):
				// "Uid:\t<real>\t<eff>\t<saved>\t<fs>"
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if v, err := strconv.ParseUint(fields[1], 10, 32); err == nil {
						uid = uint32(v)
					}
				}
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(base, "stat")); err == nil {
		s := string(b)
		// Skip past the comm field, which is parenthesized and may contain spaces.
		end := strings.LastIndex(s, ")")
		if end < 0 || end+1 >= len(s) {
			return
		}
		fields := strings.Fields(s[end+1:])
		// After the closing ), fields[0] = state, fields[1..] = ppid, pgrp, ...
		// /proc/[pid]/stat fields per proc(5): 1=pid 2=comm 3=state 4=ppid ... 22=starttime
		// We've consumed pid and comm (they're before/inside the paren); the
		// remaining fields start at #3 (state). So starttime = fields[22-3] = fields[19].
		if len(fields) > 19 {
			if v, err := strconv.ParseUint(fields[19], 10, 64); err == nil {
				starttime = v
			}
		}
	}
	return
}
