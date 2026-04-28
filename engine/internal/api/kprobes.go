package api

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
)

// /api/policy-stats execs `docker exec tetragon tetra tracingpolicy list`
// and parses the table into structured JSON. We deliberately keep this a
// best-effort parser — Tetragon's CLI doesn't (yet) emit machine-readable
// output for this command across all versions.

type policyStat struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	State        string `json:"state"`
	Sensors      string `json:"sensors"`
	KernelMemory string `json:"kernel_memory"`
	Mode         string `json:"mode"`
	NPost        int    `json:"npost"`
	NEnforce     int    `json:"nenforce"`
	NMonitor     int    `json:"nmonitor"`
}

func runTetraList() (string, error) {
	out, err := exec.Command("docker", "exec", "tetragon", "tetra", "tracingpolicy", "list").CombinedOutput()
	return string(out), err
}

// Tetra prints something like:
//   ID   NAME                    STATE     FILTERID   NAMESPACE   SENSORS         KERNELMEMORY   MODE      NPOST   NENFORCE   NMONITOR
//   1    outbound-connections    enabled   0          (global)    generic_kprobe  1.17 MB        enforce   12      0          0
// Columns are space-padded; we split on whitespace runs and map by header.
func parseTetraList(raw string) []policyStat {
	var (
		out  []policyStat
		hdr  []string
		body bool
	)
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if !body {
			if len(fields) > 0 && strings.EqualFold(fields[0], "ID") {
				hdr = make([]string, len(fields))
				for i, f := range fields {
					hdr[i] = strings.ToUpper(f)
				}
				body = true
			}
			continue
		}
		// "(global)" comes through as a single token; collapse "X MB" into "X MB".
		// Re-merge if fields > len(hdr) by joining the kernel-memory field.
		if len(fields) > len(hdr) {
			// KERNELMEMORY column is "1.17 MB" — two tokens. Stitch back.
			km := strings.Index(strings.Join(hdr, " "), "KERNELMEMORY")
			_ = km
			// Heuristic: find the index where two adjacent fields look like a number+unit.
			for i := 0; i < len(fields)-1; i++ {
				if _, err := strconv.ParseFloat(fields[i], 64); err == nil {
					if u := fields[i+1]; u == "B" || u == "KB" || u == "MB" || u == "GB" {
						merged := append([]string{}, fields[:i]...)
						merged = append(merged, fields[i]+" "+fields[i+1])
						merged = append(merged, fields[i+2:]...)
						fields = merged
						break
					}
				}
			}
		}
		row := policyStat{}
		for i, f := range fields {
			if i >= len(hdr) {
				break
			}
			switch hdr[i] {
			case "ID":
				row.ID = f
			case "NAME":
				row.Name = f
			case "STATE":
				row.State = f
			case "SENSORS":
				row.Sensors = f
			case "KERNELMEMORY":
				row.KernelMemory = f
			case "MODE":
				row.Mode = f
			case "NPOST":
				row.NPost, _ = strconv.Atoi(f)
			case "NENFORCE":
				row.NEnforce, _ = strconv.Atoi(f)
			case "NMONITOR":
				row.NMonitor, _ = strconv.Atoi(f)
			}
		}
		if row.ID != "" || row.Name != "" {
			out = append(out, row)
		}
	}
	return out
}

func (s *Server) handlePolicyStats(w http.ResponseWriter, r *http.Request) {
	raw, err := runTetraList()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "tetra unavailable: " + err.Error(),
			"raw":   raw,
		})
		return
	}
	stats := parseTetraList(raw)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"stats": stats,
		"raw":   raw,
	})
}
