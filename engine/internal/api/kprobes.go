package api

import (
	"context"
	"time"

	"encoding/json"
	"github.com/jeffmk/ebpf-poc-engine/internal/policyapply"
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
//
//	ID   NAME                    STATE     FILTERID   NAMESPACE   SENSORS         KERNELMEMORY   MODE      NPOST   NENFORCE   NMONITOR
//	1    outbound-connections    enabled   0          (global)    generic_kprobe  1.17 MB        enforce   12      0          0
//
// Columns are space-padded; we split on whitespace runs and map by header.
// parseTetraList scrapes `tetra tracingpolicy list`. The second return says
// whether the TABLE WAS RECOGNISED — which is not the same question as how many
// rows it had, and conflating the two produced a false alarm on the one surface
// that must never raise one.
//
// The parser only starts reading after a header line beginning with "ID". A
// `tetra` that printed a warning, changed its format, or failed while still
// exiting 0 therefore yields an empty slice that is indistinguishable from a
// kernel with genuinely no policies loaded. Callers used to treat "the command
// exited 0" as "I know what the kernel has", so an unrecognised output became
// "every expected detection is MISSING" — a fabricated coverage gap, reported
// as fact, on the trust surface.
//
// With the flag, a caller can say "I could not read the kernel" instead, which
// is both true and useful.
func parseTetraList(raw string) ([]policyStat, bool) {
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
	// body is true only once the "ID" header was seen, i.e. only once the
	// output was recognised as the policy table.
	return out, body
}

func (s *Server) handlePolicyStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	stats, ok, via := kernelPolicies(r.Context())
	if !ok {
		// 503 with the reason, not an empty list. An empty stats array is
		// indistinguishable from "no policies loaded", and the assistant's
		// policy_stats tool reads this endpoint — an LLM told "zero policies"
		// will report the host as undefended.
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "cannot read kernel policy state (" + via + ")",
			"via":   via,
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"stats": stats,
		"via":   via,
	})
}

// kernelPolicies reads the loaded policy set, preferring the gRPC API this
// process already holds a connection to and falling back to the CLI scrape.
//
// The second return says whether the answer is TRUSTWORTHY. Both paths can fail
// silently in their own way — gRPC by having no client configured, the scrape
// by producing output this build cannot parse — and a caller that cannot tell
// "no policies" from "no answer" reports a fabricated coverage gap.
//
// The shell-out stays as the fallback rather than being deleted: an agent that
// never called ConfigurePolicyApplier has no client, and four e2e scripts parse
// the same table independently.
func kernelPolicies(ctx context.Context) (stats []policyStat, ok bool, via string) {
	if c, _ := currentApplier(); c != nil {
		grpcCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if list, err := policyapply.List(grpcCtx, c); err == nil {
			out := make([]policyStat, 0, len(list))
			for _, p := range list {
				state := "disabled"
				if p.Enabled {
					state = "enabled"
				}
				out = append(out, policyStat{
					ID:    strconv.FormatUint(p.ID, 10),
					Name:  p.Name,
					State: state,
					// The CLI joined sensors with a comma; match it so a
					// consumer cannot tell the two paths apart by shape.
					Sensors:      strings.Join(p.Sensors, ","),
					KernelMemory: humanBytes(p.MemBytes),
					Mode:         p.Mode,
					NPost:        int(p.Posts),
				})
			}
			return out, true, "grpc"
		}
		// Fall through to the scrape rather than failing: a daemon that
		// answered the write path but not this read is still worth asking the
		// other way.
	}
	raw, err := runTetraList()
	if err != nil {
		return nil, false, "unavailable"
	}
	stats, recognised := parseTetraList(raw)
	if !recognised {
		return nil, false, "unparsed"
	}
	return stats, true, "cli"
}

// humanBytes renders a byte count the way `tetra` prints its KERNELMEMORY
// column, so the gRPC and CLI read paths produce the same string for the same
// policy. An empty result for zero, not "0 B" — the CLI omits it too.
func humanBytes(b uint64) string {
	if b == 0 {
		return ""
	}
	const unit = 1024
	if b < unit {
		return strconv.FormatUint(b, 10) + " B"
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return strconv.FormatFloat(float64(b)/float64(div), 'f', 2, 64) + " " + []string{"KB", "MB", "GB", "TB"}[exp]
}
