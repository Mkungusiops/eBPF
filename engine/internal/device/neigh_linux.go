//go:build linux

package device

import (
	"encoding/json"
	"os/exec"
)

// PollNeigh reads the kernel neighbour table (via `ip -j neigh show`) and
// returns one Device per entry that has a usable MAC. This binds MAC<->IP
// for static-IP devices that never DHCP and for devices the data plane has
// seen but whose IP we don't yet know. Best-effort: a missing `ip` binary
// or a parse error yields (nil, err) and the caller simply skips this tick.
func PollNeigh() ([]Device, error) {
	out, err := exec.Command("ip", "-j", "neigh", "show").Output()
	if err != nil {
		return nil, err
	}
	var raw []struct {
		Dst    string   `json:"dst"`
		Dev    string   `json:"dev"`
		LLAddr string   `json:"lladdr"`
		State  []string `json:"state"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}
	devs := make([]Device, 0, len(raw))
	for _, n := range raw {
		if n.LLAddr == "" || n.Dst == "" {
			continue // INCOMPLETE/FAILED entries have no MAC
		}
		devs = append(devs, Device{MAC: n.LLAddr, LastIP: n.Dst, Source: SourceNeigh})
	}
	return devs, nil
}
