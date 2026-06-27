package api

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
)

//go:embed devices.html
var devicesHTML string

// SetDeviceGateway hands the network choke gateway to the server so the
// /api/choke/device-* endpoints can call it. Wired from main(); separate
// from NewServer so the listener can start before the device wiring runs.
func (s *Server) SetDeviceGateway(g *choke.DeviceGateway) { s.deviceGW = g }

// deviceGatewayOrErr returns the wired device gateway, or 503s when the
// engine is running without network device choke enabled.
func (s *Server) deviceGatewayOrErr(w http.ResponseWriter) *choke.DeviceGateway {
	if s.deviceGW == nil {
		http.Error(w, "network device choke not enabled (start engine with -devchoke-iface)", http.StatusServiceUnavailable)
		return nil
	}
	return s.deviceGW
}

// GET /devices — the embedded device console.
func (s *Server) handleDevicesConsole(w http.ResponseWriter, r *http.Request) {
	if s.serveEmbeddedWebPage(w, "devices.html") {
		return
	}
	serveMissingEmbeddedWeb(w)
}

// GET /api/choke/devices — the device table joined with circuit state and
// kernel buckets, most-dangerous-first.
func (s *Server) handleChokeDevices(w http.ResponseWriter, r *http.Request) {
	g := s.deviceGatewayOrErr(w)
	if g == nil {
		return
	}
	writeJSON(w, g.Snapshot())
}

// GET /api/choke/device-state — data-plane tier, attach count, kill-switch,
// dry-run, counts. The operator's confirmation the box is actually enforcing.
func (s *Server) handleChokeDeviceState(w http.ResponseWriter, r *http.Request) {
	g := s.deviceGatewayOrErr(w)
	if g == nil {
		return
	}
	writeJSON(w, g.DataPlaneState())
}

// GET /api/choke/device-flows?mac=<mac> — the destinations a device is
// contacting (busiest first), so the operator can judge whether it looks
// malicious before choking. Returns {mac, flows:[{dest_ip,dest_port,proto,
// packets,bytes}, ...]}.
func (s *Server) handleChokeDeviceFlows(w http.ResponseWriter, r *http.Request) {
	g := s.deviceGatewayOrErr(w)
	if g == nil {
		return
	}
	mac := r.URL.Query().Get("mac")
	if mac == "" {
		http.Error(w, "mac query parameter required", http.StatusBadRequest)
		return
	}
	flows, err := g.DeviceFlows(mac, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]interface{}{"mac": mac, "flows": flows})
}

// POST /api/choke/device-jail — choke one or more devices by MAC.
//
// Body:
//
//	{
//	  macs:   ["aa:bb:cc:dd:ee:ff", ...],
//	  action: "throttle"|"tarpit"|"quarantine"|"sever",
//	  reason: "responding to incident #1234",   // REQUIRED for the audit row
//	  revert_after_seconds: 300                  // optional auto-revert
//	}
//
// Each MAC is audited separately; returns a per-MAC outcome list so the UI
// can show "3/4 succeeded" (a refusal — e.g. an allow-listed MAC — surfaces
// as ok=false with the reason).
func (s *Server) handleChokeDeviceJail(w http.ResponseWriter, r *http.Request) {
	g := s.deviceGatewayOrErr(w)
	if g == nil {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		MACs               []string `json:"macs"`
		Action             string   `json:"action"`
		Reason             string   `json:"reason"`
		RevertAfterSeconds int      `json:"revert_after_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	action, err := parseAction(body.Action)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.Reason == "" {
		http.Error(w, "reason is required for the audit row", http.StatusBadRequest)
		return
	}
	if len(body.MACs) == 0 {
		http.Error(w, "no macs provided", http.StatusBadRequest)
		return
	}
	actor := s.auth.Username()
	type outcome struct {
		MAC     string `json:"mac"`
		OK      bool   `json:"ok"`
		Error   string `json:"error,omitempty"`
		State   string `json:"state,omitempty"`
		Outcome string `json:"outcome,omitempty"`
	}
	results := make([]outcome, 0, len(body.MACs))
	for _, mac := range body.MACs {
		d, err := g.ManualDevice(r.Context(), mac, action, body.Reason, actor)
		if err != nil {
			results = append(results, outcome{MAC: mac, OK: false, Error: err.Error()})
			continue
		}
		if body.RevertAfterSeconds > 0 {
			g.ScheduleRevert(mac, d.From, time.Duration(body.RevertAfterSeconds)*time.Second, actor)
		}
		results = append(results, outcome{MAC: mac, OK: true, State: d.To.String()})
	}
	writeJSON(w, map[string]interface{}{
		"action":  body.Action,
		"reason":  body.Reason,
		"results": results,
	})
}

// POST /api/choke/device-thaw — clear enforcement for one or more devices.
// Body: {macs: [...], reason: "..."}. Precise per-device release (unlike the
// per-tier cgroup thaw on the process side).
func (s *Server) handleChokeDeviceThaw(w http.ResponseWriter, r *http.Request) {
	g := s.deviceGatewayOrErr(w)
	if g == nil {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		MACs   []string `json:"macs"`
		MAC    string   `json:"mac"` // convenience single-target form
		Reason string   `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.MAC != "" {
		body.MACs = append(body.MACs, body.MAC)
	}
	if len(body.MACs) == 0 {
		http.Error(w, "no macs provided", http.StatusBadRequest)
		return
	}
	reason := body.Reason
	if reason == "" {
		reason = "operator thaw"
	}
	actor := s.auth.Username()
	type outcome struct {
		MAC   string `json:"mac"`
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}
	results := make([]outcome, 0, len(body.MACs))
	for _, mac := range body.MACs {
		if _, err := g.ThawDevice(r.Context(), mac, actor, reason); err != nil {
			results = append(results, outcome{MAC: mac, OK: false, Error: err.Error()})
			continue
		}
		results = append(results, outcome{MAC: mac, OK: true})
	}
	writeJSON(w, map[string]interface{}{"results": results})
}

// POST /api/choke/device-mode — runtime swap between enforcing and
// detect-only. Body: {enforcing: bool, reason: string}. In detect-only,
// device-jail decisions are audited but the kernel data plane is untouched.
// Returns the prior mode so the caller can detect no-ops.
func (s *Server) handleChokeDeviceMode(w http.ResponseWriter, r *http.Request) {
	g := s.deviceGatewayOrErr(w)
	if g == nil {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Enforcing bool   `json:"enforcing"`
		Reason    string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	prev := g.SetEnforcing(body.Enforcing, s.auth.Username(), body.Reason)
	writeJSON(w, map[string]interface{}{"mode": g.Mode(), "previous": prev})
}

// POST /api/choke/device-kill-switch — body: {on: bool}. Global stop for
// device enforcement (decisions still audited).
func (s *Server) handleChokeDeviceKillSwitch(w http.ResponseWriter, r *http.Request) {
	g := s.deviceGatewayOrErr(w)
	if g == nil {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		On bool `json:"on"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	prev := g.SetKillSwitch(body.On)
	writeJSON(w, map[string]interface{}{"engaged": body.On, "previous": prev})
}
