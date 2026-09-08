package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
)

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
// A body that states no intent — absent, empty, whitespace-only, a literal
// null, or any JSON that is not an object — is refused 400 before a single MAC
// is touched. See decodeWrite in choke.go.
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
	// decodeWrite, not a decoder here: the process plane's writes already
	// express this rule (choke.go), and the whole reason the device plane was
	// the half of the sweep still open is that it carried its own second
	// formulation. A `null` body decodes into this struct with err == nil and
	// every field at its zero value, which on this endpoint means "jail nothing
	// with no reason" — harmless only by accident of the checks below, and the
	// same shape that disarmed the two toggles further down this file.
	if _, err := decodeWrite(r, &body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// An absent action is refused here rather than by requireStated: parseAction
	// already rejects "" and names the four rungs it wanted, which is the more
	// useful refusal. Silence never picks a rung.
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
//
// A body that states no intent — absent, empty, whitespace-only, a literal
// null, or any JSON that is not an object — is refused 400 and nothing is
// released. Naming the MACs is what this endpoint requires; the reason stays
// optional, because a release must never be blocked.
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
	if _, err := decodeWrite(r, &body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.MAC != "" {
		body.MACs = append(body.MACs, body.MAC)
	}
	if len(body.MACs) == 0 {
		http.Error(w, "no macs provided", http.StatusBadRequest)
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		// A named-MAC release stays frictionless on purpose: blocking a release
		// is how a device stays cut off longer than anyone intended, and the
		// process plane's per-target thaw asks for no reason either. What the
		// audit row must not do is read as though a reason WAS given. The
		// console used to substitute the literal "operator thaw" for a blank
		// box; it now omits the field entirely (web/src/features/devices/
		// useDeviceActions.ts), because a sentence nobody typed reads in a
		// tamper-evident row exactly like one an operator wrote. So an empty
		// reason arriving here — from the console or from a direct API call —
		// means the same thing in both cases: nobody stated one. The marker
		// says that in words, rather than letting the row carry a bare "thaw:"
		// a later reader has to interpret.
		reason = "operator thaw (no reason stated)"
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
// detect-only. Body: {enforcing: bool, reason: string}, both REQUIRED. In
// detect-only, device-jail decisions are audited but the kernel data plane is
// untouched. Returns the prior mode so the caller can detect no-ops.
//
// A body that states no intent — absent, empty, whitespace-only, a literal
// null, or any JSON that is not an object — is refused 400, as is an object
// that never names "enforcing" ({}, {"reason":"…"}, {"enforcing":null}). An
// explicit {"enforcing":false} is a legitimate instruction and still disarms
// the plane; that distinction is the whole of the rule.
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
	fields, err := decodeWrite(r, &body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// `enforcing` false DISARMS this host's network plane, and a struct cannot
	// tell that instruction from silence: `null`, `{}` and an object that never
	// names the field all decode to false with a nil error. So POST
	// /api/choke/device-mode with the body `null` dropped the device plane to
	// detect-only — every subsequent device decision audited and none of it
	// reaching the kernel — from a request that asked for nothing.
	if !requireStated(w, fields, "enforcing",
		"true arms this host's device plane, false drops it to detect-only") {
		return
	}
	// SetEnforcing now writes a hash-chained row for this transition, and the
	// reason is the only part of that row an operator supplies. Accepting an
	// empty one would record that the network plane was armed or disarmed with
	// no statement of why — an audit row that answers every question about the
	// change except the one a review asks. The console already makes the
	// operator type one (the confirm dialog is reason-gated), so this refuses
	// nothing the console can send.
	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		http.Error(w, `"reason" is required: arming or disarming the device plane is `+
			"recorded, and the record may not be empty", http.StatusBadRequest)
		return
	}
	prev := g.SetEnforcing(body.Enforcing, s.auth.Username(), reason)
	writeJSON(w, map[string]interface{}{"mode": g.Mode(), "previous": prev})
}

// POST /api/choke/device-kill-switch — body: {on: bool, reason: string}. `on`
// is REQUIRED; `reason` is required to ENGAGE. Global stop for device
// enforcement (decisions still audited).
//
// A body that states no intent — absent, empty, whitespace-only, a literal
// null, or any JSON that is not an object — is refused 400, as is an object
// that never names "on" ({}, {"on":null}). An explicit {"on":false} releases
// the kill-switch and still works: releasing is a real operator act, and
// telling it apart from silence is the point.
//
// The reason is read now because there is somewhere for it to go:
// DeviceGateway.SetKillSwitchBy writes a hash-chained row for the transition
// and hashes the operator's words into it, so this plane finally records what
// handleChokeKillSwitch records for the process plane. Engaging halts every device
// containment on this host — including a sever an operator pressed themselves —
// so, like the quarantine/sever rungs guarded by requireReasonForDestructive
// and like the neighbouring device-mode write, it may not be recorded with an
// empty justification. Releasing is never blocked for want of one: refusing to
// restore enforcement is how a plane stays halted longer than anyone intended.
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
		On     bool   `json:"on"`
		Reason string `json:"reason"`
	}
	fields, err := decodeWrite(r, &body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// The worst instance on this surface. `on` was decoded into a bool and a
	// nil error was treated as a valid request, so `null` — which decodes with
	// err == nil and zero values, unlike an empty body, which at least errored
	// — and `{}` both called SetKillSwitch(false) and DISENGAGED the device
	// kill-switch: the emergency stop an operator had deliberately engaged came
	// back off from a body that named nothing, and nothing recorded it.
	if !requireStated(w, fields, "on",
		"true engages the device kill-switch and halts all device enforcement, false releases it") {
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if body.On && reason == "" {
		http.Error(w, `"reason" is required to engage the device kill-switch: it halts every `+
			"device containment on this host, including one an operator pressed, and the record "+
			"of that may not be empty", http.StatusBadRequest)
		return
	}
	if reason == "" {
		// A release with no reason is accepted, but its row must not read as
		// though someone justified it — the same distinction device-thaw draws
		// a few handlers up.
		reason = "kill-switch released (no reason stated)"
	}
	prev := g.SetKillSwitchBy(body.On, s.auth.Username(), reason)
	writeJSON(w, map[string]interface{}{"engaged": body.On, "previous": prev})
}
