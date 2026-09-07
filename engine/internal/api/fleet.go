package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/fleetprobe"
)

// FleetPeer is one entry from the hosts file: a friendly name and a base
// URL. The local engine itself is also represented as a peer so the fleet
// view shows all N hosts uniformly (the operator's "self" host is not
// special-cased in the UI).
type FleetPeer struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Fleet drives fan-out HTTP calls across peer engines. It loads peers from
// a hosts file (chokectl.hosts format), reuses one bcrypt-validated
// session cookie per peer, and refreshes cookies on 401.
//
// Auth model is intentionally simple for Tier 1: the local engine holds the
// same admin credentials that chokectl uses, and presents them to peers on
// behalf of the logged-in operator. The audit chain on each peer captures
// who-did-what — the per-peer hash chain is the tamper-evident receipt.
type Fleet struct {
	hostsFile string
	user      string
	pass      string
	client    *http.Client

	mu    sync.Mutex
	peers []FleetPeer
	// peer name -> the pair a peer's middleware requires. The CSRF half used to
	// be discarded at login, so every fleet WRITE (preset, thresholds, thaw,
	// device-jail — and the kill-switch, the emergency stop) was rejected 403 by
	// the peer and no test covered it.
	cookies map[string]peerSession
	loaded  time.Time
}

// SetFleet hands the Fleet pointer to the server. Wired from main(); kept
// separate from NewServer so the listener can start before fleet config is
// resolved.
func (s *Server) SetFleet(f *Fleet) { s.fleet = f }

// NewFleet constructs a Fleet from a hosts-file path and shared credentials.
// An empty hostsFile disables the feature; the registered handlers will
// 503 in that case so the UI degrades gracefully.
func NewFleet(hostsFile, user, pass string) *Fleet {
	return &Fleet{
		hostsFile: hostsFile,
		user:      user,
		pass:      pass,
		client:    &http.Client{Timeout: 6 * time.Second},
		cookies:   make(map[string]peerSession),
	}
}

// Enabled reports whether a hosts file was configured.
func (f *Fleet) Enabled() bool { return f != nil && f.hostsFile != "" }

// Peers returns the parsed list, reloading when the file mtime changes or
// the cache is older than 30s. Errors are surfaced so the UI can show a
// banner instead of silently empty results.
func (f *Fleet) Peers() ([]FleetPeer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if time.Since(f.loaded) < 30*time.Second && len(f.peers) > 0 {
		return f.peers, nil
	}
	peers, err := parseHostsFile(f.hostsFile)
	if err != nil {
		return nil, err
	}
	f.peers = peers
	f.loaded = time.Now()
	return peers, nil
}

func parseHostsFile(path string) ([]FleetPeer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read hosts file %q: %w", path, err)
	}
	var out []FleetPeer
	for _, raw := range strings.Split(string(b), "\n") {
		line := raw
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name, base := fields[0], fields[1]
		if _, err := url.Parse(base); err != nil {
			continue
		}
		out = append(out, FleetPeer{Name: name, URL: strings.TrimRight(base, "/")})
	}
	return out, nil
}

// peerLogin establishes a session for one peer and caches the cookie.
// Called lazily before any peer call and again after a 401.
func (f *Fleet) peerLogin(p FleetPeer) (peerSession, error) {
	form := url.Values{}
	form.Set("user", f.user)
	form.Set("pass", f.pass)
	req, err := http.NewRequest(http.MethodPost, p.URL+"/api/login", strings.NewReader(form.Encode()))
	if err != nil {
		return peerSession{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Don't follow the 303 redirect to /; we just want the Set-Cookie.
	noRedir := *f.client
	noRedir.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := noRedir.Do(req)
	if err != nil {
		return peerSession{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		return peerSession{}, fmt.Errorf("peer login failed: %s", resp.Status)
	}
	var sess peerSession
	for _, c := range resp.Cookies() {
		switch c.Name {
		case "soc_session":
			sess.Cookie = c.Value
		case "csrf_token":
			// Required by the peer on every unsafe /api/ method; dropping it
			// here is what made fleet writes 403.
			sess.CSRF = c.Value
		}
	}
	if sess.Cookie == "" {
		return peerSession{}, errors.New("peer login: no session cookie")
	}
	return sess, nil
}

// peerSession is what one peer's auth middleware demands: the session cookie,
// plus the CSRF token that unsafe /api/ methods must echo back as a header.
type peerSession struct {
	Cookie string
	CSRF   string
}

func (f *Fleet) sessionFor(p FleetPeer) (peerSession, error) {
	f.mu.Lock()
	sess, ok := f.cookies[p.Name]
	f.mu.Unlock()
	if ok && sess.Cookie != "" {
		return sess, nil
	}
	sess, err := f.peerLogin(p)
	if err != nil {
		return peerSession{}, err
	}
	f.mu.Lock()
	f.cookies[p.Name] = sess
	f.mu.Unlock()
	return sess, nil
}

func (f *Fleet) invalidate(name string) {
	f.mu.Lock()
	delete(f.cookies, name)
	f.mu.Unlock()
}

// peerCall performs one HTTP call to one peer with auto-retry on 401.
// Returns the raw response body and the HTTP status code.
func (f *Fleet) peerCall(p FleetPeer, method, path string, body []byte) ([]byte, int, error) {
	doOnce := func() (*http.Response, error) {
		sess, err := f.sessionFor(p)
		if err != nil {
			return nil, err
		}
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequest(method, p.URL+path, rdr)
		if err != nil {
			return nil, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.AddCookie(&http.Cookie{Name: "soc_session", Value: sess.Cookie})
		// The peer compares this against the CSRF embedded in the session
		// cookie, so it must be sent on every unsafe method or the write is
		// refused before it reaches a handler.
		if isUnsafeMethod(method) {
			req.Header.Set("X-CSRF-Token", sess.CSRF)
		}
		return f.client.Do(req)
	}
	resp, err := doOnce()
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		f.invalidate(p.Name)
		// bodyclose cannot see that the deferred Close below covers this
		// reassigned response; the previous body is closed on the line above.
		resp, err = doOnce() //nolint:bodyclose
		if err != nil {
			return nil, 0, err
		}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b, resp.StatusCode, nil
}

// hostResult is the per-peer envelope returned to the UI for every fanout
// call. Stable shape: { name, url, ok, status, data | error }.
type hostResult struct {
	Name   string          `json:"name"`
	URL    string          `json:"url"`
	OK     bool            `json:"ok"`
	Status int             `json:"status,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// fanout calls path on every peer in parallel and returns a slice of
// hostResult preserving hosts-file order. Method "" means GET.
//
// This is the READ path. Reads deliberately keep reaching every peer: asking
// all hosts what their state is answers a question, it does not change one, so
// there is no blast radius to narrow. WRITES go through fanoutTo with the peer
// subset resolveTargets worked out from the request's "targets" key — that is
// where the split between "who am I asking" and "who am I changing" is made.
func (f *Fleet) fanout(method, path string, body []byte) ([]hostResult, error) {
	peers, err := f.Peers()
	if err != nil {
		return nil, err
	}
	return f.fanoutTo(peers, method, path, body), nil
}

// fanoutTo calls path on exactly the peers it is handed, in parallel, keeping
// their order in the returned slice. Callers pass hosts-file order, so the
// per-host list the console renders lines up with the table it was chosen from.
func (f *Fleet) fanoutTo(peers []FleetPeer, method, path string, body []byte) []hostResult {
	if method == "" {
		method = http.MethodGet
	}
	results := make([]hostResult, len(peers))
	var wg sync.WaitGroup
	for i, p := range peers {
		wg.Add(1)
		go func(i int, p FleetPeer) {
			defer wg.Done()
			results[i] = hostResult{Name: p.Name, URL: p.URL}
			b, status, err := f.peerCall(p, method, path, body)
			results[i].Status = status
			if err != nil {
				results[i].Error = err.Error()
				return
			}
			if status >= 400 {
				results[i].Error = fmt.Sprintf("HTTP %d: %s", status, truncate(string(b), 200))
				return
			}
			if len(b) > 0 && (b[0] == '{' || b[0] == '[') {
				results[i].Data = json.RawMessage(b)
			} else {
				results[i].Data = json.RawMessage(`null`)
			}
			results[i].OK = true
		}(i, p)
	}
	wg.Wait()
	return results
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ─────────── write targeting ───────────────────────────────────────────

// targetSelection is the outcome of reading a write's "targets" key: the peers
// the write may touch, and the body to forward to each of them.
type targetSelection struct {
	Peers []FleetPeer
	// Forward is the request body with "targets" removed. That key addresses
	// the fan-out itself, not the peer's handler, so it must not travel onward.
	Forward []byte
}

// targetError refuses a write whole, before any peer is called. Unknown holds
// the names that did not resolve so the console can say which ones it was.
type targetError struct {
	Message string
	Unknown []string
}

// resolveTargets decides which peers a fleet WRITE is allowed to reach.
//
// The console's host selection used to be inert: every write called Peers() and
// forwarded the body verbatim, so ticking one host, reading "Writes target 1
// selected host" and pressing Containment contained the entire fleet. The rules
// below are exactly what the rail claims on screen:
//
//	a JSON object with no "targets" key -> every peer ("All hosts")
//	"targets": null -> every peer, said out loud; what the console sends for
//	                   "All hosts"
//	["a","b"]       -> those peers and no others
//	[]              -> 400. "I have not picked a host yet" must never widen
//	                   into an estate-wide write by silent degradation.
//	an unknown name -> 400 naming it, with nothing dispatched: a write whose
//	                   target set was misunderstood must not half-apply and
//	                   leave the operator believing the fleet is uniform.
//
// Everything that is not a JSON object is refused 400 as well, and that is the
// whole of that class: an empty body, a whitespace-only body, a literal `null`,
// a JSON array, a string, a number, a bool, a truncated object. Only a JSON
// object can carry a "targets" key at all, so anything else is a write whose
// blast radius cannot be checked — and the previous "unset means everybody"
// default silently turned each of those into the estate-wide write this
// function exists to prevent. `null` was the sharpest edge: it decodes into a
// map without error, so it read as "no targets key present" and fanned out,
// while on the peer side it decodes into the handler's body struct as all zero
// values — POST /api/fleet/kill-switch with `null` disengaged enforcement on
// every host in the file, with an empty audit reason, from a body that says
// nothing. A body that names neither hosts nor an intent is not an estate-wide
// instruction; it is not an instruction.
//
// Validation runs before any peer call because there is no unwinding a preset
// that already landed on three boxes.
func resolveTargets(peers []FleetPeer, body []byte) (targetSelection, *targetError) {
	if len(bytes.TrimSpace(body)) == 0 {
		return targetSelection{}, &targetError{
			Message: "empty request body: a fleet write must be a JSON object; " +
				`send "targets":null to write to every host`,
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		// A body that is not a JSON object cannot be checked for a target set,
		// and forwarding it to every peer is the estate-wide write this
		// function exists to prevent. Refuse it here instead.
		//
		// This is a DELIBERATE behaviour change beyond the targeting defect,
		// and it is documented as the 400 on these paths in
		// docs/api/openapi.yaml. Such a body used to reach every peer and come
		// back as an all-failed per-host list inside a 200 envelope. That
		// envelope cannot tell an operator whether the write was scoped the way
		// they intended — it only says everybody said no — so an unreadable
		// body is now rejected whole, before any peer is called.
		return targetSelection{}, &targetError{Message: "invalid JSON body: " + err.Error()}
	}
	if fields == nil {
		// A literal `null` unmarshals into a map with err == nil and leaves the
		// map NIL, so every key lookup below would report "absent" and the write
		// would fan out to the whole hosts file. It is JSON, but it is not an
		// object, and it is refused on exactly the same ground as an array.
		return targetSelection{}, &targetError{
			Message: `a fleet write body must be a JSON object; a literal "null" ` +
				`names no hosts and asks for nothing`,
		}
	}
	raw, present := fields["targets"]
	if !present {
		return targetSelection{Peers: peers, Forward: body}, nil
	}
	delete(fields, "targets")
	forward, err := json.Marshal(fields)
	if err != nil {
		return targetSelection{}, &targetError{Message: "invalid JSON body: " + err.Error()}
	}

	var names []string
	if err := json.Unmarshal(raw, &names); err != nil {
		return targetSelection{}, &targetError{Message: `"targets" must be null or an array of host names`}
	}
	if names == nil {
		// Explicit null is the estate-wide write, same as omitting the key.
		return targetSelection{Peers: peers, Forward: forward}, nil
	}
	if len(names) == 0 {
		return targetSelection{}, &targetError{
			Message: `"targets" was an empty list: name the hosts to write to, or send null to write to every host`,
		}
	}

	known := make(map[string]bool, len(peers))
	for _, p := range peers {
		known[p.Name] = true
	}
	wanted := make(map[string]bool, len(names))
	var unknown []string
	for _, n := range names {
		name := strings.TrimSpace(n)
		if !known[name] {
			unknown = append(unknown, n)
			continue
		}
		wanted[name] = true
	}
	if len(unknown) > 0 {
		return targetSelection{}, &targetError{
			Message: "unknown fleet host(s): " + strings.Join(unknown, ", "),
			Unknown: unknown,
		}
	}

	// Hosts-file order, deduplicated: the response's per-host list is what the
	// console reconciles against its own table.
	selected := make([]FleetPeer, 0, len(wanted))
	for _, p := range peers {
		if wanted[p.Name] {
			selected = append(selected, p)
		}
	}
	return targetSelection{Peers: selected, Forward: forward}, nil
}

// ─────────── HTTP handlers ─────────────────────────────────────────────

// handleFleetConsole serves the embedded HTML.
func (s *Server) handleFleetConsole(w http.ResponseWriter, r *http.Request) {
	if s.serveEmbeddedWebPage(w, "fleet.html") {
		return
	}
	serveMissingEmbeddedWeb(w)
}

// requireFleet 503s when the feature is not configured. Centralises the
// check so each handler stays a one-liner.
func (s *Server) requireFleet(w http.ResponseWriter) *Fleet {
	if s.fleet == nil || !s.fleet.Enabled() {
		http.Error(w, "fleet mode not enabled (start engine with --fleet-hosts=PATH)", http.StatusServiceUnavailable)
		return nil
	}
	return s.fleet
}

func (s *Server) handleFleetHosts(w http.ResponseWriter, r *http.Request) {
	fl := s.requireFleet(w)
	if fl == nil {
		return
	}
	peers, err := fl.Peers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"hosts": peers})
}

// fanoutJSON is the shared body for read-only fan-outs that proxy to a
// per-peer endpoint and return the {hosts:[…]} envelope.
func (s *Server) fanoutJSON(w http.ResponseWriter, method, path string, body []byte) {
	fl := s.requireFleet(w)
	if fl == nil {
		return
	}
	results, err := fl.fanout(method, path, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"hosts": results})
}

// fanoutWriteJSON is the shared body for fleet WRITES. It differs from
// fanoutJSON in one way that matters: the peer set is whatever the request's
// "targets" key resolved to, not the whole hosts file. Everything is validated
// before the first peer call, so a rejected target set applies nowhere.
func (s *Server) fanoutWriteJSON(w http.ResponseWriter, method, path string, body []byte) {
	fl := s.requireFleet(w)
	if fl == nil {
		return
	}
	peers, err := fl.Peers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sel, terr := resolveTargets(peers, body)
	if terr != nil {
		out := map[string]interface{}{"error": terr.Message}
		if len(terr.Unknown) > 0 {
			out["unknown"] = terr.Unknown
		}
		writeJSONStatus(w, http.StatusBadRequest, out)
		return
	}
	writeJSON(w, map[string]interface{}{
		"hosts": fl.fanoutTo(sel.Peers, method, path, sel.Forward),
	})
}

func (s *Server) handleFleetState(w http.ResponseWriter, r *http.Request) {
	s.fanoutJSON(w, http.MethodGet, "/api/choke/state", nil)
}

func (s *Server) handleFleetCgroups(w http.ResponseWriter, r *http.Request) {
	s.fanoutJSON(w, http.MethodGet, "/api/choke/cgroups", nil)
}

func (s *Server) handleFleetDecisions(w http.ResponseWriter, r *http.Request) {
	limit := r.URL.Query().Get("limit")
	if limit == "" {
		limit = "50"
	}
	s.fanoutJSON(w, http.MethodGet, "/api/decisions?limit="+url.QueryEscape(limit), nil)
}

func (s *Server) handleFleetAlerts(w http.ResponseWriter, r *http.Request) {
	s.fanoutJSON(w, http.MethodGet, "/api/alerts", nil)
}

// readBody is a defensive wrapper that caps the read at 64KiB. Fleet write
// payloads are tiny (presets, threshold tuples, kill-switch toggles).
func readBody(r *http.Request) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, 64*1024))
}

// handleFleetPreset applies a choke preset across the targeted peers.
//
// Body: a JSON object — the peer's own payload, plus an optional "targets" list
// naming the hosts the write may reach. Absent or null "targets" means every
// peer in the hosts file (the estate-wide write); a named list means exactly
// those peers and no others. An empty list, a name that is not in the hosts
// file, or a body that is not a JSON object — an empty or whitespace-only body,
// a literal null, an array, a string, a number, a truncated object — is refused
// 400 with {error, unknown[]} and nothing dispatched, because there is no
// unwinding a write that already landed. The "targets" key addresses this
// fan-out, not the peer, so it is stripped before the request is forwarded.
// See resolveTargets.
func (s *Server) handleFleetPreset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := readBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.fanoutWriteJSON(w, http.MethodPost, "/api/choke/preset", body)
}

// handleFleetThresholds sets the choke ladder across the targeted peers.
//
// Body: a JSON object — the peer's own payload, plus an optional "targets" list
// naming the hosts the write may reach. Absent or null "targets" means every
// peer in the hosts file (the estate-wide write); a named list means exactly
// those peers and no others. An empty list, a name that is not in the hosts
// file, or a body that is not a JSON object — an empty or whitespace-only body,
// a literal null, an array, a string, a number, a truncated object — is refused
// 400 with {error, unknown[]} and nothing dispatched, because there is no
// unwinding a write that already landed. The "targets" key addresses this
// fan-out, not the peer, so it is stripped before the request is forwarded.
// See resolveTargets.
func (s *Server) handleFleetThresholds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := readBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.fanoutWriteJSON(w, http.MethodPut, "/api/choke/thresholds", body)
}

// handleFleetKillSwitch halts (or resumes) enforcement across the targeted
// peers — the emergency stop. Targeting matters here as much as it does for
// containment: a halt on two named hosts and a halt on the estate are
// different acts, and the console distinguishes them on screen.
//
// Body: a JSON object — the peer's own payload, plus an optional "targets" list
// naming the hosts the write may reach. Absent or null "targets" means every
// peer in the hosts file (the estate-wide write); a named list means exactly
// those peers and no others. An empty list, a name that is not in the hosts
// file, or a body that is not a JSON object — an empty or whitespace-only body,
// a literal null, an array, a string, a number, a truncated object — is refused
// 400 with {error, unknown[]} and nothing dispatched, because there is no
// unwinding a write that already landed. The "targets" key addresses this
// fan-out, not the peer, so it is stripped before the request is forwarded.
// See resolveTargets.
func (s *Server) handleFleetKillSwitch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := readBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.fanoutWriteJSON(w, http.MethodPost, "/api/choke/kill-switch", body)
}

// handleFleetThaw releases a choke across the targeted peers.
//
// Body: a JSON object — the peer's own payload, plus an optional "targets" list
// naming the hosts the write may reach. Absent or null "targets" means every
// peer in the hosts file (the estate-wide write); a named list means exactly
// those peers and no others. An empty list, a name that is not in the hosts
// file, or a body that is not a JSON object — an empty or whitespace-only body,
// a literal null, an array, a string, a number, a truncated object — is refused
// 400 with {error, unknown[]} and nothing dispatched, because there is no
// unwinding a write that already landed. The "targets" key addresses this
// fan-out, not the peer, so it is stripped before the request is forwarded.
// See resolveTargets.
func (s *Server) handleFleetThaw(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := readBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.fanoutWriteJSON(w, http.MethodPost, "/api/choke/thaw", body)
}

// handleFleetProbe answers "are these peers up?" on behalf of the browser.
//
// Deliberately NOT behind requireFleet: the hosts file is the fan-out control
// set, whereas this serves the console's ad-hoc peer directory, which is
// useful precisely on engines that have no hosts file configured. It performs
// no fan-out and carries no credentials, so it grants nothing the operator's
// session did not already imply.
func (s *Server) handleFleetProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := readBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req struct {
		URLs []string `json:"urls"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]interface{}{
		"hosts": fleetprobe.New().Probe(r.Context(), req.URLs),
	})
}

// handleFleetDevices fans the device snapshot out across every gateway so
// one operator sees all LAN devices choked anywhere in the fleet.
func (s *Server) handleFleetDevices(w http.ResponseWriter, r *http.Request) {
	s.fanoutJSON(w, http.MethodGet, "/api/choke/devices", nil)
}

// handleFleetDeviceJail chokes a device by MAC across the targeted gateways. A
// MAC only enforces on the gateway(s) actually in its traffic path; the others
// record the decision and report no-op, which the per-host envelope makes
// visible.
//
// Body: a JSON object — the peer's own payload, plus an optional "targets" list
// naming the hosts the write may reach. Absent or null "targets" means every
// peer in the hosts file (the estate-wide write); a named list means exactly
// those peers and no others. An empty list, a name that is not in the hosts
// file, or a body that is not a JSON object — an empty or whitespace-only body,
// a literal null, an array, a string, a number, a truncated object — is refused
// 400 with {error, unknown[]} and nothing dispatched, because there is no
// unwinding a write that already landed. The "targets" key addresses this
// fan-out, not the peer, so it is stripped before the request is forwarded.
// See resolveTargets.
func (s *Server) handleFleetDeviceJail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := readBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.fanoutWriteJSON(w, http.MethodPost, "/api/choke/device-jail", body)
}
