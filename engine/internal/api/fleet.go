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
func (f *Fleet) fanout(method, path string, body []byte) ([]hostResult, error) {
	peers, err := f.Peers()
	if err != nil {
		return nil, err
	}
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
	return results, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
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
	s.fanoutJSON(w, http.MethodPost, "/api/choke/preset", body)
}

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
	s.fanoutJSON(w, http.MethodPut, "/api/choke/thresholds", body)
}

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
	s.fanoutJSON(w, http.MethodPost, "/api/choke/kill-switch", body)
}

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
	s.fanoutJSON(w, http.MethodPost, "/api/choke/thaw", body)
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

// handleFleetDeviceJail chokes a device by MAC across every gateway. A MAC
// only enforces on the gateway(s) actually in its traffic path; the others
// record the decision and report no-op, which the per-host envelope makes
// visible.
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
	s.fanoutJSON(w, http.MethodPost, "/api/choke/device-jail", body)
}
