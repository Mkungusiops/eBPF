package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Fleet writes fan out to peer engines over HTTP, and every peer's middleware
// requires X-CSRF-Token on unsafe /api/ methods. peerLogin used to discard the
// csrf_token cookie and peerCall never set the header, so EVERY fleet write —
// preset, thresholds, thaw, device-jail, and the fleet-wide KILL-SWITCH, which
// is the emergency stop — was refused 403 before reaching a handler. Nothing
// covered it, so the console reported a failure the operator could not explain.
func TestPeerCallSendsCSRFOnWrites(t *testing.T) {
	var gotCSRF atomic.Value
	gotCSRF.Store("")

	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/login":
			http.SetCookie(w, &http.Cookie{Name: "soc_session", Value: "sess-abc"})
			http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: "csrf-xyz"})
			w.WriteHeader(http.StatusSeeOther)
		default:
			// Mirror the real middleware: refuse an unsafe /api/ call with no
			// matching CSRF header.
			if isUnsafeMethod(r.Method) && strings.HasPrefix(r.URL.Path, "/api/") {
				tok := r.Header.Get("X-CSRF-Token")
				gotCSRF.Store(tok)
				if tok != "csrf-xyz" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer peer.Close()

	f := NewFleet("", "admin", "pw")

	body, code, err := f.peerCall(FleetPeer{Name: "peer-1", URL: peer.URL},
		http.MethodPost, "/api/fleet/kill-switch", []byte(`{"engaged":true}`))
	if err != nil {
		t.Fatalf("peerCall: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("fleet write returned %d (body %s) — the kill-switch fan-out is being refused", code, body)
	}
	if got := gotCSRF.Load().(string); got != "csrf-xyz" {
		t.Fatalf("X-CSRF-Token = %q, want the token issued at peer login", got)
	}
}

// A GET must not need the header, and must still work.
func TestPeerCallOmitsCSRFOnReads(t *testing.T) {
	var sawHeader atomic.Bool
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/login" {
			http.SetCookie(w, &http.Cookie{Name: "soc_session", Value: "sess-abc"})
			http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: "csrf-xyz"})
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		if r.Header.Get("X-CSRF-Token") != "" {
			sawHeader.Store(true)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer peer.Close()

	f := NewFleet("", "admin", "pw")
	if _, code, err := f.peerCall(FleetPeer{Name: "peer-1", URL: peer.URL},
		http.MethodGet, "/api/choke/state", nil); err != nil || code != http.StatusOK {
		t.Fatalf("read fan-out: code=%d err=%v", code, err)
	}
	if sawHeader.Load() {
		t.Error("a CSRF header was sent on a safe method")
	}
}
