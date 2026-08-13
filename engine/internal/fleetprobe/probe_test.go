package fleetprobe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A peer that answers 401 is up — it simply does not know this caller. The old
// browser-side probe treated any non-2xx as DOWN, which is what made a healthy
// engine render as dead in the console. Reachability must not imply authz.
func TestProbeReportsUnauthorizedPeerAsReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
	}))
	defer srv.Close()

	res := New().Probe(context.Background(), []string{srv.URL})
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	if !res[0].Reachable {
		t.Fatalf("401 peer must count as reachable, got %+v", res[0])
	}
	if res[0].Status != http.StatusUnauthorized {
		t.Errorf("want status 401 reported, got %d", res[0].Status)
	}
}

// /healthz is the control plane's unauthenticated liveness route; a peer
// without one must still be probeable via its base URL.
func TestProbeFallsBackToBaseURLWhenNoHealthz(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res := New().Probe(context.Background(), []string{srv.URL})
	if !res[0].Reachable || res[0].Status != http.StatusOK {
		t.Fatalf("want reachable 200 after fallback, got %+v", res[0])
	}
	if len(paths) != 2 || paths[0] != "/healthz" || paths[1] != "/" {
		t.Errorf("want /healthz then / , got %v", paths)
	}
}

// The guard that actually matters: 169.254.169.254 is cloud instance metadata.
// Reaching it would turn the Fleet panel into a path to the host's IAM
// credentials, so it must be refused before any dial.
func TestProbeBlocksLinkLocalMetadataAddress(t *testing.T) {
	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://[fe80::1]:80/",
	} {
		res := New().Probe(context.Background(), []string{target})
		if res[0].Reachable {
			t.Errorf("%s must not be reachable", target)
		}
		if !strings.Contains(res[0].Error, "link-local") {
			t.Errorf("%s: want a link-local refusal, got %q", target, res[0].Error)
		}
	}
}

// Only http(s) may be probed. Without this the endpoint would read local files.
func TestProbeRejectsNonHTTPSchemes(t *testing.T) {
	for _, target := range []string{"file:///etc/shadow", "gopher://x/", "ftp://host/", "/api/whoami", "192.168.1.10:8080"} {
		res := New().Probe(context.Background(), []string{target})
		if res[0].Reachable {
			t.Errorf("%s must not be reachable", target)
		}
		if !strings.Contains(res[0].Error, "blocked target") {
			t.Errorf("%s: want a blocked-target error, got %q", target, res[0].Error)
		}
	}
}

// Private ranges stay probeable on purpose — LAN peers are the feature's whole
// point, so a guard that blocked RFC1918 would break what it protects.
func TestProbeAllowsPrivateAndLoopbackPeers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if host, _, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://")); !net.ParseIP(host).IsLoopback() {
		t.Skipf("httptest did not bind loopback (%s)", host)
	}

	res := New().Probe(context.Background(), []string{srv.URL})
	if !res[0].Reachable {
		t.Fatalf("loopback peer must be probeable, got %+v", res[0])
	}
}

// A dead peer is DOWN with a reason, not a silent blank row.
func TestProbeReportsUnreachablePeer(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().String()
	lis.Close() // nothing is listening now

	res := New().Probe(context.Background(), []string{"http://" + addr})
	if res[0].Reachable {
		t.Fatalf("closed port must not be reachable, got %+v", res[0])
	}
	if res[0].Error == "" {
		t.Error("want a non-empty error explaining the failure")
	}
}

// Results are positional: the UI keys rows off input order.
func TestProbePreservesInputOrderAndCapsTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	targets := []string{"file:///nope", srv.URL, "http://169.254.169.254/"}
	res := New().Probe(context.Background(), targets)
	for i, want := range targets {
		if res[i].URL != want {
			t.Errorf("result %d: want url %q, got %q", i, want, res[i].URL)
		}
	}
	if res[0].Reachable || !res[1].Reachable || res[2].Reachable {
		t.Errorf("reachability did not track the inputs: %+v", res)
	}

	over := make([]string, MaxTargets+10)
	for i := range over {
		over[i] = "http://example.invalid/"
	}
	if got := len(New().Probe(context.Background(), over)); got != MaxTargets {
		t.Errorf("want targets capped at %d, got %d", MaxTargets, got)
	}
}

// The probe must never become a general-purpose fetch proxy: no peer response
// body may reach the caller through the Result.
func TestProbeDoesNotReturnPeerResponseBody(t *testing.T) {
	const secret = "aws-session-token-do-not-exfiltrate"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(secret))
	}))
	defer srv.Close()

	res := New().Probe(context.Background(), []string{srv.URL})
	if strings.Contains(res[0].URL+res[0].Error, secret) {
		t.Fatalf("peer body leaked into the result: %+v", res[0])
	}
}
