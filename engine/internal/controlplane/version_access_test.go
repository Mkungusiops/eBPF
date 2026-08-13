package controlplane

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// /api/version was completely ungated on an internet-facing multi-tenant
// console: revision, dirty flag and build time of an enterprise security
// control plane, readable by anyone. It was live and answering dirty=true
// against a public hostname.
func TestVersionRequiresSessionFromTheEdge(t *testing.T) {
	s := &Server{} // no BFF, no admin token: principal() always fails

	proxied := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	proxied.RemoteAddr = "127.0.0.1:9999" // nginx proxies from loopback
	proxied.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	s.handleVersion(rec, proxied)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — build identity must not be public", rec.Code)
	}
	if body := rec.Body.String(); len(body) > 0 && rec.Code == http.StatusOK {
		t.Errorf("leaked build info to an unauthenticated edge request: %s", body)
	}
}

// ...but an operator on the box can still answer "what is deployed here?"
// without a login, which is the whole point.
func TestVersionReadableLocally(t *testing.T) {
	s := &Server{}

	local := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	local.RemoteAddr = "127.0.0.1:9999"
	rec := httptest.NewRecorder()
	s.handleVersion(rec, local)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a local unproxied request", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Error("empty body")
	}
}
