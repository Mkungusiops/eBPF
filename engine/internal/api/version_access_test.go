package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// /api/version is the one endpoint whose job is answering "what is deployed?",
// and it required a session — so verifying a deploy meant md5-ing binaries over
// SSH. It is now readable without a login, but only from the box itself.
//
// The predicate itself is tested in internal/edge. What matters here is that
// the exemption is scoped to exactly one path: widening it silently is how an
// endpoint that reads tenant data ends up unauthenticated.
func TestExemptionIsScopedToVersionOnly(t *testing.T) {
	a := &Auth{cookie: "sess"}
	reached := false
	h := a.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	call := func(path string, proxied bool) bool {
		reached = false
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.RemoteAddr = "127.0.0.1:54321"
		if proxied {
			r.Header.Set("X-Forwarded-Proto", "https")
		}
		h.ServeHTTP(httptest.NewRecorder(), r)
		return reached
	}

	for _, path := range []string{"/api/alerts", "/api/choke/state", "/api/events", "/api/decisions", "/"} {
		if call(path, false) {
			t.Errorf("%s passed the guard unauthenticated from loopback", path)
		}
	}
	if !call("/api/version", false) {
		t.Error("/api/version was blocked for a local unproxied request")
	}
	if call("/api/version", true) {
		t.Error("/api/version passed the guard for a request that came through the proxy")
	}
}
