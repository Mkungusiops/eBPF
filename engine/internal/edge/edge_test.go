package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func req(remote string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	r.RemoteAddr = remote
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestAllowsLoopbackWithNoProxyHeaders(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:54321", "[::1]:54321"} {
		if !LocalUnproxied(req(addr, nil)) {
			t.Errorf("%s should count as local", addr)
		}
	}
}

// The whole design rests on this one. If it ever passes, build identity is
// public on the internet for both deployments at once.
func TestRejectsProxiedRequests(t *testing.T) {
	for _, h := range proxyHeaders {
		// nginx proxies FROM loopback, so the peer address alone proves nothing.
		if LocalUnproxied(req("127.0.0.1:54321", map[string]string{h: "203.0.113.7"})) {
			t.Errorf("a request carrying %s was treated as local", h)
		}
	}
}

// A caller cannot strip what nginx adds, but they can add their own. Presence
// is disqualifying regardless of value, so a forged loopback value must not
// buy anything.
func TestForgedLoopbackValuesDoNotHelp(t *testing.T) {
	for _, h := range proxyHeaders {
		if LocalUnproxied(req("127.0.0.1:54321", map[string]string{h: "127.0.0.1", "Host": "localhost"})) {
			t.Errorf("a forged %s: 127.0.0.1 was accepted as local", h)
		}
	}
}

func TestRejectsRemotePeers(t *testing.T) {
	for _, addr := range []string{"203.0.113.7:443", "10.0.0.5:8090", "[2001:db8::1]:443"} {
		if LocalUnproxied(req(addr, nil)) {
			t.Errorf("%s should not count as local", addr)
		}
	}
}

// Fail closed on anything unparseable rather than guessing.
func TestRejectsMalformedRemoteAddr(t *testing.T) {
	for _, addr := range []string{"not-an-address", "", "127.0.0.1:notaport:extra"} {
		if LocalUnproxied(req(addr, nil)) {
			t.Errorf("unparseable RemoteAddr %q was treated as local", addr)
		}
	}
}
