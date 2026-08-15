package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// remoteIP is the key the login rate limiter buckets on, so anything a caller
// can set is a bypass of the only credential guarding the console.
//
// The deployed nginx uses $proxy_add_x_forwarded_for, which APPENDS its own
// view of the peer to whatever the client sent. Reading the leftmost entry
// therefore read attacker-supplied data, and rotating one header gave unlimited
// bcrypt guesses at a fixed 5/minute budget.
func TestRemoteIPIgnoresClientSuppliedForwardedFor(t *testing.T) {
	for _, tc := range []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{
			name:       "proxied: rightmost entry is the one nginx appended",
			remoteAddr: "127.0.0.1:54321",
			xff:        "1.2.3.4, 203.0.113.9",
			want:       "203.0.113.9",
		},
		{
			name:       "proxied, single entry: nginx saw the client directly",
			remoteAddr: "127.0.0.1:54321",
			xff:        "203.0.113.9",
			want:       "203.0.113.9",
		},
		{
			name:       "forged chain cannot shift the key off the real peer",
			remoteAddr: "127.0.0.1:54321",
			xff:        "evil-1, evil-2, evil-3, 203.0.113.9",
			want:       "203.0.113.9",
		},
		{
			name:       "direct connection: header is ignored entirely",
			remoteAddr: "198.51.100.7:44444",
			xff:        "1.2.3.4",
			want:       "198.51.100.7",
		},
		{
			name:       "no header at all",
			remoteAddr: "198.51.100.7:44444",
			want:       "198.51.100.7",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := remoteIP(r); got != tc.want {
				t.Fatalf("remoteIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// The bucket must not be movable by the caller: N attempts behind one forged
// chain and N behind another have to land in the SAME bucket.
func TestLoginRateLimitCannotBeResetByRotatingTheHeader(t *testing.T) {
	a := &Auth{loginRate: map[string]*rateBucket{}, loginRateLimit: 3}

	req := func(xff string) bool {
		r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
		r.RemoteAddr = "127.0.0.1:54321"
		r.Header.Set("X-Forwarded-For", xff)
		return a.rateAllowed(remoteIP(r))
	}

	// Three attempts exhaust the budget for the real client 203.0.113.9.
	for i := range 3 {
		if !req("attacker-chose-this, 203.0.113.9") {
			t.Fatalf("attempt %d refused while inside the budget", i+1)
		}
	}
	// A fourth, with a completely different forged prefix, must still be refused.
	if req("a-totally-different-forgery, 203.0.113.9") {
		t.Fatal("rotating X-Forwarded-For reset the rate-limit bucket — the limiter is bypassable")
	}
}
