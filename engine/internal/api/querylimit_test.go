package api

import (
	"net/http/httptest"
	"testing"
)

// The alerts and events endpoints once hardcoded their row counts and ignored
// ?limit. The console asked for 1000 alerts, silently got 100, and rendered
// them as a complete 24h window — a capped feed that does not announce its cap
// is indistinguishable from a quiet estate. These pin the contract.
func TestQueryLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query string
		def   int
		max   int
		want  int
	}{
		{"absent falls back to the default", "", 200, 2000, 200},
		{"honoured when within bounds", "?limit=1000", 200, 2000, 1000},
		{"clamped to max", "?limit=99999", 200, 2000, 2000},
		{"exactly max is allowed", "?limit=2000", 200, 2000, 2000},
		{"zero is not a limit, use the default", "?limit=0", 200, 2000, 200},
		{"negative is rejected", "?limit=-5", 200, 2000, 200},
		{"garbage is rejected", "?limit=all", 200, 2000, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/alerts"+tc.query, nil)
			if got := queryLimit(r, tc.def, tc.max); got != tc.want {
				t.Fatalf("queryLimit(%q) = %d, want %d", tc.query, got, tc.want)
			}
		})
	}
}
