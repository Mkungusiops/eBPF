package tetrabridge

import "testing"

// JoinHostPort borrowed net.JoinHostPort's name while omitting the one rule
// that makes its output parseable: brackets around IPv6.
//
// Without them a loopback health check renders "::1:8090", which nothing
// downstream can split — an address and its port are separated by a colon, and
// so are the groups of an IPv6 address. The console took everything before the
// first colon, got the empty string, and classified localhost as neither
// loopback nor LAN. What is left is "external peer": a health check against
// your own machine, drawn on the correlation graph as an outbound connection.
//
// Latent until curl entered the outbound-connections binary list, which made
// it reachable on every host several times a minute.
func TestJoinHostPortBracketsIPv6(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr string
		port uint32
		want string
	}{
		{"ipv4 keeps its bare form", "10.0.0.5", 443, "10.0.0.5:443"},
		{"ipv6 loopback is bracketed", "::1", 8090, "[::1]:8090"},
		{"ipv6 global is bracketed", "2001:db8::1", 443, "[2001:db8::1]:443"},
		{"link-local is bracketed", "fe80::1", 22, "[fe80::1]:22"},
		{"ipv4-mapped is bracketed, since it contains colons", "::ffff:127.0.0.1", 8090, "[::ffff:127.0.0.1]:8090"},
		{"a zero port omits the port entirely, unbracketed", "::1", 0, "::1"},
		{"a zero port on ipv4 too", "10.0.0.5", 0, "10.0.0.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := JoinHostPort(tc.addr, tc.port); got != tc.want {
				t.Fatalf("JoinHostPort(%q, %d) = %q, want %q", tc.addr, tc.port, got, tc.want)
			}
		})
	}
}
