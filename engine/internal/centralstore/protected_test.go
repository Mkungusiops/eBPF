package centralstore

import (
	"strings"
	"testing"
)

// Validation is the whole defence here. Both rejected forms fail SILENTLY in
// the agent — an exact-match miss and an unparseable address both leave the
// operator believing something is protected when nothing is.

func TestProtectedRejectsEntriesThatWouldProtectNothing(t *testing.T) {
	cases := []struct {
		name string
		in   Protected
		want string
	}{
		{"bare binary name", Protected{Kind: KindBinary, Value: "sshd", Reason: "login path"}, "absolute path"},
		{"empty binary", Protected{Kind: KindBinary, Value: "  ", Reason: "login path"}, "needs a path"},
		{"not a MAC", Protected{Kind: KindMAC, Value: "the uplink", Reason: "top of rack"}, "not a MAC"},
		{"unknown kind", Protected{Kind: "ip", Value: "10.0.0.1", Reason: "gateway"}, "kind must be"},
		{"no reason", Protected{Kind: KindBinary, Value: "/usr/bin/x", Reason: "hm"}, "needs a reason"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.in.Validate()
			if err == nil {
				t.Fatalf("accepted %+v, which would protect nothing", tc.in)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not explain the problem (want %q)", err, tc.want)
			}
		})
	}
}

func TestProtectedAcceptsTheFormsTheAgentCanApply(t *testing.T) {
	ok := []Protected{
		{Kind: KindBinary, Value: "/opt/monitoring/agent", Reason: "must never be contained"},
		{Kind: KindMAC, Value: "0a:1b:2c:3d:4e:5f", Reason: "top-of-rack uplink"},
		{Kind: KindMAC, Value: "0A-1B-2C-3D-4E-5F", Reason: "same address, hyphenated"},
	}
	for _, p := range ok {
		if err := p.Validate(); err != nil {
			t.Fatalf("rejected a form the agent accepts: %+v -> %v", p, err)
		}
	}
}
