package controlplane

import "testing"

// The reason requirement is the difference between an audit trail that answers
// "why was this production process killed?" and one that does not. It must be
// enforced on the server, not just in the UI.
func TestRequireReasonForDestructive(t *testing.T) {
	cases := []struct {
		action, reason string
		wantErr        bool
	}{
		{"quarantine", "", true}, // disruptive: freezes the process
		{"sever", "", true},      // terminal: SIGKILL, thaw cannot undo it
		{"sever", "   ", true},   // whitespace is not a justification
		{"quarantine", "IR-4821", false},
		{"sever", "confirmed C2 beacon", false},
		{"throttle", "", false}, // reversible rungs stay frictionless
		{"tarpit", "", false},
		{"thaw", "", false}, // releasing must never be blocked
	}
	for _, c := range cases {
		err := requireReasonForDestructive(c.action, c.reason)
		if (err != nil) != c.wantErr {
			t.Errorf("%s/%q: err=%v wantErr=%v", c.action, c.reason, err, c.wantErr)
		}
	}
}
