package main

import "testing"

// TestDisabledChatStoreIsAnUntypedNil pins a Go trap that would convert a clean
// "history is not enabled" 503 into a nil-pointer panic on the first chat
// request.
//
// openChatStore returns the chatstore.Store INTERFACE. If a future edit changes
// the disabled path to return a typed nil — `var p *chatstore.PGStore; return p`
// is the natural way to write it — the interface value is non-nil even though
// the pointer inside it is nil. The handlers' `s.chats == nil` guard then
// passes, and the first method call dereferences nil.
//
// The failure is invisible in review and invisible at startup: it appears the
// first time an operator opens the assistant on a deployment that has no chat
// history, which is precisely the deployment nobody tested.
func TestDisabledChatStoreIsAnUntypedNil(t *testing.T) {
	for _, tc := range []struct{ kind, dsn string }{
		{"sqlite", ""},
		{"sqlite", "postgres://x/y"}, // a DSN present but the wrong backend
		{"postgres", ""},             // postgres asked for, no DSN
		{"", ""},
	} {
		got := openChatStore(tc.kind, tc.dsn)
		if got != nil {
			t.Errorf("openChatStore(%q, %q) returned a non-nil interface (%T). The "+
				"handlers test `chats == nil` to answer 503; a typed nil sails past "+
				"that check and panics on first use.", tc.kind, tc.dsn, got)
		}
	}
}

// TestUnreachablePostgresDisablesChatWithoutKillingTheControlPlane asserts the
// degradation rule: chat history is a convenience, containment is not. A chat
// store that cannot be reached must not stop a SOC from responding to an
// incident, so the failure disables the feature and returns.
func TestUnreachablePostgresDisablesChatWithoutKillingTheControlPlane(t *testing.T) {
	// Port 1 with a 1-connection-attempt DSN: refused fast, no live database
	// needed. If this ever calls log.Fatalf the test binary exits non-zero and
	// the failure is unmissable — which is the point.
	if got := openChatStore("postgres", "postgres://nobody@127.0.0.1:1/none?connect_timeout=1"); got != nil {
		t.Errorf("an unreachable chat database produced a store (%T); it must disable "+
			"the feature", got)
	}
}
