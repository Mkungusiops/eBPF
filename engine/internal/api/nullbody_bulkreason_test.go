package api

import (
	"net/http"
	"strings"
	"testing"
)

// The other half of "silence is not an instruction": a body that DOES name an
// intent, and leaves out the statement of why.
//
// /api/choke/manual has always refused an unjustified quarantine or sever
// (requireReasonForDestructive), and so does the control plane's bulk handler.
// /api/choke/bulk-manual did not — so the one endpoint that quarantines or
// SIGKILLs a whole selection in a single request was also the only way to reach
// those two rungs with an empty audit reason, which is precisely the row an
// incident review goes looking for. The console's bulk confirm is reason-gated,
// so nothing it can send is refused here; a direct API caller was the hole.
func TestNullBodyBulkManualRequiresAReasonForDestructiveRungs(t *testing.T) {
	body := func(action, reason string) string {
		return `{"targets":[{"exec_id":"nullbody-bulk-1"},{"exec_id":"nullbody-bulk-2"}],` +
			`"action":"` + action + `","reason":"` + reason + `"}`
	}
	bulk := nullbodyWriteRoutes()[6] // bulk-manual

	for _, action := range []string{"quarantine", "sever"} {
		t.Run(action+"/no reason", func(t *testing.T) {
			s, st, thaws := nullbodyServer(t)
			before := nullbodySnapshot(t, s, st, thaws)

			rec := nullbodyCall(t, s, bulk, body(action, ""))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: a %s across a selection may not be recorded "+
					"with no statement of why; got %q", rec.Code, action, strings.TrimSpace(rec.Body.String()))
			}
			if after := nullbodySnapshot(t, s, st, thaws); after != before {
				t.Fatalf("a refused bulk %s still changed state: %+v -> %+v", action, before, after)
			}
		})

		t.Run(action+"/reason stated", func(t *testing.T) {
			s, _, _ := nullbodyServer(t)
			rec := nullbodyCall(t, s, bulk, body(action, "incident 4412, host is beaconing"))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 for a justified bulk %s: %q",
					rec.Code, action, strings.TrimSpace(rec.Body.String()))
			}
		})
	}

	// The reversible rungs stay frictionless, exactly as on the single-target
	// path: this gate is about the two actions an audit asks about, and
	// widening it would push operators toward not containing at all.
	t.Run("throttle needs no reason", func(t *testing.T) {
		s, _, _ := nullbodyServer(t)
		rec := nullbodyCall(t, s, bulk, body("throttle", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: a throttle is reversible and must stay frictionless: %q",
				rec.Code, strings.TrimSpace(rec.Body.String()))
		}
	})
}
