package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// The device kill-switch's audit reason.
//
// Engaging it halts EVERY device containment on this host — including a sever
// an operator pressed themselves — and the endpoint took no reason at all,
// while its neighbour /api/choke/device-mode requires one to arm or disarm the
// same plane. The fleet kill-switch collects a reason in the console and
// carries it on the wire; the device one collected nothing, so the row for
// bypassing the network plane said who and when and never why.
//
// A RELEASE is deliberately still frictionless: refusing to restore
// enforcement for want of a sentence is how a plane stays halted longer than
// anyone intended, which is the same rule device-thaw runs on.

// devConfigRows returns the config-change rows in the ledger, oldest first.
func devConfigRows(t *testing.T, st *store.Store) []store.Decision {
	t.Helper()
	rows, err := st.RecentDecisions(200)
	if err != nil {
		t.Fatalf("read decisions: %v", err)
	}
	out := make([]store.Decision, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- { // newest-first from the store
		if strings.HasPrefix(rows[i].ExecID, "config:") {
			out = append(out, rows[i])
		}
	}
	return out
}

func TestDeviceKillSwitchRefusesAReasonlessEngage(t *testing.T) {
	s, st, _ := nullbodyDevServer(t)

	rec := nullbodyCall(t, s, nullbodyDevRoutes()[0], `{"on":true}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: halting the whole device plane may not be recorded with "+
			"no statement of why; got %q", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if s.deviceGW.KillSwitched() {
		t.Fatal("the refused request engaged the kill-switch anyway")
	}
	if rows := devConfigRows(t, st); len(rows) != 0 {
		t.Fatalf("a refused engage wrote %d audit rows", len(rows))
	}
	// A whitespace reason is the same silence with a space in it.
	if rec := nullbodyCall(t, s, nullbodyDevRoutes()[0], `{"on":true,"reason":"   "}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d for a whitespace-only reason, want 400", rec.Code)
	}
}

func TestDeviceKillSwitchEngageRecordsWhoAndWhy(t *testing.T) {
	s, st, _ := nullbodyDevServer(t)
	s.auth = &Auth{user: "op-adanian"}

	rec := nullbodyCall(t, s, nullbodyDevRoutes()[0],
		`{"on":true,"reason":"IR-4821: enforcement is dropping the recovery job"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a fully stated engage: %q",
			rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if !s.deviceGW.KillSwitched() {
		t.Fatal("the kill-switch is not engaged after an accepted engage")
	}

	rows := devConfigRows(t, st)
	if len(rows) != 1 {
		t.Fatalf("config audit rows = %d, want 1 for the engage", len(rows))
	}
	got := rows[0]
	if got.Actor != "op-adanian" {
		t.Fatalf("actor = %q, want the authenticated operator", got.Actor)
	}
	if !strings.Contains(got.Reason, "IR-4821") {
		t.Fatalf("reason = %q, want the operator's own words", got.Reason)
	}
	if got.FromState != "released" || got.ToState != "engaged" {
		t.Fatalf("transition = %q -> %q, want released -> engaged", got.FromState, got.ToState)
	}
	if res, err := st.VerifyDecisionChain(); err != nil || !res.OK {
		t.Fatalf("chain = %+v err = %v, want a verifiable row", res, err)
	}
}

// The release keeps working with no reason — and the row says that is what
// happened, rather than reading as though someone justified it.
func TestDeviceKillSwitchReleaseNeedsNoReasonButSaysSo(t *testing.T) {
	s, st, _ := nullbodyDevServer(t)
	s.deviceGW.SetKillSwitch(true)

	rec := nullbodyCall(t, s, nullbodyDevRoutes()[0], `{"on":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: restoring enforcement must never be blocked for want of "+
			"a reason; got %q", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if s.deviceGW.KillSwitched() {
		t.Fatal("the kill-switch is still engaged after an explicit release")
	}

	rows := devConfigRows(t, st)
	if len(rows) == 0 {
		t.Fatal("the release wrote no audit row")
	}
	release := rows[len(rows)-1]
	if release.FromState != "engaged" || release.ToState != "released" {
		t.Fatalf("transition = %q -> %q, want engaged -> released", release.FromState, release.ToState)
	}
	if !strings.Contains(release.Reason, "no reason stated") {
		t.Fatalf("audit reason = %q; a release nobody justified must not read as though an "+
			"operator justified it", release.Reason)
	}
}
