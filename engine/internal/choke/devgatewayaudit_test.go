package choke

import (
	"strings"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// The device plane's two widest toggles, and whether an incident review can
// find them.
//
// Jailing ONE device wrote a hash-chained row. Halting device enforcement
// altogether (SetKillSwitch) and dropping the whole network plane to
// detect-only (SetEnforcing) wrote a log.Printf and nothing else — so on this
// plane the two actions with the widest blast radius were the two with no
// audit trail, while the process gateway recorded both through
// AuditConfigChange. /api/verify-chain covered neither, because there was no
// row to cover.

// devAuditRows returns the config rows this gateway wrote, in order. The
// per-device containment rows are filtered out: they were never the gap, and a
// test that counted both could pass on a jail row while the toggle stayed
// silent.
func devAuditRows(t *testing.T, st *store.Store) []store.Decision {
	t.Helper()
	rows, err := st.RecentDecisions(200)
	if err != nil {
		t.Fatalf("read decisions: %v", err)
	}
	out := make([]store.Decision, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- { // RecentDecisions is newest-first
		if strings.HasPrefix(rows[i].ExecID, "config:") {
			out = append(out, rows[i])
		}
	}
	return out
}

// A device kill-switch thrown by the signed-command path has no operator to
// name — the applier passes none — and that is exactly why the row must still
// exist: an unattributed halt is the one a review is least able to reconstruct
// from anything else.
func TestDeviceKillSwitchRecordsEvenWhenUnattributed(t *testing.T) {
	gw, _, st := newTestDeviceGateway(t)

	gw.SetKillSwitch(true)

	rows := devAuditRows(t, st)
	if len(rows) != 1 {
		t.Fatalf("config audit rows = %d, want 1 for an unattributed halt", len(rows))
	}
	if rows[0].Actor != "" {
		t.Fatalf("actor = %q, want empty: inventing a name for a caller that gave none would put "+
			"words in an operator's mouth in an audit chain", rows[0].Actor)
	}
}

func TestDeviceModeChangeWritesAChainedAuditRow(t *testing.T) {
	gw, _, st := newTestDeviceGateway(t) // starts enforcing

	if prev := gw.SetEnforcing(false, "op-adanian", "staging a new device policy"); prev != "enforcing" {
		t.Fatalf("previous mode = %q, want enforcing", prev)
	}

	rows := devAuditRows(t, st)
	if len(rows) != 1 {
		t.Fatalf("config audit rows = %d, want 1 — disarming this host's network plane must not "+
			"be recoverable only from a log line", len(rows))
	}
	got := rows[0]
	if got.Actor != "op-adanian" || !strings.Contains(got.Reason, "staging a new device policy") {
		t.Fatalf("row = %+v, want the operator and their reason", got)
	}
	if got.FromState != "enforcing" || got.ToState != "detect-only" {
		t.Fatalf("transition = %q -> %q, want enforcing -> detect-only", got.FromState, got.ToState)
	}
	if res, err := st.VerifyDecisionChain(); err != nil || !res.OK {
		t.Fatalf("chain = %+v err = %v, want a verifiable row", res, err)
	}
}

func TestDeviceKillSwitchWritesAChainedAuditRow(t *testing.T) {
	gw, _, st := newTestDeviceGateway(t)

	if prev := gw.SetKillSwitchBy(true, "op-adanian", "ransomware canary tripped; halting the device plane"); prev {
		t.Fatal("the kill-switch reported itself already engaged")
	}

	rows := devAuditRows(t, st)
	if len(rows) != 1 {
		t.Fatalf("config audit rows = %d, want 1 — halting every device containment on this "+
			"host must leave a record an incident review can read", len(rows))
	}
	got := rows[0]
	if got.Actor != "op-adanian" {
		t.Fatalf("actor = %q, want the operator who threw it", got.Actor)
	}
	if !strings.Contains(got.Reason, "ransomware canary") {
		t.Fatalf("reason = %q, want the operator's own justification", got.Reason)
	}
	if got.FromState != "released" || got.ToState != "engaged" {
		t.Fatalf("transition = %q -> %q, want released -> engaged: a row that does not say which "+
			"way the switch moved cannot answer the question it exists for", got.FromState, got.ToState)
	}
	if !strings.Contains(got.ExecID, "device") || !strings.Contains(got.Action, "kill-switch") {
		t.Fatalf("exec_id/action = %q/%q — the row does not identify itself as the DEVICE "+
			"kill-switch, so it is indistinguishable from the process plane's", got.ExecID, got.Action)
	}
	// Evidence, not decoration: actor and reason are hashed into the chain, so
	// a row cannot be re-attributed after the fact.
	res, err := st.VerifyDecisionChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK || res.Total != 1 {
		t.Fatalf("chain = %+v, want one verifiable row", res)
	}
}

// Re-engaging a switch that is already engaged changed nothing, and rows for
// changes that did not happen are how a ledger stops being evidence.
func TestDeviceTogglesRecordOnlyRealTransitions(t *testing.T) {
	gw, _, st := newTestDeviceGateway(t)

	gw.SetKillSwitchBy(true, "op", "engage")
	gw.SetKillSwitchBy(true, "op", "engage again")
	gw.SetEnforcing(false, "op", "staging device policy")
	gw.SetEnforcing(false, "op", "staging device policy again")

	if rows := devAuditRows(t, st); len(rows) != 2 {
		t.Fatalf("config audit rows = %d, want 2 — a no-op toggle wrote a row for a change that "+
			"never happened", len(rows))
	}
}

// The mode row names the ENFORCING FLAG's transition and says which wider stop
// is masking it. Mode() folds the stops in, so a flip made while the
// kill-switch is engaged reads "kill-switched -> kill-switched" — a row that
// records an arming as though nothing happened.
func TestDeviceModeRowSurvivesAMaskingKillSwitch(t *testing.T) {
	gw, _, st := newTestDeviceGateway(t)
	gw.SetKillSwitchBy(true, "op", "halt everything")

	gw.SetEnforcing(false, "op", "and disarm the plane while it is halted")

	rows := devAuditRows(t, st)
	if len(rows) != 2 {
		t.Fatalf("config audit rows = %d, want 2 (the halt and the mode change)", len(rows))
	}
	mode := rows[1]
	if mode.FromState == mode.ToState {
		t.Fatalf("transition = %q -> %q: the kill-switch masked the mode strings, so the row "+
			"records a change that reads as no change", mode.FromState, mode.ToState)
	}
	if !strings.Contains(mode.ToState, "kill-switch") {
		t.Fatalf("to_state = %q — the row claims the plane is in a posture the engaged "+
			"kill-switch overrides", mode.ToState)
	}
}
