package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
)

// The control plane and the console agree by FIELD NAME and nothing checked it.
//
// /api/decisions sent seven fields while the wire record carried twenty, and
// the console reads by name: it groups Top Offenders on `binary`, keys tape
// rows on `id` + `exec_id`, routes drill-down through `exec_id` and tracks ack
// on `id`. None were sent. So on the fleet console Top Offenders read
// "0 binaries" beside 39 real decisions, every row keyed to "0-undefined" —
// collapsing selection and ack onto one another — and clicking a row went
// nowhere. Nothing failed; it just quietly did less.
//
// This reads the console's own TypeScript declaration rather than a list
// maintained here, so adding a field to the console forces a decision about
// whether the control plane can supply it.

// engineOnlyDecisionFields are console fields the control plane legitimately
// cannot fill, each for a stated reason. Anything NOT listed here must be sent.
var engineOnlyDecisionFields = map[string]string{
	"prev_hash":          "the chain is verified on the agent; the CP does not hash-chain centrally",
	"hash":               "same",
	"origin_kind":        "SSH origin attribution is resolved on the host that saw the session",
	"origin_ip":          "same",
	"origin_port":        "same",
	"origin_user":        "same",
	"origin_fingerprint": "same",
	"dry_run":            "sent, but omitted from JSON when false",
	"actor":              "sent, but omitted from JSON when empty (an automatic decision)",
}

func tsInterfaceFields(t *testing.T, file, name string, minFields int) []string {
	t.Helper()
	raw, err := os.ReadFile(file) //nolint:gosec // repo-relative test fixture
	if err != nil {
		t.Skipf("console types not found (%v)", err)
	}
	body := regexp.MustCompile(`(?s)export interface ` + name + ` \{(.*?)\n\}`).FindStringSubmatch(string(raw))
	if body == nil {
		t.Fatalf("could not find `export interface %s` in %s — this test has stopped checking anything", name, file)
	}
	field := regexp.MustCompile(`(?m)^\s{2}(\w+)\??:`)
	var out []string
	for _, m := range field.FindAllStringSubmatch(body[1], -1) {
		out = append(out, m[1])
	}
	// A floor per interface, not a global one: BucketEntry legitimately has
	// six fields, and a fixed minimum tuned for Decision reports a correct
	// parse as a broken regex.
	if len(out) < minFields {
		t.Fatalf("parsed only %d fields from %s (want >= %d); the regex has stopped matching and this check is vacuous",
			len(out), name, minFields)
	}
	sort.Strings(out)
	return out
}

func consoleTypesPath(t *testing.T) string {
	t.Helper()
	for _, up := range []string{"../..", "../../..", "../../../.."} {
		p := filepath.Join(up, "web", "src", "features", "choke", "types.ts")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("web/src/features/choke/types.ts not found from this working directory")
	return ""
}

func TestDecisionsEndpointSendsEveryFieldTheConsoleReads(t *testing.T) {
	cs, err := centralstore.Open(t.TempDir() + "/c.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	// Every field populated, so an omission is the handler dropping it rather
	// than the fixture never supplying it.
	rec := &ebpfsocv1.TelemetryRecord{
		DedupKey: "d1",
		Payload: &ebpfsocv1.TelemetryRecord_Decision{Decision: &ebpfsocv1.Decision{
			Id: 42, OccurredAt: timestamppb.New(time.Now().UTC()),
			Action: "sever", FromState: "quarantined", ToState: "severed",
			ExecId: "exec-1", Pid: 4021, Binary: "/usr/bin/curl", Score: 210,
			Reason: "confirmed C2", DryRun: true, Backend: "cgroupv2",
			Outcome: "ok", Actor: "op-adanian",
		}},
	}
	if err := cs.Put(ingest.StampedRecord{TenantID: "acme", AgentID: "a1", Record: rec}); err != nil {
		t.Fatal(err)
	}

	s := &Server{registry: heartbeat.NewRegistry(), auditor: authz.NewMemAuditor()}
	s.cfg.Store = cs
	s.cfg.Logf = func(string, ...any) {}
	s.cfg.AdminToken = "admin-secret"

	req := httptest.NewRequest(http.MethodGet, "/api/decisions?tenant=acme&limit=5", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	w := httptest.NewRecorder()
	s.handleDecisions(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var rows []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode: %v — body %s", err, w.Body.String())
	}
	if len(rows) == 0 {
		t.Fatal("no decisions returned; the fixture did not reach the handler")
	}
	sent := map[string]bool{}
	for k := range rows[0] {
		sent[k] = true
	}

	var missing []string
	for _, f := range tsInterfaceFields(t, consoleTypesPath(t), "Decision", 15) {
		if sent[f] {
			continue
		}
		if _, ok := engineOnlyDecisionFields[f]; ok {
			continue
		}
		missing = append(missing, f)
	}
	if len(missing) > 0 {
		t.Errorf("the console reads these fields and /api/decisions does not send them: %v\n"+
			"Either send them, or add each to engineOnlyDecisionFields with the reason it cannot be supplied.",
			missing)
	}
}

func TestTheContractCheckItselfIsLoadBearing(t *testing.T) {
	// A parser that silently stops matching turns this whole file into a test
	// that passes by finding nothing — the failure mode the assistant's
	// denylist ratchet was built to avoid.
	fields := tsInterfaceFields(t, consoleTypesPath(t), "Decision", 15)
	for _, must := range []string{"binary", "exec_id", "id", "pid", "action"} {
		if !contains(fields, must) {
			t.Fatalf("parsed console fields %v do not include %q; the regex has drifted", fields, must)
		}
	}
	// And every exception must name a real console field, or the allow-list is
	// silently excusing something that no longer exists.
	for f := range engineOnlyDecisionFields {
		if !contains(fields, f) {
			t.Errorf("engineOnlyDecisionFields excuses %q, which the console no longer declares", f)
		}
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

// engineOnlyBucketFields are console BucketEntry fields the control plane
// cannot supply, each with a reason. Anything not listed must be sent.
var engineOnlyBucketFields = map[string]string{}

func TestBucketsEndpointSendsEveryFieldTheConsoleReads(t *testing.T) {
	// BucketEntry was missing `agent` until it was found by eye rather than by
	// test — and PIDs are per-host, so the fleet's kernel map was not merely
	// unlabelled but ambiguous, with two hosts sharing a row key.
	s := &Server{registry: heartbeat.NewRegistry(), auditor: authz.NewMemAuditor()}
	s.cfg.Logf = func(string, ...any) {}
	s.cfg.AdminToken = "admin-secret"
	s.registry.Record("acme", "a1", &ebpfsocv1.HeartbeatRequest{
		AgentInfo: &ebpfsocv1.AgentInfo{Hostname: "h1", AgentVersion: "0.2.0-agent"},
		Buckets: []*ebpfsocv1.BucketSummary{
			{Pid: 4021, RatePerSec: 50, Burst: 100, Tokens: 0, Flags: 1},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/choke/buckets?tenant=acme", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	w := httptest.NewRecorder()
	s.handleChokeBuckets(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var rows []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("no buckets returned; the fixture did not reach the handler")
	}
	sent := map[string]bool{}
	for k := range rows[0] {
		sent[k] = true
	}
	var missing []string
	for _, f := range tsInterfaceFields(t, consoleTypesPath(t), "BucketEntry", 6) {
		if sent[f] {
			continue
		}
		if _, ok := engineOnlyBucketFields[f]; ok {
			continue
		}
		missing = append(missing, f)
	}
	if len(missing) > 0 {
		t.Errorf("the console reads these BucketEntry fields and /api/choke/buckets does not send them: %v\n"+
			"Either send them, or add each to engineOnlyBucketFields with the reason.", missing)
	}
}

// engineOnlyCircuitFields are console CircuitEntry fields the control plane
// cannot supply from a heartbeat snapshot.
// ChokeSummary carries exec_id, pid, binary, state and score — nothing else.
// Every entry below is a field the console renders empty on the fleet console
// and populated on the single-host engine.
//
// revert_pending is the one worth revisiting: a scheduled auto-revert is
// invisible to a fleet operator, so a containment that will lift itself in
// five minutes looks permanent. Closing that needs a heartbeat field, which is
// an agent change rather than a console one.
var engineOnlyCircuitFields = map[string]string{
	"uid":            "the heartbeat's choke snapshot carries no uid",
	"args":           "argv is not part of the choke snapshot",
	"parent_id":      "process lineage is resolved on the host, not in the snapshot",
	"start_time":     "same",
	"annotation":     "operator notes live in the agent's local store",
	"last_seen":      "the snapshot is itself the last-seen moment; the heartbeat carries no per-entry timestamp",
	"origin":         "SSH origin attribution is resolved on the host that saw the session",
	"revert_pending": "no heartbeat field carries a scheduled auto-revert — see the note above",
}

func TestCircuitsEndpointSendsEveryFieldTheConsoleReads(t *testing.T) {
	s := &Server{registry: heartbeat.NewRegistry(), auditor: authz.NewMemAuditor()}
	s.cfg.Logf = func(string, ...any) {}
	s.cfg.AdminToken = "admin-secret"
	s.registry.Record("acme", "a1", &ebpfsocv1.HeartbeatRequest{
		AgentInfo: &ebpfsocv1.AgentInfo{Hostname: "h1", AgentVersion: "0.2.0-agent"},
		Chokes: []*ebpfsocv1.ChokeSummary{
			{ExecId: "e1", Pid: 4021, Binary: "/usr/bin/curl", State: "throttled", Score: 42},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/choke/circuits?tenant=acme", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	w := httptest.NewRecorder()
	s.handleChokeCircuits(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var rows []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("no circuits returned; the fixture did not reach the handler")
	}
	sent := map[string]bool{}
	for k := range rows[0] {
		sent[k] = true
	}
	var missing []string
	for _, f := range tsInterfaceFields(t, consoleTypesPath(t), "CircuitEntry", 10) {
		if sent[f] || engineOnlyCircuitFields[f] != "" {
			continue
		}
		missing = append(missing, f)
	}
	if len(missing) > 0 {
		t.Errorf("the console reads these CircuitEntry fields and /api/choke/circuits does not send them: %v\n"+
			"Either send them, or add each to engineOnlyCircuitFields with the reason.", missing)
	}
}

func TestEveryContractExceptionNamesARealConsoleField(t *testing.T) {
	// An allow-list that excuses a field the console no longer declares is
	// silently excusing nothing, and hides the next real omission behind a
	// stale entry.
	for iface, exceptions := range map[string]map[string]string{
		"Decision":     engineOnlyDecisionFields,
		"BucketEntry":  engineOnlyBucketFields,
		"CircuitEntry": engineOnlyCircuitFields,
	} {
		fields := tsInterfaceFields(t, consoleTypesPath(t), iface, 6)
		for f := range exceptions {
			if !contains(fields, f) {
				t.Errorf("%s exception excuses %q, which the console no longer declares", iface, f)
			}
		}
	}
}
