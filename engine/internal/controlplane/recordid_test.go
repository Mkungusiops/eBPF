package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
)

// A RECORD'S IDENTITY MUST SURVIVE A RE-POLL.
//
// The event, alert and decision views published no stable id (decisions
// published the agent-local audit-chain row number, which is unique on one host
// and collides across a tenant's hosts). The console therefore synthesised
// `<type>-<timestamp>-<index>` — the record's POSITION in the response — so the
// same real record changed identity the moment a newer one arrived ahead of it,
// and acknowledgement state and pins keyed on it re-attached to a different
// record.
//
// These tests poll twice with a new record inserted in between, which is
// exactly what a live console does every few seconds, and require the id of the
// record present in both responses to be the same string.

func idTestServer(t *testing.T) (*Server, *centralstore.Store) {
	t.Helper()
	cs, err := centralstore.Open(t.TempDir() + "/c.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	s := &Server{registry: heartbeat.NewRegistry(), auditor: authz.NewMemAuditor()}
	s.cfg.Store = cs
	s.cfg.Logf = func(string, ...any) {}
	s.cfg.AdminToken = "admin-secret"
	return s, cs
}

func putRecord(t *testing.T, cs *centralstore.Store, tenant, agent, dedup string, rec *ebpfsocv1.TelemetryRecord) {
	t.Helper()
	rec.DedupKey = dedup
	if err := cs.Put(ingest.StampedRecord{TenantID: tenant, AgentID: agent, Record: rec}); err != nil {
		t.Fatal(err)
	}
}

func eventRecord(binary string, pid uint32, at time.Time) *ebpfsocv1.TelemetryRecord {
	return &ebpfsocv1.TelemetryRecord{Payload: &ebpfsocv1.TelemetryRecord_Event{Event: &ebpfsocv1.ProcessEvent{
		OccurredAt: timestamppb.New(at), EventType: "exec", Pid: pid, ExecId: "exec-" + binary, Binary: binary,
	}}}
}

func alertRecord(title string, at time.Time) *ebpfsocv1.TelemetryRecord {
	return &ebpfsocv1.TelemetryRecord{Payload: &ebpfsocv1.TelemetryRecord_Alert{Alert: &ebpfsocv1.Alert{
		OccurredAt: timestamppb.New(at), Severity: "high", Title: title, ExecId: "exec-" + title,
	}}}
}

func decisionRecord(id int64, at time.Time) *ebpfsocv1.TelemetryRecord {
	return &ebpfsocv1.TelemetryRecord{Payload: &ebpfsocv1.TelemetryRecord_Decision{Decision: &ebpfsocv1.Decision{
		Id: id, OccurredAt: timestamppb.New(at), Action: "quarantine", ToState: "quarantined",
		ExecId: "exec-d", Binary: "/usr/bin/curl", Outcome: "ok",
	}}}
}

// pollIDs runs one handler and returns the id of every row, keyed by a field
// that identifies the record independently of this id — so the test compares
// the SAME record across polls rather than the same array slot.
func pollIDs(t *testing.T, h http.HandlerFunc, path, key string) map[string]string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != 200 {
		t.Fatalf("%s: status %d: %s", path, w.Code, w.Body.String())
	}
	var rows []map[string]any
	body := w.Body.Bytes()
	if err := json.Unmarshal(body, &rows); err != nil {
		var wrapped map[string]json.RawMessage
		if err2 := json.Unmarshal(body, &wrapped); err2 != nil {
			t.Fatalf("%s: decode: %v / %v — body %s", path, err, err2, body)
		}
		for _, k := range []string{"events", "alerts", "decisions"} {
			if raw, ok := wrapped[k]; ok {
				if err := json.Unmarshal(raw, &rows); err != nil {
					t.Fatalf("%s: decode %s: %v", path, k, err)
				}
			}
		}
	}
	out := map[string]string{}
	for _, row := range rows {
		id, _ := row["id"].(string)
		name, _ := row[key].(string)
		if name == "" {
			t.Fatalf("%s: a row carries no %s, so this test cannot tell records apart", path, key)
		}
		if id == "" {
			t.Errorf("%s: the row for %s=%q carries no id, so the console must key it by position", path, key, name)
		}
		out[name] = id
	}
	return out
}

func TestFeedViewsPublishAnIdThatSurvivesARePoll(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name    string
		path    string
		key     string
		handler func(*Server) http.HandlerFunc
		first   func(*centralstore.Store, *testing.T)
		second  func(*centralstore.Store, *testing.T)
		want    string
	}{
		{
			name: "events", path: "/api/events?tenant=acme", key: "process",
			handler: func(s *Server) http.HandlerFunc { return s.handleEvents },
			first: func(cs *centralstore.Store, t *testing.T) {
				putRecord(t, cs, "acme", "a1", "evt:1", eventRecord("/usr/bin/curl", 100, now.Add(-time.Minute)))
			},
			second: func(cs *centralstore.Store, t *testing.T) {
				putRecord(t, cs, "acme", "a1", "evt:2", eventRecord("/usr/bin/nc", 101, now))
			},
			want: "/usr/bin/curl",
		},
		{
			name: "alerts", path: "/api/alerts?tenant=acme", key: "title",
			handler: func(s *Server) http.HandlerFunc { return s.handleAlerts },
			first: func(cs *centralstore.Store, t *testing.T) {
				putRecord(t, cs, "acme", "a1", "alt:1", alertRecord("shadow", now.Add(-time.Minute)))
			},
			second: func(cs *centralstore.Store, t *testing.T) {
				putRecord(t, cs, "acme", "a1", "alt:2", alertRecord("beacon", now))
			},
			want: "shadow",
		},
		{
			name: "decisions", path: "/api/decisions?tenant=acme", key: "action",
			handler: func(s *Server) http.HandlerFunc { return s.handleDecisions },
			first: func(cs *centralstore.Store, t *testing.T) {
				putRecord(t, cs, "acme", "a1", "dec:1", decisionRecord(1, now.Add(-time.Minute)))
			},
			second: func(cs *centralstore.Store, t *testing.T) {
				putRecord(t, cs, "acme", "a2", "dec:2", decisionRecord(2, now))
			},
			want: "quarantine",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, cs := idTestServer(t)
			c.first(cs, t)
			before := pollIDs(t, c.handler(s), c.path, c.key)
			c.second(cs, t)
			after := pollIDs(t, c.handler(s), c.path, c.key)

			if before[c.want] == "" {
				t.Fatalf("the first poll published no id for %q", c.want)
			}
			if before[c.want] != after[c.want] {
				t.Errorf("%q changed identity when a newer record arrived: %q then %q — "+
					"ack state and pins keyed on this now point at a different record",
					c.want, before[c.want], after[c.want])
			}
		})
	}
}

// TWO AGENTS IN ONE TENANT NUMBER THEIR OWN RECORDS FROM 1.
//
// The dedup key is agent-assigned ("evt:<local row id>"), and the store's
// primary key is (tenant_id, agent_id, dedup_key) — so the key alone is NOT an
// identity within a tenant. acme-corp runs two agents on this estate, and both
// send "evt:1" for two entirely different executions. Publishing the bare
// dedup key as `id` would fold them into one record on the console, which is
// the same defect as the positional id with the blame moved server-side.
func TestTwoAgentsInOneTenantDoNotShareARecordID(t *testing.T) {
	s, cs := idTestServer(t)
	now := time.Now().UTC()
	putRecord(t, cs, "acme", "a1", "evt:1", eventRecord("/usr/bin/curl", 100, now.Add(-time.Minute)))
	putRecord(t, cs, "acme", "a2", "evt:1", eventRecord("/usr/bin/nc", 200, now))

	ids := pollIDs(t, s.handleEvents, "/api/events?tenant=acme", "process")
	if len(ids) != 2 {
		t.Fatalf("expected both agents' events, got %d", len(ids))
	}
	if ids["/usr/bin/curl"] == ids["/usr/bin/nc"] {
		t.Errorf("two different executions on two agents share the id %q — the console will merge them "+
			"into one record and ack one by acking the other", ids["/usr/bin/curl"])
	}
}

// AND THE SAME COLLISION, ON THE LEDGER THAT AN AUDIT READS.
//
// A decision's own Id is the row number of the ORIGINATING AGENT'S local audit
// chain, so two hosts in one tenant both write decision 1. That number was what
// /api/decisions published as `id`, and the console tracks acknowledgement on
// `id` — so acking one host's quarantine acked another host's. The agent-local
// number is still published, as decision_id, because it is what an operator
// quotes when re-verifying that host's chain.
func TestTwoAgentsDecisionsDoNotShareARecordID(t *testing.T) {
	s, cs := idTestServer(t)
	now := time.Now().UTC()
	putRecord(t, cs, "acme", "a1", "dec:1", decisionRecord(1, now.Add(-time.Minute)))
	putRecord(t, cs, "acme", "a2", "dec:1", decisionRecord(1, now))

	req := httptest.NewRequest(http.MethodGet, "/api/decisions?tenant=acme", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	w := httptest.NewRecorder()
	s.handleDecisions(w, req)
	var rows []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode: %v — body %s", err, w.Body.String())
	}
	if len(rows) != 2 {
		t.Fatalf("expected both agents' decisions, got %d", len(rows))
	}
	if rows[0]["id"] == rows[1]["id"] {
		t.Errorf("two hosts' decisions share the id %v — acking one acks the other", rows[0]["id"])
	}
	// The agent-local chain row number must survive, or an operator can no
	// longer match a console row to that host's audit chain.
	for _, row := range rows {
		if row["decision_id"] != float64(1) {
			t.Errorf("decision_id = %v, want the agent-local chain row 1", row["decision_id"])
		}
	}
}

// THE LIVE TAIL AND THE POLL MUST AGREE ABOUT WHAT IS ONE RECORD.
//
// The console merges the SSE stream into the buffer it polled, by id. Two
// spellings of one record's identity is two rows in the feed — which is what
// shipped: streamFrame sent the bare dedup key while the views sent nothing.
func TestStreamAndPollAgreeOnRecordIdentity(t *testing.T) {
	s, cs := idTestServer(t)
	now := time.Now().UTC()
	putRecord(t, cs, "acme", "a1", "evt:1", eventRecord("/usr/bin/curl", 100, now))

	polled := pollIDs(t, s.handleEvents, "/api/events?tenant=acme", "process")

	rows, err := s.cfg.Store.Query(centralstore.Scope{TenantID: "acme", Kind: "event"}, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("store read: %v (%d rows)", err, len(rows))
	}
	var frame struct {
		Payload map[string]any `json:"payload"`
	}
	if err := json.Unmarshal([]byte(streamFrame(rows[0])), &frame); err != nil {
		t.Fatalf("stream frame: %v", err)
	}
	if got, _ := frame.Payload["id"].(string); got != polled["/usr/bin/curl"] {
		t.Errorf("the streamed copy of one event is keyed %q and the polled copy %q — "+
			"the console will show it twice", got, polled["/usr/bin/curl"])
	}
}

// A DECISION FRAME CARRIED NO ID AT ALL, so every streamed decision normalised
// to `decision-<timestamp>-0` and the whole ledger collapsed into one bucket.
func TestStreamedDecisionsAreDistinguishable(t *testing.T) {
	_, cs := idTestServer(t)
	now := time.Now().UTC()
	putRecord(t, cs, "acme", "a1", "dec:1", decisionRecord(1, now.Add(-time.Second)))
	putRecord(t, cs, "acme", "a1", "dec:2", decisionRecord(2, now))

	rows, err := cs.Query(centralstore.Scope{TenantID: "acme", Kind: "decision"}, 10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("store read: %v (%d rows)", err, len(rows))
	}
	seen := map[string]bool{}
	for _, row := range rows {
		var frame struct {
			Payload map[string]any `json:"payload"`
		}
		if err := json.Unmarshal([]byte(streamFrame(row)), &frame); err != nil {
			t.Fatalf("stream frame: %v", err)
		}
		id, _ := frame.Payload["id"].(string)
		if id == "" {
			t.Fatal("a streamed decision carries no id")
		}
		if seen[id] {
			t.Errorf("two decisions share the streamed id %q", id)
		}
		seen[id] = true
	}
}

// A RECORD WITH NO DEDUP KEY MUST NOT GET A SHARED PLACEHOLDER. Every such
// record sharing one id is worse than no id at all: the console's content-key
// fallback handles the absence correctly, but it cannot un-merge rows an id
// told it were the same.
func TestARecordWithNoDedupKeyPublishesNoID(t *testing.T) {
	if got := recordID(centralstore.Row{TenantID: "acme", AgentID: "a1"}); got != "" {
		t.Errorf("recordID invented %q for a record with no dedup key", got)
	}
}
