package uplink

import (
	"testing"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/store"
)

// The control plane re-verifies each tenant's hash chain from the records it
// receives. That only works if every field the LOCAL hash covers survives the
// wire — and actor does, via Decision.actorTail.
//
// Until actor was added to the proto, wiring the uplink would have shipped
// every operator action with actor="", the far end would have re-canonicalised
// it without the actor tail, and the chain would have reported BROKEN on
// exactly the decisions an audit cares about most. That is worse than having
// no uplink: a missing audit is visibly missing, a false tamper alarm is not.

func TestDecisionRecordCarriesEveryChainHashedField(t *testing.T) {
	st, err := store.New(t.TempDir() + "/d.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	d := &store.Decision{
		Timestamp: time.Now().UTC(),
		ExecID:    "exec-1", PID: 4021, Binary: "/usr/bin/curl",
		Action: "sever", FromState: "quarantined", ToState: "severed",
		Score: 210, Reason: "confirmed C2", Backend: "cgroupv2", Outcome: "ok",
		Actor: "op-adanian",
	}
	if _, err := st.InsertDecision(d); err != nil {
		t.Fatal(err)
	}

	rec := DecisionRecord(d)
	got := rec.GetDecision()
	if got == nil {
		t.Fatal("no decision payload")
	}
	if got.GetActor() != "op-adanian" {
		t.Fatalf("actor = %q — it is chain-hashed, so losing it makes the far end report the chain broken", got.GetActor())
	}
	// The chain link must be carried verbatim, not recomputed.
	if got.GetHash() != d.Hash || got.GetPrevHash() != d.PrevHash {
		t.Fatalf("chain link altered in transit: hash %q vs %q", got.GetHash(), d.Hash)
	}
	if got.GetId() != d.ID || d.ID == 0 {
		t.Fatalf("id = %d, want the stamped id %d", got.GetId(), d.ID)
	}
}

func TestEachDecisionGetsItsOwnDedupKey(t *testing.T) {
	// The dedup key is built from the record id, which InsertDecision stamps.
	// Sinking a decision BEFORE the insert would leave every one of them at
	// id 0 — one shared key, and the uplink keeps exactly one decision ever.
	st, err := store.New(t.TempDir() + "/d.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		d := &store.Decision{
			Timestamp: time.Now().UTC(), ExecID: "e", Action: "throttle",
			FromState: "pristine", ToState: "throttled", Backend: "cgroupv2", Outcome: "ok",
		}
		if _, err := st.InsertDecision(d); err != nil {
			t.Fatal(err)
		}
		k := DecisionRecord(d).GetDedupKey()
		if seen[k] {
			t.Fatalf("two decisions share dedup key %q — the uplink would keep only one", k)
		}
		seen[k] = true
	}
}
