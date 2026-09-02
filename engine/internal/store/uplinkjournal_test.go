package store

import "testing"

// The durable half of the outbound queue. architecture.md §2 called for "the
// local SQLite WAL becomes a durable queue"; the seam was left in the uplink
// buffer and the implementation never arrived, so every agent restart lost the
// un-acked backlog — and every deploy restarts every agent.

func journalStore(t *testing.T) *Store {
	t.Helper()
	st, err := New(t.TempDir() + "/j.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestTheBacklogSurvivesReopeningTheDatabase(t *testing.T) {
	dir := t.TempDir() + "/j.db"
	st, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i, k := range []string{"a", "b", "c"} {
		if err := st.AppendUplink(uint64(i+1), k, []byte(k)); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.DeleteUplinkThrough(1); err != nil { // the CP acked the first
		t.Fatal(err)
	}
	_ = st.Close()

	// Reopen: this is the restart.
	again, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = again.Close() })
	rows, err := again.LoadUplink()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("recovered %d records, want the 2 un-acked ones", len(rows))
	}
	// Oldest first: the control plane's ack is cumulative, so an out-of-order
	// replay would ack records that were never sent.
	if rows[0].Seq != 2 || string(rows[0].Payload) != "b" {
		t.Fatalf("recovered out of order: first is seq=%d %q", rows[0].Seq, rows[0].Payload)
	}
}

func TestReAppendingTheSameSequenceIsHarmless(t *testing.T) {
	// A retry after a partial write must not fail the send path.
	st := journalStore(t)
	if err := st.AppendUplink(1, "a", []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendUplink(1, "a", []byte("a")); err != nil {
		t.Fatalf("re-appending the same sequence failed: %v", err)
	}
	rows, _ := st.LoadUplink()
	if len(rows) != 1 {
		t.Fatalf("%d rows, want 1", len(rows))
	}
}

func TestAnEmptyBacklogRecoversCleanly(t *testing.T) {
	st := journalStore(t)
	rows, err := st.LoadUplink()
	if err != nil {
		t.Fatalf("loading an empty queue failed: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("%d rows from an empty queue", len(rows))
	}
}
