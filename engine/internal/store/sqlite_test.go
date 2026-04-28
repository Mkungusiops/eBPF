package store

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	st, err := New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestInsertAndRecentEvents(t *testing.T) {
	st := newTestStore(t)
	for i := 0; i < 3; i++ {
		_, err := st.InsertEvent(&Event{
			Timestamp: time.Now(),
			EventType: "process_exec",
			PID:       uint32(100 + i),
			ExecID:    "exec-x",
			Binary:    "/bin/bash",
		})
		if err != nil {
			t.Fatalf("InsertEvent: %v", err)
		}
	}
	rows, err := st.RecentEvents(10)
	if err != nil {
		t.Fatalf("RecentEvents: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d events want 3", len(rows))
	}
}

func TestEventsByExecID(t *testing.T) {
	st := newTestStore(t)
	_, _ = st.InsertEvent(&Event{Timestamp: time.Now(), EventType: "process_exec", ExecID: "match", Binary: "/a"})
	_, _ = st.InsertEvent(&Event{Timestamp: time.Now(), EventType: "process_exec", ExecID: "other", Binary: "/b"})
	_, _ = st.InsertEvent(&Event{Timestamp: time.Now(), EventType: "process_exec", ExecID: "match", Binary: "/c"})

	rows, err := st.EventsByExecID("match")
	if err != nil {
		t.Fatalf("EventsByExecID: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d want 2", len(rows))
	}
	for _, r := range rows {
		if r.ExecID != "match" {
			t.Fatalf("filter leak: %+v", r)
		}
	}
}

func TestInsertAndRecentAlerts(t *testing.T) {
	st := newTestStore(t)
	id, err := st.InsertAlert(&Alert{
		Timestamp:   time.Now(),
		Severity:    "high",
		Title:       "test alert",
		Description: "because",
		ExecID:      "x",
		Score:       42,
		EventIDs:    []int64{1, 2, 3},
	})
	if err != nil || id == 0 {
		t.Fatalf("InsertAlert: id=%d err=%v", id, err)
	}
	rows, err := st.RecentAlerts(10)
	if err != nil {
		t.Fatalf("RecentAlerts: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d want 1", len(rows))
	}
	a := rows[0]
	if a.Severity != "high" || a.Score != 42 || len(a.EventIDs) != 3 {
		t.Fatalf("alert roundtrip wrong: %+v", a)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rerun.db")
	a, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	b, err := New(path)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer b.Close()
	if _, err := b.InsertEvent(&Event{Timestamp: time.Now(), EventType: "process_exec", Binary: "/bin/sh"}); err != nil {
		t.Fatalf("insert after reopen: %v", err)
	}
}
