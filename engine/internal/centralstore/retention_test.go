package centralstore

import (
	"testing"
	"time"
)

// Nothing was ever deleted from telemetry. On the production control plane
// that was 268 MB/day against 19 GB free — a disk-full deadline about 73 days
// out, and a full disk stops Postgres accepting writes, not just the console
// rendering.

func putRow(t *testing.T, st *Store, kind, key string, age time.Duration) {
	t.Helper()
	_, err := st.db.Exec(
		`INSERT INTO telemetry (tenant_id, agent_id, dedup_key, kind, at, payload) VALUES (?,?,?,?,?,?)`,
		"acme", "a1", key, kind, time.Now().Add(-age).UnixNano(), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
}

func countKind(t *testing.T, st *Store, kind string) int {
	t.Helper()
	var n int
	if err := st.db.QueryRow(`SELECT count(*) FROM telemetry WHERE kind = ?`, kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPruneRemovesAgedEventsAndKeepsRecent(t *testing.T) {
	st := sevStore(t)
	putRow(t, st, "event", "old", 40*24*time.Hour)
	putRow(t, st, "event", "edge", 31*24*time.Hour)
	putRow(t, st, "event", "fresh", 2*time.Hour)
	putRow(t, st, "event", "now", 0)

	pruneOnce(st.db, "sqlite", defaultRetainEvents, defaultRetainAlerts)

	if got := countKind(t, st, "event"); got != 2 {
		t.Fatalf("events remaining = %d, want 2 (the two inside 30 days)", got)
	}
	// If `at` were ever compared against a SECONDS cutoff, nothing at all would
	// match and this count would be 4 — a silent no-op, which is why the
	// nanosecond unit is asserted rather than assumed.
	var survivor string
	if err := st.db.QueryRow(`SELECT dedup_key FROM telemetry WHERE dedup_key = 'now'`).Scan(&survivor); err != nil {
		t.Fatalf("a row written this instant was pruned: %v", err)
	}
}

func TestAlertsOutliveEvents(t *testing.T) {
	st := sevStore(t)
	// Same age, both past the event horizon, neither past the alert horizon.
	putRow(t, st, "event", "e45", 45*24*time.Hour)
	putRow(t, st, "alert", "a45", 45*24*time.Hour)

	pruneOnce(st.db, "sqlite", defaultRetainEvents, defaultRetainAlerts)

	if got := countKind(t, st, "event"); got != 0 {
		t.Errorf("event at 45d survived a 30d horizon (%d rows)", got)
	}
	if got := countKind(t, st, "alert"); got != 1 {
		t.Errorf("alert at 45d was pruned under a 90d horizon (%d rows)", got)
	}
}

// The enforcement audit trail is not a disk-space decision. Deleting the record
// of what the platform did to a host has to be a deliberate, separate act.
func TestDecisionsAreNeverPruned(t *testing.T) {
	st := sevStore(t)
	putRow(t, st, "decision", "d", 400*24*time.Hour)

	pruneOnce(st.db, "sqlite", defaultRetainEvents, defaultRetainAlerts)

	if got := countKind(t, st, "decision"); got != 1 {
		t.Fatalf("a 400-day-old decision was pruned; the audit trail must survive retention")
	}
}

// Retention shorter than twice the largest console range does not shrink the
// window — it makes the oldest window's DELTA wrong, because every KPI is
// rendered against the prior window of the same length. Trading a visible disk
// problem for an invisible correctness one is not a trade we take silently.
func TestOverrideCannotGoBelowTheWindowFloor(t *testing.T) {
	t.Setenv("EBPF_SOC_RETAIN_EVENT_DAYS", "3")
	got := horizonFromEnv("EBPF_SOC_RETAIN_EVENT_DAYS", defaultRetainEvents)
	if want := retentionFloor(); got != want {
		t.Fatalf("horizon = %v, want the floor %v", got, want)
	}
	if retentionFloor() != 2*maxConsoleWindow {
		t.Fatalf("floor %v is not twice the largest console window %v", retentionFloor(), maxConsoleWindow)
	}
}

func TestOverrideAppliesAboveTheFloor(t *testing.T) {
	t.Setenv("EBPF_SOC_RETAIN_EVENT_DAYS", "21")
	if got, want := horizonFromEnv("EBPF_SOC_RETAIN_EVENT_DAYS", defaultRetainEvents), 21*24*time.Hour; got != want {
		t.Fatalf("horizon = %v, want %v", got, want)
	}
}

func TestUnparseableOverrideFallsBackToDefault(t *testing.T) {
	for _, bad := range []string{"soon", "-5", "0"} {
		t.Setenv("EBPF_SOC_RETAIN_EVENT_DAYS", bad)
		if got := horizonFromEnv("EBPF_SOC_RETAIN_EVENT_DAYS", defaultRetainEvents); got != defaultRetainEvents {
			t.Errorf("override %q gave %v, want the default %v", bad, got, defaultRetainEvents)
		}
	}
}

// The defaults have to clear the floor themselves, or the shipped
// configuration is the one that breaks deltas.
func TestDefaultsClearTheFloor(t *testing.T) {
	if defaultRetainEvents < retentionFloor() {
		t.Errorf("default event retention %v is below the floor %v", defaultRetainEvents, retentionFloor())
	}
	if defaultRetainAlerts < defaultRetainEvents {
		t.Errorf("alerts (%v) must be kept at least as long as events (%v)", defaultRetainAlerts, defaultRetainEvents)
	}
}

// A prune pass that removes nothing must not vacuum: on a big table that is a
// full scan for no reason, every interval.
func TestPruneReportsNothingWhenClean(t *testing.T) {
	st := sevStore(t)
	putRow(t, st, "event", "fresh", time.Hour)
	if n := pruneOnce(st.db, "sqlite", defaultRetainEvents, defaultRetainAlerts); n != 0 {
		t.Fatalf("pruned %d rows from a table with nothing aged out", n)
	}
}

// Deletes are batched; the loop must terminate and clear the whole backlog
// rather than one batch per interval.
func TestPruneClearsMoreThanOneBatch(t *testing.T) {
	st := sevStore(t)
	tx, err := st.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO telemetry (tenant_id, agent_id, dedup_key, kind, at, payload) VALUES (?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-40 * 24 * time.Hour).UnixNano()
	const rows = retentionBatch + 250
	for i := 0; i < rows; i++ {
		if _, err := stmt.Exec("acme", "a1", "k"+strconvItoa(i), "event", old, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	if n := pruneOnce(st.db, "sqlite", defaultRetainEvents, defaultRetainAlerts); n != rows {
		t.Fatalf("pruned %d of %d rows — the batch loop stopped early", n, rows)
	}
	if got := countKind(t, st, "event"); got != 0 {
		t.Fatalf("%d aged events survived", got)
	}
}

func strconvItoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
