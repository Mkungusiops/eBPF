package centralstore

import (
	"database/sql"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
)

// Severity as a COLUMN, so the control plane can aggregate alert counts in SQL
// the way the single-tenant engine already does.
//
// Why this exists. Severity lives inside each record's protobuf payload, so the
// control plane could not GROUP BY it — every windowed count had to ship rows
// into Go and tally them there, bounded by a 200k scan limit. Measured on the
// live rig: a 7-day view scans the window AND the one before it for the delta,
// which is 935,600 alert rows — 4.7x the limit. The endpoint then honestly
// reported Truncated, and the console honestly rendered "counts are a floor,
// not a total". Correct, and useless: no window beyond a day could ever show a
// true number.
//
// The engine has had the right shape all along — an indexed `severity` column
// and `SELECT severity, COUNT(*) ... GROUP BY severity`, which reads no
// payloads, transfers no rows and has no limit to exceed. This gives the
// central store the same, so both deployments answer the same question the same
// way rather than one of them approximating.
//
// The column is nullable on purpose: NULL means "not yet backfilled", which is
// distinguishable from a genuine empty severity and lets the migration below be
// resumable and idempotent.

// SeverityCounter is the optional capability of counting a tenant's alerts by
// severity in the database.
//
// Optional, like RangeQuerier, so a backend that cannot do it (the ClickHouse
// firehose) is not forced to grow a method with no caller. Consumers type-assert
// and fall back to the bounded scan.
type SeverityCounter interface {
	// CountBySeverity totals a tenant's alerts per severity in [from, to).
	CountBySeverity(scope Scope, from, to time.Time) (map[string]int, error)
	// SeverityBuckets returns per-bucket severity totals for the timeline,
	// bucketed IN THE DATABASE.
	//
	// The obvious version streams (at, severity) per alert and buckets in Go,
	// which for a 7-day window means shipping ~116k rows to build 30 columns —
	// measured at ~1.4s of the endpoint's latency, and growing linearly with
	// the window. Grouping by bucket index in SQL returns buckets x severities
	// rows (~150) regardless of how many alerts the window holds, which is what
	// keeps 30d and 1y tractable later.
	SeverityBuckets(scope Scope, from, to time.Time, buckets int) ([]map[string]int, error)
	// SeverityBackfillPending reports how many alert rows still lack a
	// severity. Non-zero means counts would under-report, so callers must not
	// present them as complete.
	SeverityBackfillPending(scope Scope) (int, error)
}

var (
	_ SeverityCounter = (*Store)(nil)
	_ SeverityCounter = (*PGStore)(nil)
)

// severityOf extracts the severity an alert record carries, "" for non-alerts.
func severityOf(rec *ebpfsocv1.TelemetryRecord) string {
	if a := rec.GetAlert(); a != nil {
		return a.GetSeverity()
	}
	return ""
}

// backfillBatch is how many rows one backfill step rewrites.
//
// Small enough that each UPDATE holds its locks briefly and the fleet keeps
// writing; large enough that ~936k rows finish in minutes rather than hours.
const backfillBatch = 5_000

// backfillSeverity populates the severity column for alert rows that predate it.
//
// Runs in the BACKGROUND and in batches, deliberately. This codebase has already
// been bitten twice by migrations that block: startup DDL took an ACCESS
// EXCLUSIVE lock on a live telemetry table and hung the control plane with
// systemd still reporting it active, and an unindexed read path exhausted the
// connection pool. A backfill of a million rows is exactly that shape, so it
// never runs on the startup path and never holds a long transaction.
//
// Idempotent and resumable: it only ever touches rows WHERE severity IS NULL,
// so a restart mid-migration continues where it stopped and a completed
// migration costs one cheap indexed probe.
func backfillSeverity(db *sql.DB, dialect string) {
	sel := `SELECT tenant_id, agent_id, dedup_key, payload FROM telemetry
	        WHERE kind = 'alert' AND severity IS NULL LIMIT ?`
	upd := `UPDATE telemetry SET severity = ? WHERE tenant_id = ? AND agent_id = ? AND dedup_key = ?`
	if dialect == "postgres" {
		sel = `SELECT tenant_id, agent_id, dedup_key, payload FROM telemetry
		       WHERE kind = 'alert' AND severity IS NULL LIMIT $1`
		upd = `UPDATE telemetry SET severity = $1 WHERE tenant_id = $2 AND agent_id = $3 AND dedup_key = $4`
	}

	start := time.Now()
	total := 0
	for {
		rows, err := db.Query(sel, backfillBatch)
		if err != nil {
			slog.Error("severity backfill: select failed", "error", err)
			return
		}
		type item struct {
			tenant, agent, dedup, sev string
		}
		batch := make([]item, 0, backfillBatch)
		for rows.Next() {
			var it item
			var payload []byte
			if err := rows.Scan(&it.tenant, &it.agent, &it.dedup, &payload); err != nil {
				rows.Close()
				slog.Error("severity backfill: scan failed", "error", err)
				return
			}
			var rec ebpfsocv1.TelemetryRecord
			if err := proto.Unmarshal(payload, &rec); err != nil {
				// Undecodable payload: stamp it so the row is not retried
				// forever. An empty severity still counts as an alert.
				it.sev = ""
			} else {
				it.sev = severityOf(&rec)
			}
			batch = append(batch, it)
		}
		rows.Close()
		if len(batch) == 0 {
			if total > 0 {
				slog.Info("severity backfill complete", "rows", total, "took", time.Since(start))
				// Every UPDATE above left a dead tuple behind — ~928k of them,
				// measured. Until they are reclaimed the table is bloated AND
				// the visibility map is stale, which silently downgrades the
				// covering index from an index-ONLY scan to one that fetches
				// every heap page: 1.8 GB of reads and 3.0s for a 7-day window,
				// against 0.9s once vacuumed. Autovacuum would get there
				// eventually; "eventually" is after the operator has formed an
				// opinion about whether the feature works.
				//
				// Plain VACUUM, never FULL: it takes no exclusive lock, so the
				// fleet keeps writing throughout.
				vacuumAfterBackfill(db, dialect)
			}
			return
		}
		tx, err := db.Begin()
		if err != nil {
			slog.Error("severity backfill: begin failed", "error", err)
			return
		}
		for _, it := range batch {
			if _, err := tx.Exec(upd, it.sev, it.tenant, it.agent, it.dedup); err != nil {
				_ = tx.Rollback()
				slog.Error("severity backfill: update failed", "error", err)
				return
			}
		}
		if err := tx.Commit(); err != nil {
			slog.Error("severity backfill: commit failed", "error", err)
			return
		}
		total += len(batch)
		// Yield between batches so a migration never starves live ingest.
		time.Sleep(50 * time.Millisecond)
	}
}

// ─── SQLite ────────────────────────────────────────────────────────────────

func (s *Store) CountBySeverity(scope Scope, from, to time.Time) (map[string]int, error) {
	if scope.TenantID == "" {
		return nil, ErrNoScope
	}
	rows, err := s.db.Query(`SELECT COALESCE(severity,''), COUNT(*) FROM telemetry
	    WHERE tenant_id = ? AND kind = 'alert' AND at >= ? AND at < ? GROUP BY 1`,
		scope.TenantID, from.UnixNano(), to.UnixNano())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSeverityCounts(rows)
}

func (s *Store) SeverityBuckets(scope Scope, from, to time.Time, buckets int) ([]map[string]int, error) {
	if scope.TenantID == "" {
		return nil, ErrNoScope
	}
	width := bucketWidth(from, to, buckets)
	rows, err := s.db.Query(`SELECT (at - ?) / ? AS b, COALESCE(severity,''), COUNT(*)
	    FROM telemetry WHERE tenant_id = ? AND kind = 'alert' AND at >= ? AND at < ?
	    GROUP BY b, 2`,
		from.UnixNano(), width, scope.TenantID, from.UnixNano(), to.UnixNano())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanBuckets(rows, buckets)
}

func (s *Store) SeverityBackfillPending(scope Scope) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM telemetry
	    WHERE tenant_id = ? AND kind = 'alert' AND severity IS NULL`, scope.TenantID).Scan(&n)
	return n, err
}

// ─── PostgreSQL ────────────────────────────────────────────────────────────

func (s *PGStore) CountBySeverity(scope Scope, from, to time.Time) (map[string]int, error) {
	if scope.TenantID == "" {
		return nil, ErrNoScope
	}
	var out map[string]int
	err := s.withTenant(scope.TenantID, func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT COALESCE(severity,''), COUNT(*) FROM telemetry
		    WHERE kind = 'alert' AND at >= $1 AND at < $2 GROUP BY 1`,
			from.UnixNano(), to.UnixNano())
		if err != nil {
			return err
		}
		defer rows.Close()
		out, err = scanSeverityCounts(rows)
		return err
	})
	return out, err
}

func (s *PGStore) SeverityBuckets(scope Scope, from, to time.Time, buckets int) ([]map[string]int, error) {
	if scope.TenantID == "" {
		return nil, ErrNoScope
	}
	width := bucketWidth(from, to, buckets)
	var out []map[string]int
	err := s.withTenant(scope.TenantID, func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT (at - $1) / $2 AS b, COALESCE(severity,''), COUNT(*)
		    FROM telemetry WHERE kind = 'alert' AND at >= $3 AND at < $4
		    GROUP BY b, 2`,
			from.UnixNano(), width, from.UnixNano(), to.UnixNano())
		if err != nil {
			return err
		}
		defer rows.Close()
		out, err = scanBuckets(rows, buckets)
		return err
	})
	return out, err
}

func (s *PGStore) SeverityBackfillPending(scope Scope) (int, error) {
	var n int
	err := s.withTenant(scope.TenantID, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT COUNT(*) FROM telemetry
		    WHERE kind = 'alert' AND severity IS NULL`).Scan(&n)
	})
	return n, err
}

func scanSeverityCounts(rows *sql.Rows) (map[string]int, error) {
	out := map[string]int{}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, err
		}
		out[sev] = n
	}
	return out, rows.Err()
}

// bucketWidth is the nanosecond span of one timeline column, never zero.
func bucketWidth(from, to time.Time, buckets int) int64 {
	if buckets < 1 {
		buckets = 1
	}
	w := to.Sub(from).Nanoseconds() / int64(buckets)
	if w < 1 {
		w = 1
	}
	return w
}

func scanBuckets(rows *sql.Rows, buckets int) ([]map[string]int, error) {
	out := make([]map[string]int, buckets)
	for i := range out {
		out[i] = map[string]int{}
	}
	for rows.Next() {
		var idx int64
		var sev string
		var n int
		if err := rows.Scan(&idx, &sev, &n); err != nil {
			return nil, err
		}
		// Integer division puts a row landing exactly on `to` one past the end.
		if idx < 0 {
			idx = 0
		}
		if idx >= int64(buckets) {
			idx = int64(buckets) - 1
		}
		out[idx][sev] += n
	}
	return out, rows.Err()
}

// ─── Migration for already-provisioned databases ───────────────────────────

// ensureSeverityColumn adds the column to a database that predates it and then
// backfills it, both in the background.
//
// schemaReady deliberately skips the startup DDL on a provisioned database (so
// a restart never takes an ACCESS EXCLUSIVE lock on a live telemetry table), so
// an existing deployment would otherwise never gain the column at all — the same
// gap ensureIndexes exists to close for the read-path indexes.
//
// ADD COLUMN of a nullable column with no default is a catalogue-only change in
// PostgreSQL 11+: it does not rewrite the table, so it is safe against a live
// multi-gigabyte one. The row rewrite that DOES cost something is the backfill,
// which is batched and yields.
//
// Intended to be called as `go ensureSeverityColumn(db, dialect)`.
func ensureSeverityColumn(db *sql.DB, dialect string) {
	alter := `ALTER TABLE telemetry ADD COLUMN severity text`
	if dialect == "sqlite" {
		alter = `ALTER TABLE telemetry ADD COLUMN severity TEXT`
	}
	if _, err := db.Exec(alter); err != nil {
		// Already present is the overwhelmingly common case (every restart
		// after the first), and neither engine offers ADD COLUMN IF NOT EXISTS
		// portably. Probe rather than treat it as fatal.
		var probe sql.NullString
		if perr := db.QueryRow(`SELECT severity FROM telemetry LIMIT 1`).Scan(&probe); perr != nil &&
			!errorIsNoRows(perr) {
			slog.Error("severity column unavailable; alert counts fall back to a bounded scan", "error", err)
			return
		}
	}
	backfillSeverity(db, dialect)

	// The covering index is built HERE, after the column exists — not in
	// ensureIndexes. Both run as goroutines at startup, so listing it there
	// raced the ALTER TABLE and failed with `column "severity" does not exist`,
	// leaving the aggregation to sequential-scan the table forever (measured:
	// 4.9s for a 7-day window). Ordering is the whole point of doing it here.
	if dialect != "postgres" {
		return
	}
	const ix = "telemetry_alert_sev"
	var valid bool
	err := db.QueryRow(
		`SELECT i.indisvalid FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid WHERE c.relname = $1`,
		ix).Scan(&valid)
	if err == nil && valid {
		return
	}
	if err == nil && !valid {
		// A failed CONCURRENTLY build leaves an INVALID index the planner
		// ignores but IF NOT EXISTS would skip — drop it or it is permanent.
		if _, derr := db.Exec(`DROP INDEX CONCURRENTLY IF EXISTS ` + ix); derr != nil {
			slog.Error("could not drop invalid severity index", "error", derr)
			return
		}
	}
	slog.Info("building the alert-severity covering index (concurrent; writes continue)")
	start := time.Now()
	if _, err := db.Exec(`CREATE INDEX CONCURRENTLY IF NOT EXISTS ` + ix +
		` ON telemetry (tenant_id, at DESC) INCLUDE (severity) WHERE kind = 'alert'`); err != nil {
		slog.Error("severity index build failed; alert counts will full-scan", "error", err)
		return
	}
	slog.Info("alert-severity covering index built", "took", time.Since(start))
}

func errorIsNoRows(err error) bool { return err == sql.ErrNoRows }

// vacuumAfterBackfill reclaims the dead tuples a mass UPDATE leaves and
// refreshes the planner statistics + visibility map the covering index needs.
func vacuumAfterBackfill(db *sql.DB, dialect string) {
	stmt := `VACUUM (ANALYZE) telemetry`
	if dialect == "sqlite" {
		// SQLite has no per-table VACUUM and no visibility map; ANALYZE alone
		// refreshes the statistics the query planner uses.
		stmt = `ANALYZE`
	}
	start := time.Now()
	if _, err := db.Exec(stmt); err != nil {
		slog.Warn("post-backfill vacuum failed; counts stay correct but slower until autovacuum runs",
			"error", err)
		return
	}
	slog.Info("post-backfill vacuum complete", "took", time.Since(start))
}
