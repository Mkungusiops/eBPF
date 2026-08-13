package centralstore

import (
	"database/sql"
	"log/slog"
	"os"
	"strconv"
	"time"
)

// Raw telemetry is the only table here that grows without bound, and nothing
// ever deleted from it. Measured on the production control plane on 2026-08-11:
// 13 days of history, 5.22M rows, 3486 MB including indexes — about 268 MB a
// day, against 19 GB free. That is a disk-full deadline roughly 73 days out,
// and a full disk on this box is not a degraded console: the control plane
// stops accepting telemetry and Postgres stops accepting writes at all.
//
// Retention is split by kind because the two behave nothing alike. Raw events
// are 81% of the rows and effectively all of the growth; alerts are the
// evidence an analyst comes back to, and cost about 50 MB a day. Decisions are
// the enforcement audit trail — 1,645 rows in 13 days — and are NEVER pruned
// here, because deleting the record of what the platform did to a host is not
// a disk-space decision.
const (
	// The console's largest range, mirrored from the selector in SocRoute
	// ([5, 30, 60, 1440, 10080] minutes). Every KPI is rendered with a delta
	// against the PRIOR window of the same length, so a 7-day view reads 14
	// days of history. Retention below twice this does not shrink the window —
	// it makes the oldest window's delta quietly wrong, which is worse than
	// refusing the range outright.
	maxConsoleWindow = 7 * 24 * time.Hour

	defaultRetainEvents = 30 * 24 * time.Hour
	defaultRetainAlerts = 90 * 24 * time.Hour

	// Deletes are batched for the same reason the severity backfill was: one
	// unbounded statement takes a long lock and writes a WAL segment large
	// enough to matter on a box that is already short of disk.
	retentionBatch = 10_000

	retentionInterval = 6 * time.Hour
)

// retentionFloor is the shortest honest retention: twice the largest window the
// console offers.
func retentionFloor() time.Duration { return 2 * maxConsoleWindow }

// horizonFromEnv reads an operator override in days. An operator watching a
// disk fill needs to shorten retention without waiting for a rebuild — but not
// below the floor, because that trades a visible disk problem for an invisible
// correctness one.
func horizonFromEnv(name string, def time.Duration) time.Duration {
	raw := os.Getenv(name)
	if raw == "" {
		return def
	}
	days, err := strconv.Atoi(raw)
	if err != nil || days <= 0 {
		slog.Warn("retention: ignoring unparseable override", "var", name, "value", raw, "using", def)
		return def
	}
	d := time.Duration(days) * 24 * time.Hour
	if floor := retentionFloor(); d < floor {
		slog.Warn("retention: override is below the floor and would corrupt window deltas; clamping",
			"var", name, "requested", d, "floor", floor,
			"why", "the console renders every range against the prior range of the same length")
		return floor
	}
	return d
}

// RunRetention prunes aged telemetry on a schedule until ctx-less shutdown.
// Intended to be called as `go RunRetention(db, dialect)`.
func RunRetention(db *sql.DB, dialect string) {
	events := horizonFromEnv("EBPF_SOC_RETAIN_EVENT_DAYS", defaultRetainEvents)
	alerts := horizonFromEnv("EBPF_SOC_RETAIN_ALERT_DAYS", defaultRetainAlerts)
	slog.Info("retention enabled", "events", events, "alerts", alerts,
		"decisions", "never pruned", "every", retentionInterval)

	for {
		pruneOnce(db, dialect, events, alerts)
		time.Sleep(retentionInterval)
	}
}

// pruneOnce runs one pass and vacuums if it actually removed anything.
func pruneOnce(db *sql.DB, dialect string, events, alerts time.Duration) int64 {
	now := time.Now()
	var total int64
	for _, target := range []struct {
		kind   string
		retain time.Duration
	}{
		{"event", events},
		{"alert", alerts},
	} {
		cutoff := now.Add(-target.retain)
		n, err := pruneKind(db, dialect, target.kind, cutoff)
		if err != nil {
			slog.Error("retention: prune failed", "kind", target.kind, "error", err)
			continue
		}
		if n > 0 {
			slog.Info("retention: pruned", "kind", target.kind, "rows", n,
				"older_than", cutoff.UTC().Format(time.RFC3339))
		}
		total += n
	}

	// A bulk DELETE leaves exactly the dead tuples an UPDATE does, with the
	// same consequence: a stale visibility map downgrades the covering index
	// from an index-only scan to one that fetches every heap page, and the
	// space is not returned to the filesystem for reuse until it is reclaimed.
	// The severity backfill learned this at 3.0s vs 0.9s on a 7-day window.
	if total > 0 {
		vacuumAfterBackfill(db, dialect)
	}
	return total
}

// pruneKind deletes one kind older than cutoff, in bounded batches.
func pruneKind(db *sql.DB, dialect, kind string, cutoff time.Time) (int64, error) {
	// `at` is epoch NANOSECONDS (bigint), not seconds. Getting this wrong by
	// 1e9 either deletes everything or nothing, and "nothing" fails silently.
	cutoffNanos := cutoff.UnixNano()

	// Both engines expose a physical row identifier, which keeps the batch
	// bound cheap: the subquery picks rows by the read-path index and the
	// delete addresses them directly, with no second predicate evaluation.
	stmt := `DELETE FROM telemetry WHERE rowid IN (
	             SELECT rowid FROM telemetry WHERE kind = ? AND at < ? LIMIT ?)`
	if dialect == "postgres" {
		stmt = `DELETE FROM telemetry WHERE ctid IN (
		            SELECT ctid FROM telemetry WHERE kind = $1 AND at < $2 LIMIT $3)`
	}

	var total int64
	for {
		res, err := db.Exec(stmt, kind, cutoffNanos, retentionBatch)
		if err != nil {
			return total, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, err
		}
		total += n
		if n < retentionBatch {
			return total, nil
		}
	}
}
