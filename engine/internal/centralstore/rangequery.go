package centralstore

import (
	"database/sql"
	"strconv"
	"time"
)

// RangeQuerier reads a tenant's records within a time range, oldest bound
// inclusive and newest bound exclusive.
//
// It is an OPTIONAL capability rather than part of TenantStore: not every
// backend needs it, and widening the core interface would force every
// implementation (including the ClickHouse firehose) to grow a method it has no
// caller for. Consumers type-assert and fall back when it is absent.
//
// It exists so aggregate endpoints can bound their work by TIME instead of by
// row count. Asking for "the newest N rows" and hoping N covers the window is
// what made the console's 24h numbers wrong; asking for "the rows in this
// window" cannot be wrong in that way.
type RangeQuerier interface {
	QueryRange(scope Scope, from, to time.Time, limit int) ([]Row, error)
}

var (
	_ RangeQuerier = (*Store)(nil)
	_ RangeQuerier = (*PGStore)(nil)
)

// maxRangeRows bounds a single range scan. A window with more records than this
// is truncated rather than allowed to exhaust memory — the same lesson as the
// unbounded uplink buffer and the unbounded connection pool. Callers that care
// whether they saw everything compare the returned count against their limit.
const maxRangeRows = 500_000

// QueryRange implements RangeQuerier for the SQLite central store.
func (s *Store) QueryRange(scope Scope, from, to time.Time, limit int) ([]Row, error) {
	if scope.TenantID == "" {
		return nil, ErrNoScope
	}
	if limit <= 0 || limit > maxRangeRows {
		limit = maxRangeRows
	}
	q := `SELECT tenant_id,agent_id,dedup_key,kind,exec_id,binary,at,payload FROM telemetry
	      WHERE tenant_id = ? AND at >= ? AND at < ?`
	args := []any{scope.TenantID, from.UnixNano(), to.UnixNano()}
	if scope.Kind != "" {
		q += ` AND kind = ?`
		args = append(args, scope.Kind)
	}
	q += ` ORDER BY at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

// QueryRange implements RangeQuerier for the Postgres central store.
//
// Runs under the same RLS transaction as every other read: the tenant filter is
// enforced by the database policy, not by this WHERE clause. The (tenant_id,
// kind, at DESC) index added after the 2026-08-05 outage makes this an index
// range scan rather than the full-table sort that took that deployment down.
func (s *PGStore) QueryRange(scope Scope, from, to time.Time, limit int) ([]Row, error) {
	if scope.TenantID == "" {
		return nil, ErrNoScope
	}
	if limit <= 0 || limit > maxRangeRows {
		limit = maxRangeRows
	}
	var out []Row
	err := s.withTenant(scope.TenantID, func(tx *sql.Tx) error {
		// No tenant predicate: RLS supplies it (see PGStore's doc comment).
		q := `SELECT tenant_id,agent_id,dedup_key,kind,exec_id,"binary",at,payload FROM telemetry
		      WHERE at >= $1 AND at < $2`
		args := []any{from.UnixNano(), to.UnixNano()}
		if scope.Kind != "" {
			q += ` AND kind = $3`
			args = append(args, scope.Kind)
		}
		q += ` ORDER BY at DESC LIMIT $` + strconv.Itoa(len(args)+1)
		args = append(args, limit)
		rows, err := tx.Query(q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		out, err = scanRows(rows)
		return err
	})
	return out, err
}
