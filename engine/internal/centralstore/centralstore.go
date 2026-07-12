// Package centralstore is the tenant-partitioned central store for stamped
// telemetry — the Layer 3 enforcement point of the tenant isolation invariant
// (docs/plan/tenant-isolation-invariant.md).
//
// Two properties are structural, not conventions:
//
//  1. tenant_id is part of the PRIMARY KEY, not an incidental column, so records
//     are physically partitioned by tenant.
//  2. Every read goes through a Scope carrying a non-empty tenant; a read with
//     no scope returns ErrNoScope (fails CLOSED — it never falls back to
//     returning another tenant's rows). There is no method that returns rows
//     without a tenant, except the explicit, separate cross-tenant path
//     (QueryAcross) reserved for an audited MSOC role.
//
// The SQLite backing (pure-Go modernc driver, so it stays CGO-free) is the
// Phase 1 stand-in for the Postgres + ClickHouse data platform of
// architecture.md §3.3; the tenant-scoping discipline is identical behind any
// backend.
package centralstore

import (
	"database/sql"
	"errors"
	"time"

	_ "modernc.org/sqlite"

	"google.golang.org/protobuf/proto"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
)

// ErrNoScope is returned by any read attempted without a tenant scope. The
// invariant fails closed: no tenant ⇒ no rows, never another tenant's rows.
var ErrNoScope = errors.New("centralstore: read requires a non-empty tenant scope (fail-closed)")

// Scope is the tenant a read is authorized for.
type Scope struct{ TenantID string }

// Row is a stored, tenant-stamped telemetry record.
type Row struct {
	TenantID string
	AgentID  string
	DedupKey string
	Kind     string // event | alert | decision
	ExecID   string
	Binary   string
	At       time.Time
	Record   *ebpfsocv1.TelemetryRecord
}

// Store is the tenant-partitioned telemetry store. It satisfies ingest.Sink.
type Store struct{ db *sql.DB }

var _ ingest.Sink = (*Store)(nil)

const schema = `
CREATE TABLE IF NOT EXISTS telemetry (
  tenant_id TEXT NOT NULL,
  agent_id  TEXT NOT NULL,
  dedup_key TEXT NOT NULL,
  kind      TEXT NOT NULL,
  exec_id   TEXT,
  binary    TEXT,
  at        INTEGER NOT NULL,
  payload   BLOB NOT NULL,
  PRIMARY KEY (tenant_id, agent_id, dedup_key)
);
CREATE INDEX IF NOT EXISTS idx_telemetry_tenant_at ON telemetry(tenant_id, at);
`

// Open opens (creating if needed) a central store at path. Use a file path for
// durability or ":memory:" for ephemeral use.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Put persists a stamped record. It refuses records with no tenant (the ingest
// collector must have stamped one) and is idempotent on
// (tenant_id, agent_id, dedup_key) — storage-level dedup, defense in depth
// alongside the collector's dedup.
func (s *Store) Put(r ingest.StampedRecord) error {
	if r.TenantID == "" {
		return errors.New("centralstore: refusing to persist a record with no tenant stamp")
	}
	kind, execID, binary := classify(r.Record)
	payload, err := proto.Marshal(r.Record)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT OR IGNORE INTO telemetry(tenant_id,agent_id,dedup_key,kind,exec_id,binary,at,payload)
		 VALUES(?,?,?,?,?,?,?,?)`,
		r.TenantID, r.AgentID, r.Record.GetDedupKey(), kind, execID, binary, time.Now().UnixNano(), payload)
	return err
}

// Count returns how many records are stored for the scoped tenant.
func (s *Store) Count(scope Scope) (int, error) {
	if scope.TenantID == "" {
		return 0, ErrNoScope
	}
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM telemetry WHERE tenant_id = ?`, scope.TenantID).Scan(&n)
	return n, err
}

// Query returns up to limit records for the scoped tenant, oldest first. It is
// the ONLY row-returning read, and it is impossible to call it without a tenant.
func (s *Store) Query(scope Scope, limit int) ([]Row, error) {
	if scope.TenantID == "" {
		return nil, ErrNoScope
	}
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.db.Query(
		`SELECT tenant_id,agent_id,dedup_key,kind,exec_id,binary,at,payload
		   FROM telemetry WHERE tenant_id = ? ORDER BY at LIMIT ?`, scope.TenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

// QueryAcross is the explicit, separate cross-tenant read reserved for an
// audited MSOC role. It requires the caller to name each tenant — there is no
// "all tenants" wildcard — so an accidental unscoped read is impossible. The
// AUTHORIZATION for this path (the cross-tenant role check + audit) lives in the
// API/authz layer (Layer 4); this method is the data-access primitive it calls.
func (s *Store) QueryAcross(tenantIDs []string, limitPerTenant int) ([]Row, error) {
	if len(tenantIDs) == 0 {
		return nil, ErrNoScope
	}
	var out []Row
	for _, t := range tenantIDs {
		rows, err := s.Query(Scope{TenantID: t}, limitPerTenant)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	return out, nil
}

func scanRows(rows *sql.Rows) ([]Row, error) {
	var out []Row
	for rows.Next() {
		var r Row
		var atNano int64
		var payload []byte
		if err := rows.Scan(&r.TenantID, &r.AgentID, &r.DedupKey, &r.Kind, &r.ExecID, &r.Binary, &atNano, &payload); err != nil {
			return nil, err
		}
		r.At = time.Unix(0, atNano)
		rec := &ebpfsocv1.TelemetryRecord{}
		if err := proto.Unmarshal(payload, rec); err == nil {
			r.Record = rec
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func classify(rec *ebpfsocv1.TelemetryRecord) (kind, execID, binary string) {
	switch p := rec.GetPayload().(type) {
	case *ebpfsocv1.TelemetryRecord_Event:
		return "event", p.Event.GetExecId(), p.Event.GetBinary()
	case *ebpfsocv1.TelemetryRecord_Alert:
		return "alert", p.Alert.GetExecId(), ""
	case *ebpfsocv1.TelemetryRecord_Decision:
		return "decision", p.Decision.GetExecId(), p.Decision.GetBinary()
	default:
		return "unknown", "", ""
	}
}
