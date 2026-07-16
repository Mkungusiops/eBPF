package centralstore

import (
	"database/sql"
	"errors"
	"time"

	_ "github.com/ClickHouse/clickhouse-go/v2" // registers the "clickhouse" sql driver

	"google.golang.org/protobuf/proto"

	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
)

// chSchema partitions BY tenant_id (isolation + retention are tenant-scoped) and
// dedups on (tenant_id, agent_id, dedup_key) via ReplacingMergeTree. Production
// adds a time dimension to PARTITION BY for TTL retention tiers; the tenant
// partitioning — the isolation-relevant part — is identical.
const chSchema = "" +
	"CREATE TABLE IF NOT EXISTS telemetry (" +
	"  tenant_id String, agent_id String, dedup_key String, kind String," +
	"  exec_id String, `binary` String, at Int64, payload String," +
	"  ingested_at DateTime64(9) DEFAULT now64(9)" +
	") ENGINE = ReplacingMergeTree(ingested_at)" +
	" PARTITION BY tenant_id" +
	" ORDER BY (tenant_id, agent_id, dedup_key)"

// CHStore is the ClickHouse-backed central store for the events firehose — the
// high-volume Layer 3 backend (docs/plan/d4c-tech-decisions.md §3.2). Tenant is
// the partition key; every read is tenant-scoped by the shared data-access layer
// (the interface makes an unscoped read impossible — fail closed). Reads use
// FINAL so ReplacingMergeTree duplicates collapse at query time.
type CHStore struct{ db *sql.DB }

var _ TenantStore = (*CHStore)(nil)

// OpenClickHouse connects (dsn e.g. clickhouse://user:pass@host:9000/db) and
// creates the telemetry table.
func OpenClickHouse(dsn string) (*CHStore, error) {
	db, err := sql.Open("clickhouse", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(chSchema); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &CHStore{db: db}, nil
}

func (s *CHStore) Close() error { return s.db.Close() }

func (s *CHStore) Put(r ingest.StampedRecord) error {
	if r.TenantID == "" {
		return errors.New("centralstore: refusing to persist a record with no tenant stamp")
	}
	kind, execID, binary := classify(r.Record)
	payload, err := proto.Marshal(r.Record)
	if err != nil {
		return err
	}
	// ClickHouse INSERT via the database/sql batch pattern.
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare("INSERT INTO telemetry (tenant_id, agent_id, dedup_key, kind, exec_id, `binary`, at, payload)")
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := stmt.Exec(r.TenantID, r.AgentID, r.Record.GetDedupKey(), kind, execID, binary, time.Now().UnixNano(), string(payload)); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *CHStore) Count(scope Scope) (int, error) {
	if scope.TenantID == "" {
		return 0, ErrNoScope
	}
	var n uint64
	if err := s.db.QueryRow("SELECT count() FROM telemetry FINAL WHERE tenant_id = ?", scope.TenantID).Scan(&n); err != nil {
		return 0, err
	}
	return int(n), nil
}

func (s *CHStore) Query(scope Scope, limit int) ([]Row, error) {
	if scope.TenantID == "" {
		return nil, ErrNoScope
	}
	if limit <= 0 {
		limit = 1000
	}
	q := "SELECT tenant_id, agent_id, dedup_key, kind, exec_id, `binary`, at, payload " +
		"FROM telemetry FINAL WHERE tenant_id = ?"
	args := []any{scope.TenantID}
	if scope.Kind != "" {
		q += " AND kind = ?"
		args = append(args, scope.Kind)
	}
	q += " ORDER BY at DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

func (s *CHStore) QueryAcross(tenantIDs []string, limitPerTenant int) ([]Row, error) {
	if len(tenantIDs) == 0 {
		return nil, ErrNoScope
	}
	var out []Row
	for _, t := range tenantIDs {
		rs, err := s.Query(Scope{TenantID: t}, limitPerTenant)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	return out, nil
}
