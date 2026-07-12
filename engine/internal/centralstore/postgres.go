package centralstore

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // postgres driver ("pgx")

	"google.golang.org/protobuf/proto"

	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
)

// appRole is the non-superuser role the store drops to for every data access,
// so Row-Level Security is enforced (a superuser would bypass it).
const appRole = "ebpf_app"

const pgSchema = `
CREATE TABLE IF NOT EXISTS telemetry (
  tenant_id text NOT NULL,
  agent_id  text NOT NULL,
  dedup_key text NOT NULL,
  kind      text NOT NULL,
  exec_id   text NOT NULL DEFAULT '',
  "binary"  text NOT NULL DEFAULT '',
  at        bigint NOT NULL,
  payload   bytea NOT NULL,
  PRIMARY KEY (tenant_id, agent_id, dedup_key)
);
ALTER TABLE telemetry ENABLE ROW LEVEL SECURITY;
-- FORCE so RLS applies even to the table owner; without it the owner bypasses.
ALTER TABLE telemetry FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON telemetry;
CREATE POLICY tenant_isolation ON telemetry
  USING      (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
`

// PGStore is the PostgreSQL-backed, RLS-enforced central store — the Layer 3
// production backend (docs/plan/d4c-tech-decisions.md §3.3).
//
// Row-Level Security is a SECOND, database-level enforcement of tenant scoping
// beneath the app layer (internal/authz + internal/centralstore). Every access
// runs inside a transaction that (a) drops to a non-superuser role and (b) sets
// app.tenant_id; the RLS policy then filters by it. The read queries carry NO
// tenant WHERE clause — RLS does the scoping — so a forgotten filter cannot leak.
type PGStore struct{ db *sql.DB }

var _ TenantStore = (*PGStore)(nil)

// OpenPostgres connects, creates the schema + RLS policy, and ensures the
// non-superuser app role exists.
func OpenPostgres(dsn string) (*PGStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(pgSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("centralstore: schema: %w", err)
	}
	if _, err := db.Exec(fmt.Sprintf(`DO $$ BEGIN
	  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '%s') THEN
	    CREATE ROLE %s NOSUPERUSER NOLOGIN;
	  END IF;
	END $$;`, appRole, appRole)); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("centralstore: app role: %w", err)
	}
	if _, err := db.Exec(fmt.Sprintf(`GRANT SELECT, INSERT ON telemetry TO %s;`, appRole)); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &PGStore{db: db}, nil
}

func (s *PGStore) Close() error { return s.db.Close() }

// withTenant runs fn in a transaction scoped to tenant: it drops to the
// non-superuser app role and sets app.tenant_id, so RLS enforces isolation for
// every statement fn runs.
func (s *PGStore) withTenant(tenant string, fn func(*sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec("SET LOCAL ROLE " + appRole); err != nil {
		return err
	}
	if _, err := tx.Exec("SELECT set_config('app.tenant_id', $1, true)", tenant); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PGStore) Put(r ingest.StampedRecord) error {
	if r.TenantID == "" {
		return errors.New("centralstore: refusing to persist a record with no tenant stamp")
	}
	kind, execID, binary := classify(r.Record)
	payload, err := proto.Marshal(r.Record)
	if err != nil {
		return err
	}
	return s.withTenant(r.TenantID, func(tx *sql.Tx) error {
		_, err := tx.Exec(
			`INSERT INTO telemetry(tenant_id,agent_id,dedup_key,kind,exec_id,"binary",at,payload)
			 VALUES($1,$2,$3,$4,$5,$6,$7,$8)
			 ON CONFLICT (tenant_id,agent_id,dedup_key) DO NOTHING`,
			r.TenantID, r.AgentID, r.Record.GetDedupKey(), kind, execID, binary, time.Now().UnixNano(), payload)
		return err
	})
}

func (s *PGStore) Count(scope Scope) (int, error) {
	if scope.TenantID == "" {
		return 0, ErrNoScope
	}
	var n int
	err := s.withTenant(scope.TenantID, func(tx *sql.Tx) error {
		// No WHERE clause: RLS scopes it. This is the defense-in-depth proof.
		return tx.QueryRow(`SELECT COUNT(*) FROM telemetry`).Scan(&n)
	})
	return n, err
}

func (s *PGStore) Query(scope Scope, limit int) ([]Row, error) {
	if scope.TenantID == "" {
		return nil, ErrNoScope
	}
	if limit <= 0 {
		limit = 1000
	}
	var out []Row
	err := s.withTenant(scope.TenantID, func(tx *sql.Tx) error {
		rows, err := tx.Query(
			`SELECT tenant_id,agent_id,dedup_key,kind,exec_id,"binary",at,payload
			   FROM telemetry ORDER BY at LIMIT $1`, limit) // RLS supplies the tenant filter
		if err != nil {
			return err
		}
		defer rows.Close()
		out, err = scanRows(rows)
		return err
	})
	return out, err
}

func (s *PGStore) QueryAcross(tenantIDs []string, limitPerTenant int) ([]Row, error) {
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
