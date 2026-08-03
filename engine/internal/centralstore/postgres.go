package centralstore

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
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

// schemaReady reports whether the database is already in the exact state the
// DDL would put it in: table present, RLS both ENABLED and FORCED, the
// tenant_isolation policy defined, the app role existing, and that role holding
// SELECT+INSERT on telemetry.
//
// Every condition here corresponds to one statement in the provisioning path,
// so a false means something is genuinely missing and the DDL must run. It
// reads only catalogue views, which take no lock on `telemetry` — that is the
// entire point, since locking that table is what wedged the control plane.
//
// FORCE matters as much as ENABLE: without it the table owner bypasses RLS
// entirely, so a database with RLS enabled but not forced is NOT provisioned
// and must not be treated as ready — that would silently disable the
// database-level half of tenant isolation.
func schemaReady(db *sql.DB) (bool, error) {
	var ready bool
	err := db.QueryRow(`
SELECT
  COALESCE((SELECT c.relrowsecurity AND c.relforcerowsecurity
              FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE c.relname = 'telemetry' AND n.nspname = current_schema()), false)
  AND EXISTS (SELECT 1 FROM pg_policies
               WHERE tablename = 'telemetry' AND policyname = 'tenant_isolation')
  AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)
  AND EXISTS (SELECT 1 FROM information_schema.role_table_grants
               WHERE table_name = 'telemetry' AND grantee = $1 AND privilege_type = 'SELECT')
  AND EXISTS (SELECT 1 FROM information_schema.role_table_grants
               WHERE table_name = 'telemetry' AND grantee = $1 AND privilege_type = 'INSERT')`,
		appRole).Scan(&ready)
	if err != nil {
		return false, err
	}
	return ready, nil
}

// startupLockTimeout bounds how long the DDL below will wait for a lock.
//
// Every one of those statements needs a lock on `telemetry`, and agents INSERT
// into that table continuously. Postgres defaults lock_timeout to 0 — wait
// FOREVER — so a restart that lands while the fleet is writing blocks in
// OpenPostgres and never returns. Observed in production: the control plane sat
// between "starting" and "postgres store ready" with nothing listening, while
// systemd cheerfully reported the unit as `active` and Postgres answered every
// other session normally. A second restart succeeded only because the agents
// had backed off by then.
//
// The failure mode gets MORE likely as the fleet grows: more agents means
// denser inserts means a smaller gap for the DDL to slip through. That is
// exactly backwards for a platform meant to scale, and it turns "restart the
// control plane" — the first thing anyone does — into a coin flip.
//
// Five seconds is far longer than an uncontended lock needs and short enough
// that a contended one fails fast with a clear error instead of hanging.
const startupLockTimeout = "5s"

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
	// Session-scoped: applies to this connection's DDL only, and is not
	// inherited by the pooled connections used for queries afterwards.
	if _, err := db.Exec(fmt.Sprintf("SET lock_timeout = '%s'", startupLockTimeout)); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("centralstore: set lock_timeout: %w", err)
	}

	// THE ROOT CAUSE, not just its symptom: skip the DDL entirely when the
	// schema is already what we want. The lock_timeout above turns an infinite
	// hang into a fast failure, which is a better failure — but it is still a
	// failure, and a control plane that cannot restart while its fleet is
	// writing is not fixed by failing quicker.
	//
	// Every restart used to re-run ALTER TABLE / DROP POLICY / CREATE POLICY /
	// GRANT against `telemetry`, each needing an ACCESS EXCLUSIVE lock on a
	// table agents INSERT into continuously. None of that work was ever
	// necessary on a healthy database: the statements are idempotent, so they
	// were paying a lock to arrive at the state they were already in.
	//
	// Checking first costs one catalogue query against pg_class/pg_policies/
	// pg_roles — no lock on telemetry at all — so the common path (restart an
	// already-provisioned control plane) no longer contends with the fleet.
	// First boot, or a database someone has altered underneath us, still runs
	// the full DDL and still needs its lock.
	provisioned, err := schemaReady(db)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("centralstore: schema probe: %w", err)
	}
	if provisioned {
		return &PGStore{db: db}, nil
	}

	if _, err := db.Exec(pgSchema); err != nil {
		_ = db.Close()
		// A lock_timeout expiry here is contention, not corruption: agents are
		// writing and the DDL could not get its lock. Say so, because
		// "centralstore: schema: ..." alone sends an operator hunting a
		// migration problem that does not exist.
		return nil, fmt.Errorf("centralstore: schema (retry in a moment if this is lock contention with agent writes): %w", err)
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
		// Newest-first: an operator console shows recent activity, and the LIMIT
		// must take the most recent rows. RLS supplies the tenant filter; an
		// optional kind narrows to alerts/events/decisions.
		q := `SELECT tenant_id,agent_id,dedup_key,kind,exec_id,"binary",at,payload FROM telemetry`
		args := []any{}
		if scope.Kind != "" {
			args = append(args, scope.Kind)
			q += ` WHERE kind = $1`
		}
		args = append(args, limit)
		q += ` ORDER BY at DESC LIMIT $` + strconv.Itoa(len(args))
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
