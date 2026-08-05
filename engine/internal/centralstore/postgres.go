package centralstore

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
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
-- Every operator read is "newest N rows for this tenant, optionally of one
-- kind": WHERE kind = $1 ORDER BY at DESC LIMIT $2, with RLS supplying the
-- tenant predicate. The primary key leads with tenant_id but cannot order by
-- "at", so without these indexes Postgres scans the tenant's entire history and
-- top-N sorts it — per request.
--
-- That is not a tuning nicety. It took the production control plane down on
-- 2026-08-05 with only 2.8M rows (~1 GB of data): the console polls
-- /api/policy-stats continuously, each sort took longer than the poll interval,
-- and because the Go pool was unbounded every overlap opened another Postgres
-- connection until max_connections (100) was exhausted. Every store-backed
-- endpoint then returned HTTP 500 at once, the box sat at load 106 on 2 vCPUs,
-- and the sorts spilled 20 GB of pgsql_tmp until the disk hit 100%. Adding the
-- index took the same query from >10 minutes to 7 ms.
CREATE INDEX IF NOT EXISTS telemetry_tenant_kind_at ON telemetry (tenant_id, kind, at DESC);
CREATE INDEX IF NOT EXISTS telemetry_tenant_at      ON telemetry (tenant_id, at DESC);
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

// Connection pool bounds. Sized against a stock max_connections of 100: the
// control plane is one of several clients (psql, pg_dump backups, the readiness
// probe), and leaving most of the server's budget unclaimed is what keeps an
// overloaded control plane diagnosable instead of locking every operator out.
//
// Idle connections are capped and aged out so a burst does not leave the pool
// permanently holding connections the server could give to someone else.
const (
	maxOpenConns    = 20
	maxIdleConns    = 10
	connMaxLifetime = 30 * time.Minute
	connMaxIdleTime = 5 * time.Minute
)

// readPathIndexes are the indexes the operator read path depends on. They live
// in pgSchema too (fresh databases get them at provisioning, on an empty table,
// instantly) — but an ALREADY-provisioned database never re-runs pgSchema,
// because schemaReady deliberately short-circuits the DDL to avoid locking a
// live table. So every deployment that existed before these indexes did would
// have gone on full-scanning forever. ensureIndexes is that migration.
var readPathIndexes = []struct{ name, create string }{
	{"telemetry_tenant_kind_at", `CREATE INDEX CONCURRENTLY IF NOT EXISTS telemetry_tenant_kind_at ON telemetry (tenant_id, kind, at DESC)`},
	{"telemetry_tenant_at", `CREATE INDEX CONCURRENTLY IF NOT EXISTS telemetry_tenant_at ON telemetry (tenant_id, at DESC)`},
}

// ensureIndexes builds any missing read-path index, CONCURRENTLY, in the
// background.
//
// CONCURRENTLY takes SHARE UPDATE EXCLUSIVE rather than ACCESS EXCLUSIVE, so
// agents keep writing throughout — the whole point, since on a multi-gigabyte
// telemetry table this takes minutes and a blocking build would stall the fleet
// for all of them. It runs in a goroutine so a restart never waits on it.
//
// Intended to be called as `go ensureIndexes(db)`.
func ensureIndexes(db *sql.DB) {
	for _, ix := range readPathIndexes {
		var valid bool
		err := db.QueryRow(
			`SELECT i.indisvalid FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid WHERE c.relname = $1`,
			ix.name).Scan(&valid)
		switch {
		case err == nil && valid:
			continue // already present and usable by the planner
		case err == nil && !valid:
			// A previous CONCURRENTLY build failed partway and left an INVALID
			// index behind. The planner ignores it, but CREATE INDEX IF NOT
			// EXISTS sees it and skips — so without this drop the table would
			// never get a working index, and the failure would be permanent
			// and silent.
			slog.Warn("dropping invalid index from a failed build", "index", ix.name)
			if _, err := db.Exec(`DROP INDEX CONCURRENTLY IF EXISTS ` + ix.name); err != nil {
				slog.Error("could not drop invalid index", "index", ix.name, "error", err)
				continue
			}
		case errors.Is(err, sql.ErrNoRows):
			// Missing: build it.
		default:
			slog.Error("could not probe index", "index", ix.name, "error", err)
			continue
		}

		slog.Info("building read-path index (concurrent; writes continue)", "index", ix.name)
		start := time.Now()
		if _, err := db.Exec(ix.create); err != nil {
			slog.Error("read-path index build failed; operator reads will full-scan until this succeeds",
				"index", ix.name, "error", err)
			continue
		}
		slog.Info("read-path index ready", "index", ix.name, "took", time.Since(start).String())
	}
}

// OpenPostgres connects, creates the schema + RLS policy, and ensures the
// non-superuser app role exists.
func OpenPostgres(dsn string) (*PGStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	// database/sql defaults MaxOpenConns to UNLIMITED. That default is what
	// turned a slow-query problem into a total outage: when reads outran the
	// console's poll interval, every overlapping request opened another
	// Postgres connection instead of waiting for one, until the server hit
	// max_connections (100) and answered "sorry, too many clients already" —
	// to everything, including the health surfaces meant to report the fault.
	//
	// A bounded pool converts that failure into backpressure: request N+1
	// waits for a free connection rather than manufacturing one, so overload
	// degrades into latency instead of a cascading 500 across every endpoint.
	// The ceiling stays well under a stock max_connections so psql, backups and
	// the readiness probe always have room to get in and diagnose.
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)
	db.SetConnMaxIdleTime(connMaxIdleTime)
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
		go ensureIndexes(db)
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
	// pgSchema just built these on an empty table, so this is a cheap no-op
	// here; it runs anyway so there is exactly one path that guarantees them.
	go ensureIndexes(db)
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
