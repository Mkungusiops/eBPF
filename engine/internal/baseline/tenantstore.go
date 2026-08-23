package baseline

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Tenant-scoped persistence for the control plane's per-tenant profiles.
//
// # Why this is a separate store from the host one
//
// Store (persist.go) keys on (facet, key) and lives inside one sensor's own
// database, where every row belongs to that host by construction. The control
// plane holds one profile PER TENANT in a shared database, so the same data
// needs a tenant column, and the moment it has one it falls under the isolation
// invariant like every other tenant-partitioned table: RLS enabled, RLS FORCED,
// every statement running as a non-superuser with app.tenant_id set.
//
// A behavioural profile is not innocuous data. It is a precise description of
// what a tenant's estate does all day — which binaries, which users, which
// lineages, at which hours. Leaking one across tenants would be worse than
// leaking a page of alerts.
//
// # Why it exists at all
//
// The tenant profile was in-memory only, so it relearned from nothing on every
// control-plane restart and spent its warm-up window reporting ready=false. A
// restart is exactly when an operator is watching, and "deploy the new build"
// and "switch the cross-host view off for half an hour" were the same action.
//
// It does NOT reintroduce the query that caused the 2026-08-05 outage. Nothing
// here touches `telemetry`. The profile is fed from the ingest stream as
// before; this only snapshots the resulting bounded key set — a few thousand
// rows per tenant — and reads it back once at startup.

const tenantSchema = `
CREATE TABLE IF NOT EXISTS baseline_tenant_counts (
  tenant_id  TEXT NOT NULL,
  facet      TEXT NOT NULL,
  key        TEXT NOT NULL,
  weight     DOUBLE PRECISION NOT NULL,
  count      BIGINT NOT NULL,
  first_seen TIMESTAMPTZ NOT NULL,
  last_seen  TIMESTAMPTZ NOT NULL,
  total      DOUBLE PRECISION NOT NULL,
  total_at   TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, facet, key)
);

CREATE TABLE IF NOT EXISTS baseline_tenant_meta (
  tenant_id    TEXT PRIMARY KEY,
  observations BIGINT NOT NULL,
  oldest       TIMESTAMPTZ,
  newest       TIMESTAMPTZ,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE baseline_tenant_counts ENABLE ROW LEVEL SECURITY;
ALTER TABLE baseline_tenant_counts FORCE  ROW LEVEL SECURITY;
ALTER TABLE baseline_tenant_meta   ENABLE ROW LEVEL SECURITY;
ALTER TABLE baseline_tenant_meta   FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON baseline_tenant_counts;
CREATE POLICY tenant_isolation ON baseline_tenant_counts
  USING      (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS tenant_isolation ON baseline_tenant_meta;
CREATE POLICY tenant_isolation ON baseline_tenant_meta
  USING      (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
`

// Pool ceilings, matching internal/chatstore. The unbounded default is what
// exhausted max_connections on 2026-08-05; a second pool must not reintroduce
// it just because it is small and occasional.
const (
	maxOpenConns    = 4
	maxIdleConns    = 2
	connMaxLifetime = 30 * time.Minute
	connMaxIdleTime = 5 * time.Minute
)

// TenantStore persists per-tenant profiles under RLS.
type TenantStore struct {
	db   *sql.DB
	role string
	// ownsDB is true only when this store opened the pool, so Close never takes
	// down a pool somebody else handed in.
	ownsDB bool
}

// OpenPostgres connects on its own bounded pool and provisions the schema.
//
// role must be the same non-superuser role the rest of the application drops
// to (centralstore.AppRole): RLS is bypassed by a superuser even with FORCE,
// so dropping privilege is not optional.
func OpenPostgres(dsn, role string) (*TenantStore, error) {
	if strings.TrimSpace(role) == "" {
		return nil, fmt.Errorf("baseline: no app role given; pass centralstore.AppRole")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)
	db.SetConnMaxIdleTime(connMaxIdleTime)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(tenantSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("baseline: provisioning tenant tables: %w", err)
	}
	if _, err := db.Exec(
		`GRANT SELECT, INSERT, UPDATE, DELETE ON baseline_tenant_counts, baseline_tenant_meta TO ` +
			quoteIdent(role)); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("baseline: granting to %s: %w", role, err)
	}
	return &TenantStore{db: db, role: role, ownsDB: true}, nil
}

func (t *TenantStore) Close() error {
	if t == nil || !t.ownsDB {
		return nil
	}
	return t.db.Close()
}

// quoteIdent guards the one place an identifier is interpolated: SET ROLE and
// GRANT take no parameters.
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// withTenant runs fn inside a transaction scoped to one tenant.
func (t *TenantStore) withTenant(tenant string, fn func(*sql.Tx) error) error {
	if strings.TrimSpace(tenant) == "" {
		// Fail closed. A blank tenant would set app.tenant_id to '' and match
		// no rows — which is safe but silent, and silence here means a profile
		// that never persists and nobody notices.
		return fmt.Errorf("baseline: refusing a tenant-scoped write with no tenant")
	}
	tx, err := t.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec("SET LOCAL ROLE " + quoteIdent(t.role)); err != nil {
		return fmt.Errorf("baseline: drop privilege: %w", err)
	}
	if _, err := tx.Exec("SELECT set_config('app.tenant_id', $1, true)", tenant); err != nil {
		return fmt.Errorf("baseline: set tenant: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Save replaces one tenant's stored profile.
//
// DELETE then INSERT, like the host store and for the same reason: an upsert
// would leave keys that eviction dropped in the database forever, so a profile
// bounded in memory would be unbounded on disk.
func (t *TenantStore) Save(tenant string, snap Snapshot) error {
	return t.withTenant(tenant, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM baseline_tenant_counts WHERE tenant_id = $1`, tenant); err != nil {
			return err
		}
		ins, err := tx.Prepare(`INSERT INTO baseline_tenant_counts
			(tenant_id, facet, key, weight, count, first_seen, last_seen, total, total_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`)
		if err != nil {
			return err
		}
		defer func() { _ = ins.Close() }()
		for _, r := range snap.Rows {
			if _, err := ins.Exec(tenant, r.Facet, r.Key, r.Weight, r.Count,
				r.FirstSeen, r.LastSeen, r.Total, r.TotalAt); err != nil {
				return err
			}
		}
		_, err = tx.Exec(`INSERT INTO baseline_tenant_meta (tenant_id, observations, oldest, newest, updated_at)
			VALUES ($1,$2,$3,$4, now())
			ON CONFLICT (tenant_id) DO UPDATE SET
			  observations = EXCLUDED.observations,
			  oldest = EXCLUDED.oldest,
			  newest = EXCLUDED.newest,
			  updated_at = now()`,
			tenant, snap.Observations, nullTime(snap.Oldest), nullTime(snap.Newest))
		return err
	})
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// Load reads one tenant's stored profile. A tenant with nothing stored returns
// an empty snapshot and no error — that is a first run, not a failure.
func (t *TenantStore) Load(tenant string) (Snapshot, error) {
	var snap Snapshot
	err := t.withTenant(tenant, func(tx *sql.Tx) error {
		var oldest, newest sql.NullTime
		row := tx.QueryRow(`SELECT observations, oldest, newest FROM baseline_tenant_meta WHERE tenant_id = $1`, tenant)
		if err := row.Scan(&snap.Observations, &oldest, &newest); err != nil {
			if err == sql.ErrNoRows {
				return nil
			}
			return err
		}
		snap.Oldest, snap.Newest = oldest.Time, newest.Time

		rows, err := tx.Query(`SELECT facet, key, weight, count, first_seen, last_seen, total, total_at
			FROM baseline_tenant_counts WHERE tenant_id = $1`, tenant)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var r SnapshotRow
			if err := rows.Scan(&r.Facet, &r.Key, &r.Weight, &r.Count,
				&r.FirstSeen, &r.LastSeen, &r.Total, &r.TotalAt); err != nil {
				return err
			}
			snap.Rows = append(snap.Rows, r)
		}
		// A partial result must not read as "the profile is this small" — that
		// silently narrows what a tenant considers normal.
		return rows.Err()
	})
	return snap, err
}

// Tenants lists every tenant with a stored profile, so the control plane can
// restore them all at startup without being told which exist.
//
// This is the ONE cross-tenant read here, and it deliberately returns ids only,
// never profile content. It runs as the owner rather than under RLS because a
// per-tenant scoped read cannot enumerate tenants it does not already know —
// the same reason centralstore keeps an explicit, separate QueryAcross path.
func (t *TenantStore) Tenants() ([]string, error) {
	rows, err := t.db.Query(`SELECT tenant_id FROM baseline_tenant_meta ORDER BY tenant_id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
