package centralstore

import (
	"database/sql"
	"log/slog"
	"time"
)

// The tenant roster.
//
// migration 0001 created this table and nothing ever wrote to it — the third
// of three dead tables from that migration. It is not merely unused: agents
// has a foreign key onto it, so the agent roster could not be populated at all
// until tenants existed. That surfaced the moment the roster started writing:
//
//	insert or update on table "agents" violates foreign key constraint
//	"agents_tenant_id_fkey"
//
// It also carries retention_days, the per-tenant retention control that has
// been described as "in the schema and nothing reads it".
type Tenant struct {
	TenantID      string    `json:"tenant_id"`
	DisplayName   string    `json:"display_name"`
	Status        string    `json:"status"`
	RetentionDays int       `json:"retention_days"`
	CreatedAt     time.Time `json:"created_at"`
}

// EnsureTenant records that a tenant exists, without touching anything an
// operator may have set.
//
// DO NOTHING on conflict rather than DO UPDATE: this is called from the
// heartbeat path, and the only thing it knows is the tenant id from the
// agent's certificate. Overwriting display_name or retention_days from that
// would erase an operator's retention policy every thirty seconds.
func (s *PGStore) EnsureTenant(tenantID string) {
	if tenantID == "" {
		return
	}
	if _, err := s.db.Exec(
		`INSERT INTO tenants (tenant_id) VALUES ($1) ON CONFLICT (tenant_id) DO NOTHING`,
		tenantID); err != nil {
		slog.Error("tenant not recorded", "tenant", tenantID, "error", err)
	}
}

// RetentionDaysFor returns a tenant's configured retention, or 0 when it has
// none and the deployment default should stand.
//
// Zero rather than a guessed default: the caller already knows the deployment
// value, and returning a made-up 90 here would silently override an operator's
// EBPF_SOC_RETAIN_EVENT_DAYS with a number this function invented.
//
// NULL is the unset state — see migration 0009. Before it, the column defaulted
// to 90 with CHECK (> 0), so "the operator has chosen nothing" was
// unrepresentable and every tenant on a normal deployment resolved to a
// 90-day request against a 30-day deployment. The console dutifully reported
// that as "this setting is not doing what it says", on every tenant, forever.
func (s *PGStore) RetentionDaysFor(tenantID string) int {
	var days sql.NullInt64
	if err := s.db.QueryRow(
		`SELECT retention_days FROM tenants WHERE tenant_id = $1`, tenantID).Scan(&days); err != nil {
		return 0
	}
	if !days.Valid || days.Int64 <= 0 {
		return 0
	}
	return int(days.Int64)
}

// SetRetentionDays sets one tenant's retention; days <= 0 clears it, and the
// deployment default takes over again.
//
// Clearing writes NULL rather than 0. The CHECK constraint refuses a
// non-positive value, so before migration 0009 the documented way back to the
// deployment default was a constraint violation — the control accepted "clear"
// and the database refused it.
//
// The floor that protects the console's window deltas lives in the retention
// runner, which clamps whatever it is given. Two guards, because a retention
// shorter than the largest console window turns a visible disk problem into an
// invisible correctness one.
func (s *PGStore) SetRetentionDays(tenantID string, days int) error {
	var v any
	if days > 0 {
		v = days
	} // else nil: the SQL NULL that means "no tenant choice"
	_, err := s.db.Exec(
		`INSERT INTO tenants (tenant_id, retention_days) VALUES ($1,$2)
		 ON CONFLICT (tenant_id) DO UPDATE SET retention_days = EXCLUDED.retention_days`,
		tenantID, v)
	return err
}

// Tenants lists every tenant this control plane knows.
func (s *PGStore) Tenants() ([]Tenant, error) {
	rows, err := s.db.Query(
		`SELECT tenant_id, display_name, status, retention_days, created_at FROM tenants ORDER BY tenant_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Tenant{}
	for rows.Next() {
		var t Tenant
		var days sql.NullInt64
		if err := rows.Scan(&t.TenantID, &t.DisplayName, &t.Status, &days, &t.CreatedAt); err != nil {
			return nil, err
		}
		if days.Valid {
			t.RetentionDays = int(days.Int64)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
