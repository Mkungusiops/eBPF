package centralstore

import (
	"database/sql"
	"log/slog"
	"time"
)

// The durable record of who did what on the control plane.
//
// migration 0001 created operator_audit — subject, tenant, action, allowed,
// detail — and no code ever wrote to it. What stood in for it was an in-memory
// slice, appended without bound, read only by tests, and erased by a restart.
// So on an MSSP control plane the question "which operator read which
// customer's data" had no answer at all.
//
// That is distinct from the decision chain: that records what the PLATFORM
// did, this records what a PERSON did. A regulator asks both.
type OperatorAudit struct {
	Subject     string    `json:"subject"`
	TenantID    string    `json:"tenant_id"`
	Action      string    `json:"action"`
	Allowed     bool      `json:"allowed"`
	CrossTenant bool      `json:"cross_tenant"`
	Detail      string    `json:"detail,omitempty"`
	At          time.Time `json:"at"`
}

// RecordAccess implements authz.AccessAuditor against Postgres.
//
// # Why this never returns an error
//
// It is called from inside the authorization decision, and a failure to write
// the audit must not deny an operator their access — an audit backend outage
// would otherwise lock every tenant out of their own console. Logged instead,
// at error level, because the consequence is silent: authorization keeps
// working and the trail stops.
//
// The inverse trade would be defensible for a bank. It is not for a platform
// whose whole purpose is being reachable during an incident.
func (s *PGStore) RecordAccess(subject, tenant, action string, allowed, crossTenant bool, detail string) {
	// Own-tenant reads are the overwhelming majority and carry no information:
	// an operator reading their own tenant is the system working. Recording
	// every one would bury the cross-tenant and denied entries an auditor is
	// actually looking for, and turn the table into a write-amplifier on the
	// read path.
	if allowed && !crossTenant {
		return
	}
	// Not scoped by RLS: this table records access ACROSS tenants, including
	// denied attempts on tenants the caller has no grant for, so a
	// tenant-scoped write would refuse exactly the rows that matter most.
	_, err := s.db.Exec(
		`INSERT INTO operator_audit (subject, tenant_id, action, allowed, detail)
		 VALUES ($1,$2,$3,$4,$5)`,
		subject, tenant, action, allowed, detail)
	if err != nil {
		slog.Error("operator access not recorded", "subject", subject, "tenant", tenant,
			"action", action, "allowed", allowed, "error", err)
	}
}

// RecordCrossTenant satisfies the older authz.Auditor interface.
func (s *PGStore) RecordCrossTenant(subject, tenant, action string) {
	s.RecordAccess(subject, tenant, action, true, true, "")
}

// OperatorAuditRecent returns the newest operator access records.
//
// Unscoped by tenant on purpose: the rows worth reading are the cross-tenant
// and denied ones, and both are about a tenant boundary being crossed or
// refused. Restricted to cross-tenant operators at the handler.
func (s *PGStore) OperatorAuditRecent(limit int) ([]OperatorAudit, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.Query(
		`SELECT subject, tenant_id, action, allowed, detail, at
		 FROM operator_audit ORDER BY at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanOperatorAudit(rows)
}

// OperatorAuditForTenant returns the access records that concern ONE tenant.
//
// # Why a tenant-bound analyst gets to read this at all
//
// On an MSSP control plane the customer is not the operator. Safaricom's own
// analysts cannot see which MSOC engineer opened their estate at 3am unless
// the platform tells them, and "trust us, it is logged" is not a transparency
// control — it is a promise about a table only the provider can read.
//
// So the same rows are served to both, cut differently: a cross-tenant
// operator sees the whole trail including attempts on tenants they were
// refused, and a tenant-bound analyst sees exactly the rows naming their own
// tenant. Neither view invents a row the other cannot see.
func (s *PGStore) OperatorAuditForTenant(tenant string, limit int) ([]OperatorAudit, error) {
	if tenant == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.Query(
		`SELECT subject, tenant_id, action, allowed, detail, at
		 FROM operator_audit WHERE tenant_id = $1 ORDER BY at DESC LIMIT $2`, tenant, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanOperatorAudit(rows)
}

// OperatorAuditCount reports how many records exist, so a view showing the
// newest N can say what it is NOT showing rather than implying it is all.
func (s *PGStore) OperatorAuditCount(tenant string) (int, error) {
	q, args := `SELECT count(*) FROM operator_audit`, []any{}
	if tenant != "" {
		q += ` WHERE tenant_id = $1`
		args = append(args, tenant)
	}
	var n int
	if err := s.db.QueryRow(q, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func scanOperatorAudit(rows *sql.Rows) ([]OperatorAudit, error) {
	out := []OperatorAudit{}
	for rows.Next() {
		var r OperatorAudit
		var detail sql.NullString
		if err := rows.Scan(&r.Subject, &r.TenantID, &r.Action, &r.Allowed, &detail, &r.At); err != nil {
			return nil, err
		}
		r.Detail = detail.String
		// Derived rather than stored: a row is here because it was denied or
		// crossed a boundary, and an allowed row can only be the latter.
		r.CrossTenant = r.Allowed
		out = append(out, r)
	}
	return out, rows.Err()
}
