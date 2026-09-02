package centralstore

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Per-tenant scoring suppressions.
//
// Every read and write goes through withTenant, so RLS enforces isolation at
// the database rather than in a WHERE clause a future refactor could drop. A
// suppression states what one tenant stops detecting; a cross-tenant leak here
// would let one customer blind another, which is the isolation invariant this
// platform is built around.
type Suppression struct {
	ID        int64     `json:"id"`
	Binary    string    `json:"binary"`
	Policy    string    `json:"policy,omitempty"`
	Parent    string    `json:"parent,omitempty"`
	Reason    string    `json:"reason"`
	Actor     string    `json:"actor"`
	CreatedAt time.Time `json:"created_at"`
}

// Validate mirrors the engine's rule exactly. Two implementations of "what is
// a valid suppression" would drift, and the drift would show up as a rule the
// console accepted and an agent refused.
func (s Suppression) Validate() error {
	if strings.TrimSpace(s.Binary) == "" {
		return fmt.Errorf("a suppression needs a binary path")
	}
	if !strings.HasPrefix(s.Binary, "/") {
		return fmt.Errorf("binary must be an absolute path, got %q — matching is exact, "+
			"so a bare name would never fire and would look like a working rule", s.Binary)
	}
	if len(strings.TrimSpace(s.Reason)) < 3 {
		return fmt.Errorf("a suppression needs a reason: it is a deliberate reduction in what this platform detects")
	}
	return nil
}

// Suppressions lists a tenant's rules, newest first.
func (s *PGStore) Suppressions(tenant string) ([]Suppression, error) {
	if tenant == "" {
		return nil, ErrNoScope
	}
	out := []Suppression{}
	err := s.withTenant(tenant, func(tx *sql.Tx) error {
		rows, err := tx.Query(
			`SELECT id, binary_path, policy, parent, reason, actor, created_at
			 FROM tenant_suppressions ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var x Suppression
			if err := rows.Scan(&x.ID, &x.Binary, &x.Policy, &x.Parent, &x.Reason, &x.Actor, &x.CreatedAt); err != nil {
				return err
			}
			out = append(out, x)
		}
		return rows.Err()
	})
	return out, err
}

// AddSuppression upserts one for a tenant.
func (s *PGStore) AddSuppression(tenant string, sup *Suppression) error {
	if tenant == "" {
		return ErrNoScope
	}
	if err := sup.Validate(); err != nil {
		return err
	}
	return s.withTenant(tenant, func(tx *sql.Tx) error {
		return tx.QueryRow(
			`INSERT INTO tenant_suppressions (tenant_id, binary_path, policy, parent, reason, actor)
			 VALUES ($1,$2,$3,$4,$5,$6)
			 ON CONFLICT (tenant_id, binary_path, policy, parent)
			 DO UPDATE SET reason = EXCLUDED.reason, actor = EXCLUDED.actor, created_at = now()
			 RETURNING id, created_at`,
			tenant, sup.Binary, sup.Policy, sup.Parent, strings.TrimSpace(sup.Reason), sup.Actor,
		).Scan(&sup.ID, &sup.CreatedAt)
	})
}

// DeleteSuppression removes one. Reports whether a row actually went away, so
// the caller can tell "removed" from "was not there" instead of reporting
// success for a no-op.
func (s *PGStore) DeleteSuppression(tenant string, id int64) (bool, error) {
	if tenant == "" {
		return false, ErrNoScope
	}
	var gone bool
	err := s.withTenant(tenant, func(tx *sql.Tx) error {
		res, err := tx.Exec(`DELETE FROM tenant_suppressions WHERE id = $1`, id)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		gone = n > 0
		return nil
	})
	return gone, err
}
