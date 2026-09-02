package centralstore

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Per-tenant change control (threat-model EN-2): whether a destructive
// containment action has to be approved by a second operator.
//
// The switch used to be a startup flag, which meant a tenant that decided
// mid-incident it wanted four-eyes had to edit a unit file and restart the
// control plane. Everything else the control needs — the queue, the four-eyes
// check in approval.Store.Decide, the TTL, and the rule that nothing which
// STOPS enforcement may wait on a quorum — already existed.
type ChangeControl struct {
	RequireApproval bool      `json:"require_approval"`
	Reason          string    `json:"reason"`
	Actor           string    `json:"actor"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// ErrNoChangeControlRow reports that a tenant has never set this, so the
// caller must fall back to the deployment default.
//
// A distinct error rather than a zero value: "this tenant chose OFF" and "this
// tenant has never chosen" must not collapse into the same false, because a
// deployment whose default is ON would then be silently downgraded by the
// absence of a row.
var ErrNoChangeControlRow = errors.New("centralstore: no change-control row for this tenant")

// ChangeControlFor reads one tenant's setting.
func (s *PGStore) ChangeControlFor(tenant string) (ChangeControl, error) {
	var cc ChangeControl
	if tenant == "" {
		return cc, ErrNoScope
	}
	err := s.withTenant(tenant, func(tx *sql.Tx) error {
		row := tx.QueryRow(
			`SELECT require_approval, reason, actor, updated_at FROM tenant_change_control`)
		switch err := row.Scan(&cc.RequireApproval, &cc.Reason, &cc.Actor, &cc.UpdatedAt); {
		case errors.Is(err, sql.ErrNoRows):
			return ErrNoChangeControlRow
		case err != nil:
			return err
		}
		return nil
	})
	return cc, err
}

// SetChangeControl upserts one tenant's setting.
//
// A reason is mandatory in both directions. Turning four-eyes ON is a safety
// improvement and still deserves a record of who decided it; turning it OFF
// removes a control an auditor will ask about, and an empty reason under time
// pressure is how that question goes unanswered.
func (s *PGStore) SetChangeControl(tenant string, require bool, reason, actor string) (ChangeControl, error) {
	cc := ChangeControl{RequireApproval: require, Reason: strings.TrimSpace(reason), Actor: actor}
	if tenant == "" {
		return cc, ErrNoScope
	}
	if len(cc.Reason) < 3 {
		return cc, fmt.Errorf("a reason is required: this decides whether a second operator must approve a sever")
	}
	err := s.withTenant(tenant, func(tx *sql.Tx) error {
		return tx.QueryRow(
			`INSERT INTO tenant_change_control (tenant_id, require_approval, reason, actor, updated_at)
			 VALUES ($1,$2,$3,$4, now())
			 ON CONFLICT (tenant_id) DO UPDATE SET
			   require_approval = EXCLUDED.require_approval,
			   reason = EXCLUDED.reason, actor = EXCLUDED.actor, updated_at = now()
			 RETURNING updated_at`,
			tenant, require, cc.Reason, actor).Scan(&cc.UpdatedAt)
	})
	return cc, err
}
