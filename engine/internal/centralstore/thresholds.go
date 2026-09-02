package centralstore

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
)

// The containment ladder as a per-tenant policy.
//
// It already persists per host, so an operator's change survives a restart.
// This is the other half: an agent enrolled tomorrow would otherwise start on
// whatever the deploy configured, silently ignoring a ladder its tenant chose.
// On a control plane running many customers that is the difference between a
// policy and a per-box preference.
type TenantThresholds struct {
	Config    circuit.Config `json:"config"`
	Reason    string         `json:"reason"`
	Actor     string         `json:"actor"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// ErrNoTenantThresholds reports that a tenant has never set a ladder, which is
// distinct from one that happens to match the deploy default.
var ErrNoTenantThresholds = errors.New("centralstore: no ladder stored for this tenant")

// ThresholdsFor reads a tenant's ladder.
func (s *PGStore) ThresholdsFor(tenant string) (TenantThresholds, error) {
	var t TenantThresholds
	if tenant == "" {
		return t, ErrNoScope
	}
	err := s.withTenant(tenant, func(tx *sql.Tx) error {
		row := tx.QueryRow(`SELECT throttle_at, tarpit_at, quarantine_at, sever_at,
		                           reason, actor, updated_at FROM tenant_thresholds`)
		switch err := row.Scan(&t.Config.ThrottleAt, &t.Config.TarpitAt, &t.Config.QuarantineAt,
			&t.Config.SeverAt, &t.Reason, &t.Actor, &t.UpdatedAt); {
		case errors.Is(err, sql.ErrNoRows):
			return ErrNoTenantThresholds
		case err != nil:
			return err
		}
		return nil
	})
	if err != nil {
		return t, err
	}
	// Validated on the way OUT as well as in. This value is read when an agent
	// enrols, with no operator watching, and a ladder that somehow got past the
	// CHECK constraint would arrive at a host that severs everything it tracks.
	if err := t.Config.Validate(); err != nil {
		return t, err
	}
	return t, nil
}

// SetThresholds stores a tenant's ladder.
func (s *PGStore) SetThresholds(tenant string, cfg circuit.Config, reason, actor string) error {
	if tenant == "" {
		return ErrNoScope
	}
	// The same rule the engine, the agent and the fleet handler each apply.
	// Four hops, one rule — a ladder that reaches storage unvalidated is one
	// that reaches an agent unvalidated on the next enrolment.
	if err := cfg.Validate(); err != nil {
		return err
	}
	return s.withTenant(tenant, func(tx *sql.Tx) error {
		_, err := tx.Exec(
			`INSERT INTO tenant_thresholds
			   (tenant_id, throttle_at, tarpit_at, quarantine_at, sever_at, reason, actor, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7, now())
			 ON CONFLICT (tenant_id) DO UPDATE SET
			   throttle_at = EXCLUDED.throttle_at, tarpit_at = EXCLUDED.tarpit_at,
			   quarantine_at = EXCLUDED.quarantine_at, sever_at = EXCLUDED.sever_at,
			   reason = EXCLUDED.reason, actor = EXCLUDED.actor, updated_at = now()`,
			tenant, cfg.ThrottleAt, cfg.TarpitAt, cfg.QuarantineAt, cfg.SeverAt,
			strings.TrimSpace(reason), actor)
		return err
	})
}
