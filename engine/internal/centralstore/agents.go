package centralstore

import (
	"log/slog"
	"time"
)

// The durable agent roster.
//
// migration 0001 created this table — hostname, agent_version, arch,
// enrolled_at, last_seen_at, last_mode, buffer_depth — and nothing ever wrote
// to it. Agent identity lived only in the heartbeat registry, which is memory:
// a control-plane restart forgot every agent until each one called home again.
//
// That is not merely untidy. The synthetic-telemetry marking asks the registry
// whether an agent is a simulator, so during the window after a restart a
// simulator's records were stamped as real — the exact confusion that marking
// exists to prevent. It also means the platform cannot answer "which hosts
// have ever reported to this tenant", only "which are reporting right now".
type AgentRecord struct {
	TenantID    string    `json:"tenant_id"`
	AgentID     string    `json:"agent_id"`
	Hostname    string    `json:"hostname"`
	Version     string    `json:"agent_version"`
	Arch        string    `json:"arch"`
	EnrolledAt  time.Time `json:"enrolled_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	LastMode    string    `json:"last_mode"`
	BufferDepth int64     `json:"buffer_depth"`
}

// UpsertAgent records an agent's identity and last contact.
//
// enrolled_at is set once and never updated: it is when this control plane
// first saw the agent, and overwriting it on every heartbeat would erase the
// only record of how long a host has been in the fleet.
//
// Errors are logged rather than returned. This runs on the heartbeat path, and
// an agent that cannot update its roster row must still be able to report
// telemetry and receive commands — refusing the heartbeat would turn a
// bookkeeping failure into a fleet outage.
func (s *PGStore) UpsertAgent(a AgentRecord) {
	if a.TenantID == "" || a.AgentID == "" {
		return
	}
	// The tenant row first: agents has a foreign key onto tenants, so an agent
	// from a tenant this control plane has never recorded is refused outright.
	// Discovered exactly that way — the roster wrote nothing until tenants
	// existed, and said so on every heartbeat.
	s.EnsureTenant(a.TenantID)
	_, err := s.db.Exec(
		`INSERT INTO agents (tenant_id, agent_id, hostname, agent_version, arch,
		                     last_seen_at, last_mode, buffer_depth)
		 VALUES ($1,$2,$3,$4,$5, now(), $6, $7)
		 ON CONFLICT (tenant_id, agent_id) DO UPDATE SET
		   hostname = EXCLUDED.hostname, agent_version = EXCLUDED.agent_version,
		   arch = EXCLUDED.arch, last_seen_at = now(),
		   last_mode = EXCLUDED.last_mode, buffer_depth = EXCLUDED.buffer_depth`,
		a.TenantID, a.AgentID, a.Hostname, a.Version, a.Arch, a.LastMode, a.BufferDepth)
	if err != nil {
		slog.Error("agent roster not updated", "tenant", a.TenantID, "agent", a.AgentID, "error", err)
	}
}

// AgentIsSimulated answers from the DURABLE roster rather than live memory.
//
// This is what makes the synthetic marking survive a restart: the registry is
// empty until each agent heartbeats again, and telemetry that arrives in that
// window would otherwise be stamped as real.
//
// Unknown answers false. A real agent must never be mislabelled as demo data —
// mislabelling in that direction hides evidence, where the reverse merely
// leaves a simulator's record briefly unmarked.
func (s *PGStore) AgentIsSimulated(tenant, agent string) bool {
	var version string
	err := s.db.QueryRow(
		`SELECT agent_version FROM agents WHERE tenant_id = $1 AND agent_id = $2`,
		tenant, agent).Scan(&version)
	if err != nil {
		return false
	}
	return isSimulatedVersion(version)
}

// isSimulatedVersion mirrors heartbeat.Record.Simulated. Duplicated rather than
// imported because centralstore must not depend on the heartbeat package, and
// the rule is one line — but the two are asserted equal by a test so they
// cannot drift into disagreeing about what a simulator is.
func isSimulatedVersion(v string) bool {
	return len(v) >= 4 && v[:4] == "sim-"
}
