-- The containment ladder as a TENANT policy, not a per-host preference.
--
-- The ladder persists per host, so an operator who tightens it during an
-- incident keeps it across a restart. That is not the same as a fleet policy:
-- an agent enrolled tomorrow starts on whatever the deploy configured, and a
-- tenant that decided its own thresholds silently gets a host that did not.
-- On an MSSP control plane running many customers, that is the difference
-- between a policy and a preference.
--
-- Stored per tenant so a new agent can be handed the tenant's ladder on its
-- first heartbeat rather than waiting for someone to notice and re-push.
CREATE TABLE IF NOT EXISTS tenant_thresholds (
  tenant_id     TEXT PRIMARY KEY,
  throttle_at   INTEGER NOT NULL,
  tarpit_at     INTEGER NOT NULL,
  quarantine_at INTEGER NOT NULL,
  sever_at      INTEGER NOT NULL,
  reason        TEXT NOT NULL DEFAULT '',
  actor         TEXT NOT NULL DEFAULT '',
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- The same rule circuit.Config.Validate enforces in Go, at all three hops.
  -- A fourth copy here because this row is read at agent-enrolment time with
  -- no operator watching: a descending ladder that reached an agent would
  -- sever everything it tracks, and the database is the last place that can
  -- refuse it.
  CONSTRAINT tenant_thresholds_ascending CHECK (
    throttle_at > 0 AND throttle_at < tarpit_at
    AND tarpit_at < quarantine_at AND quarantine_at < sever_at
  )
);

ALTER TABLE tenant_thresholds ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_thresholds FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_thresholds;
CREATE POLICY tenant_isolation ON tenant_thresholds
  USING      (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- Non-superuser app role, so RLS applies and the grant is required. No
-- sequence: the primary key is the tenant id.
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_thresholds TO ebpf_app;
