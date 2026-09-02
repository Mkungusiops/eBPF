-- Per-tenant change control (threat-model EN-2).
--
-- The approval machinery — the queue, the four-eyes check inside
-- approval.Store.Decide, the TTL, and the rule that nothing which STOPS
-- enforcement may ever wait on a quorum — has been built and running since
-- before this table existed. The only thing that was deploy-time was the
-- switch, so turning four-eyes on meant editing a unit file and restarting the
-- control plane: during the incident in which you decided you wanted it.
--
-- Stored per tenant because an MSSP runs one control plane for customers with
-- different change-control obligations. A regulated tenant may require a
-- second operator on every sever while a lab tenant does not, and forcing one
-- answer on both means the strict customer sets the policy for everyone or
-- nobody gets it.
--
-- The deploy flag remains a FLOOR, not a default: if the platform was deployed
-- with -require-approval, no tenant row can switch it off. Same asymmetry as
-- the protected-binary floor in 0004, for the same reason — a control that can
-- only be tightened from here cannot be used to weaken the platform.
CREATE TABLE IF NOT EXISTS tenant_change_control (
  tenant_id        TEXT PRIMARY KEY,
  require_approval BOOLEAN NOT NULL,
  -- reason and actor are the audit. The control plane has no hash-chained
  -- decision ledger of its own (that lives per-agent), so the row itself has
  -- to carry who changed this and why, or the change is unattributable.
  reason           TEXT NOT NULL,
  actor            TEXT NOT NULL DEFAULT '',
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE tenant_change_control ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_change_control FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_change_control;
CREATE POLICY tenant_isolation ON tenant_change_control
  USING      (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- FORCE ROW LEVEL SECURITY applies to the table owner too, so there is
-- deliberately no "load every tenant in one pass" here: the control plane
-- reads this per tenant through withTenant and caches the result, which keeps
-- one isolation model rather than carving an exception into it for a startup
-- convenience. The read is a primary-key lookup, once per tenant per process.
--
-- The app role is not a superuser, so RLS actually applies and the grant is
-- required — without it every read and write returns "permission denied".
-- No sequence grant: the primary key is the tenant id, not a BIGSERIAL.
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_change_control TO ebpf_app;
