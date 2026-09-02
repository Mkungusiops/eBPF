-- Per-tenant guardrails: what containment must always refuse to touch.
--
-- This is threat-model EN-1 in the database. The agent already unions a
-- compiled-in floor (sshd, sudo, su, login, systemd) that no signed command
-- can strip, so this table can only ever WIDEN protection. It exists because
-- the floor is generic and an estate is not: Safaricom's jump hosts, their
-- monitoring agent, the uplink MAC of a top-of-rack switch are all things a
-- containment mistake must not reach, and none of them are guessable at
-- build time.
--
-- Stored rather than fire-and-forget for the same reason suppressions are:
-- the desired state has to survive an agent that was offline when the
-- operator made the change, and has to be re-dispatchable without the
-- operator retyping it during an incident.
CREATE TABLE IF NOT EXISTS tenant_protected (
  id         BIGSERIAL PRIMARY KEY,
  tenant_id  TEXT NOT NULL,
  -- kind is 'binary' or 'mac'. One table, because the two lists are always
  -- read together, always dispatched in one command, and a second table
  -- would only add a join to every query.
  kind       TEXT NOT NULL CHECK (kind IN ('binary', 'mac')),
  -- value: an absolute binary path, or a MAC in any form ParseMAC accepts.
  -- Named "value" and not "binary" for the reason 0003 documents.
  value      TEXT NOT NULL,
  reason     TEXT NOT NULL,
  actor      TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, kind, value)
);

ALTER TABLE tenant_protected ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_protected FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_protected;
CREATE POLICY tenant_isolation ON tenant_protected
  USING      (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE INDEX IF NOT EXISTS tenant_protected_tenant_kind_idx
  ON tenant_protected (tenant_id, kind, value);

-- The app role is deliberately not a superuser, so RLS applies and every new
-- table needs its own grant. Without these two lines every read and write
-- returns "permission denied" — see 0003.
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_protected TO ebpf_app;
GRANT USAGE, SELECT ON SEQUENCE tenant_protected_id_seq TO ebpf_app;
