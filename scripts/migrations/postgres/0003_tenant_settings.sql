-- Per-tenant operator settings.
--
-- The first is scoring suppressions: "this behaviour is expected on OUR
-- estate". Without them a customer with noisy-but-legitimate activity either
-- lives with false positives or disarms the platform, and they disarm it.
--
-- RLS is not optional here and not decoration. A suppression is a statement
-- about what one tenant stops detecting; leaking or cross-writing one would
-- let a tenant blind another. Same shape as telemetry's policy so there is one
-- isolation model to reason about, not two.
CREATE TABLE IF NOT EXISTS tenant_suppressions (
  id         BIGSERIAL PRIMARY KEY,
  tenant_id  TEXT NOT NULL,
  -- binary_path, not "binary": binary is a RESERVED WORD in Postgres and an
  -- unquoted reference is a syntax error. A column that must be quoted at
  -- every use is one somebody eventually forgets to quote.
  binary_path TEXT NOT NULL,
  policy     TEXT NOT NULL DEFAULT '',
  parent     TEXT NOT NULL DEFAULT '',
  reason     TEXT NOT NULL,
  actor      TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- One rule per (tenant, binary, policy, parent). Re-adding the same rule is
  -- an update, not a duplicate that would have to be deleted twice.
  UNIQUE (tenant_id, binary_path, policy, parent)
);

ALTER TABLE tenant_suppressions ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_suppressions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_suppressions;
CREATE POLICY tenant_isolation ON tenant_suppressions
  USING      (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- Every read is "this tenant's rules, newest first". The primary key cannot
-- serve that.
CREATE INDEX IF NOT EXISTS tenant_suppressions_tenant_created_idx
  ON tenant_suppressions (tenant_id, created_at DESC);

-- The application connects as a NON-SUPERUSER role so RLS actually applies —
-- a superuser bypasses row-level security entirely, which would make the
-- isolation policy above decorative. That role therefore needs explicit
-- privileges on every new table, and the sequence behind BIGSERIAL.
--
-- Omitting this is not a soft failure: RLS is enforced, the role has no grant,
-- and every read and write returns "permission denied" — which is how this was
-- found.
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_suppressions TO ebpf_app;
GRANT USAGE, SELECT ON SEQUENCE tenant_suppressions_id_seq TO ebpf_app;
