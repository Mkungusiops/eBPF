-- 0002_telemetry_indexes.sql — make the telemetry reads survive real volume.
--
-- The telemetry DDL below is a VERBATIM copy of pgSchema in
-- engine/internal/centralstore/postgres.go. It is repeated here (not modified)
-- so this migration works whether it runs before or after the control plane's
-- first Open(): both are CREATE TABLE IF NOT EXISTS, so whichever is second is
-- a no-op. If you change the DDL in postgres.go, change it here too — they must
-- stay byte-for-byte equivalent or the two paths will produce different schemas.
CREATE TABLE IF NOT EXISTS telemetry (
  tenant_id text NOT NULL,
  agent_id  text NOT NULL,
  dedup_key text NOT NULL,
  kind      text NOT NULL,
  exec_id   text NOT NULL DEFAULT '',
  "binary"  text NOT NULL DEFAULT '',
  at        bigint NOT NULL,
  payload   bytea NOT NULL,
  PRIMARY KEY (tenant_id, agent_id, dedup_key)
);
ALTER TABLE telemetry ENABLE ROW LEVEL SECURITY;
ALTER TABLE telemetry FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON telemetry;
CREATE POLICY tenant_isolation ON telemetry
  USING      (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- The primary key is (tenant_id, agent_id, dedup_key) — the dedup/resume path.
-- Every console read is instead "this tenant's newest rows", which that key
-- cannot serve: without this index the query degrades to a full scan of the
-- tenant's partition as soon as it holds real event volume.
CREATE INDEX IF NOT EXISTS telemetry_tenant_at_idx ON telemetry (tenant_id, at DESC);

-- Chain reconstruction (walking a process tree by exec_id) and binary-name
-- hunting are the two other access patterns the console drives.
CREATE INDEX IF NOT EXISTS telemetry_exec_idx   ON telemetry (tenant_id, exec_id) WHERE exec_id <> '';
CREATE INDEX IF NOT EXISTS telemetry_binary_idx ON telemetry (tenant_id, "binary") WHERE "binary" <> '';

-- The app role exists already (postgres.go creates it), but a fresh database
-- migrated before the control plane's first start will not have it yet. RLS is
-- only enforced for a NOSUPERUSER role, so this must exist before any read.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ebpf_app') THEN
    CREATE ROLE ebpf_app NOSUPERUSER NOLOGIN;
  END IF;
END $$;
GRANT SELECT, INSERT ON telemetry TO ebpf_app;
