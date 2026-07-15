-- 0001_control_state.sql — the control-state tables the app does not create.
--
-- centralstore/postgres.go creates `telemetry` (+ RLS) on Open(). It does not
-- create the tenant registry, the agent registry, or the operator audit log —
-- those are control state, and until now they lived only in memory.
--
-- Every statement is idempotent: this file must be safe to re-run against a
-- database the application has already bootstrapped.

-- The tenant registry. tenant_id is the isolation key stamped into every agent
-- certificate (Subject.Organization) and every telemetry row, so it is the join
-- point for the whole platform — text, not a surrogate key, on purpose.
CREATE TABLE IF NOT EXISTS tenants (
  tenant_id   text PRIMARY KEY,
  display_name text NOT NULL DEFAULT '',
  status      text NOT NULL DEFAULT 'active'
              CHECK (status IN ('active', 'suspended', 'deleted')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  -- Retention is per-tenant: residency and DPA commitments differ per customer.
  retention_days integer NOT NULL DEFAULT 90 CHECK (retention_days > 0)
);

-- The agent registry: one row per enrolled agent. agent_id is the certificate's
-- Subject.CommonName; the (tenant_id, agent_id) pair is what the control plane
-- derives from the client cert at ingest (isolation Layer 1).
CREATE TABLE IF NOT EXISTS agents (
  tenant_id     text NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
  agent_id      text NOT NULL,
  hostname      text NOT NULL DEFAULT '',
  agent_version text NOT NULL DEFAULT '',
  arch          text NOT NULL DEFAULT '',
  enrolled_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at  timestamptz,
  -- The autonomy contract: an agent that has not checked in is not necessarily
  -- broken — it may be enforcing offline. Never treat stale as disarmed.
  last_mode     text NOT NULL DEFAULT 'unknown',
  buffer_depth  bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, agent_id)
);

CREATE INDEX IF NOT EXISTS agents_last_seen_idx ON agents (last_seen_at DESC);

-- Operator audit. Enrollment-token minting, command dispatch, and every
-- authz decision land here. Append-only by convention; the hash-chained
-- enforcement audit stays with the agent (internal/store/decisions.go).
CREATE TABLE IF NOT EXISTS operator_audit (
  id          bigserial PRIMARY KEY,
  at          timestamptz NOT NULL DEFAULT now(),
  subject     text NOT NULL,              -- operator principal (OIDC sub or 'admin')
  tenant_id   text NOT NULL DEFAULT '',   -- the tenant acted upon ('' = cross-tenant)
  action      text NOT NULL,              -- read | respond | enroll | command | …
  allowed     boolean NOT NULL,
  detail      text NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS operator_audit_at_idx     ON operator_audit (at DESC);
CREATE INDEX IF NOT EXISTS operator_audit_tenant_idx ON operator_audit (tenant_id, at DESC);
