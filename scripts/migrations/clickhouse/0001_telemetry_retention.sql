-- 0001_telemetry_retention.sql — the events firehose, with retention.
--
-- The telemetry DDL is a VERBATIM copy of chSchema in
-- engine/internal/centralstore/clickhouse.go, for the same reason as the
-- Postgres migration: the app applies it with CREATE TABLE IF NOT EXISTS on
-- Open(), so if this migration created the table with a DIFFERENT engine or
-- partition key, the app's create would silently no-op and the two would
-- disagree forever. Keep them identical.
CREATE TABLE IF NOT EXISTS telemetry (
  tenant_id String, agent_id String, dedup_key String, kind String,
  exec_id String, `binary` String, at Int64, payload String,
  ingested_at DateTime64(9) DEFAULT now64(9)
) ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY tenant_id
ORDER BY (tenant_id, agent_id, dedup_key);

-- Retention. The application never expires anything — it cannot, because
-- retention is a per-tenant commitment (DPA / residency), not a code constant.
-- 90 days is the platform default; a tenant with a different contract gets its
-- own TTL applied on top of this one.
--
-- MODIFY TTL is idempotent: re-running sets the same policy rather than
-- stacking a second one. It only starts dropping parts on the next merge, so
-- applying it to a populated table is safe and gradual.
ALTER TABLE telemetry MODIFY TTL toDateTime(ingested_at) + INTERVAL 90 DAY;

-- The console reads "this tenant's newest events", but ORDER BY starts with
-- (tenant_id, agent_id, dedup_key) — nothing in the sort key is temporal, so a
-- recency query scans the whole tenant partition. A minmax skip index on `at`
-- lets ClickHouse drop granules that cannot contain the requested window.
ALTER TABLE telemetry ADD INDEX IF NOT EXISTS telemetry_at_idx at TYPE minmax GRANULARITY 4;
