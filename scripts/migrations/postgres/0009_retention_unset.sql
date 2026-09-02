-- Make "this tenant has chosen no retention" representable.
--
-- 0001 declared:
--
--   retention_days integer NOT NULL DEFAULT 90 CHECK (retention_days > 0)
--
-- which has no value meaning "unset". That was harmless while nothing read the
-- column. The moment per-tenant retention went live it produced two defects at
-- once, both visible on the first live deployment:
--
--   1. Every tenant carried 90 — a number no operator chose — and the console
--      resolves 90 days against a deployment that keeps events for 30. It
--      reported "this setting is not doing what it says" on every tenant of a
--      completely normal deployment. A control that cries wolf by default is
--      one operators learn to ignore before it ever means anything.
--
--   2. Clearing was impossible. The API accepts 0 for "follow the deployment",
--      and 0 fails CHECK (retention_days > 0), so the one way back to the
--      default was a constraint violation.
--
-- NULL is the honest third state, so the column becomes nullable and the
-- default is dropped.
--
-- # Why backfilling every 90 to NULL is safe HERE and would not be later
--
-- Nothing has ever written this column: it was one of the three dead columns
-- from 0001, wired up on 2026-08-25. So every 90 in the table is provably the
-- schema default and not an operator's choice. That is a one-time property of
-- this exact moment — the same backfill run after anyone sets 90 deliberately
-- would erase a real retention policy.

ALTER TABLE tenants ALTER COLUMN retention_days DROP NOT NULL;
ALTER TABLE tenants ALTER COLUMN retention_days DROP DEFAULT;

-- The CHECK must tolerate NULL. A CHECK is satisfied when it evaluates to NULL,
-- so `retention_days > 0` already permits it, but it is restated explicitly so
-- the intent survives the next reader.
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_retention_days_check;
ALTER TABLE tenants ADD CONSTRAINT tenants_retention_days_check
  CHECK (retention_days IS NULL OR retention_days > 0);

-- The one-time backfill described above.
UPDATE tenants SET retention_days = NULL WHERE retention_days = 90;
