-- Separate demo data from evidence in the tenant ledger.
--
-- cmd/simagent has always identified itself — AgentVersion "sim-0.1", Kernel
-- "6.8.0-sim" — and nothing ever read it, so its telemetry landed in the same
-- table as real containment with nothing to tell them apart. On the live
-- estate that left 431 fabricated containment decisions sitting beside real
-- ones in the audit an incident review reads.
--
-- Marked rather than deleted, deliberately. An audit ledger must not contain
-- fabrications, and there are two ways to satisfy that: remove them, or label
-- them unmistakably. "431 rows marked synthetic, retained for transparency" is
-- a better answer to a regulator than "we deleted 431 rows from the audit
-- ledger", and it keeps the record of what the platform was shown doing during
-- the demo period.
ALTER TABLE telemetry ADD COLUMN IF NOT EXISTS synthetic BOOLEAN NOT NULL DEFAULT FALSE;

-- Reading the ledger without the fabrications is the common case, so it gets
-- the index rather than paying a filter on every scan.
CREATE INDEX IF NOT EXISTS telemetry_real_at_idx
  ON telemetry (tenant_id, at DESC) WHERE synthetic = FALSE;

-- Backfill for the two simulators that ran before this column existed.
--
-- Identified by evidence, not by guesswork: both stopped emitting at
-- 2026-08-15 14:28 — the hour DATA_MODE=none disabled the simulators — and
-- neither has produced a record since, while every real agent has been
-- reporting continuously. They are also absent from the agents table.
--
-- Written as a rule rather than two hardcoded ids so it stays correct on any
-- deployment: any agent whose telemetry stopped before the simulators were
-- switched off, and which has produced nothing in the eight days since, was a
-- simulator. A real agent that silently died in that window would be marked
-- too — and that is the safer error, because a dead agent's last decisions
-- being flagged for review is better than a fabricated one passing as real.
UPDATE telemetry SET synthetic = TRUE
WHERE agent_id IN (
  SELECT agent_id FROM telemetry
  GROUP BY agent_id
  HAVING MAX(at) < 1755300000000000000  -- 2026-08-16T00:00:00Z, in epoch nanos
);
