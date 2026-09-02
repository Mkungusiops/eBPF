-- Backfill the synthetic mark, correctly this time.
--
-- 0006 added the column and its backfill matched nothing: the cutoff was
-- written as a hand-computed epoch-nanosecond literal and it was a YEAR out
-- (2025-08-15 instead of 2026-08-16), so `HAVING MAX(at) < cutoff` excluded
-- every agent. The column shipped and the fabrications stayed unmarked, which
-- is the worst of both — a mechanism that looks applied and changes nothing.
--
-- 0006 cannot be edited: the runner records a checksum per migration and
-- treats a changed applied file as a hard error, deliberately, so two
-- environments can never disagree about what the schema is. Hence a new file.
--
-- The cutoff is now computed BY POSTGRES from a date literal rather than by
-- hand. There is no arithmetic here to get wrong, and the intent is legible to
-- the next reader instead of being an 19-digit number they have to decode.
UPDATE telemetry SET synthetic = TRUE
WHERE agent_id IN (
  SELECT agent_id FROM telemetry
  GROUP BY agent_id
  HAVING MAX(at) < (EXTRACT(EPOCH FROM TIMESTAMPTZ '2026-08-16 00:00:00+00') * 1e9)::bigint
);
