# The posture dial

One number, 0–100, answering "how is this estate doing right now". It has been
wrong three times, in three different ways, and each fix is still load-bearing.

## 1. It measured the window selector

The original score was `critical*8 + high*3 + medium`, clamped to 100 — a
**cumulative count**. The single-tenant engine, at one instant, read 0 / 3 / 31 /
100 as the range widened 5m → 30m → 60m → 24h. Nothing about the host changed;
a longer window simply contains more alerts.

**Fix:** score a *rate* — weighted alerts per hour. The four ranges now agree
when the estate is steady and disagree only when the rate genuinely changed.

## 2. It saturated

The clamp meant thirteen criticals (13 × 8 = 104) pinned the gauge at 100. Past
that, a tenfold worsening looked identical to scraping over the line.

**Fix:** a soft knee, `r / (r + k)`, which is asymptotic. There is always
headroom, so a worsening estate always moves the dial.

## 3. It had no dynamic range on a busy estate

The knee's half-scale `k` was a fixed 200 weighted alerts/hour. That is fine for
a quiet estate and useless for a busy one: a tenant normally running 400/hr sat
at 67 permanently, and everything from "normal Tuesday" to "actively breached"
was compressed into the top third of the scale. The curve had headroom; the
estate was already past the part of it where movement is visible. Same defect as
the clamp, one layer out.

**Fix:** scale to the estate's **own** typical rate.

```
typical    = median hourly weighted rate over the trailing 7 days
half-scale = max(20, typical × 3)
```

- **Median, not mean.** Alert history is a quiet floor with occasional spikes,
  and the mean is dragged up by exactly the incidents the dial exists to show —
  one bad night last week would quietly raise "normal" and hide the next one.
- **× 3, not × 1.** At ×1 the dial sits at 50 whenever the estate is behaving
  exactly normally, which is alarming and useless. At ×3, normal reads ≈25 with
  room above it.
- **A floor of 20.** Without it a genuinely quiet estate has a typical rate near
  zero, the scale collapses, and one medium alert reads as catastrophe.
- **Unknown ≠ zero.** Fewer than 24 hourly buckets returns `null`, the dial
  falls back to the fixed 200, and the console *says* it is doing so.

### The trade, stated plainly

**An estate that is chronically bad now reads "normal".** That is the classic
failure of every baseline-relative metric and it is not solved here — it is
*disclosed*. The dial is never the only number on screen: the band beside it
always shows the absolute rate and the baseline being measured against.

```
67 / 100   high
340 weighted alerts/hr vs 190/hr typical here
```

The dial answers "compared with usual here". The text answers "and how bad is
usual". Neither is sufficient alone, which is why neither ships alone.

## An API-shape hazard worth remembering

`riskScoreFromRate` briefly took an optional second parameter for the
half-scale. That broke every point-free `views.map(riskScoreFromRate)`, because
`Array.map` passes `(element, index, array)` — so the **index** silently became
the half-scale and three of four windows were scored against 1, 2 and 3.

An existing test caught it. The shape that made it possible is gone: the
single-argument function stayed single-argument, and the explicit-scale version
is a separate `riskScoreAgainst(rate, halfScale)`. A single-argument function
cannot be handed an index it will mistake for configuration.

## Where the code is

| Piece | File |
|---|---|
| The curve, the baseline maths | `web/src/features/soc/risk.ts` |
| The 7-day baseline fetch | `useEstateBaseline` in `hooks.ts` |
| Wiring | `useSocWindowModel.ts` |
| Disclosure beside the dial | `ExecutiveBand.tsx` |
| Tests | `web/src/test/posture.test.ts`, `riskScore.test.ts` |

The baseline fetch is deliberately **separate and slow** — fixed at 7 days
regardless of the selected range, refreshed every ten minutes. Folding it into
`useAlertStats`, which re-requests every 15 seconds and on every range change,
would put a seven-day aggregate on the request pattern that took the control
plane down on 2026-08-05.
