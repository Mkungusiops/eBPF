// Package baseline learns what is NORMAL on a host and turns a departure from
// it into points the chain scorer can use.
//
// # The gap this closes
//
// internal/score is a static rule table: curl piped to a shell scores 25 on
// every host, forever, whether that host has run it ten thousand times as part
// of its build pipeline or has never run it once. That is the "no baseline
// learning" gap. It cuts both ways and both hurt:
//
//   - A host whose normal work LOOKS like the rules fires constantly, so its
//     operators learn to ignore it.
//   - Behaviour that is obviously novel FOR THIS HOST — a web server that has
//     never spawned a shell in six weeks suddenly spawning one — scores zero,
//     because no rule matches "this has never happened here".
//
// The second is the one that matters. The single most discriminating fact in
// process telemetry is not what a binary is called, it is whether this parent
// has ever launched this child on this machine before.
//
// # What it learns
//
// Four facets, each a decayed frequency count:
//
//	binary   which executables run here
//	edge     which parent launches which child   ← the highest-value facet
//	userbin  which uid runs which executable
//	hour     when this host is active
//
// Counts decay exponentially (14-day half-life) so a host that changes role
// stops being alarming after a fortnight rather than forever. A key that has
// never been seen carries weight 0, which is what "novel" means here.
//
// # Three properties that keep it honest
//
// ASSESS BEFORE OBSERVE. If an event is folded into the profile before it is
// judged, it has already made itself normal and nothing is ever novel. Callers
// must Assess first; TestAssessBeforeObserveIsTheCallersContract pins it.
//
// IT NEVER SCORES BEFORE IT IS READY. A fresh profile thinks everything is
// novel, which on day one means every process on the box is an anomaly — the
// classic UEBA failure that teaches operators the feature is noise. Assess
// returns zero points until Ready() holds, and the API reports how far along it
// is so "still learning" is visible rather than looking like "nothing found".
// PrimeFromHistory replays the store's existing events so an established
// deployment is warm immediately instead of blind for a day.
//
// IT ONLY EVER ADDS. Points are additive and bounded — never negative. A
// negative contribution would let an attacker pad a chain with routine activity
// to drag it back under the containment threshold, and chain scores are
// cumulative, so nothing may push one DOWN. When behaviour is strongly typical
// the assessment says so in Routine, which is an annotation for the analyst and
// carries no points at all.
//
// Bounded on purpose, twice: at most MaxEventPoints from one event, and the
// caller applies a per-chain ceiling. Novelty escalates suspicion; it must
// never be able to manufacture a critical alert on its own out of a host that
// simply got a software update.
package baseline
