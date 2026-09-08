import { useCallback, useEffect, useState } from "react";
import { tenantScopedPath, useSelectedTenant } from "../../lib/tenantScope";

/**
 * A one-line summary of whether the two enrichment layers are actually working.
 *
 * Lives in features/common because BOTH the Behaviour & Reputation panel and the
 * assistant sidebar need it, and neither owns the other.
 *
 * # Why the sidebar needs it at all
 *
 * The Behaviour & Intel panel came out of the side menu and is now reached from
 * the assistant. That is only safe if the assistant surfaces the ONE thing the
 * panel showed at a glance and a conversation does not: whether the detector is
 * alive. "No anomalies" means three different things — the layer is off, the
 * baseline is still warming, or no indicators are loaded — and an analyst who
 * has to ask a question to find out will not ask.
 *
 * So this is deliberately not a chat answer. It is a fact on screen, next to the
 * link that opens the evidence.
 */
export interface EnrichmentSummary {
  /** null while loading, or when the endpoints are not served here. */
  baselineReady: boolean | null;
  /** Warm-up progress, 0..1. null when unknown. */
  baselineProgress: number | null;
  indicators: number | null;
  /** True when enrichment is not enabled on this deployment at all. */
  unavailable: boolean;
}

interface BaselineResponse {
  enabled: boolean;
  status: {
    ready: boolean;
    observations: number;
    need_observations: number;
    span_seconds: number;
    need_span_seconds: number;
  };
}

interface IntelResponse {
  status: { loaded: boolean; indicators: number };
}

/**
 * The two status reads, carrying the customer the console is pointed at.
 *
 * `tenantScopedPath` is lib/api.ts's own scoping step. This hook raw-fetched
 * instead, so the line it produces — "Baseline ready · 414 indicators", printed
 * beside the selected customer's console — was asked with no customer named on
 * it at all. That is the one sentence this strip exists to get right: it is the
 * analyst's evidence that the detector behind an empty findings list is
 * actually running, and evidence about a customer nobody named is not weaker
 * evidence, it is false evidence.
 *
 * Naming the customer is this side's half of it; see IntelligenceBody's helper
 * for the control-plane handler that does not yet read the parameter.
 *
 * It stays on fetch's own `res.json()` rather than calling lib/api.ts's `api()`
 * for the reason that helper gives: `api()` parses a response only when the
 * server labelled it `application/json` and otherwise hands back the raw text.
 * The scoping is the part that must match, and it does.
 *
 * 503 is the documented "not enabled on this deployment" answer and is a
 * normal state, not a fault.
 */
async function getJSON<T>(path: string, signal: AbortSignal): Promise<T | null> {
  const res = await fetch(tenantScopedPath(path), { credentials: "same-origin", signal });
  if (!res.ok) return null;
  return (await res.json()) as T;
}

/**
 * Nothing is known until something has answered: the sidebar renders its
 * neutral "Behaviour & reputation" label for this, rather than a readiness it
 * has not been told.
 */
const NOTHING_KNOWN_YET: EnrichmentSummary = {
  baselineReady: null,
  baselineProgress: null,
  indicators: null,
  unavailable: false
};

/**
 * Fetches the summary once per `enabled` transition, and again whenever the
 * console is pointed at a different customer. No polling: this is a status line
 * beside a link, not a live panel, and the panel it links to does its own
 * refreshing.
 *
 * The customer is a dependency because this line is EVIDENCE — "Baseline ready
 * · 414 indicators" is what tells an analyst that an empty findings list is a
 * finding. Left on the answer it got before a switch, it would go on vouching
 * for the previous customer's detector while the console named another.
 */
export function useEnrichmentSummary(enabled: boolean): EnrichmentSummary {
  const [summary, setSummary] = useState<EnrichmentSummary>(NOTHING_KNOWN_YET);
  const selectedTenant = useSelectedTenant();

  const load = useCallback((signal: AbortSignal) => {
    void Promise.all([
      getJSON<BaselineResponse>("/api/baseline?top=1", signal),
      getJSON<IntelResponse>("/api/intel", signal)
    ])
      .then(([b, i]) => {
        // A switch re-runs the effect below, whose cleanup aborts this
        // controller — so an answer about the customer just left is dropped
        // here rather than stated beside the new one's name.
        if (signal.aborted) return;
        if (!b && !i) {
          setSummary({ baselineReady: null, baselineProgress: null, indicators: null, unavailable: true });
          return;
        }
        let progress: number | null = null;
        if (b?.status) {
          const obs = b.status.need_observations > 0 ? b.status.observations / b.status.need_observations : 1;
          const age = b.status.need_span_seconds > 0 ? b.status.span_seconds / b.status.need_span_seconds : 1;
          progress = Math.max(0, Math.min(1, Math.min(obs, age)));
        }
        setSummary({
          baselineReady: b ? b.enabled && b.status.ready : null,
          baselineProgress: progress,
          indicators: i ? i.status.indicators : null,
          unavailable: false
        });
      })
      .catch(() => {
        if (signal.aborted) return;
        setSummary({ baselineReady: null, baselineProgress: null, indicators: null, unavailable: true });
      });
  }, []);

  useEffect(() => {
    if (!enabled) return;
    // What was known was known about the customer the console was pointed at
    // when it was read. On a switch that is no longer the customer on screen,
    // and a stale "Baseline ready" beside the new one's name is not a weaker
    // claim than none — it is a false one. Forgotten first, then re-read.
    setSummary(NOTHING_KNOWN_YET);
    const ctl = new AbortController();
    load(ctl.signal);
    return () => ctl.abort();
  }, [enabled, load, selectedTenant]);

  return summary;
}

/** The status line, as the sidebar renders it. Exported so it can be tested. */
export function enrichmentSummaryText(s: EnrichmentSummary): string {
  if (s.unavailable) return "Enrichment is not enabled on this deployment";
  const parts: string[] = [];
  if (s.baselineReady === true) parts.push("Baseline ready");
  else if (s.baselineReady === false) {
    const pct = s.baselineProgress === null ? null : Math.round(s.baselineProgress * 100);
    // "Still learning" is the whole point of showing this: it is NOT the same
    // statement as "nothing unusual", and only this line distinguishes them.
    parts.push(pct === null ? "Baseline still learning" : `Baseline still learning — ${pct}%`);
  }
  if (s.indicators !== null) {
    parts.push(s.indicators === 0 ? "no threat-intel indicators loaded" : `${s.indicators.toLocaleString()} indicators`);
  }
  return parts.join(" · ");
}
