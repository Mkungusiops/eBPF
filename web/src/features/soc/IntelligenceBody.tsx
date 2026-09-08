import { useCallback, useEffect, useMemo, useState } from "react";
import { Sparkles } from "lucide-react";
import { selectedTenantNow, tenantScopedPath, useSelectedTenant } from "../../lib/tenantScope";
import { useAssistantChat } from "../assistant/AssistantChatProvider";

/**
 * The Behaviour & Reputation panel: what this deployment has LEARNED is normal,
 * and what it has matched against threat-intelligence feeds.
 *
 * # The one thing this panel must never do
 *
 * Show an empty list that means three different things. "No anomalies" is a
 * genuine finding only when the baseline is ready; before that it means "still
 * learning", and if a feed directory is empty it means "nothing to match
 * against". Rendering all three as a quiet, tidy, empty table is how an
 * operator concludes the estate is clean when the detector is simply switched
 * off — the same failure /api/system-health exists to prevent for telemetry.
 *
 * So readiness and feed counts are stated FIRST, above the findings, and an
 * empty list always carries the reason it is empty.
 */

interface FacetTopKey {
  key: string;
  share: number;
  count: number;
}

interface FacetStatus {
  facet: string;
  keys: number;
  total_weight: number;
  top: FacetTopKey[];
}

interface BaselineStatus {
  ready: boolean;
  observations: number;
  need_observations: number;
  span_seconds: number;
  need_span_seconds: number;
  half_life_hours: number;
  facets: FacetStatus[];
}

interface BaselineResponse {
  enabled: boolean;
  status: BaselineStatus;
  anomalies_total: number;
  scope?: string;
}

interface IntelMatch {
  value: string;
  kind: string;
  source: string;
  category?: string;
  confidence: string;
  observed: string;
  points: number;
}

interface Finding {
  at: string;
  kind: string;
  exec_id: string;
  pid: number;
  binary: string;
  points: number;
  reasons?: string[];
  match?: IntelMatch;
  agent?: string;
}

interface IntelSource {
  source: string;
  indicators: number;
}

interface IntelStatus {
  loaded: boolean;
  indicators: number;
  ips: number;
  cidrs: number;
  domains: number;
  hashes: number;
  allowlisted: number;
  sources: IntelSource[];
  loaded_at?: string;
  errors?: string[];
}

interface IntelResponse {
  status: IntelStatus;
  refresh: { enabled: boolean; feeds: number; interval?: string; last_run?: string; last_error?: string };
  matches_total: number;
}

const FACET_LABEL: Record<string, string> = {
  edge: "Process lineage (parent → child)",
  binary: "Executables",
  userbin: "User × executable",
  hour: "Hour of day"
};

function pct(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return "0%";
  if (n < 0.001) return "<0.1%";
  return `${(n * 100).toFixed(1)}%`;
}

function duration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "0m";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function when(iso: string): string {
  const t = new Date(iso);
  return Number.isNaN(t.getTime()) ? "—" : t.toLocaleTimeString();
}

/**
 * Every read this panel makes, carrying the customer the console is pointed at.
 *
 * `tenantScopedPath` is lib/api.ts's own scoping step. This panel raw-fetched
 * instead, which is the one way past the funnel, so its four reads left the
 * browser with no `tenant` on them at all — nothing on the wire said which
 * customer they were about, while the banner over this route said every panel
 * here is the selected customer's data only. A read-scoped screen with an
 * unscoped panel inside it is worse than an unscoped screen: the banner is the
 * reason the operator believes the panel. Anything added here that fetches must
 * go through this helper, or through lib/api.ts, so it cannot be forgotten
 * again.
 *
 * ASKING IS THIS SIDE'S HALF OF IT. The control plane still resolves these five
 * endpoints from the session alone — `tenantScope` in
 * internal/controlplane/enrichment.go reads the principal's own scope and
 * ignores `?tenant=`, unlike `authorizeRead`, which every other read goes
 * through — so a provider's answer here is not the selected customer's until
 * that handler honours the parameter. What changes here is that the console no
 * longer displays one customer while having asked about no one in particular.
 *
 * Scoped at the moment each request goes out rather than when the panel
 * mounted: the 20s refresh re-enters this helper, so every poll names the
 * customer selected at the time it is sent.
 *
 * It stays on fetch's own `res.json()` rather than calling lib/api.ts's `api()`
 * because the two disagree about an unlabelled body: `api()` parses a response
 * only when the server marked it `application/json` and otherwise hands back
 * the raw text, while this panel reads JSON from these endpoints regardless.
 * The scoping is the part that must match, and it does.
 *
 * 503 is the documented "not enabled on this deployment" answer, and it is a
 * normal state rather than a fault — the caller renders an explanation, not an
 * error. Anything else is genuinely unexpected.
 */
async function getJSON<T>(path: string, signal: AbortSignal): Promise<T | null> {
  const res = await fetch(tenantScopedPath(path), { credentials: "same-origin", signal });
  if (!res.ok) return null;
  return (await res.json()) as T;
}

export function IntelligenceBody({ open }: { open: boolean }) {
  // The assistant, reachable from the evidence rather than replacing it.
  //
  // These two surfaces answer different questions and both are needed: this
  // panel is what an analyst SCANS, the assistant is what they ASK. An assistant
  // answer about anomalies is only worth acting on if the findings behind it are
  // one click away — "show the work" is the discipline the whole assistant is
  // built around, and a conversation that has replaced its own evidence has
  // quietly abandoned it.
  const assistantChat = useAssistantChat();
  // THE CUSTOMER THIS PANEL IS ABOUT. Held as a dependency of the load effect
  // below, so a switch re-reads at once instead of leaving the customer just
  // left on screen until the 20s refresh happens to come round.
  const selectedTenant = useSelectedTenant();
  const [baseline, setBaseline] = useState<BaselineResponse | null>(null);
  const [intel, setIntel] = useState<IntelResponse | null>(null);
  const [anomalies, setAnomalies] = useState<Finding[]>([]);
  const [matches, setMatches] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [lookup, setLookup] = useState("");
  const [lookupResult, setLookupResult] = useState<string | null>(null);
  // THE CUSTOMER THE CONTENTS ON SCREEN DESCRIBE, as opposed to the one the
  // console is pointed at. They are the same except between a switch and the
  // answer to the reads it triggers; see the render below.
  const [shownFor, setShownFor] = useState<string | null>(selectedTenant);

  const load = useCallback((signal: AbortSignal) => {
    setLoading(true);
    // THE CUSTOMER THESE FOUR READS ARE ABOUT, read once before they go out and
    // carried through to `shownFor` below, so what lands is labelled with the
    // customer it was asked about rather than whoever is selected when it
    // arrives. There is no second check on the way back: a switch re-runs the
    // effect below, whose cleanup aborts this controller, so an answer for the
    // customer just left is already dropped by the `signal.aborted` guard.
    const scopedTo = selectedTenantNow();
    void Promise.all([
      getJSON<BaselineResponse>("/api/baseline?top=8", signal),
      getJSON<IntelResponse>("/api/intel", signal),
      getJSON<{ findings: Finding[] }>("/api/baseline/anomalies?limit=100", signal),
      getJSON<{ findings: Finding[] }>("/api/intel/matches?limit=100", signal)
    ])
      .then(([b, i, a, m]) => {
        if (signal.aborted) return;
        setBaseline(b);
        setIntel(i);
        setAnomalies(a?.findings ?? []);
        setMatches(m?.findings ?? []);
        setUnavailable(b === null && i === null);
        setShownFor(scopedTo);
        setLoading(false);
      })
      .catch(() => {
        if (signal.aborted) return;
        setUnavailable(true);
        setShownFor(scopedTo);
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    if (!open) return;
    // A LOOKUP ANSWER MUST NOT OUTLIVE THE VIEW IT WAS ASKED IN. It quotes the
    // indicator count of the deployment as this panel last read it, and after a
    // customer switch — or a re-open minutes later — it is an answer to a
    // question nobody on this screen asked. The fetched rows need no such
    // clearing: they are replaced by the load below, and until it lands
    // `shownFor` keeps the previous customer's off the screen.
    setLookupResult(null);
    const ctl = new AbortController();
    load(ctl.signal);
    // Refreshed on a timer because both layers are fed by a live event stream;
    // a static snapshot of "recent findings" goes stale while it is being read.
    const t = window.setInterval(() => load(ctl.signal), 20_000);
    return () => {
      ctl.abort();
      window.clearInterval(t);
    };
  }, [open, load, selectedTenant]);

  const runLookup = useCallback(() => {
    const q = lookup.trim();
    if (!q) return;
    setLookupResult("checking…");
    const ctl = new AbortController();
    // The scope this question is asked in. Unlike the polls above, this request
    // has its own controller that no switch aborts, so its answer can arrive
    // after the operator has moved on — and the verdict it carries was obtained
    // under the customer they left. Printed then, it would sit beside the new
    // customer's name.
    const scopedTo = selectedTenantNow();
    void getJSON<{ matched: boolean; match?: IntelMatch }>(
      `/api/intel/lookup?q=${encodeURIComponent(q)}`,
      ctl.signal
    ).then((res) => {
      if (selectedTenantNow() !== scopedTo) return;
      if (!res) {
        setLookupResult("lookup unavailable on this deployment");
        return;
      }
      if (!res.matched || !res.match) {
        // Precise wording: this is not a clean bill of health.
        setLookupResult(`not present in the ${intel?.status.indicators ?? 0} loaded indicators — that is not the same as safe`);
        return;
      }
      const m = res.match;
      setLookupResult(
        `MATCH — ${m.value} (${m.kind}) from ${m.source}${m.category ? `, ${m.category}` : ""}, ${m.confidence} confidence`
      );
    });
  }, [lookup, intel]);

  const warmup = useMemo(() => {
    const st = baseline?.status;
    if (!st) return null;
    const obs = Math.min(1, st.need_observations > 0 ? st.observations / st.need_observations : 1);
    const age = Math.min(1, st.need_span_seconds > 0 ? st.span_seconds / st.need_span_seconds : 1);
    return { obs, age, pct: Math.round(Math.min(obs, age) * 100) };
  }, [baseline]);

  // THE CONTENTS BELONG TO THE CUSTOMER THE CONSOLE HAS SINCE LEFT.
  //
  // Every card below states a fact — a readiness, a feed count, a findings
  // table — and the banner over this route says whose. Between a switch and the
  // answer to the reads it triggers, those two disagree, and one customer's
  // evidence read as another's is the whole defect this scoping exists to
  // prevent. So the panel says it is reading rather than showing rows it can no
  // longer attribute. Not reached on first paint: `shownFor` starts on the
  // selection, so an unanswered panel renders its cards exactly as it always
  // did, each carrying its own reason for being empty.
  if (shownFor !== selectedTenant) {
    return <div className="soc-empty">Reading this customer’s baseline and threat-intelligence…</div>;
  }

  if (unavailable) {
    return (
      <div className="soc-empty">
        <strong>Enrichment is not enabled on this deployment.</strong>
        <p>
          The behavioural baseline and threat-intelligence matching are not running here, so this
          panel has nothing to report. That is a configuration state, not a fault.
        </p>
      </div>
    );
  }

  return (
    <div className="soc-intel">
      {assistantChat ? (
        <div className="soc-intel-ask">
          <button
            type="button"
            onClick={() =>
              assistantChat.openAssistant({
                surface: "behaviour",
                question: "What is unusual on this deployment right now, and has anything matched a threat-intel feed?"
              })
            }
          >
            <Sparkles size={13} aria-hidden /> Ask the assistant about these findings
          </button>
          <span>It reads this same data — the tables below are the evidence for whatever it says.</span>
        </div>
      ) : null}

      <section className="soc-intel-band">
        <div className="soc-intel-card">
          <header>Behavioural baseline</header>
          {!baseline?.enabled ? (
            <p className="soc-intel-note">Not enabled on this deployment.</p>
          ) : baseline.status.ready ? (
            <>
              <div className="soc-intel-metric soc-intel-ok">Ready</div>
              <p className="soc-intel-note">
                Learned from {baseline.status.observations.toLocaleString()} executions over{" "}
                {duration(baseline.status.span_seconds)}. Counts decay with a{" "}
                {Math.round(baseline.status.half_life_hours / 24)}-day half-life.
                {baseline.scope === "tenant" ? " Scope: this tenant, across every host." : " Scope: this host."}
              </p>
            </>
          ) : (
            <>
              <div className="soc-intel-metric soc-intel-warn">Still learning — {warmup?.pct ?? 0}%</div>
              {/* Stated explicitly, because an unready baseline and a clean
                  estate produce an identical empty findings list below. */}
              <p className="soc-intel-note">
                {baseline.status.observations.toLocaleString()} of{" "}
                {baseline.status.need_observations.toLocaleString()} executions,{" "}
                {duration(baseline.status.span_seconds)} of {duration(baseline.status.need_span_seconds)}. It
                is not scoring yet, so an empty anomaly list below means <em>not yet known</em>, not{" "}
                <em>nothing unusual</em>.
              </p>
            </>
          )}
          <div className="soc-intel-total">{(baseline?.anomalies_total ?? 0).toLocaleString()} anomalies to date</div>
        </div>

        <div className="soc-intel-card">
          <header>Threat-intelligence feeds</header>
          {!intel?.status.loaded ? (
            <>
              <div className="soc-intel-metric soc-intel-warn">No feeds loaded</div>
              <p className="soc-intel-note">
                No indicator files were found. Nothing can match, so an empty match list below is
                not evidence that the estate is clean. Drop feed files into the deployment's intel
                directory.
              </p>
            </>
          ) : (
            <>
              <div className="soc-intel-metric soc-intel-ok">
                {intel.status.indicators.toLocaleString()} indicators
              </div>
              <p className="soc-intel-note">
                {intel.status.ips.toLocaleString()} IP · {intel.status.cidrs.toLocaleString()} range ·{" "}
                {intel.status.domains.toLocaleString()} domain · {intel.status.hashes.toLocaleString()} hash
                {intel.status.allowlisted > 0 ? ` · ${intel.status.allowlisted} allowlisted` : ""}
                {intel.status.sources.length > 0
                  ? ` — from ${intel.status.sources.map((s) => `${s.source} (${s.indicators})`).join(", ")}`
                  : ""}
              </p>
              {intel.status.errors && intel.status.errors.length > 0 ? (
                <p className="soc-intel-err">
                  {intel.status.errors.length} feed problem{intel.status.errors.length === 1 ? "" : "s"}:{" "}
                  {intel.status.errors.join("; ")}
                </p>
              ) : null}
            </>
          )}
          <div className="soc-intel-total">{(intel?.matches_total ?? 0).toLocaleString()} matches to date</div>
        </div>

        <div className="soc-intel-card">
          <header>Check an indicator</header>
          <div className="soc-intel-lookup">
            <input
              value={lookup}
              onChange={(e) => setLookup(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") runLookup();
              }}
              placeholder="IP, domain or SHA-256"
              aria-label="Indicator to check"
            />
            <button type="button" onClick={runLookup} disabled={!lookup.trim()}>
              Check
            </button>
          </div>
          {lookupResult ? <p className="soc-intel-note">{lookupResult}</p> : null}
          <div className="soc-intel-total">Matched locally — nothing is sent to a third party</div>
        </div>
      </section>

      <section className="soc-intel-section">
        <h3>Threat-intelligence matches</h3>
        {matches.length === 0 ? (
          <p className="soc-intel-note">
            {intel?.status.loaded
              ? `No observed address, domain or hash has matched the ${intel.status.indicators.toLocaleString()} loaded indicators.`
              : "No feeds are loaded, so nothing can match."}
          </p>
        ) : (
          <table className="soc-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Indicator</th>
                <th>Category</th>
                <th>Source</th>
                <th>Confidence</th>
                <th>Process</th>
                <th>Points</th>
              </tr>
            </thead>
            <tbody>
              {matches.map((f, i) => (
                <tr key={`${f.exec_id}-${f.at}-${i}`}>
                  <td>{when(f.at)}</td>
                  <td className="soc-mono">{f.match?.observed ?? "—"}</td>
                  <td>{f.match?.category || "—"}</td>
                  <td>{f.match?.source ?? "—"}</td>
                  <td>{f.match?.confidence ?? "—"}</td>
                  <td className="soc-mono">
                    {f.binary}
                    {f.agent ? ` @ ${f.agent}` : ""}
                  </td>
                  <td>+{f.points}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="soc-intel-section">
        <h3>Behavioural anomalies</h3>
        {anomalies.length === 0 ? (
          <p className="soc-intel-note">
            {baseline?.status.ready
              ? "Nothing has departed from this deployment's learned normal."
              : "The baseline is still learning and is not scoring yet — this is not a finding of 'nothing unusual'."}
          </p>
        ) : (
          <table className="soc-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Process</th>
                <th>Why it stood out</th>
                <th>Points</th>
              </tr>
            </thead>
            <tbody>
              {anomalies.map((f, i) => (
                <tr key={`${f.exec_id}-${f.at}-${i}`}>
                  <td>{when(f.at)}</td>
                  <td className="soc-mono">
                    {f.binary}
                    {f.agent ? ` @ ${f.agent}` : ""}
                  </td>
                  <td>{(f.reasons ?? []).join("; ")}</td>
                  <td>+{f.points}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="soc-intel-section">
        <h3>What this deployment considers normal</h3>
        {!baseline?.enabled || baseline.status.facets.length === 0 ? (
          <p className="soc-intel-note">Nothing learned yet.</p>
        ) : (
          <div className="soc-intel-facets">
            {baseline.status.facets.map((f) => (
              <div key={f.facet} className="soc-intel-facet">
                <header>
                  {FACET_LABEL[f.facet] ?? f.facet}
                  <span>{f.keys.toLocaleString()} distinct</span>
                </header>
                <ol>
                  {f.top.map((k) => (
                    <li key={k.key}>
                      <span className="soc-mono">{k.key}</span>
                      <span>{pct(k.share)}</span>
                    </li>
                  ))}
                </ol>
              </div>
            ))}
          </div>
        )}
      </section>

      {loading ? <p className="soc-intel-note">Refreshing…</p> : null}
    </div>
  );
}
