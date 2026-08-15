// Time Machine — replay the buffered telemetry as it was at any instant.
import { useEffect, useMemo, useState } from "react";
import { Clock, Minimize2, Plus, Zap } from "lucide-react";
import { EmptyState, cx } from "./components";
import { SIM_SEVERITY_COLOR } from "./dashboard";
import { useLocalJsonState } from "./hooks";
import { MITRE_MATRIX, techniqueForAlert } from "./panels";
import type { Severity, SocAlert, SocEvent } from "./types";

const EMPTY_TECH_MAP = new Map<string, string>();

function mitreTechniqueLabel(id: string): string {
  for (const tactic of MITRE_MATRIX) {
    const hit = tactic.techniques.find((t) => t.id === id);
    if (hit) return hit.name;
  }
  return "technique";
}

interface TmBookmark { id: string; label: string; t: number }

/**
 * Time Machine — a real timeline scrubber over the buffered telemetry. It was a
 * stub ("no bookmarks loaded"). Now the operator drags a playhead across an
 * alert-density track and the whole posture (severity mix, risk, top technique,
 * event rate, and what was firing) re-renders AS IT WAS at that instant. Play to
 * watch an incident unfold, bookmark a moment ("intrusion start"), or switch to
 * Diff to see exactly what changed between two points in time.
 */
export function TimeMachineBody({ alerts, events, open }: { alerts: SocAlert[]; events: SocEvent[]; open: boolean }) {
  const stamped = useMemo(
    () => alerts.map((a) => ({ a, t: Date.parse(a.timestamp) })).filter((x) => !Number.isNaN(x.t)).sort((x, y) => x.t - y.t),
    [alerts]
  );
  const eventTimes = useMemo(
    () => events.map((e) => Date.parse(e.timestamp)).filter((t) => !Number.isNaN(t)).sort((x, y) => x - y),
    [events]
  );

  const tMin = stamped.length ? stamped[0].t : Date.now() - 3_600_000;
  const tMax = stamped.length ? stamped[stamped.length - 1].t : Date.now();
  const span = Math.max(1, tMax - tMin);

  const [t, setT] = useState(tMax);
  const [playing, setPlaying] = useState(false);
  const [mode, setMode] = useState<"scrub" | "diff">("scrub");
  const [diffA, setDiffA] = useState<number | null>(null);
  const [bookmarks, setBookmarks] = useLocalJsonState<TmBookmark[]>("soc.tmBookmarks", []);

  // Reset the playhead to "now" whenever the panel opens or the buffer grows.
  useEffect(() => { if (open) setT(tMax); }, [open, tMax]);

  // Play: advance the head across the span in ~5s, then stop at the end.
  useEffect(() => {
    if (!playing) return undefined;
    const step = span / 100;
    const id = window.setInterval(() => {
      setT((cur) => {
        const next = cur + step;
        if (next >= tMax) { setPlaying(false); return tMax; }
        return next;
      });
    }, 50);
    return () => window.clearInterval(id);
  }, [playing, span, tMax]);

  const sevRank: Severity[] = ["critical", "high", "medium", "low", "info"];
  const stateAt = (at: number) => {
    const upTo = stamped.filter((x) => x.t <= at);
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
    const techniques = new Map<string, number>();
    for (const { a } of upTo) {
      counts[a.severity] += 1;
      // Resolve the technique the same way the Navigator does (mitre tag, then
      // known policy name, then alert-text keywords) so the timeline shows the
      // real top technique instead of "none" on untagged real-agent data.
      const id = techniqueForAlert(a, EMPTY_TECH_MAP);
      if (id) techniques.set(`${id} ${mitreTechniqueLabel(id)}`, (techniques.get(`${id} ${mitreTechniqueLabel(id)}`) || 0) + 1);
    }
    const risk = Math.min(100, counts.critical * 8 + counts.high * 3 + counts.medium);
    const rate = eventTimes.filter((et) => et > at - 60_000 && et <= at).length / 60;
    const topTech = [...techniques.entries()].sort((a, b) => b[1] - a[1])[0];
    return { total: upTo.length, counts, risk, rate, topTech, recent: upTo.slice(-6).reverse().map((x) => x.a) };
  };

  const now = stateAt(t);

  // Alert-density track: 60 bins of alert volume across the span.
  const bins = 60;
  const density = useMemo(() => {
    const acc = new Array(bins).fill(0);
    for (const { t: at } of stamped) acc[Math.min(bins - 1, Math.floor(((at - tMin) / span) * bins))] += 1;
    return acc;
  }, [stamped, tMin, span]);
  const maxDensity = Math.max(1, ...density);

  const fmtClock = (ms: number) => new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const pctOf = (ms: number) => `${((ms - tMin) / span) * 100}%`;

  // Diff: A is pinned, B is the current head.
  const diff = mode === "diff" && diffA != null ? (() => {
    const a = Math.min(diffA, t), b = Math.max(diffA, t);
    const sa = stateAt(a), sb = stateAt(b);
    const between = stamped.filter((x) => x.t > a && x.t <= b).map((x) => x.a);
    const newTechs = new Set<string>();
    const seenBefore = new Set(stamped.filter((x) => x.t <= a).map((x) => x.a.mitreId?.match(/T\d{4}/)?.[0]).filter(Boolean) as string[]);
    for (const al of between) { const id = al.mitreId?.match(/T\d{4}/)?.[0]; if (id && !seenBefore.has(id)) newTechs.add(id); }
    return { a, b, sa, sb, added: between.length, newTechs: [...newTechs] };
  })() : null;

  if (!stamped.length) {
    return <EmptyState title="No telemetry in the buffer yet" detail="Alerts will populate the timeline as the engine emits them." />;
  }

  return (
    <div className="soc-tm">
      <div className="soc-tm-controls">
        <div className="soc-tm-modes">
          <button type="button" className={cx("soc-tm-mode", mode === "scrub" && "is-active")} onClick={() => { setMode("scrub"); setDiffA(null); }}>Scrub</button>
          <button type="button" className={cx("soc-tm-mode", mode === "diff" && "is-active")} onClick={() => { setMode("diff"); setDiffA((v) => v ?? t); }}>Diff</button>
        </div>
        {mode === "scrub" ? (
          <button type="button" className="soc-tm-play" onClick={() => { if (t >= tMax) setT(tMin); setPlaying((p) => !p); }}>
            {playing ? <><Minimize2 size={13} /> Pause</> : <><Zap size={13} /> Play incident</>}
          </button>
        ) : (
          <span className="soc-tm-diff-hint">A pinned at {diffA != null ? fmtClock(diffA) : "—"} · drag for B</span>
        )}
        <span className="soc-tm-clock">{fmtClock(t)}</span>
      </div>

      {/* Density track + playhead. */}
      <div className="soc-tm-track">
        <div className="soc-tm-density">
          {density.map((d, i) => <span key={i} style={{ height: `${(d / maxDensity) * 100}%` }} />)}
        </div>
        {bookmarks.map((bm) => (
          <button
            key={bm.id}
            type="button"
            className="soc-tm-bm-tick"
            style={{ left: pctOf(bm.t) }}
            title={`${bm.label} · ${fmtClock(bm.t)}`}
            onClick={() => { setT(bm.t); setPlaying(false); }}
          />
        ))}
        {mode === "diff" && diffA != null ? <div className="soc-tm-head is-a" style={{ left: pctOf(diffA) }} /> : null}
        <div className={cx("soc-tm-head", mode === "diff" && "is-b")} style={{ left: pctOf(t) }} />
        <input
          type="range"
          className="soc-tm-range"
          min={tMin}
          max={tMax}
          value={t}
          onChange={(e) => { setPlaying(false); setT(Number(e.target.value)); }}
        />
      </div>
      <div className="soc-tm-axis"><span>{fmtClock(tMin)}</span><span>{fmtClock(tMax)}</span></div>

      {mode === "scrub" ? (
        <>
          <div className="soc-tm-state">
            <div className="soc-tm-risk" data-tone={now.risk >= 80 ? "critical" : now.risk >= 45 ? "high" : now.risk >= 18 ? "elevated" : "low"}>
              <span className="soc-stat-label">Posture at {fmtClock(t)}</span>
              <strong>{now.risk}<i>/100</i></strong>
              <em>{now.total} alerts · {now.rate.toFixed(1)}/s events</em>
            </div>
            <div className="soc-tm-sevs">
              {sevRank.map((s) => (
                <div key={s} className="soc-tm-sev" style={{ borderTopColor: SIM_SEVERITY_COLOR[s] }}>
                  <span>{s}</span>
                  <strong>{now.counts[s]}</strong>
                </div>
              ))}
            </div>
          </div>

          <div className="soc-tm-cols">
            <div className="soc-tm-col">
              <span className="soc-stat-label">Top technique then</span>
              {now.topTech ? (
                <div className="soc-tm-tech"><strong>{now.topTech[0]}</strong><em>×{now.topTech[1]}</em></div>
              ) : <p className="soc-graph-selection-empty">none yet</p>}
            </div>
            <div className="soc-tm-col">
              <span className="soc-stat-label">Firing at this moment</span>
              {now.recent.length ? now.recent.map((a) => (
                <div key={a.id} className={cx("soc-tm-alert", `sev-${a.severity}`)}>
                  <span>{a.title}</span><em>{fmtClock(Date.parse(a.timestamp))}</em>
                </div>
              )) : <p className="soc-graph-selection-empty">quiet</p>}
            </div>
          </div>
        </>
      ) : diff ? (
        <div className="soc-tm-diffbox">
          <div className="soc-tm-diff-head">
            <span><b>A</b> {fmtClock(diff.a)}</span>
            <span className="soc-tm-diff-arrow">→</span>
            <span><b>B</b> {fmtClock(diff.b)}</span>
          </div>
          <div className="soc-tm-diff-metrics">
            <div><span className="soc-stat-label">Alerts added</span><strong>+{diff.added}</strong></div>
            <div><span className="soc-stat-label">Risk</span><strong>{diff.sa.risk} → {diff.sb.risk}</strong></div>
            <div><span className="soc-stat-label">New techniques</span><strong>{diff.newTechs.length}</strong></div>
          </div>
          {sevRank.some((s) => diff.sb.counts[s] - diff.sa.counts[s] !== 0) ? (
            <div className="soc-tm-sevs">
              {sevRank.map((s) => {
                const d = diff.sb.counts[s] - diff.sa.counts[s];
                return (
                  <div key={s} className="soc-tm-sev" style={{ borderTopColor: SIM_SEVERITY_COLOR[s] }}>
                    <span>{s}</span><strong>{d > 0 ? `+${d}` : d}</strong>
                  </div>
                );
              })}
            </div>
          ) : null}
          {diff.newTechs.length ? (
            <div className="soc-tm-col">
              <span className="soc-stat-label">First seen in this window</span>
              {diff.newTechs.map((id) => (
                <div key={id} className="soc-tm-tech"><strong>{id}</strong><em>{mitreTechniqueLabel(id)}</em></div>
              ))}
            </div>
          ) : null}
        </div>
      ) : null}

      {/* Bookmarks */}
      <div className="soc-tm-bookmarks">
        <div className="soc-tm-bm-head">
          <span className="soc-stat-label"><Clock size={12} aria-hidden="true" /> Bookmarks</span>
          <button
            type="button"
            className="soc-tm-bm-add"
            onClick={() => {
              const label = window.prompt("Bookmark this moment as:", `Marker ${fmtClock(t)}`)?.trim();
              if (label) setBookmarks((b) => [...b, { id: `${Date.now()}`, label, t }].sort((x, y) => x.t - y.t));
            }}
          >
            <Plus size={12} /> Mark {fmtClock(t)}
          </button>
        </div>
        {bookmarks.length ? (
          <div className="soc-tm-bm-list">
            {bookmarks.map((bm) => (
              <div key={bm.id} className="soc-tm-bm">
                <button type="button" className="soc-tm-bm-jump" onClick={() => { setT(bm.t); setPlaying(false); }}>
                  <b>{bm.label}</b><em>{fmtClock(bm.t)}</em>
                </button>
                <button type="button" className="soc-tm-bm-del" onClick={() => setBookmarks((b) => b.filter((x) => x.id !== bm.id))} aria-label="Remove bookmark">×</button>
              </div>
            ))}
          </div>
        ) : (
          <p className="soc-graph-selection-empty">Drag to a moment and mark it — jump back anytime.</p>
        )}
      </div>
    </div>
  );
}
