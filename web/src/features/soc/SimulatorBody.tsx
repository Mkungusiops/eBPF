// The score → severity threshold studio.
import { classifyScore } from "./analytics";
import { cx } from "./components";
import { SEVERITIES, SIM_SEVERITY_COLOR } from "./dashboard";
import { useLocalJsonState } from "./hooks";
import type { Severity, SocAlert } from "./types";

type SimThresholds = { low: number; medium: number; high: number; critical: number };
const SIM_PRESETS: Record<string, SimThresholds> = {
  Aggressive: { low: 3, medium: 7, high: 14, critical: 28 },
  Balanced: { low: 5, medium: 10, high: 20, critical: 40 },
  Quiet: { low: 10, medium: 25, high: 50, critical: 90 }
};

/**
 * Threshold studio: a live what-if for the score → severity thresholds. Rather
 * than typing four numbers blind, the operator sees the score DISTRIBUTION with
 * the thresholds drawn on it, watches each band recolour as they drag, and gets
 * the two things that actually matter for a tuning decision: how the severity
 * mix shifts (before → after) and exactly which alerts flip.
 */
export function SimulatorBody({ alerts }: { alerts: SocAlert[] }) {
  const [th, setTh] = useLocalJsonState<SimThresholds>("soc.simThresholds", SIM_PRESETS.Balanced);
  const set = (key: keyof SimThresholds, value: number) =>
    setTh((prev) => {
      const next = { ...prev, [key]: Math.max(0, value) };
      // Keep the ladder monotonic so the bands never cross.
      if (key === "low") next.medium = Math.max(next.medium, next.low + 1);
      if (key === "medium") { next.low = Math.min(next.low, next.medium - 1); next.high = Math.max(next.high, next.medium + 1); }
      if (key === "high") { next.medium = Math.min(next.medium, next.high - 1); next.critical = Math.max(next.critical, next.high + 1); }
      if (key === "critical") next.high = Math.min(next.high, next.critical - 1);
      return next;
    });

  const maxScore = Math.max(60, ...alerts.map((a) => a.score));
  const axisMax = Math.ceil(maxScore / 10) * 10;

  const sim = (score: number) => classifyScore(score, th.low, th.medium, th.high, th.critical);

  // Actual (engine-assigned severity) vs simulated (re-bucketed by the sliders).
  const actual = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
  const simulated = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
  const flips: Array<{ alert: SocAlert; from: Severity; to: Severity }> = [];
  for (const a of alerts) {
    const to = sim(a.score);
    actual[a.severity] += 1;
    simulated[to] += 1;
    if (a.severity !== to) flips.push({ alert: a, from: a.severity, to });
  }

  // Score histogram: 20 bins across the axis, each coloured by the band its
  // score range now falls in.
  const bins = 20;
  const binW = axisMax / bins;
  const hist = Array.from({ length: bins }, (_, i) => ({ from: i * binW, to: (i + 1) * binW, count: 0 }));
  for (const a of alerts) {
    const idx = Math.min(bins - 1, Math.floor(a.score / binW));
    hist[idx].count += 1;
  }
  const maxBin = Math.max(1, ...hist.map((b) => b.count));

  const H = 120;
  const pct = (score: number) => `${(score / axisMax) * 100}%`;
  const markers: Array<[keyof SimThresholds, Severity]> = [
    ["low", "low"],
    ["medium", "medium"],
    ["high", "high"],
    ["critical", "critical"]
  ];

  return (
    <div className="soc-sim">
      <div className="soc-sim-presets">
        <span className="soc-stat-label">Preset</span>
        {Object.keys(SIM_PRESETS).map((name) => {
          const p = SIM_PRESETS[name];
          const active = p.low === th.low && p.medium === th.medium && p.high === th.high && p.critical === th.critical;
          return (
            <button key={name} type="button" className={cx("soc-sim-preset", active && "is-active")} onClick={() => setTh(p)}>
              {name}
            </button>
          );
        })}
      </div>

      {/* Distribution with the thresholds drawn on it. */}
      <div className="soc-sim-chart" style={{ height: `${H}px` }}>
        {markers.map(([key, sev]) => (
          <div key={key} className="soc-sim-marker" style={{ left: pct(th[key]) }}>
            <span className="soc-sim-marker-flag" style={{ background: SIM_SEVERITY_COLOR[sev] }}>{th[key]}</span>
          </div>
        ))}
        <div className="soc-sim-bars">
          {hist.map((b, i) => {
            const mid = (b.from + b.to) / 2;
            return (
              <div
                key={i}
                className="soc-sim-bar"
                title={`score ${Math.round(b.from)}–${Math.round(b.to)} · ${b.count} alerts · ${sim(mid)}`}
                style={{ height: `${(b.count / maxBin) * 100}%`, background: SIM_SEVERITY_COLOR[sim(mid)] }}
              />
            );
          })}
        </div>
      </div>
      <div className="soc-sim-axis">
        <span>0</span><span>score</span><span>{axisMax}</span>
      </div>

      {/* Sliders — dragging one recolours the chart live. */}
      <div className="soc-sim-sliders">
        {markers.map(([key, sev]) => (
          <label key={key} className="soc-sim-slider">
            <span className="soc-sim-slider-head">
              <i style={{ background: SIM_SEVERITY_COLOR[sev] }} />
              {key} ≥ <strong>{th[key]}</strong>
            </span>
            <input
              type="range"
              min={0}
              max={axisMax}
              value={th[key]}
              onChange={(e) => set(key, Number(e.target.value))}
              style={{ accentColor: SIM_SEVERITY_COLOR[sev] }}
            />
          </label>
        ))}
      </div>

      {/* Before → after and the flips: the decision inputs. */}
      <div className="soc-sim-compare">
        {SEVERITIES.map((s) => {
          const delta = simulated[s] - actual[s];
          return (
            <div key={s} className="soc-sim-cell" style={{ borderTopColor: SIM_SEVERITY_COLOR[s] }}>
              <span className="soc-sim-cell-label">{s}</span>
              <span className="soc-sim-cell-vals">
                <em>{actual[s]}</em> → <strong>{simulated[s]}</strong>
              </span>
              {delta !== 0 ? (
                <span className={cx("soc-sim-delta", delta > 0 ? "up" : "down")}>
                  {delta > 0 ? "▲" : "▼"} {Math.abs(delta)}
                </span>
              ) : (
                <span className="soc-sim-delta flat">—</span>
              )}
            </div>
          );
        })}
      </div>

      <div className="soc-sim-flips">
        <span className="soc-stat-label">
          {flips.length} of {alerts.length} alerts change severity
          {flips.length ? ` · ${simulated.info - actual.info > 0 ? `${simulated.info - actual.info} newly suppressed` : "signal preserved"}` : ""}
        </span>
        {flips.slice(0, 8).map(({ alert, from, to }) => (
          <div key={alert.id} className="soc-sim-flip">
            <span className="soc-sim-flip-title">{alert.title}</span>
            <span className="soc-sim-flip-move">
              <b style={{ color: SIM_SEVERITY_COLOR[from] }}>{from}</b>
              →
              <b style={{ color: SIM_SEVERITY_COLOR[to] }}>{to}</b>
              <em>score {alert.score}</em>
            </span>
          </div>
        ))}
        {flips.length === 0 ? <p className="soc-graph-selection-empty">These thresholds match the engine's current severities exactly.</p> : null}
      </div>
    </div>
  );
}
