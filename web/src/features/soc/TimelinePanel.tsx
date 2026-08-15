// Stacked alert-volume-over-time chart. Each bar is a time bucket; segments are
// severity-coloured; red dots mark statistical spikes. Hover any bar for a full
// breakdown so an analyst can see exactly what happened in that window.
import { useState } from "react";
import { cx } from "./components";
import { SEVERITIES, type TimelineBucket } from "./dashboard";
import { formatDuration } from "./format";

export function TimelinePanel({ buckets, rangeMin }: { buckets: TimelineBucket[]; rangeMin: number }) {
  const [hover, setHover] = useState<number | null>(null);
  const max = Math.max(1, ...buckets.map((bucket) => bucket.total));
  const total = buckets.reduce((sum, bucket) => sum + bucket.total, 0);
  const avg = total / Math.max(1, buckets.length);
  // A 5m range across 30 buckets is 10s per bar. The old label rounded that to
  // minutes and clamped at 1, so every short range claimed "each bar ≈ 1m" and
  // the per-bar average silently read as a per-minute rate — off by 6x.
  const bucketMs = (rangeMin * 60_000) / Math.max(1, buckets.length);
  const bucketSpan = formatDuration(bucketMs);

  return (
    <div className="soc-timeline-wrap">
      <div
        className="soc-timeline"
        onMouseLeave={() => setHover(null)}
        role="img"
        aria-label={`Alert volume over the last ${rangeMin >= 1440 ? "24 hours" : `${rangeMin} minutes`}: ${total} alerts, peak ${max} per bar. Hover a bar for the severity breakdown.`}
      >
        {buckets.map((bucket, index) => (
          <div
            key={`${bucket.label}-${index}`}
            className={cx("soc-timeline-bucket", hover === index && "is-hover", bucket.anomaly && "is-anomaly")}
            onMouseEnter={() => setHover(index)}
          >
            {bucket.anomaly ? <span className="soc-anomaly" /> : null}
            <div className="soc-timeline-stack" style={{ height: `${Math.max(bucket.total ? 6 : 2, (bucket.total / max) * 100)}%` }}>
              {SEVERITIES.map((severity) => {
                const value = bucket.counts[severity];
                if (!value) return null;
                return <span key={severity} className={`severity-${severity}`} style={{ flex: value }} />;
              })}
            </div>
            <small>{index % 5 === 0 ? bucket.label : ""}</small>
          </div>
        ))}
        {hover != null && buckets[hover] ? (
          <TimelineTooltip
            bucket={buckets[hover]}
            leftPct={((hover + 0.5) / Math.max(1, buckets.length)) * 100}
            avg={avg}
            bucketSpan={bucketSpan}
          />
        ) : null}
      </div>
      <div className="soc-timeline-legend">
        <span>{buckets[0]?.label}</span>
        <span className="soc-timeline-legend-mid">
          each bar {bucketSpan} · avg {avg.toFixed(1)} · peak {max} alerts per bar
        </span>
        <span>
          {buckets.at(-1)?.label} <em>· now</em>
        </span>
      </div>
    </div>
  );
}

function TimelineTooltip({
  bucket,
  leftPct,
  avg,
  bucketSpan
}: {
  bucket: TimelineBucket;
  leftPct: number;
  avg: number;
  bucketSpan: string;
}) {
  // Absolutely positioned inside the chart; the column index drives a pure-CSS
  // clamp so the card tracks the hovered bar yet never spills past either edge.
  return (
    <div className="soc-timeline-tip" style={{ left: `clamp(8px, ${leftPct.toFixed(2)}%, calc(100% - 218px))` }} role="tooltip">
      <div className="soc-timeline-tip-head">
        <strong>{bucket.label}</strong>
        <span>{bucketSpan} bucket</span>
      </div>
      {bucket.total === 0 ? (
        <p className="soc-timeline-tip-empty">No alerts in this window.</p>
      ) : (
        <>
          <div className="soc-timeline-tip-total">
            {bucket.total} alert{bucket.total === 1 ? "" : "s"}
          </div>
          <div className="soc-timeline-tip-rows">
            {SEVERITIES.map((severity) =>
              bucket.counts[severity] ? (
                <div key={severity} className="soc-timeline-tip-row">
                  <span className={cx("soc-timeline-tip-dot", `sev-${severity}`)} />
                  <span>{severity}</span>
                  <strong>{bucket.counts[severity]}</strong>
                </div>
              ) : null
            )}
          </div>
        </>
      )}
      {bucket.anomaly ? (
        <div className="soc-timeline-tip-anomaly">⚠ Anomalous spike — far above the {avg.toFixed(1)}/bar baseline</div>
      ) : null}
    </div>
  );
}
