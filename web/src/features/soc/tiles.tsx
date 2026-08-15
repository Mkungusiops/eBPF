// The two KPI tile shapes: the big clickable metric on the dashboard's top row,
// and the compact stat used inside a drill-down.
import type * as React from "react";
import { cx } from "./components";
import type { Severity } from "./types";

export function ExecutiveMetricTile({
  label,
  value,
  sub,
  meta,
  delta,
  badge,
  tone,
  onClick,
  children
}: {
  label: string;
  value: string | number;
  sub: string;
  meta: string;
  delta?: number;
  badge: string;
  tone: Severity | "accent" | "good";
  onClick: () => void;
  children?: React.ReactNode;
}) {
  const trend = delta === undefined ? null : delta > 0 ? "up" : delta < 0 ? "down" : "flat";
  const deltaText = delta === undefined ? "" : delta === 0 ? "0" : `${delta > 0 ? "+" : ""}${delta}`;
  return (
    <button className={cx("soc-exec-metric", `tone-${tone}`)} type="button" onClick={onClick}>
      <span className="soc-exec-metric-glow" aria-hidden="true" />
      <div className="soc-exec-metric-head">
        <span>{label}</span>
        <em>{badge}</em>
      </div>
      <div className="soc-exec-metric-value">
        <strong>{value}</strong>
        {trend ? (
          <span className={cx("soc-exec-trend", `is-${trend}`)}>
            {deltaText} vs prior
          </span>
        ) : null}
      </div>
      <div className="soc-exec-metric-sub">{sub}</div>
      <div className="soc-exec-metric-foot">
        <span>{meta}</span>
        {children}
      </div>
    </button>
  );
}

export function KpiStat({
  label,
  value,
  meta,
  tone
}: {
  label: string;
  value: string | number;
  meta: string;
  tone?: Severity | "accent" | "good";
}) {
  return (
    <div className={cx("soc-kpi-stat", tone && `tone-${tone}`)}>
      <span>{label}</span>
      <strong>{value}</strong>
      <em>{meta}</em>
    </div>
  );
}
