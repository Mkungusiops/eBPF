// Presentational primitives for the Choke Gateway. Nothing here fetches,
// polls, or decides — every one of these takes what it renders as a prop, so
// the containment surfaces above them stay the only place state lives.
import type { ReactNode } from "react";
import { X } from "lucide-react";
import type { ToastMessage } from "./types";
import { STATE_ORDER, basename } from "./utils";

export function Panel({ title, children, actions, dataPanel }: { title: string; children: ReactNode; actions?: ReactNode; dataPanel?: string }) {
  return (
    <section className="choke-panel" data-panel={dataPanel}>
      <header className="choke-panel-header">
        <h2>{title}</h2>
        {actions ? <div className="choke-panel-actions">{actions}</div> : null}
      </header>
      {children}
    </section>
  );
}

export function MiniPanel({ title, meta, children }: { title: string; meta?: string; children: ReactNode }) {
  return (
    <div className="choke-mini-panel">
      <header><span>{title}</span><small>{meta}</small></header>
      {children}
    </div>
  );
}

export function Banner({ title, children, tone, dataPanel }: { title: string; children: ReactNode; tone: "warn" | "danger"; dataPanel: string }) {
  return (
    <div className={`choke-banner ${tone}`} data-panel={dataPanel} role="status" aria-live="polite">
      <strong>{title}</strong>
      <span>{children}</span>
    </div>
  );
}

export function StateBadge({ state }: { state?: string }) {
  const value = state || "pristine";
  return <span className={`choke-state-badge state-${value}`}>{value}</span>;
}

export function Sparkline({ bars, tone = "accent" }: { bars: number[]; tone?: "accent" | "warn" | "danger" }) {
  const peak = Math.max(1, ...bars);
  return (
    <div className={`choke-spark ${tone}`} aria-hidden="true">
      {bars.map((bar, index) => (
        <span key={index} style={{ height: `${bar === 0 ? 2 : Math.max(2, Math.round((bar / peak) * 28))}px` }} />
      ))}
    </div>
  );
}

export function SegmentedControl({
  values,
  value,
  format,
  onChange,
}: {
  values: number[];
  value: number;
  format: (value: number) => string;
  onChange: (value: number) => void;
}) {
  return (
    <div className="choke-segmented">
      {values.map((item) => (
        <button key={item} type="button" className={item === value ? "active" : ""} onClick={() => onChange(item)}>
          {format(item)}
        </button>
      ))}
    </div>
  );
}

/**
 * The ladder, showing DECIDED against APPLIED.
 *
 * These were two panels — a State Ladder of what the engine decided, and a
 * Cgroup Tiers panel of what is in the kernel — sitting apart with no
 * relationship drawn between them. Read separately they look like duplicates
 * with one of them broken: the ladder said seven throttled while the tiers said
 * zero and "empty", which reads as a bug rather than as detect-only working
 * exactly as designed.
 *
 * Read together they are the assurance answer this console exists to give: what
 * did the platform decide, what did the kernel actually receive, and when those
 * differ, WHY. A gap with no reason offered is the one thing this must never
 * show, because the honest reasons (detect-only, dry-run, kill-switch) and the
 * alarming one (enforcement silently failing) look identical without it.
 *
 * `applied` is omitted where the concept does not exist rather than shown as
 * zero: nothing is pristine "in a cgroup", and a sever is a SIGKILL with no
 * cgroup to land in. A zero there would be a claim, and a false one.
 */
export function StateLadder({
  counts,
  applied,
  gapReason
}: {
  counts: Partial<Record<string, number>>;
  /** PIDs actually in each enforcement cgroup. Absent when unknown. */
  applied?: Partial<Record<string, number>>;
  /** Why decided and applied differ, when they do. */
  gapReason?: string;
}) {
  const max = Math.max(1, ...STATE_ORDER.map((state) => counts[state] || 0));
  // Only the three tiers that HAVE a cgroup can be compared.
  const comparable = new Set(["throttled", "tarpit", "quarantined"]);
  const showApplied = !!applied;
  const gap =
    showApplied &&
    STATE_ORDER.some((s) => comparable.has(s) && (counts[s] || 0) > (applied?.[s] || 0));
  return (
    <div className="choke-ladder">
      {showApplied ? (
        <div className="choke-ladder-head">
          <span />
          <span>decided</span>
          <span>in cgroup</span>
        </div>
      ) : null}
      {STATE_ORDER.map((state) => {
        const count = counts[state] || 0;
        return (
          <div key={state} className="choke-ladder-row">
            <StateBadge state={state} />
            <span className="choke-ladder-track"><span style={{ width: `${(count / max) * 100}%` }} /></span>
            <strong>{count}</strong>
            {showApplied ? (
              <em className="choke-ladder-applied">
                {comparable.has(state) ? (applied?.[state] ?? 0) : "—"}
              </em>
            ) : null}
          </div>
        );
      })}
      {gap ? (
        <p className="choke-ladder-note">
          {gapReason ||
            "Decided but not in a cgroup, and this deployment does not report why — treat enforcement as unconfirmed."}
        </p>
      ) : null}
    </div>
  );
}

export function RankedList({ rows, onPick }: { rows: Array<{ key: string; count: number }>; onPick: (key: string) => void }) {
  if (rows.length === 0) return <span className="choke-muted">no decisions in window</span>;
  const max = Math.max(1, ...rows.map((row) => row.count));
  return (
    <div className="choke-ranked-list">
      {rows.map((row) => (
        <button key={row.key} type="button" onClick={() => onPick(row.key)}>
          <span className="truncate">{basename(row.key)}</span>
          <strong>{row.count}</strong>
          <em style={{ width: `${(row.count / max) * 100}%` }} />
        </button>
      ))}
    </div>
  );
}

export function PopoverHeader({ title, onClose }: { title: string; onClose: () => void }) {
  return (
    <header className="choke-popover-header">
      <h3>{title}</h3>
      <button type="button" className="choke-popover-close" onClick={onClose} aria-label={`Close ${title}`}>
        <X size={15} aria-hidden="true" />
      </button>
    </header>
  );
}

export function ToastStack({ toasts }: { toasts: ToastMessage[] }) {
  return (
    <div className="choke-toasts" aria-live="polite">
      {toasts.map((toast) => <div key={toast.id} className={toast.kind}>{toast.message}</div>)}
    </div>
  );
}

export function EmptyState({ title, body }: { title: string; body: string }) {
  return <div className="choke-empty"><strong>{title}</strong><span>{body}</span></div>;
}

export function LoadingState({ label }: { label: string }) {
  return <div className="choke-empty loading"><strong>{label}</strong><span>Waiting for the API response.</span></div>;
}

export function ErrorState({ title, body }: { title: string; body: string }) {
  return <div className="choke-empty error"><strong>{title}</strong><span>{body}</span></div>;
}

export function FilterChip({ label, onClear }: { label: string; onClear: () => void }) {
  return <button className="choke-filter-chip" type="button" onClick={onClear}>{label} x</button>;
}
