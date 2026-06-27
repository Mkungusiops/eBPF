import type { ReactNode } from "react";
import { X } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { Severity, SocPanelInventoryItem } from "./types";

export function cx(...classes: Array<string | false | null | undefined>): string {
  return classes.filter(Boolean).join(" ");
}

// Compact, human-friendly relative time ("just now", "3m", "2h"). Pair with an
// absolute timestamp in a title attribute for precision on hover.
export function relTime(value: string, now = Date.now()): string {
  const ts = new Date(value).getTime();
  if (Number.isNaN(ts)) return "—";
  const secs = Math.max(0, Math.round((now - ts) / 1000));
  if (secs < 5) return "just now";
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h`;
  return `${Math.floor(secs / 86400)}d`;
}

// Enterprise filter toggle: a pill with an on/off LED. Replaces bare checkboxes
// in toolbars — bigger touch target (PWA), clearer state, keyboard + a11y ready.
export function ToggleChip({
  label,
  active,
  onChange,
  icon: Icon,
  tone = "accent"
}: {
  label: string;
  active: boolean;
  onChange: (next: boolean) => void;
  icon?: LucideIcon;
  tone?: "accent" | "warn" | "good" | "danger";
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={active}
      className={cx("soc-toggle-chip", active && "is-on", `tone-${tone}`)}
      onClick={() => onChange(!active)}
    >
      <i className="soc-toggle-chip-led" aria-hidden="true" />
      {Icon ? <Icon size={13} aria-hidden="true" /> : null}
      <span>{label}</span>
    </button>
  );
}

export function IconButton({
  icon: Icon,
  label,
  onClick,
  active,
  disabled,
  tone = "neutral"
}: {
  icon: LucideIcon;
  label: string;
  onClick?: () => void;
  active?: boolean;
  disabled?: boolean;
  tone?: "neutral" | "accent" | "danger";
}) {
  return (
    <button
      className={cx("soc-icon-button", active && "is-active", tone !== "neutral" && `tone-${tone}`)}
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={label}
      aria-label={label}
    >
      <Icon size={16} aria-hidden="true" />
    </button>
  );
}

export function PanelFrame({
  panel,
  title,
  eyebrow,
  status,
  actions,
  children,
  className
}: {
  panel?: SocPanelInventoryItem;
  title?: string;
  eyebrow?: string;
  status?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={cx("soc-panel", className)} data-panel={panel?.id}>
      <div className="soc-panel-header">
        <div className="soc-panel-title-group">
          <span className="soc-eyebrow">{eyebrow || panel?.mode || "panel"}</span>
          <h2>{title || panel?.title}</h2>
        </div>
        <div className="soc-panel-actions">
          {status}
          {actions}
        </div>
      </div>
      {panel?.description ? <p className="soc-panel-copy">{panel.description}</p> : null}
      {children}
    </section>
  );
}

export function StatusPill({
  label,
  tone = "neutral"
}: {
  label: string;
  tone?: "ok" | "warn" | "danger" | "info" | "neutral";
}) {
  return <span className={cx("soc-pill", `tone-${tone}`)}>{label}</span>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={cx("soc-severity", `severity-${severity}`)}>{severity}</span>;
}

export function MetricTile({
  label,
  value,
  sub,
  tone,
  onClick,
  children
}: {
  label: string;
  value: string | number;
  sub?: string;
  tone?: Severity | "accent" | "good";
  onClick?: () => void;
  children?: ReactNode;
}) {
  const content = (
    <>
      <div className="soc-metric-label">{label}</div>
      <div className="soc-metric-value">{value}</div>
      {sub ? <div className="soc-metric-sub">{sub}</div> : null}
      {children}
    </>
  );

  if (onClick) {
    return (
      <button className={cx("soc-metric", tone && `tone-${tone}`)} type="button" onClick={onClick}>
        {content}
      </button>
    );
  }

  return <div className={cx("soc-metric", tone && `tone-${tone}`)}>{content}</div>;
}

export function Sparkline({ values, tone = "accent" }: { values: number[]; tone?: string }) {
  const max = Math.max(1, ...values);
  const bars = values.length ? values : Array.from({ length: 12 }, () => 0);
  return (
    <div className={cx("soc-sparkline", `tone-${tone}`)} aria-hidden="true">
      {bars.map((value, index) => (
        <span key={`${index}-${value}`} style={{ height: `${Math.max(8, (value / max) * 100)}%` }} />
      ))}
    </div>
  );
}

export function EmptyState({ title, detail }: { title: string; detail?: string }) {
  return (
    <div className="soc-empty">
      <strong>{title}</strong>
      {detail ? <span>{detail}</span> : null}
    </div>
  );
}

export function InlineNotice({
  tone = "info",
  title,
  children
}: {
  tone?: "info" | "warn" | "danger" | "ok";
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className={cx("soc-notice", `tone-${tone}`)} role={tone === "danger" ? "alert" : "status"}>
      <strong>{title}</strong>
      {children ? <span>{children}</span> : null}
    </div>
  );
}

export function ModalShell({
  panel,
  open,
  title,
  children,
  onClose,
  wide,
  fullScreen
}: {
  panel: SocPanelInventoryItem;
  open: boolean;
  title?: string;
  children: ReactNode;
  onClose: () => void;
  wide?: boolean;
  // fullScreen promotes the surface from a centered card to a full-viewport
  // page — for data-dense views (e.g. the correlation graph) that need room
  // to explore rather than a cramped modal box.
  fullScreen?: boolean;
}) {
  return (
    <div
      className={cx("soc-modal-back", open && "is-open", fullScreen && "is-fullscreen")}
      data-panel={panel.id}
      aria-hidden={!open}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className={cx("soc-modal-card", wide && "is-wide", fullScreen && "is-fullscreen")} role="dialog" aria-modal="true" aria-label={title || panel.title}>
        <div className="soc-modal-head">
          <div>
            <span className="soc-eyebrow">{panel.mode}</span>
            <h2>{title || panel.title}</h2>
          </div>
          <button type="button" className="soc-close-button" onClick={onClose} aria-label="Close">
            <X size={16} aria-hidden="true" />
          </button>
        </div>
        <p className="soc-panel-copy">{panel.description}</p>
        {children}
      </div>
    </div>
  );
}

export function SlideOver({
  panel,
  open,
  title,
  children,
  onClose
}: {
  panel: SocPanelInventoryItem;
  open: boolean;
  title?: string;
  children: ReactNode;
  onClose: () => void;
}) {
  return (
    <>
      <div className={cx("soc-slide-backdrop", open && "is-open")} onClick={onClose} aria-hidden="true" />
      <aside className={cx("soc-slide-over", open && "is-open")} data-panel={panel.id} aria-hidden={!open}>
        <div className="soc-modal-head">
          <div>
            <span className="soc-eyebrow">{panel.mode}</span>
            <h2>{title || panel.title}</h2>
          </div>
          <button type="button" className="soc-close-button" onClick={onClose} aria-label="Close">
            <X size={16} aria-hidden="true" />
          </button>
        </div>
        <p className="soc-panel-copy">{panel.description}</p>
        {children}
      </aside>
    </>
  );
}

export function PopoverCard({
  open,
  panel,
  title,
  children,
  onClose
}: {
  open: boolean;
  panel: SocPanelInventoryItem;
  title: string;
  children: ReactNode;
  onClose: () => void;
}) {
  return (
    <div className={cx("soc-popover", open && "is-open")} data-panel={panel.id} aria-hidden={!open}>
      <div className="soc-popover-head">
        <h3>{title}</h3>
        <button type="button" className="soc-close-button" onClick={onClose} aria-label="Close">
            <X size={16} aria-hidden="true" />
        </button>
      </div>
      {children}
    </div>
  );
}
