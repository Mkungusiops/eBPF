// The repeating rows of the dashboard: one alert in the triage queue, one event
// in the live stream, and the three small aggregate lists that fill the right
// rail — plus the two floating surfaces (hover preview, context menu) that hang
// off an alert row.
//
// All presentational: every one takes the data it draws and the callbacks it
// fires, and computes nothing the route does not already know.
import type { MouseEvent } from "react";
import { EmptyState, SeverityBadge, StatusPill, cx, relTime } from "./components";
import { classificationLabel, classifyAlert, processChainFromAlert } from "./analytics";
import { PANELS, type AckState, type AlertGroup, type ContextMenuState, type HoverPreviewState } from "./dashboard";
import { formatDuration } from "./format";
import type { SocAlert, SocEvent } from "./types";

// A panel whose feed cannot reach the whole window says so in its own header,
// rather than the page carrying a permanent band about it. Renders nothing when
// the panel's feed covers the range, so a complete panel is unmarked.
export function CoveragePill({ feed }: { feed: { short: boolean; coveredMs: number } }) {
  return feed.short ? <StatusPill label={`last ${formatDuration(feed.coveredMs)}`} tone="warn" /> : null;
}

export function AlertRow({
  alert,
  ack,
  selected,
  pinned,
  onSelect,
  onOpen,
  onAck,
  onPin,
  onContext,
  onHover,
  onLeave
}: {
  alert: AlertGroup;
  ack: AckState;
  selected: boolean;
  pinned: boolean;
  onSelect: () => void;
  onOpen: () => void;
  onAck: (value: AckState) => void;
  onPin: () => void;
  onContext: (event: MouseEvent) => void;
  onHover: (event: MouseEvent) => void;
  onLeave: () => void;
}) {
  const classification = classifyAlert(alert);
  const classLabel = classificationLabel(classification);
  const chain = processChainFromAlert(alert);
  const processLabel = chain.at(-1) || alert.process || "unknown process";
  const technique = alert.mitreId ? /T\d{4}/.exec(alert.mitreId)?.[0] : undefined;
  return (
    <article
      className={cx(
        "soc-alert-row",
        selected && "is-selected",
        pinned && "is-pinned",
        ack !== "new" && "is-acked",
        `severity-rail-${alert.severity}`,
        `class-${classification}`
      )}
      onContextMenu={onContext}
      onMouseMove={onHover}
      onMouseLeave={onLeave}
    >
      <input
        className="soc-alert-check"
        type="checkbox"
        checked={selected}
        onChange={onSelect}
        aria-label={`Select ${alert.title}`}
      />
      <button type="button" className="soc-alert-main" onClick={onOpen}>
        <div className="soc-alert-head">
          <SeverityBadge severity={alert.severity} />
          <strong title={alert.title}>{alert.title}</strong>
          {alert.groupCount > 1 ? <span className="soc-group-count">×{alert.groupCount}</span> : null}
          <time className="soc-alert-time" title={new Date(alert.timestamp).toLocaleString()}>
            {relTime(alert.timestamp)}
          </time>
        </div>
        <p className="soc-alert-desc">{alert.description}</p>
        <div className="soc-alert-chips">
          <span className={cx("soc-entity-chip", `cls-${classification}`)}>{classLabel}</span>
          <span className="soc-entity-chip is-score">score {alert.score}</span>
          {technique ? <span className="soc-entity-chip is-mitre">{technique}</span> : null}
          <span className="soc-entity-chip is-proc" title={processLabel}>
            {processLabel}
          </span>
          {alert.pid ? <span className="soc-entity-chip">pid {alert.pid}</span> : null}
          {alert.policyName ? <span className="soc-entity-chip is-policy">{alert.policyName}</span> : null}
        </div>
      </button>
      <div className="soc-alert-actions">
        <button type="button" className={cx("soc-pin", pinned && "is-active")} onClick={onPin} title={pinned ? "Unpin" : "Pin to top"}>
          {pinned ? "Pinned" : "Pin"}
        </button>
        <span className={cx("soc-ack", `ack-${ack}`)}>{ack === "new" ? "New" : ack === "ack" ? "Ack'd" : "Resolved"}</span>
        {ack === "new" ? (
          <button type="button" onClick={() => onAck("ack")}>
            Ack
          </button>
        ) : null}
        {ack !== "resolved" ? (
          <button type="button" onClick={() => onAck("resolved")}>
            Resolve
          </button>
        ) : (
          <button type="button" onClick={() => onAck("new")}>
            Reopen
          </button>
        )}
      </div>
    </article>
  );
}

// Group raw event types into a few human-meaningful kinds so the stream reads
// at a glance (and colours consistently) instead of showing opaque API strings.
function eventKind(eventType: string): { key: string; label: string } {
  const t = eventType.toLowerCase();
  if (t.includes("exit")) return { key: "exit", label: "exit" };
  if (t.includes("kprobe")) return { key: "kprobe", label: "syscall" };
  if (t.includes("exec") || t.includes("bprm")) return { key: "exec", label: "exec" };
  if (t.includes("connect") || t.includes("tcp") || t.includes("net")) return { key: "net", label: "network" };
  return { key: "event", label: "event" };
}

export function EventRow({ event, onOpen }: { event: SocEvent; onOpen: (event: SocEvent) => void }) {
  const kind = eventKind(event.eventType);
  const detail =
    event.args ||
    event.path ||
    (event.destIp ? `${event.destIp}${event.destPort ? `:${event.destPort}` : ""}` : "") ||
    event.policyName ||
    "—";
  return (
    <button
      type="button"
      className={cx("soc-event-row", `kind-${kind.key}`)}
      aria-label={`${event.eventType} ${event.process || "process"} ${detail}`}
      onClick={() => onOpen(event)}
    >
      <time title={new Date(event.timestamp).toLocaleString()}>{relTime(event.timestamp)}</time>
      <span className={cx("soc-event-kind", `kind-${kind.key}`)}>{kind.label}</span>
      <code className="soc-event-proc" title={event.process || ""}>
        {event.process || "process"}
      </code>
      <span className="soc-event-detail" title={detail}>
        {detail}
      </span>
    </button>
  );
}

export function MiniBarList({
  rows,
  empty,
  onClick
}: {
  rows: Array<{ label: string; value: number; meta?: string; id?: string }>;
  empty: string;
  onClick?: (id: string) => void;
}) {
  const max = Math.max(1, ...rows.map((row) => row.value));
  if (!rows.length) return <EmptyState title={empty} />;
  return (
    <div className="soc-mini-bars">
      {rows.slice(0, 8).map((row) => {
        const body = (
          <>
            <span>{row.label}</span>
            <em>{row.meta || row.value}</em>
            <i style={{ width: `${Math.max(4, (row.value / max) * 100)}%` }} />
          </>
        );
        return onClick && row.id ? (
          <button key={row.label} type="button" onClick={() => onClick(row.id || "")}>
            {body}
          </button>
        ) : (
          <div key={row.label}>{body}</div>
        );
      })}
    </div>
  );
}

export function IocList({ files, peers }: { files: Array<[string, number]>; peers: Array<[string, number]> }) {
  if (!files.length && !peers.length) {
    return <EmptyState title="No IOCs yet" detail="File and network indicators appear here after matching alerts or events." />;
  }
  return (
    <div className="soc-ioc-list">
      <strong>files</strong>
      {files.slice(0, 5).map(([file, count]) => (
        <span key={file}>
          <code>{file}</code>
          <em>x{count}</em>
        </span>
      ))}
      <strong>network</strong>
      {peers.slice(0, 5).map(([peer, count]) => (
        <span key={peer}>
          <code>{peer}</code>
          <em>x{count}</em>
        </span>
      ))}
    </div>
  );
}

export function NetworkList({ rows }: { rows: Array<{ peer: string; count: number; procs: string[] }> }) {
  if (!rows.length) return <EmptyState title="No outbound peers" detail="Network activity from shell events and LOLBins will aggregate here." />;
  return (
    <div className="soc-network-list">
      {rows.slice(0, 8).map((row) => (
        <div key={row.peer}>
          <code>{row.peer}</code>
          <span>{row.procs.slice(0, 3).join(", ") || "unknown"} x{row.count}</span>
        </div>
      ))}
    </div>
  );
}

export function AlertPreview({ preview }: { preview: HoverPreviewState | null }) {
  return (
    <div
      className={cx("soc-alert-preview", preview && "is-open")}
      data-panel={PANELS["alert-hover-preview-context-menu"].id}
      style={preview ? { left: preview.x, top: preview.y } : undefined}
      aria-hidden={!preview}
    >
      {preview ? (
        <>
          <SeverityBadge severity={preview.alert.severity} />
          <strong>{preview.alert.title}</strong>
          <span>{preview.alert.description}</span>
          <code>{preview.alert.execId || preview.alert.process || preview.alert.id}</code>
        </>
      ) : null}
    </div>
  );
}

export function AlertContextMenu({
  state,
  onClose,
  onOpen,
  onAck,
  onResolve,
  onPin
}: {
  state: ContextMenuState | null;
  onClose: () => void;
  onOpen: (alert: SocAlert) => void;
  onAck: (alert: SocAlert) => void;
  onResolve: (alert: SocAlert) => void;
  onPin: (alert: SocAlert) => void;
}) {
  return (
    <div
      className={cx("soc-context-menu", state && "is-open")}
      data-panel={PANELS["alert-hover-preview-context-menu"].id}
      style={state ? { left: state.x, top: state.y } : undefined}
      aria-hidden={!state}
      onMouseLeave={onClose}
    >
      {state ? (
        <>
          <button type="button" onClick={() => onOpen(state.alert)}>
            Open drill
          </button>
          <button type="button" onClick={() => onAck(state.alert)}>
            Acknowledge
          </button>
          <button type="button" onClick={() => onResolve(state.alert)}>
            Resolve
          </button>
          <button type="button" onClick={() => onPin(state.alert)}>
            Toggle pin
          </button>
        </>
      ) : null}
    </div>
  );
}
