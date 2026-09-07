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
import type { SocEvent } from "./types";

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
      {rows.slice(0, 8).map((row, index) => {
        // Keyed by the row's own id, NOT its label. Top-processes rows are one
        // per exec instance, so two runs of the same binary are two rows with
        // the same label — React then warns about duplicate keys and is free to
        // drop or duplicate one of them, which is a row an analyst is looking
        // at going missing.
        const key = row.id || `${row.label}#${index}`;
        const body = (
          <>
            <span>{row.label}</span>
            <em>{row.meta || row.value}</em>
            <i style={{ width: `${Math.max(4, (row.value / max) * 100)}%` }} />
          </>
        );
        return onClick && row.id ? (
          <button key={key} type="button" onClick={() => onClick(row.id || "")}>
            {body}
          </button>
        ) : (
          <div key={key}>{body}</div>
        );
      })}
    </div>
  );
}

/**
 * What an empty panel should say.
 *
 * "Nothing here" and "nothing here IN THIS WINDOW, while N sit just outside
 * it" are different statements, and only the second is actionable. At a
 * five-minute window on a live estate the first is actively misleading — this
 * rig showed 2 alerts in 5m against 1,841 in 24h, so every context panel
 * rendered an empty state with the data one click away.
 */
export function emptyBecause(kind: string, beyond: number, unit: string): string {
  if (beyond > 0) {
    return `Nothing in the selected window — ${beyond.toLocaleString()} ${unit} sit outside it. Widen the range.`;
  }
  return `No ${kind} recorded yet on this estate.`;
}

export function IocList({
  files,
  peers,
  beyond = 0
}: {
  files: Array<[string, number]>;
  peers: Array<[string, number]>;
  beyond?: number;
}) {
  if (!files.length && !peers.length) {
    // "Nothing happened" and "I cannot see this here" look identical, and
    // only one of them is fine. Say which — the window is the usual answer on
    // a quiet estate, and an analyst who reads "no IOCs" as "no IOCs ever"
    // draws the wrong conclusion from a five-minute view.
    return (
      <EmptyState
        title="No indicators in this window"
        detail={`${emptyBecause("indicators", beyond, "events")} File paths come from event arguments; addresses come from the destination the sensor reported.`}
      />
    );
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

export function NetworkList({
  rows,
  beyond = 0
}: {
  rows: Array<{ peer: string; count: number; procs: string[] }>;
  beyond?: number;
}) {
  if (!rows.length) {
    return (
      <EmptyState
        title="No outbound connections in this window"
        detail={`${emptyBecause("outbound connections", beyond, "events")} Destinations come from the peer the sensor reports on a connection event. An address that only appears in a command line is not counted — it is an intent, not an observation.`}
      />
    );
  }
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
  // AlertGroup, not SocAlert: this menu is opened from a queue row, and a row
  // can stand for N alerts. Typed as a lone alert, every handler behind it
  // reached for `.id` and triaged one member of a ×N row — the row then went on
  // reading "New" beside a menu that had just reported the work done.
  onOpen: (alert: AlertGroup) => void;
  onAck: (alert: AlertGroup) => void;
  onResolve: (alert: AlertGroup) => void;
  onPin: (alert: AlertGroup) => void;
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
