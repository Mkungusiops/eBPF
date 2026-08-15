// The dialog layer: the operator profile drawer, the command palette, the
// confirm gate every destructive action passes through, and the keyboard map.
//
// ConfirmModal is the one that matters. Nothing on this page severs, freezes
// or flips the kill-switch without coming through it, and it is where the
// audit reason is captured — so its failure path surfaces the error inline
// AND as a toast rather than closing over a silent rejection.
import { useState } from "react";
import { X } from "lucide-react";
import { Command as CommandPrimitive } from "cmdk";
import type { ConfirmRequest, ToastMessage } from "./types";
import { formatWindow } from "./constants";
import { formatUptime } from "./utils";
import { EmptyState } from "./components";

export function ProfilePanel({
  userLabel,
  bootMs,
  decisionsSeen,
  ackedCount,
  theme,
  density,
  windowMin,
  windowOptions,
  onDensity,
  onWindow,
  onSnapshot,
  onCommand,
  onHelp,
  onThaw,
  onClose,
}: {
  userLabel: string;
  bootMs: number;
  decisionsSeen: number;
  ackedCount: number;
  theme: string;
  density: string;
  windowMin: number;
  windowOptions: number[];
  onDensity: () => void;
  onWindow: (value: number) => void;
  onSnapshot: () => void;
  onCommand: () => void;
  onHelp: () => void;
  onThaw: () => void;
  onClose: () => void;
}) {
  return (
    <aside className="choke-floating-panel profile" data-panel="admin-profile-dropdown-avatar">
      <header>
        <h3>{userLabel}</h3>
        <span>Operator</span>
        <button type="button" className="choke-popover-close" onClick={onClose} aria-label="Close profile">
          <X size={15} aria-hidden="true" />
        </button>
      </header>
      <div className="choke-profile-tools">
        <button type="button" onClick={onCommand}>Command palette</button>
        <button type="button" onClick={onHelp}>Help &amp; shortcuts</button>
      </div>
      <div className="choke-kv-list">
        <div><span>session</span><strong>{formatUptime(Date.now() - bootMs)}</strong></div>
        <div><span>decisions seen</span><strong>{decisionsSeen}</strong></div>
        <div><span>acked</span><strong>{ackedCount}</strong></div>
        <div><span>theme</span><strong>{theme} (follows OS)</strong></div>
        <div><span>density</span><button type="button" onClick={onDensity}>{density}</button></div>
      </div>
      <label className="choke-profile-window">Default window
        <select value={windowMin} onChange={(event) => onWindow(Number(event.target.value))}>
          {windowOptions.map((value) => <option key={value} value={value}>{formatWindow(value)}</option>)}
        </select>
      </label>
      <div className="choke-popover-actions">
        <button type="button" onClick={onSnapshot}>Snapshot</button>
        <button type="button" onClick={onThaw}>Thaw all</button>
        <a href="/api/logout">Sign out</a>
      </div>
    </aside>
  );
}

export function CommandPalette({ items, onClose }: { items: Array<{ group: string; label: string; run: () => void }>; onClose: () => void }) {
  function run(item: { run: () => void }) {
    item.run();
    onClose();
  }
  return (
    <div className="choke-modal-backdrop command" data-panel="command-palette" role="dialog" aria-modal="true" onClick={(event) => event.target === event.currentTarget && onClose()}>
      <CommandPrimitive className="choke-command-card" label="Choke command palette">
        <CommandPrimitive.Input
          autoFocus
          onKeyDown={(event) => {
            if (event.key === "Escape") onClose();
          }}
          placeholder="Type a command"
        />
        <CommandPrimitive.List>
          <CommandPrimitive.Empty>
            <EmptyState title="No results" body="Try preset, jail, snapshot, theme, or a process name." />
          </CommandPrimitive.Empty>
          {items.map((item) => (
            <CommandPrimitive.Item
              key={`${item.group}-${item.label}`}
              value={`${item.group} ${item.label}`}
              onSelect={() => run(item)}
            >
              <span>{item.group}</span><strong>{item.label}</strong>
            </CommandPrimitive.Item>
          ))}
        </CommandPrimitive.List>
      </CommandPrimitive>
    </div>
  );
}

export function ConfirmModal({ request, onClose, pushToast }: { request: ConfirmRequest; onClose: () => void; pushToast: (message: string, kind?: ToastMessage["kind"]) => void }) {
  const [reason, setReason] = useState(request.initialReason || "");
  const [revert, setRevert] = useState(false);
  const [revertSeconds, setRevertSeconds] = useState(300);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(): Promise<void> {
    if (request.reasonRequired && !reason.trim()) {
      setError("reason required for audit");
      return;
    }
    setBusy(true);
    setError("");
    try {
      await request.onConfirm({
        reason: reason.trim(),
        revert_after_seconds: request.withRevert && revert ? revertSeconds : undefined,
      });
      onClose();
    } catch (err) {
      const message = err instanceof Error ? err.message : "action failed";
      setError(message);
      pushToast(message, "err");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="choke-modal-backdrop" data-panel="confirm-modal" role="dialog" aria-modal="true" onClick={(event) => event.target === event.currentTarget && onClose()}>
      <div className={`choke-confirm ${request.danger ? "danger" : ""}`}>
        <h2>{request.title}</h2>
        <p>{request.body}</p>
        {request.reasonRequired ? <input autoFocus value={reason} onChange={(event) => setReason(event.target.value)} placeholder="audit reason" /> : null}
        {request.withRevert ? (
          <label><input type="checkbox" checked={revert} onChange={(event) => setRevert(event.target.checked)} /> auto-revert
            <select value={revertSeconds} onChange={(event) => setRevertSeconds(Number(event.target.value))} disabled={!revert}>
              <option value={60}>1 min</option>
              <option value={300}>5 min</option>
              <option value={900}>15 min</option>
              <option value={3600}>1 hour</option>
            </select>
          </label>
        ) : null}
        {error ? <span className="choke-form-error">{error}</span> : null}
        <footer>
          <button type="button" onClick={onClose}>Cancel</button>
          <button className={request.danger ? "danger" : "ok"} type="button" disabled={busy} onClick={() => void submit()}>{busy ? "Working" : request.confirmLabel || "Confirm"}</button>
        </footer>
      </div>
    </div>
  );
}

export function HelpModal({ onClose }: { onClose: () => void }) {
  const rows = [
    ["Ctrl+K", "Command palette"],
    ["?", "Help"],
    ["/", "Focus search"],
    ["J", "Jail picker"],
    ["K", "Kill-switch"],
    ["c/f/m/d", "IR presets"],
    ["t", "Theme"],
    ["g", "SOC dashboard"],
    ["Esc", "Close top layer"],
  ];
  return (
    <div className="choke-modal-backdrop" data-panel="help-modal" role="dialog" aria-modal="true" onClick={(event) => event.target === event.currentTarget && onClose()}>
      <div className="choke-help">
        <header><h2>Keyboard map</h2><button type="button" onClick={onClose}>Close</button></header>
        <div>{rows.map(([key, desc]) => <p key={key}><kbd>{key}</kbd><span>{desc}</span></p>)}</div>
      </div>
    </div>
  );
}
