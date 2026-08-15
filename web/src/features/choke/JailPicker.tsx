// Jail picker: act on a process the gateway is NOT already tracking. It reads
// the raw /proc table, so it is the only surface where the operator picks a
// target by PID rather than exec_id — hence the mandatory audit reason before
// anything is submitted.
import { useCallback, useEffect, useMemo, useState } from "react";
import { getProcesses } from "./api";
import type { ChokeAction, SysProcEntry, ToastMessage } from "./types";
import type { JailDetail } from "./constants";
import { toggleNumber } from "./constants";
import { useInterval } from "./hooks";
import { ACTIONS, classifyProc, deriveProcSignals, readJsonStorage, writeJsonStorage } from "./utils";
import { EmptyState, ErrorState, LoadingState, StateBadge } from "./components";

export function JailPicker({
  open,
  disabled,
  detail,
  onClose,
  onInspect,
  onOpenDrill,
  onAction,
  pushToast,
}: {
  open: boolean;
  disabled: boolean;
  detail: JailDetail;
  onClose: () => void;
  onInspect: (process: SysProcEntry) => void;
  onOpenDrill: (process: SysProcEntry) => void;
  onAction: (payload: { pids: number[]; action: ChokeAction; reason: string; descendants: boolean; revert_after_seconds?: number }) => Promise<void>;
  pushToast: (message: string, kind?: ToastMessage["kind"]) => void;
}) {
  const [processes, setProcesses] = useState<SysProcEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState("");
  const [chips, setChips] = useState(() => readJsonStorage("choke.jail.filters", { user: true, system: true, kernel: false, tracked: false, high: false }));
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [reason, setReason] = useState("");
  const [descendants, setDescendants] = useState(false);
  const [revert, setRevert] = useState(false);
  const [revertSeconds, setRevertSeconds] = useState(300);
  const [sortKey, setSortKey] = useState<"score" | "pid" | "ppid" | "uid" | "comm" | "state">("score");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const refresh = useCallback(async () => {
    if (!open || disabled) return;
    setLoading(true);
    try {
      setProcesses(await getProcesses());
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "process list failed", "err");
    } finally {
      setLoading(false);
    }
  }, [disabled, open, pushToast]);

  useEffect(() => {
    if (!open) return;
    setSelected(new Set());
    void refresh();
  }, [open, refresh]);
  useInterval(() => void refresh(), 4000, open && !disabled);

  useEffect(() => writeJsonStorage("choke.jail.filters", chips), [chips]);

  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return processes
      .filter((process) => {
        const cls = classifyProc(process);
        if (!chips[cls as keyof typeof chips]) return false;
        if (chips.tracked && !process.tracked) return false;
        if (chips.high && (process.score || 0) < 5) return false;
        if (!q) return true;
        return [process.pid, process.ppid, process.uid, process.comm, process.exe, process.cmdline, process.state].join(" ").toLowerCase().includes(q);
      })
      .sort((a, b) => {
        const dir = sortDir === "asc" ? 1 : -1;
        let diff = 0;
        if (sortKey === "score") diff = (a.score || 0) - (b.score || 0);
        else if (sortKey === "pid") diff = a.pid - b.pid;
        else if (sortKey === "ppid") diff = (a.ppid || 0) - (b.ppid || 0);
        else if (sortKey === "uid") diff = (a.uid || 0) - (b.uid || 0);
        else if (sortKey === "comm") diff = (a.comm || "").localeCompare(b.comm || "");
        else diff = (a.state || "").localeCompare(b.state || "");
        return diff === 0 ? a.pid - b.pid : diff * dir;
      });
  }, [chips, filter, processes, sortDir, sortKey]);

  function toggleChip(key: keyof typeof chips): void {
    setChips((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  async function submit(action: ChokeAction, explicitPid?: number): Promise<void> {
    const pids = explicitPid ? [explicitPid] : Array.from(selected);
    if (pids.length === 0) return pushToast("select at least one process", "err");
    if (!reason.trim()) return pushToast("reason required for audit", "err");
    await onAction({
      pids,
      action,
      reason: reason.trim(),
      descendants,
      revert_after_seconds: revert ? revertSeconds : undefined,
    });
    onClose();
  }

  if (!open) return null;
  return (
    <div className="choke-modal-backdrop" data-panel="jail-process-picker-modal" role="dialog" aria-modal="true">
      <div className="choke-jail-modal">
        <header>
          <h2>Jail a process</h2>
          <span>{visible.length} / {processes.length} processes</span>
          <button type="button" onClick={refresh}>{loading ? "Refreshing" : "Refresh"}</button>
          <button type="button" onClick={onClose}>Close</button>
        </header>
        {disabled ? <ErrorState title="Gateway disabled" body="The process picker is unavailable while /api/choke/processes returns 503." /> : null}
        <div className="choke-jail-tools">
          <input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="filter pid, comm, exe, cmdline, uid" />
          {(["user", "system", "kernel", "tracked", "high"] as Array<keyof typeof chips>).map((chip) => (
            <button key={chip} type="button" className={`choke-chip ${chips[chip] ? "on" : ""}`} onClick={() => toggleChip(chip)}>
              {chip}
            </button>
          ))}
        </div>
        <div className="choke-jail-grid">
          <div className="choke-jail-list">
            <div className="choke-jail-head">
              <input
                type="checkbox"
                checked={visible.length > 0 && visible.every((process) => selected.has(process.pid))}
                onChange={(event) => setSelected(event.target.checked ? new Set(visible.map((process) => process.pid)) : new Set())}
              />
              {(["pid", "ppid", "uid", "comm", "score", "state"] as const).map((key) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => {
                    if (sortKey === key) setSortDir((prev) => (prev === "asc" ? "desc" : "asc"));
                    else {
                      setSortKey(key);
                      setSortDir(key === "comm" || key === "state" ? "asc" : "desc");
                    }
                  }}
                >
                  {key}{sortKey === key ? (sortDir === "asc" ? " up" : " down") : ""}
                </button>
              ))}
            </div>
            {visible.length === 0 ? <EmptyState title="No processes match" body="Clear the search or enable more chips." /> : null}
            {visible.slice(0, 1000).map((process) => {
              const checked = selected.has(process.pid);
              return (
                <div key={process.pid} className={`choke-jail-row ${checked ? "selected" : ""}`}>
                  <input type="checkbox" checked={checked} onChange={() => setSelected((prev) => toggleNumber(prev, process.pid))} />
                  <button type="button" onClick={() => onInspect(process)}>{process.pid}</button>
                  <span>{process.ppid || "-"}</span>
                  <span>{process.uid ?? "-"}</span>
                  <span className="truncate" title={process.exe || process.comm}>{process.exe || process.comm || "-"}</span>
                  <span>{process.score || 0}</span>
                  <StateBadge state={process.state || "pristine"} />
                  <span className="choke-row-actions">
                    {ACTIONS.map((action) => <button key={action} type="button" onClick={() => void submit(action, process.pid)}>{action.slice(0, 3)}</button>)}
                    <button type="button" onClick={() => onOpenDrill(process)}>detail</button>
                  </span>
                </div>
              );
            })}
          </div>
          <div className="choke-jail-inspect">
            <JailInspect detail={detail} />
          </div>
        </div>
        <footer>
          <div className="choke-row-actions wide">
            {ACTIONS.map((action) => <button key={action} type="button" onClick={() => void submit(action)}>{action}</button>)}
          </div>
          <input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="audit reason (required)" />
          <label><input type="checkbox" checked={descendants} onChange={(event) => setDescendants(event.target.checked)} /> include descendants</label>
          <label><input type="checkbox" checked={revert} onChange={(event) => setRevert(event.target.checked)} /> auto-revert</label>
          <select value={revertSeconds} onChange={(event) => setRevertSeconds(Number(event.target.value))} disabled={!revert}>
            <option value={60}>1 min</option>
            <option value={300}>5 min</option>
            <option value={900}>15 min</option>
            <option value={3600}>1 hour</option>
          </select>
          <span>{selected.size} selected</span>
        </footer>
      </div>
    </div>
  );
}

function JailInspect({ detail }: { detail: JailDetail }) {
  if (detail.kind === "closed") return <EmptyState title="No process selected" body="Select a row to inspect live /proc state, signals, and lineage shell." />;
  const process = detail.process;
  const signals = deriveProcSignals(process);
  return (
    <div>
      <h3>{process.exe || process.comm || `pid ${process.pid}`}</h3>
      <div className="choke-jail-meta">
        <span>pid {process.pid}</span>
        <span>ppid {process.ppid || "-"}</span>
        <span>uid {process.uid ?? "-"}</span>
        <span>score {process.score || 0}</span>
        <StateBadge state={process.state || "pristine"} />
      </div>
      <code>{process.cmdline || process.comm || ""}</code>
      <div className="choke-chip-row">
        {signals.length ? signals.map((signal) => <span key={signal} className="choke-signal-chip">{signal}</span>) : <span className="choke-muted">no local risk signals</span>}
      </div>
      {detail.kind === "loading" ? <LoadingState label="loading live /proc state" /> : null}
      {detail.kind === "error" ? <ErrorState title="Live state failed" body={detail.message} /> : null}
      {detail.kind === "ready" ? (
        <div className="choke-kv-list">
          <div><span>status</span><strong>{detail.detail.status || "-"}</strong></div>
          <div><span>threads</span><strong>{detail.detail.threads || 0}</strong></div>
          <div><span>rss</span><strong>{detail.detail.vm_rss_kb || 0} KB</strong></div>
          <div><span>fds</span><strong>{detail.detail.num_fds || 0}</strong></div>
          <div><span>conns</span><strong>{detail.detail.num_conns || 0}</strong></div>
          <div><span>cwd</span><strong>{detail.detail.cwd || "-"}</strong></div>
        </div>
      ) : null}
    </div>
  );
}
