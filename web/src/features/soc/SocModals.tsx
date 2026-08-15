// The modal layer: sixteen surfaces, one shell each.
//
// Every ModalShell renders its body unconditionally and hides it with CSS, so
// the bodies are all mounted all the time. That is load-bearing — several of
// them (Time Machine, the graph) keep local state across opens, and the e2e
// suite selects panels that are in the DOM before they are visible — so this
// component is a fan-out and nothing more. It must not learn to conditionally
// mount.
import { useState } from "react";
import { Command as CommandPrimitive } from "cmdk";
import { Search } from "lucide-react";
import type * as React from "react";
import { runSocAttack } from "./api";
import { EmptyState, InlineNotice, ModalShell } from "./components";
import { DEFAULT_WATCHLIST, PANELS, type AckState, type KpiDrill, type OpenSurface, type StreamTelemetry } from "./dashboard";
import { KpiDrillBody } from "./KpiDrillBody";
import { SimulatorBody } from "./SimulatorBody";
import { TimeMachineBody } from "./TimeMachineBody";
import { WatchlistBody } from "./WatchlistBody";
import { downloadMitrePdf } from "./pdf";
import {
  AccountBody,
  FleetBody,
  HoneypotsBody,
  KprobeBody,
  MitreNavigatorBody,
  NotificationsBody,
  PoliciesBody
} from "./panels";
import { SOC_STORAGE_KEYS } from "./panelInventory";
import type { SocWindowModel } from "./useSocWindowModel";
import type { Severity, SocSnapshot } from "./types";

type NotifyHistoryItem = { title?: string; body?: string; ts?: string; read?: boolean; severity?: Severity };

export function SocModals({
  openSurface,
  closeModal,
  openSurfaceByName,
  snapshot,
  model,
  watchlist,
  setWatchlist,
  fleetHosts,
  setFleetHosts,
  now,
  notifications,
  kpiDrill,
  ackStates,
  commandQuery,
  setCommandQuery,
  theme,
  stream,
  onActionComplete,
  graphBody,
  exportBody
}: {
  openSurface: OpenSurface | null;
  closeModal: () => void;
  openSurfaceByName: (surface: OpenSurface) => void;
  snapshot: SocSnapshot;
  /** Everything derived from the snapshot for the selected window. */
  model: SocWindowModel;
  watchlist: typeof DEFAULT_WATCHLIST;
  setWatchlist: React.Dispatch<React.SetStateAction<typeof DEFAULT_WATCHLIST>>;
  fleetHosts: Array<{ name: string; url: string }>;
  setFleetHosts: React.Dispatch<React.SetStateAction<Array<{ name: string; url: string }>>>;
  now: number;
  /** The notification centre's own persisted state, which only it reads. */
  notifications: {
    history: NotifyHistoryItem[];
    setHistory: React.Dispatch<React.SetStateAction<NotifyHistoryItem[]>>;
    active: boolean;
    setActive: React.Dispatch<React.SetStateAction<boolean>>;
    channels: { inApp: boolean; desktop: boolean; audio: boolean };
    setChannels: React.Dispatch<React.SetStateAction<{ inApp: boolean; desktop: boolean; audio: boolean }>>;
  };
  kpiDrill: KpiDrill | null;
  ackStates: Record<string, AckState>;
  commandQuery: string;
  setCommandQuery: React.Dispatch<React.SetStateAction<string>>;
  theme: "dark" | "light";
  stream: StreamTelemetry;
  onActionComplete: () => void;
  /**
   * The correlation graph and the export studio arrive as elements rather than
   * being constructed here. Both are built by the route — one owns an
   * imperative D3 bridge over an <svg>, the other owns the report model — and
   * this component's job is only to say which shell hosts which surface.
   */
  graphBody: React.ReactNode;
  exportBody: React.ReactNode;
}) {
  const { rangeAlerts, rangeEvents, mitreRows, activeProcesses } = model;
  return (
    <>
      <ModalShell panel={PANELS["policy-viewer-modal"]} open={openSurface === "policies"} onClose={closeModal} wide>
        <PoliciesBody
          policies={snapshot.policies}
          alerts={rangeAlerts}
          events={rangeEvents}
          policyStats={snapshot.policyStats}
          now={now}
        />
      </ModalShell>

      <ModalShell panel={PANELS["quick-fire-attacks-modal"]} open={openSurface === "attacks"} onClose={closeModal}>
        <AttackRunnerList attacks={snapshot.attacks} onActionComplete={onActionComplete} />
      </ModalShell>

      <ModalShell panel={PANELS["process-correlation-graph-modal"]} open={openSurface === "graph"} onClose={closeModal} fullScreen>
        {graphBody}
      </ModalShell>

      <ModalShell panel={PANELS["rule-simulator-modal"]} open={openSurface === "simulator"} onClose={closeModal}>
        <SimulatorBody alerts={rangeAlerts} />
      </ModalShell>

      <ModalShell panel={PANELS["mitre-navigator-modal"]} open={openSurface === "mitre"} onClose={closeModal} wide>
        <MitreNavigatorBody
          mitreRows={mitreRows}
          alerts={rangeAlerts}
          policies={snapshot.policies}
          onExport={() => void downloadMitrePdf(mitreRows, rangeAlerts, snapshot.policies, snapshot.whoami)}
        />
      </ModalShell>

      <ModalShell panel={PANELS["fleet-modal"]} open={openSurface === "fleet"} onClose={closeModal} wide>
        <FleetBody hosts={fleetHosts} setHosts={setFleetHosts} whoami={snapshot.whoami} currentTracked={activeProcesses.count} />
      </ModalShell>

      <ModalShell panel={PANELS["watchlist-modal"]} open={openSurface === "watchlist"} onClose={closeModal}>
        <WatchlistBody watchlist={watchlist} setWatchlist={setWatchlist} alerts={rangeAlerts} events={rangeEvents} />
      </ModalShell>

      <ModalShell panel={PANELS["honeypots-modal"]} open={openSurface === "honeypots"} onClose={closeModal} wide>
        <HoneypotsBody honeypots={snapshot.honeypots} now={now} />
      </ModalShell>

      <ModalShell panel={PANELS["kprobe-performance-modal"]} open={openSurface === "kprobes"} onClose={closeModal} wide>
        <KprobeBody policyStats={snapshot.policyStats} />
      </ModalShell>

      <ModalShell panel={PANELS["time-machine-modal"]} open={openSurface === "time-machine"} onClose={closeModal}>
        <TimeMachineBody alerts={rangeAlerts} events={rangeEvents} open={openSurface === "time-machine"} />
      </ModalShell>

      <ModalShell panel={PANELS["command-palette"]} open={openSurface === "command"} onClose={closeModal}>
        <CommandPrimitive label="SOC command palette" value={commandQuery} onValueChange={setCommandQuery}>
          <label className="soc-command-input">
            <Search size={16} />
            <CommandPrimitive.Input placeholder="Type a command" autoFocus />
          </label>
          <CommandPrimitive.List className="soc-command-list">
            <CommandPrimitive.Empty>No matching commands.</CommandPrimitive.Empty>
            {commandItems.map((item) => (
              <CommandPrimitive.Item
                key={item.label}
                value={`${item.kind} ${item.label}`}
                onSelect={() => openSurfaceByName(item.surface)}
              >
                <span>{item.kind}</span>
                <strong>{item.label}</strong>
              </CommandPrimitive.Item>
            ))}
          </CommandPrimitive.List>
        </CommandPrimitive>
      </ModalShell>

      <ModalShell panel={PANELS["notifications-center-modal"]} open={openSurface === "notifications"} onClose={closeModal} wide>
        <NotificationsBody
          history={notifications.history}
          active={notifications.active}
          channels={notifications.channels}
          onActiveChange={notifications.setActive}
          onChannelsChange={notifications.setChannels}
          onMarkAllRead={() => notifications.setHistory((items) => items.map((item) => ({ ...item, read: true })))}
          onClearAll={() => notifications.setHistory([])}
        />
      </ModalShell>

      <ModalShell panel={PANELS["account-profile-modal"]} open={openSurface === "profile"} onClose={closeModal}>
        <AccountBody
          user={snapshot.whoami.user}
          host={snapshot.whoami.host}
          role={snapshot.whoami.role}
          theme={theme}
          streamState={stream.state}
          versionSha={snapshot.version.sha}
          storageKeyCount={SOC_STORAGE_KEYS.length}
        />
      </ModalShell>

      <ModalShell panel={PANELS["kpi-drill-modal"]} open={openSurface === "kpi"} title={kpiDrill?.title || "KPI drill"} onClose={closeModal}>
        <KpiDrillBody drill={kpiDrill} alerts={rangeAlerts} events={rangeEvents} ackStates={ackStates} now={now} />
      </ModalShell>

      <ModalShell panel={PANELS["help-modal"]} open={openSurface === "help"} onClose={closeModal}>
        <div className="soc-help-grid">
          <span>/</span>
          <strong>Focus search</strong>
          <span>Ctrl+K</span>
          <strong>Command palette</strong>
          <span>Esc</span>
          <strong>Close modal or drill panel</strong>
          <span>a/r</span>
          <strong>Ack or resolve selected drill alert</strong>
        </div>
      </ModalShell>

      <ModalShell panel={PANELS["export-confirm-modal"]} open={openSurface === "export"} onClose={closeModal}>
        {exportBody}
      </ModalShell>
    </>
  );
}

const commandItems: Array<{ label: string; kind: string; surface: OpenSurface }> = [
  { label: "Show policies", kind: "panel", surface: "policies" },
  { label: "Open attacks", kind: "panel", surface: "attacks" },
  { label: "Open correlation graph", kind: "panel", surface: "graph" },
  { label: "Open watchlist", kind: "panel", surface: "watchlist" },
  { label: "Show honeypots", kind: "panel", surface: "honeypots" },
  { label: "Show kprobe perf", kind: "panel", surface: "kprobes" },
  { label: "Open export", kind: "action", surface: "export" },
  { label: "Show help", kind: "panel", surface: "help" }
];

function AttackRunnerList({
  attacks,
  onActionComplete
}: {
  attacks: SocSnapshot["attacks"];
  onActionComplete: () => void;
}) {
  const [runningId, setRunningId] = useState("");
  const [result, setResult] = useState<{ tone: "ok" | "warn"; message: string } | null>(null);

  async function runAttack(id: string) {
    setRunningId(id);
    setResult(null);
    try {
      await runSocAttack(id);
      setResult({ tone: "ok", message: `${id} launched. The engine will stream resulting events when they arrive.` });
      onActionComplete();
    } catch (error) {
      setResult({ tone: "warn", message: error instanceof Error ? error.message : String(error) });
    } finally {
      setRunningId("");
    }
  }

  return (
    <>
      <InlineNotice tone="warn" title="Runs on the engine host">
        Attack scripts are allowlisted by the backend and require the same CSRF-protected POST path as the legacy UI.
      </InlineNotice>
      {result ? <InlineNotice tone={result.tone} title="Attack result">{result.message}</InlineNotice> : null}
      <div className="soc-modal-list">
        {attacks.length ? (
          attacks.map((attack) => (
            <article key={attack.id}>
              <strong>{attack.name}</strong>
              <span>{attack.description || attack.id}</span>
              <button type="button" disabled={Boolean(runningId)} onClick={() => void runAttack(attack.id)}>
                {runningId === attack.id ? "Launching" : "Run"}
              </button>
            </article>
          ))
        ) : (
          <EmptyState title="No attack catalog returned" />
        )}
      </div>
    </>
  );
}
