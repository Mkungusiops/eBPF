// The modal layer: sixteen surfaces, one shell each.
//
// Every ModalShell renders its body unconditionally and hides it with CSS, so
// the bodies are all mounted all the time. That is load-bearing — several of
// them (Time Machine, the graph) keep local state across opens, and the e2e
// suite selects panels that are in the DOM before they are visible — so this
// component is a fan-out and nothing more. It must not learn to conditionally
// mount.
import { useLayoutEffect, useRef, useState } from "react";
import { Command as CommandPrimitive } from "cmdk";
import { Search } from "lucide-react";
import type * as React from "react";
import { runSocAttack } from "./api";
import { EmptyState, InlineNotice, ModalShell } from "./components";
import { DEFAULT_WATCHLIST, PANELS, type AckState, type KpiDrill, type OpenSurface, type StreamTelemetry } from "./dashboard";
import { KpiDrillBody } from "./KpiDrillBody";
import { SimulatorBody } from "./SimulatorBody";
import { DetectionsBody } from "./DetectionsBody";
import { SensorHealthBody } from "./SensorHealthBody";
import { SettingsBody } from "./SettingsBody";
import { TimeMachineBody } from "./TimeMachineBody";
import { WatchlistBody } from "./WatchlistBody";
import { IntelligenceBody } from "./IntelligenceBody";
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
import { surfaceOffered } from "./Sidebar";
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
      {/* Detections replaces the read-only Policy viewer. The viewer showed an
          `alerts` count that was structurally always 0 and a mode pill that
          fell back to the literal "loaded" — a positive claim about kernel
          state with no evidence. This shows what the kernel reports, names the
          expected policies NO host has loaded, and can push a change. */}
      <ModalShell panel={PANELS["detections-modal"]} open={openSurface === "policies"} onClose={closeModal} wide>
        <DetectionsBody
          policies={snapshot.policies}
          open={openSurface === "policies"}
          onRefresh={onActionComplete}
          canPush={snapshot.whoami.canPushPolicy === true}
          scope={snapshot.whoami.policyScope}
          /* identityAnswered is NOT passed, and that is deliberate: this shell
             has no way to tell an empty whoami from one that has not arrived —
             `snapshot.whoami` is the same placeholder object either way, which
             is why every operator opening this panel on first paint was told
             the deployment has no Tetragon connection. DetectionsBody reads the
             shared authority store itself, which knows. */
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

      <ModalShell panel={PANELS["behaviour-modal"]} open={openSurface === "behaviour"} onClose={closeModal} wide>
        {/* `open` is passed through so the body only polls while it is on
            screen. A closed modal that keeps a 20-second timer running is four
            needless requests a minute per open tab. */}
        <IntelligenceBody open={openSurface === "behaviour"} />
      </ModalShell>

      {/* Settings sits beside Sensor Health deliberately: one says what the
          platform can see and do, the other lets you tune it. */}
      <ModalShell panel={PANELS["settings-modal"]} open={openSurface === "settings"} onClose={closeModal} wide>
        <SettingsBody open={openSurface === "settings"} />
      </ModalShell>

      <ModalShell panel={PANELS["sensor-health-modal"]} open={openSurface === "kprobes"} onClose={closeModal} wide>
        <SensorHealthBody
          policyStats={snapshot.policyStats}
          open={openSurface === "kprobes"}
          onOpenDetections={() => openSurfaceByName("policies")}
        />
      </ModalShell>

      <ModalShell panel={PANELS["time-machine-modal"]} open={openSurface === "time-machine"} onClose={closeModal}>
        <TimeMachineBody alerts={rangeAlerts} events={rangeEvents} open={openSurface === "time-machine"} />
      </ModalShell>

      <ModalShell panel={PANELS["command-palette"]} open={openSurface === "command"} onClose={closeModal}>
        {/* The palette is gated on the SAME server-reported lab_mode the rail
            is. Every body here is mounted permanently, so an ungated palette
            was a second, unlocked door onto surfaces the deployment hides on
            purpose — the attack runner among them. */}
        <CommandPalette
          open={openSurface === "command"}
          value={commandQuery}
          onValueChange={setCommandQuery}
          items={paletteCommands(snapshot.version.labMode)}
          onSelect={openSurfaceByName}
        />
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

export interface CommandItem {
  label: string;
  kind: string;
  surface: OpenSurface;
}

const commandItems: CommandItem[] = [
  { label: "Show policies", kind: "panel", surface: "policies" },
  { label: "Open attacks", kind: "panel", surface: "attacks" },
  { label: "Open correlation graph", kind: "panel", surface: "graph" },
  { label: "Open watchlist", kind: "panel", surface: "watchlist" },
  { label: "Show honeypots", kind: "panel", surface: "honeypots" },
  { label: "Show sensor health", kind: "panel", surface: "kprobes" },
  { label: "Open export", kind: "action", surface: "export" },
  { label: "Show help", kind: "panel", surface: "help" }
];

/**
 * What the palette offers on THIS deployment.
 *
 * A command is a way into a surface, so it has to answer the same question the
 * rail answers before it draws a nav entry: does this deployment offer that
 * surface at all? It asks the rail's own predicate rather than keeping a second
 * list — a copy would drift, and the direction it drifts in is offering the
 * attack runner on a customer estate.
 */
export function paletteCommands(labMode: boolean): CommandItem[] {
  return commandItems.filter((item) => surfaceOffered(item.surface, labMode));
}

/**
 * The command palette, and the focus it has to take.
 *
 * cmdk's `autoFocus` runs once, when the input mounts. Every body in this file
 * is mounted at route load inside a shell that is `display: none` until it
 * opens, so that single attempt landed on a hidden input and did nothing:
 * Ctrl+K opened the palette with focus still on <body>, the next keystroke went
 * nowhere, and the operator had to reach for the mouse — which is the whole
 * reason a palette exists. Focus therefore moves when `open` flips, not when
 * the input mounts.
 *
 * Closing has to be handled too. The shell hides itself with `display: none`,
 * and a focused element inside it would keep taking keystrokes into a field
 * nobody can see, so focus goes back to whatever the operator was on when they
 * pressed Ctrl+K.
 */
export function CommandPalette({
  open,
  value,
  onValueChange,
  items,
  onSelect
}: {
  open: boolean;
  value: string;
  onValueChange: (value: string) => void;
  items: CommandItem[];
  onSelect: (surface: OpenSurface) => void;
}) {
  const inputRef = useRef<HTMLInputElement | null>(null);
  /** Where focus was before Ctrl+K, so Escape can put it back. */
  const returnTo = useRef<HTMLElement | null>(null);

  // Layout effect, not an effect: the shell's `is-open` class is already in the
  // DOM here, so the input is focusable — and focus never lands in a subtree
  // the same commit is about to mark aria-hidden.
  useLayoutEffect(() => {
    const input = inputRef.current;
    if (!input) return;
    if (open) {
      const active = document.activeElement;
      returnTo.current = active instanceof HTMLElement && active !== document.body ? active : null;
      input.focus();
      // Any query left over from the last open is selected rather than kept:
      // the first keystroke replaces a stale filter instead of extending it.
      input.select();
      return;
    }
    const back = returnTo.current;
    returnTo.current = null;
    // Only reclaim focus the palette itself was holding. Hiding the shell drops
    // focus to <body>, so this cannot ask whether the input is still focused —
    // but if something else has deliberately taken focus, leave it there.
    const active = document.activeElement;
    if (active && active !== document.body && active !== input) return;
    if (back?.isConnected) back.focus();
    else if (active === input) input.blur();
  }, [open]);

  return (
    <CommandPrimitive label="SOC command palette" value={value} onValueChange={onValueChange}>
      <label className="soc-command-input">
        <Search size={16} />
        <CommandPrimitive.Input ref={inputRef} placeholder="Type a command" />
      </label>
      <CommandPrimitive.List className="soc-command-list">
        <CommandPrimitive.Empty>No matching commands.</CommandPrimitive.Empty>
        {items.map((item) => (
          <CommandPrimitive.Item
            key={item.label}
            value={`${item.kind} ${item.label}`}
            onSelect={() => onSelect(item.surface)}
          >
            <span>{item.kind}</span>
            <strong>{item.label}</strong>
          </CommandPrimitive.Item>
        ))}
      </CommandPrimitive.List>
    </CommandPrimitive>
  );
}

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
