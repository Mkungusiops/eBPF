// The modal layer: nineteen surfaces, one shell each.
//
// Every ModalShell renders its SHELL unconditionally and hides it with CSS —
// the backdrop, the card, the head and the panel description are in the DOM
// whether the surface is open or not, which is what the e2e suite selects
// (`[data-panel]`, and `is-open` rather than visibility) on surfaces that are
// still shut. The BODY is mounted on first open and kept from then on, so a
// surface nobody has opened costs no effects, no subscriptions and no polls;
// see the note in components.tsx for why it is kept rather than unmounted on
// close. This component decides which shell hosts which surface and nothing
// else — the one exception is the URL fragment below, which says which surface
// the address the operator arrived on names.
import { useEffect, useLayoutEffect, useRef, useState } from "react";
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
// PoliciesBody is deliberately NOT imported. Both "kprobes" and "policies"
// below are still reachable, but each is now served by a body that reports what
// the kernel actually says: SensorHealthBody and DetectionsBody. The old pair
// stayed imported after the swap and rendered nowhere, which reads like a panel
// that was dropped rather than replaced. KprobeBody was the other half of that
// pair and has since been DELETED from panels.tsx — src/test/deadSymbols.test.ts
// pins its absence — so only PoliciesBody is still an export a reader could
// wire back in by accident.
import { AccountBody, FleetBody, HoneypotsBody, MitreNavigatorBody, NotificationsBody } from "./panels";
import { FLEET_SURFACE_HASH } from "../fleet/address";
import { FleetSurface } from "../fleet/FleetSurface";
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
  useAddressedSurface(openSurfaceByName);
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

      {/* THE HOSTS RUNG of the drill — estate, customer, hosts, process — and
          until now the only rung that lived outside this console, at its own
          URL with its own topbar, nav and sign-out. Full screen rather than a
          card: it is a control rail, a host table, a cgroup panel and two live
          feeds, and the correlation graph set the precedent for a surface that
          needs the page.

          `open` is passed into the body as well as to the shell. The shell
          decides whether the body exists; the body decides whether it POLLS,
          and this one fans six requests across every configured peer every five
          seconds. ModalShell keeps a body once it has been opened, so without
          this a surface the operator closed would go on polling the estate for
          the rest of the shift. */}
      <ModalShell panel={PANELS["fleet-console-modal"]} open={openSurface === "fleet-console"} onClose={closeModal} fullScreen>
        <FleetSurface open={openSurface === "fleet-console"} />
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
            is. Every surface this file hosts has its shell rendered here
            whatever the deployment is, and naming one from the palette opens
            it — bodies are mounted lazily, and an open is what mounts them — so
            an ungated palette was a second, unlocked door onto surfaces the
            deployment hides on purpose, the attack runner among them. The gate
            is on the entries offered, not on what is mounted.

            `paletteItems`, not `paletteCommands`: the palette offers the gated
            surface commands AND the consoles that are routes rather than
            surfaces, the fleet console among them. */}
        <CommandPalette
          open={openSurface === "command"}
          value={commandQuery}
          onValueChange={setCommandQuery}
          items={paletteItems(snapshot.version.labMode)}
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

/** A palette entry that opens one of the surfaces this file mounts. */
export interface CommandItem {
  label: string;
  kind: string;
  surface: OpenSurface;
}

/**
 * A palette entry that LEAVES this console for an ADDRESS.
 *
 * It exists because the palette could only ever express an OpenSurface, so the
 * one view that shows host-level drift — then a console of its own at /fleet —
 * was the only one Ctrl+K could not reach while every lesser surface was a
 * keystroke away.
 *
 * /fleet is now a redirect into this console with the fleet surface open, so
 * this entry still arrives in the right place and still arrives by leaving:
 * one document load out and one back, where opening the surface directly would
 * cost neither. It is left as a route deliberately for now — the entry, its
 * label and its navigation are pinned by two suites outside this change's
 * ownership (src/test/fleetReachPalette.test.tsx and
 * paletteCallsiteFleetReach.test.tsx), and converting it to a surface command
 * is a one-line change that belongs with the edit to those.
 *
 * It carries an href and NO surface, and that is what keeps the lab gate
 * honest: `surfaceOffered` still decides every entry that names a surface, and
 * a route can never smuggle a gated surface past it because it cannot name one.
 * A route that must itself be withheld would need its own gate here — nothing
 * this platform ships at a URL of its own is lab-only.
 */
export interface RouteCommand {
  label: string;
  kind: string;
  href: string;
}

export type PaletteCommand = CommandItem | RouteCommand;

function isRouteCommand(item: PaletteCommand): item is RouteCommand {
  return "href" in item;
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
 * The addresses the palette can send an operator to.
 *
 * Named with the rail's own words — "Fleet Console" is what the sidebar calls
 * this entry too — so the operator searching the palette types the name they
 * have already read.
 */
const routeCommands: RouteCommand[] = [{ label: "Open Fleet Console", kind: "console", href: "/fleet" }];

/**
 * The SURFACE commands this deployment offers.
 *
 * A command is a way into a surface, so it has to answer the same question the
 * rail answers before it draws a nav entry: does this deployment offer that
 * surface at all? It asks the rail's own predicate rather than keeping a second
 * list — a copy would drift, and the direction it drifts in is offering the
 * attack runner on a customer estate.
 *
 * This is not the whole palette; `paletteItems` is. It stays separate so the
 * gate has exactly one subject — entries that name a surface.
 */
export function paletteCommands(labMode: boolean): CommandItem[] {
  return commandItems.filter((item) => surfaceOffered(item.surface, labMode));
}

/** Everything the palette is given on THIS deployment: gated surfaces, then consoles. */
export function paletteItems(labMode: boolean): PaletteCommand[] {
  return [...paletteCommands(labMode), ...routeCommands];
}

/**
 * How a route command leaves. A full document load: there is no shared router
 * in this multi-page console to hand an href to, and /fleet in particular is
 * still its own HTML entry — one whose only job now is to redirect back here
 * with the fleet surface open.
 */
export function navigateToRoute(href: string): void {
  window.location.assign(href);
}

/**
 * THE SURFACE THE ADDRESS NAMES.
 *
 * /fleet used to be a console; it is a redirect now, and what it redirects to
 * is this console with a fragment naming the surface to open (see
 * features/fleet/address.ts for why a fragment and not a query parameter). This
 * is the only place that reading happens, so a bookmark, the palette's route
 * entry and a middle-clicked rail link all land the same way.
 *
 * ONCE, on mount, and the ref guard is the whole point: `openSurfaceByName` is
 * a plain function declaration in the route, so it is a new value on every
 * render — re-running this would slam the surface back open every time the
 * operator closed it.
 *
 * READ ONLY. This console never writes the fragment and never clears it: the
 * only thing that sets it is the /fleet redirect entry (features/fleet/address.ts,
 * src/entries/fleet.tsx). So it names the address the operator ARRIVED on, not
 * what is on screen now — after arriving at /#fleet and closing the surface the
 * fragment still reads #fleet, and a reload opens it again; while a fleet
 * surface opened from the rail leaves the address bare, so that view is not a
 * URL anyone can share. Making the fragment track the open surface would mean
 * writing it from here on every open and close, which is a deliberate change
 * this has not made.
 */
function useAddressedSurface(openSurfaceByName: (surface: OpenSurface) => void): void {
  const open = useRef(openSurfaceByName);
  open.current = openSurfaceByName;
  const consumed = useRef(false);
  useEffect(() => {
    if (consumed.current) return;
    consumed.current = true;
    if (typeof window === "undefined") return;
    const surface = surfaceForHash(window.location.hash);
    if (surface) open.current(surface);
  }, []);
}

/** The surface a URL fragment names, or null when it names none. */
export function surfaceForHash(hash: string): OpenSurface | null {
  return hash === FLEET_SURFACE_HASH ? "fleet-console" : null;
}

/**
 * The command palette, and the focus it has to take.
 *
 * cmdk's `autoFocus` runs once, when the input mounts, and that one attempt
 * cannot carry this. ModalShell mounts a body on first open and KEEPS it, so
 * every open after the first finds the input already mounted and autoFocus long
 * spent; before bodies were lazy the input mounted at route load inside a shell
 * that is `display: none` until it opens, so even the FIRST open landed on a
 * hidden input. That first-open case is history — the body now mounts in the
 * same commit that adds `is-open`, onto a shell that is already visible — and
 * it is the only half that lazy mounting fixed. Every open after it is the
 * original bug: Ctrl+K with focus still on <body>, the next keystroke going
 * nowhere, and the operator reaching for the mouse, which is the whole reason a
 * palette exists. Focus therefore moves when `open` flips, not when the input
 * mounts.
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
  onSelect,
  onNavigate = navigateToRoute
}: {
  open: boolean;
  value: string;
  onValueChange: (value: string) => void;
  items: PaletteCommand[];
  /** Selecting an entry that names a surface. */
  onSelect: (surface: OpenSurface) => void;
  /** Selecting an entry that names another console's route. Injectable for tests. */
  onNavigate?: (href: string) => void;
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
            onSelect={() => (isRouteCommand(item) ? onNavigate(item.href) : onSelect(item.surface))}
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
