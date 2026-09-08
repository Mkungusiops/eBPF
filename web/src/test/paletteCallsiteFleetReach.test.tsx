import { fireEvent, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { EMPTY_SOC_SNAPSHOT } from "../features/soc/api";
import { SocModals } from "../features/soc/SocModals";
import { useSocWindowModel } from "../features/soc/useSocWindowModel";
import { LAB_ONLY_SURFACES } from "../features/soc/Sidebar";
import { DEFAULT_WATCHLIST, type OpenSurface } from "../features/soc/dashboard";
import type { SocSnapshot } from "../features/soc/types";

/**
 * THE PALETTE AS SocModals ACTUALLY RENDERS IT.
 *
 * fleetReachPalette.test.tsx drives CommandPalette with `paletteItems(...)`
 * passed in by the test itself, so it proves the item list is right and proves
 * nothing about what the console hands the component. Reverting the call site
 * to the old `paletteCommands(...)` builder — the exact defect that work fixed,
 * a one-line revert — left every one of those tests green: the fleet console
 * would have gone back to being the one console Ctrl+K cannot reach with no
 * failure anywhere.
 *
 * So these tests never build an item list. They mount SocModals with the
 * command surface open and read what comes out of it: the entry must be there,
 * selecting it must leave for /fleet, and the lab gate the palette walked
 * around once already must still hold on the rendered thing.
 */

// cmdk keeps its selected item in view with a ResizeObserver, which jsdom does
// not implement; without this the palette throws on mount.
class NoopResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver = globalThis.ResizeObserver ?? (NoopResizeObserver as unknown as typeof ResizeObserver);

/**
 * WHY THE NETWORK IS STUBBED AT ALL, now that ModalShell mounts a body only on
 * first open: it is not the modal bodies. The command surface is the one that
 * is open here, so it is the only body that mounts, and it fetches nothing. The
 * requests come from the real `useSocWindowModel` this harness runs — two
 * /api/alert-stats windows and /api/decision-stats — and jsdom inherits node's
 * global fetch, so unstubbed those go out as real requests against the test
 * runner's own origin. Nothing in this file reads a response, so one empty JSON
 * body serves every call rather than a per-endpoint mock.
 */
function stubFetch() {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }))
  );
}

/**
 * The real component, with the real window model, given only a lab_mode value.
 * Everything else is the empty snapshot the console itself starts from.
 */
function Harness({ labMode, onSelectSurface }: { labMode: boolean; onSelectSurface: (surface: OpenSurface) => void }) {
  const snapshot: SocSnapshot = { ...EMPTY_SOC_SNAPSHOT, version: { sha: "test", labMode } };
  const model = useSocWindowModel({
    snapshot,
    rangeMin: 30,
    now: Date.parse("2026-09-08T09:00:00Z"),
    truncated: { alerts: false, events: false },
    errors: {},
    statuses: {},
    query: "",
    hideBaseline: false,
    filterUnack: false,
    groupAlerts: false,
    sortField: "time",
    ackStates: {},
    pinnedAlerts: [],
    timelineHidden: [],
    streamFilter: "",
    streamHideNoise: false,
    streamPaused: false
  });
  return (
    <SocModals
      openSurface="command"
      closeModal={() => {}}
      openSurfaceByName={onSelectSurface}
      snapshot={snapshot}
      model={model}
      watchlist={DEFAULT_WATCHLIST}
      setWatchlist={() => {}}
      fleetHosts={[]}
      setFleetHosts={() => {}}
      now={Date.parse("2026-09-08T09:00:00Z")}
      notifications={{
        history: [],
        setHistory: () => {},
        active: false,
        setActive: () => {},
        channels: { inApp: false, desktop: false, audio: false },
        setChannels: () => {}
      }}
      kpiDrill={null}
      ackStates={{}}
      commandQuery=""
      setCommandQuery={() => {}}
      theme="dark"
      stream={{ state: "down", frames: 0 }}
      onActionComplete={() => {}}
      graphBody={null}
      exportBody={null}
    />
  );
}

/**
 * Every entry the rendered palette offers, in the order it offers them, plus
 * the browser navigation those entries would perform.
 *
 * SocModals passes no `onNavigate`, so a route entry runs the component's own
 * default — `window.location.assign`. jsdom's location is unforgeable and its
 * real assign throws "navigation not implemented", so the whole object is
 * stubbed here rather than the method patched, and the spy is what every test
 * below reads to decide where a selection went.
 */
function renderedPalette(labMode: boolean, onSelectSurface: (surface: OpenSurface) => void = () => {}) {
  stubFetch();
  const assign = vi.fn();
  vi.stubGlobal("location", { ...window.location, assign });
  const view = render(<Harness labMode={labMode} onSelectSurface={onSelectSurface} />);
  const items = Array.from(view.container.querySelectorAll("[cmdk-item]")) as HTMLElement[];
  // Non-empty, or every "does not offer" assertion below passes on a palette
  // that rendered nothing at all.
  expect(items.length, "SocModals rendered a palette with no entries").toBeGreaterThan(0);
  return { view, items, assign, labels: items.map((item) => (item.textContent ?? "").trim()) };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the palette SocModals renders reaches the fleet console", () => {
  it("offers the entry on a production deployment", () => {
    const { view, labels } = renderedPalette(false);
    expect(
      labels.some((label) => label.includes("Open Fleet Console")),
      "SocModals hands the palette a list with no route out of this console"
    ).toBe(true);
    view.unmount();
  });

  it("leaves for /fleet when that entry is selected, opening no surface", () => {
    const opened: OpenSurface[] = [];
    // The assign spy is the component's own default navigation, not an
    // injected handler: SocModals passes no onNavigate.
    const { view, items, assign } = renderedPalette(false, (surface) => opened.push(surface));
    const entry = items.find((item) => (item.textContent ?? "").includes("Open Fleet Console"));
    fireEvent.click(entry as HTMLElement);

    expect(assign, "selecting the fleet entry in the rendered palette went nowhere").toHaveBeenCalledWith("/fleet");
    // A route is not a surface: routed through openSurfaceByName it would open
    // whichever modal shares the name and never leave the page.
    expect(opened).toEqual([]);
    view.unmount();
  });

  it("still opens ordinary surfaces from the same rendered list", () => {
    const opened: OpenSurface[] = [];
    const { view, items } = renderedPalette(false, (surface) => opened.push(surface));
    const entry = items.find((item) => (item.textContent ?? "").includes("Show help"));
    fireEvent.click(entry as HTMLElement);
    expect(opened).toEqual(["help"]);
    view.unmount();
  });
});

describe("the rendered palette still honours the lab gate", () => {
  it("withholds the lab surfaces when the server reports lab_mode false", () => {
    const opened: OpenSurface[] = [];
    const { view, items, labels } = renderedPalette(false, (surface) => opened.push(surface));
    // Press everything: an entry that is rendered and clickable is the defect,
    // so the surfaces are collected from the handler rather than from labels.
    for (const item of items) fireEvent.click(item);
    for (const surface of LAB_ONLY_SURFACES) {
      expect(opened, `${surface} was one Ctrl+K away on a production deployment`).not.toContain(surface);
    }
    expect(labels.some((label) => label.includes("Open attacks"))).toBe(false);
    expect(labels.some((label) => label.includes("Show honeypots"))).toBe(false);
    // Narrow, or the gate could "pass" by offering nothing an analyst needs.
    expect(opened).toEqual(expect.arrayContaining(["policies", "kprobes", "help"]));
    view.unmount();
  });

  it("gives them back, and keeps the route, when the server reports a lab", () => {
    const opened: OpenSurface[] = [];
    const { view, items, labels, assign } = renderedPalette(true, (surface) => opened.push(surface));
    for (const item of items) fireEvent.click(item);
    expect(opened).toEqual(expect.arrayContaining(["attacks", "honeypots"]));
    // The route is not lab-gated — /fleet ships to every deployment and does
    // its own authorisation — so it is offered here too.
    expect(labels.some((label) => label.includes("Open Fleet Console"))).toBe(true);
    expect(assign).toHaveBeenCalledWith("/fleet");
    view.unmount();
  });
});
