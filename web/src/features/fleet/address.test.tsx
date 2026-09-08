/**
 * /fleet AFTER THE MOVE: still an address, no longer a console.
 *
 * The fleet view is a surface inside the SOC console now. Its URL was NOT
 * deleted, and three things depend on that: operators have it bookmarked, the
 * live probe suite signs in at it against the estate, and the command palette
 * still offers it as a route. So the entry survives as a redirect and the
 * console reads the fragment it redirects to.
 *
 * What is pinned here is the whole path an operator can take to the surface —
 * the rail entry, the fragment, and the redirect that produces it — because
 * each half is useless without the other: a redirect to a fragment nothing
 * reads lands on a closed console, and a fragment reader with no redirect
 * leaves every bookmark on a blank page.
 */
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { FLEET_SURFACE_HASH, FLEET_SURFACE_URL } from "./address";
import { EMPTY_SOC_SNAPSHOT } from "../soc/api";
import { SocModals, surfaceForHash } from "../soc/SocModals";
import { SocSidebar } from "../soc/Sidebar";
import { useSocWindowModel } from "../soc/useSocWindowModel";
import { DEFAULT_WATCHLIST, type OpenSurface } from "../soc/dashboard";

// cmdk keeps its selected item in view with a ResizeObserver, which jsdom does
// not implement; SocModals mounts the palette shell, so without this the
// component throws before anything under test has run.
class NoopResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver = globalThis.ResizeObserver ?? (NoopResizeObserver as unknown as typeof ResizeObserver);

afterEach(() => {
  vi.unstubAllGlobals();
});

/**
 * SocModals with nothing open. No surface body is mounted in this state, which
 * is the point: what is under test is the fragment being READ at mount, before
 * and independently of anything the surfaces themselves do.
 */
function Harness({ onOpen }: { onOpen: (surface: OpenSurface) => void }) {
  const snapshot = { ...EMPTY_SOC_SNAPSHOT, version: { sha: "test", labMode: false } };
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
      openSurface={null}
      closeModal={() => {}}
      openSurfaceByName={onOpen}
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

function withHash(hash: string) {
  vi.stubGlobal("location", { ...window.location, hash });
}

describe("the fragment names the surface", () => {
  it("maps the fleet fragment, and nothing else", () => {
    expect(surfaceForHash(FLEET_SURFACE_HASH)).toBe("fleet-console");
    expect(surfaceForHash("")).toBeNull();
    // Near misses must NOT open it: "#fleet-hosts" is somebody else's anchor,
    // and a prefix match would open a containment surface on a scroll link.
    expect(surfaceForHash("#fleet-hosts")).toBeNull();
    expect(surfaceForHash("#graph")).toBeNull();
  });
});

describe("arriving on the console at the fleet address", () => {
  it("opens the fleet surface", () => {
    withHash(FLEET_SURFACE_HASH);
    const opened: OpenSurface[] = [];
    const view = render(<Harness onOpen={(surface) => opened.push(surface)} />);
    expect(
      opened,
      "an operator who followed a /fleet bookmark landed on a console with nothing open"
    ).toEqual(["fleet-console"]);
    view.unmount();
  });

  it("opens nothing when the address names no surface", () => {
    withHash("");
    const opened: OpenSurface[] = [];
    const view = render(<Harness onOpen={(surface) => opened.push(surface)} />);
    expect(opened, "the plain console opened a surface nobody asked for").toEqual([]);
    view.unmount();
  });

  it("does not re-open the surface on every render", () => {
    // `openSurfaceByName` is a plain function declaration in the route, so it is
    // a new value on every render. A reader that depended on it would slam the
    // surface back open the moment the operator closed it.
    withHash(FLEET_SURFACE_HASH);
    const opened: OpenSurface[] = [];
    const view = render(<Harness onOpen={(surface) => opened.push(surface)} />);
    view.rerender(<Harness onOpen={(surface) => opened.push(surface)} />);
    view.rerender(<Harness onOpen={(surface) => opened.push(surface)} />);
    expect(opened, "closing the fleet surface would be undone by the next render").toEqual([
      "fleet-console"
    ]);
    view.unmount();
  });
});

describe("the rail entry is both an address and a surface", () => {
  function renderRail(onOpen: (surface: OpenSurface) => void = () => {}) {
    return render(
      <SocSidebar
        sidebarOpen
        openSurface={null}
        onToggleSidebar={() => {}}
        onCloseSidebar={() => {}}
        onOpenSurface={onOpen}
        onOpenAssistant={() => {}}
        assistantOpen={false}
        assistantAvailable
        watchlistCount={0}
        labMode={false}
        notificationBadge={undefined}
        userName="admin"
      />
    );
  }

  it("opens the surface in place on a plain click, without leaving the console", () => {
    const opened: OpenSurface[] = [];
    const view = renderRail((surface) => opened.push(surface));
    const link = screen.getByRole("link", { name: "Fleet Console" });
    expect(link.getAttribute("href"), "the address the bookmark and the probe use is gone").toBe("/fleet");

    // fireEvent.click reports the result of preventDefault, which is what
    // decides whether the browser would have navigated.
    const followed = fireEvent.click(link);
    expect(opened, "the rail entry did not open the fleet surface").toEqual(["fleet-console"]);
    expect(
      followed,
      "the rail reloaded the whole console to reach a surface it already hosts"
    ).toBe(false);
    view.unmount();
  });

  it("leaves a modified click to the browser, so open-in-new-tab still works", () => {
    const opened: OpenSurface[] = [];
    const view = renderRail((surface) => opened.push(surface));
    const followed = fireEvent.click(screen.getByRole("link", { name: "Fleet Console" }), {
      metaKey: true
    });
    expect(opened, "a cmd-click opened the surface in the tab the operator was leaving").toEqual([]);
    expect(followed, "cmd-click was swallowed, so the entry cannot be opened in a new tab").toBe(true);
    view.unmount();
  });
});

describe("/fleet itself", () => {
  it("redirects into the console with the fleet surface named", async () => {
    const replace = vi.fn();
    // jsdom's window.location is unforgeable, so the whole object is stubbed
    // rather than the method patched.
    vi.stubGlobal("location", { ...window.location, replace });
    // The entry's redirect is a module side effect: it must run before the
    // browser has painted, not after a React tree has mounted.
    await import("../../entries/fleet");
    expect(replace, "the /fleet bookmark landed on a blank page").toHaveBeenCalledWith(
      FLEET_SURFACE_URL
    );
    expect(FLEET_SURFACE_URL, "the redirect and the reader disagree about the address").toBe(
      `/${FLEET_SURFACE_HASH}`
    );
  });
});
