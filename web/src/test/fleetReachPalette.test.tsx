import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { CommandPalette, paletteCommands, paletteItems } from "../features/soc/SocModals";
import { LAB_ONLY_SURFACES, SocSidebar, surfaceOffered } from "../features/soc/Sidebar";
import { PANELS } from "../features/soc/dashboard";
import type { OpenSurface } from "../features/soc/dashboard";

/**
 * TWO WAYS AN OPERATOR FAILS TO FIND THE FLEET CONSOLE.
 *
 * REACH: the palette's item shape could only carry an OpenSurface, and /fleet
 * was not one — it was a console of its own, with its own entry, bundle and
 * five-second fan-out. So Ctrl+K reached every lesser surface and could not
 * express the one console that shows host-level drift. THAT HAS CHANGED UNDER
 * THESE TESTS AND THEY STILL HOLD: the fleet view is a full-screen surface
 * inside this console now and /fleet is a redirect into it
 * (features/fleet/address.ts), so the palette's entry is still an href rather
 * than a surface name — an address the browser follows, which lands on the
 * console with the surface open. It must be offered, must navigate, and must
 * NOT become a way around the lab gate, which the palette has walked around
 * once already.
 *
 * VOCABULARY: the fleet console used to carry a nav of its own that called the
 * SOC dashboard "Single Host" and itself "Fleet", while the SOC rail calls this
 * page "Fleet Console" and keeps a separate browser-local bookmark list called
 * "Peer Consoles". Three names for two places, one of them ("Fleet") the name
 * of the list that is NOT the console. THAT NAV IS GONE — the surface renders
 * no chrome of its own (pinned in features/fleet/FleetSurface.test.tsx) — so
 * there is one navigation left and nothing for it to disagree with. What is
 * still worth pinning is that the three doors an operator reaches the fleet
 * view through say the same word: the rail entry, the palette command, and the
 * title of the surface they open.
 *
 * What is NOT pinned here: every palette render below is handed an item list
 * this file builds, so nothing in it can see SocModals handing the component
 * the wrong builder — reverting that call site to `paletteCommands(...)` left
 * this whole file green. paletteCallsiteFleetReach.test.tsx mounts SocModals
 * itself and pins that; keep the two apart, item shape here, call site there.
 */

// cmdk keeps its selected item in view with a ResizeObserver, which jsdom does
// not implement; without this every render below throws before the component
// under test has done anything.
class NoopResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver = globalThis.ResizeObserver ?? (NoopResizeObserver as unknown as typeof ResizeObserver);

function renderPalette(labMode: boolean, handlers: { onSelect?: (surface: OpenSurface) => void; onNavigate?: (href: string) => void } = {}) {
  return render(
    <CommandPalette
      open
      value=""
      onValueChange={() => {}}
      items={paletteItems(labMode)}
      onSelect={handlers.onSelect ?? (() => {})}
      onNavigate={handlers.onNavigate ?? (() => {})}
    />
  );
}

function renderRail() {
  return render(
    <SocSidebar
      sidebarOpen
      openSurface={null}
      onToggleSidebar={() => {}}
      onCloseSidebar={() => {}}
      onOpenSurface={() => {}}
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

/** Every label the rail offers, links and buttons alike — the console's only nav. */
function railLabels(container: HTMLElement): string[] {
  return Array.from(container.querySelectorAll("a[href], button")).map((node) =>
    (node.textContent ?? "").trim()
  );
}

describe("the command palette can reach the fleet console", () => {
  it("offers it on a production deployment, as a route rather than a surface", () => {
    const fleet = paletteItems(false).filter((item) => "href" in item && item.href === "/fleet");
    expect(fleet.length, "the palette offers no way to /fleet").toBe(1);
    expect(fleet[0].label).toBe("Open Fleet Console");
  });

  it("navigates when the entry is selected, and opens no surface", () => {
    const opened: OpenSurface[] = [];
    const navigated: string[] = [];
    const { container } = renderPalette(false, {
      onSelect: (surface) => opened.push(surface),
      onNavigate: (href) => navigated.push(href)
    });

    const item = Array.from(container.querySelectorAll("[cmdk-item]")).find((node) =>
      (node.textContent ?? "").includes("Open Fleet Console")
    );
    expect(item, "the rendered palette has no Fleet Console entry").toBeTruthy();
    fireEvent.click(item as HTMLElement);

    expect(navigated, "selecting the fleet entry went nowhere").toEqual(["/fleet"]);
    // A route is not a surface: routing it through openSurfaceByName would open
    // whichever modal happened to share the name and never leave the page.
    expect(opened).toEqual([]);
  });

  it("still opens surfaces the ordinary way", () => {
    const opened: OpenSurface[] = [];
    const navigated: string[] = [];
    const { container } = renderPalette(false, {
      onSelect: (surface) => opened.push(surface),
      onNavigate: (href) => navigated.push(href)
    });
    const item = Array.from(container.querySelectorAll("[cmdk-item]")).find((node) =>
      (node.textContent ?? "").includes("Show help")
    );
    fireEvent.click(item as HTMLElement);
    expect(opened).toEqual(["help"]);
    expect(navigated, "a surface command left the page").toEqual([]);
  });
});

describe("the route entry is not a way around the lab gate", () => {
  it("withholds exactly what it withheld before when the server says this is no lab", () => {
    const items = paletteItems(false);
    const labels = items.map((item) => item.label);
    expect(labels).not.toContain("Open attacks");
    expect(labels).not.toContain("Show honeypots");
    // Narrow, or the assertion above passes on a palette that offers nothing.
    expect(labels).toContain("Show policies");
    expect(labels).toContain("Show help");

    // Every entry that NAMES a surface is still decided by the rail's own
    // predicate. A route names none, which is why it cannot smuggle one past.
    for (const item of items) {
      if ("surface" in item) expect(surfaceOffered(item.surface, false)).toBe(true);
    }
    for (const surface of LAB_ONLY_SURFACES) {
      expect(items.some((item) => "surface" in item && item.surface === surface), `${surface} was one Ctrl+K away on a production deployment`).toBe(false);
    }
  });

  it("gives the lab surfaces back when the server reports a lab, and keeps the route in both", () => {
    const labLabels = paletteItems(true).map((item) => item.label);
    expect(labLabels).toContain("Open attacks");
    expect(labLabels).toContain("Show honeypots");
    expect(labLabels).toContain("Open Fleet Console");
    // The route is not lab-gated: it is a console this platform ships to every
    // deployment, and /fleet does its own authorisation.
    expect(paletteItems(false).map((item) => item.label)).toContain("Open Fleet Console");
  });

  it("keeps the gated surface list free of routes, so the gate has one subject", () => {
    for (const item of paletteCommands(true)) {
      expect("href" in item, `${item.label} is a route inside the surface list`).toBe(false);
    }
  });
});

describe("one navigation, and one name for the console it opens", () => {
  it("keeps every door the deleted fleet nav offered", () => {
    // The fleet view's own nav linked to the other three consoles; it is gone
    // with the topbar, so the rail is the only way across. If the rail ever
    // stopped carrying one of these, the move would have cost an operator a
    // door rather than removed a duplicate one.
    const rail = renderRail();
    const hrefs = Array.from(rail.container.querySelectorAll<HTMLAnchorElement>("a[href]")).map((a) =>
      a.getAttribute("href")
    );
    for (const href of ["/", "/choke", "/devices", "/fleet"]) {
      expect(hrefs, `the rail has no link to ${href}`).toContain(href);
    }
    rail.unmount();
  });

  it("calls the surface what the rail and the palette call it", () => {
    const rail = renderRail();
    const railLabel = (screen.getByRole("link", { name: "Fleet Console" }).textContent ?? "").trim();
    rail.unmount();

    // The title the operator reads on the surface itself is the modal shell's,
    // from the panel inventory — the fleet body renders no heading of its own.
    expect(PANELS["fleet-console-modal"].title, "the surface opens under a name the rail never used").toBe(
      railLabel
    );

    // And the third door says it too, so a search for the name the operator
    // read in the rail finds the console rather than the bookmark list.
    const route = paletteItems(false).find((item) => "href" in item && item.href === "/fleet");
    expect(route?.label).toBe(`Open ${railLabel}`);
  });

  it("leaves no entry called 'Fleet' or 'Single Host' to be mistaken for something else", () => {
    // "Fleet" is the name the rail's browser-local bookmark list used to carry
    // (it is "Peer Consoles" now); "Single Host" was the deleted fleet nav's
    // private name for the SOC dashboard and appeared nowhere else in the
    // product. Asserted over the two navigations that are left.
    const rail = renderRail();
    const labels = railLabels(rail.container);
    rail.unmount();
    expect(labels).not.toContain("Fleet");
    expect(labels).not.toContain("Single Host");

    const paletteLabels = paletteItems(true).map((item) => item.label);
    expect(paletteLabels).not.toContain("Fleet");
    expect(paletteLabels).not.toContain("Single Host");
  });
});

describe("the default navigation is a document load", () => {
  it("hands the href to the browser, because /fleet is a separate entry with no shared router", async () => {
    // The palette's own default, not an injected spy: SocModals passes nothing.
    const { navigateToRoute } = await import("../features/soc/SocModals");
    const assign = vi.fn();
    // jsdom's window.location is unforgeable, so the whole object is stubbed
    // rather than the method patched.
    vi.stubGlobal("location", { ...window.location, assign });
    navigateToRoute("/fleet");
    vi.unstubAllGlobals();
    expect(assign).toHaveBeenCalledWith("/fleet");
  });
});
