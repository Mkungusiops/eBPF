import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SocSidebar } from "../features/soc/Sidebar";
import { SOC_PANEL_INVENTORY } from "../features/soc/panelInventory";
import type { OpenSurface } from "../features/soc/dashboard";

/**
 * The fleet console was reachable only by typing its URL.
 *
 * The rail's "Fleet" entry never opened it. It mounts FleetBody — a
 * browser-local directory of OTHER consoles' URLs, kept in soc.fleet.hosts and
 * probed via /api/fleet/probe, which by its own comment deliberately does not
 * enumerate enrolled agents. It has no mode, no ladder, no kill switch, no
 * drift and no writes. web/src/features/fleet, served at /fleet, has all of
 * them — and nothing outside features/fleet linked to it, so the only surface
 * that can see host drift and scope a targeted containment was a URL an
 * operator had to already know.
 *
 * Two things are pinned here, and they are the pair: the real console has a
 * door in the rail, and the bookmark list keeps its own door under a name that
 * says what it is. Renaming without linking, or linking without renaming,
 * leaves two "Fleet" entries meaning different things.
 */

function renderRail(onOpenSurface: (surface: OpenSurface) => void = () => {}) {
  return render(
    <SocSidebar
      sidebarOpen
      openSurface={null}
      onToggleSidebar={() => {}}
      onCloseSidebar={() => {}}
      onOpenSurface={onOpenSurface}
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

describe("the fleet console has a door in the SOC rail", () => {
  it("renders a Fleet Console link pointing at /fleet", () => {
    renderRail();
    const link = screen.getByRole("link", { name: "Fleet Console" });
    expect(link.getAttribute("href")).toBe("/fleet");
  });

  it("puts it in Respond, beside the two choke gateways it shares a job with", () => {
    const { container } = renderRail();
    // Sectioned by heading text rather than by index: the group is what makes
    // the item findable, and an entry that drifted into Manage would still
    // satisfy the href assertion above while reading as a diagnostic tool.
    const respond = Array.from(container.querySelectorAll(".soc-sidebar-section")).find((section) =>
      section.textContent?.startsWith("Respond")
    );
    expect(respond, "the rail has no Respond section").toBeTruthy();
    const hrefs = Array.from(within(respond as HTMLElement).getAllByRole("link")).map((a) => a.getAttribute("href"));
    expect(hrefs).toEqual(["/choke", "/devices", "/fleet"]);
  });
});

describe("the browser-local peer directory keeps its door under a truthful name", () => {
  it("opens the same 'fleet' surface it always did, from an item named Peer Consoles", () => {
    const opened: OpenSurface[] = [];
    renderRail((surface) => opened.push(surface));
    fireEvent.click(screen.getByRole("button", { name: "Peer Consoles" }));
    expect(opened).toEqual(["fleet"]);
  });

  it("leaves no rail entry still called 'Fleet' to be confused with the console", () => {
    renderRail();
    // getByRole with an exact string still matches "Fleet Console" under the
    // default substring-free accessible-name compare only if the name IS
    // "Fleet", which is the thing being ruled out.
    expect(screen.queryByRole("button", { name: "Fleet" })).toBeNull();
  });

  it("says the same thing in the panel inventory the account page counts", () => {
    // The inventory is the console's own account of itself, and a spec asserts
    // every storage key it advertises is really written. A title left at
    // "Fleet" here would re-introduce the ambiguity one screen over.
    const entry = SOC_PANEL_INVENTORY.find((item) => item.id === "fleet-modal");
    expect(entry?.title).toBe("Peer Consoles");
    expect(entry?.storage).toEqual(["soc.fleet.hosts"]);
  });
});
