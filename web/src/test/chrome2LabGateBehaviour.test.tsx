import { fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { normalizeVersion } from "../features/soc/api";
import { CommandPalette, paletteCommands } from "../features/soc/SocModals";
import { LAB_ONLY_SURFACES, SocSidebar, surfaceOffered } from "../features/soc/Sidebar";
import type { OpenSurface } from "../features/soc/dashboard";

/**
 * The lab gate, proven by DRIVING the two doors rather than by reading them.
 *
 * Attack Sim runs a script as root on the host being defended and, on the
 * control plane, writes fabricated alerts into the tenant's real evidence
 * store; Honeypots reports decoy hits no host produced; the Rule Simulator
 * tunes a ladder no endpoint can persist. The rail hides all three unless the
 * SERVER reports lab_mode — and the command palette is a second door onto the
 * same surfaces, which for a while was gated on nothing at all.
 *
 * The first attempt at pinning that asserted over a 400-character lookback in
 * Sidebar.tsx source, which is not a test: it passes on a file that has been
 * reformatted and fails on one that has not, it never presses anything, and it
 * cannot see a fourth entry added without a guard. What follows instead opens
 * both doors for each value the server can report and collects the surfaces
 * they actually hand back.
 *
 * The gate is driven from the version PAYLOAD through normalizeVersion, because
 * that is the path a deployment takes: `lab_mode` off the wire → SocVersion →
 * the rail and the palette (SocRoute passes the same field to both).
 */

const LAB_PAYLOAD = { sha: "abc", lab_mode: true };
const PROD_PAYLOAD = { sha: "abc", lab_mode: false };

function railSurfaces(labMode: boolean): OpenSurface[] {
  const opened: OpenSurface[] = [];
  const { container, unmount } = render(
    <SocSidebar
      sidebarOpen
      openSurface={null}
      onToggleSidebar={() => {}}
      onCloseSidebar={() => {}}
      onOpenSurface={(surface) => opened.push(surface)}
      onOpenAssistant={() => {}}
      assistantOpen={false}
      assistantAvailable
      watchlistCount={0}
      labMode={labMode}
      notificationBadge={undefined}
      userName="admin"
    />
  );
  // Press everything the rail offers. A gated entry that is rendered but
  // unreachable would still be a defect, and a rendered-and-clickable one is
  // exactly what this has to catch — so the surfaces are collected from the
  // handler, not from the labels.
  for (const button of Array.from(container.querySelectorAll("button"))) fireEvent.click(button);
  unmount();
  return opened;
}

function paletteSurfaces(labMode: boolean): OpenSurface[] {
  const selected: OpenSurface[] = [];
  const { container, unmount } = render(
    <CommandPalette
      open
      value=""
      onValueChange={() => {}}
      items={paletteCommands(labMode)}
      onSelect={(surface) => selected.push(surface)}
    />
  );
  for (const item of Array.from(container.querySelectorAll("[cmdk-item]"))) fireEvent.click(item);
  unmount();
  return selected;
}

class NoopResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

beforeEach(() => {
  globalThis.ResizeObserver = globalThis.ResizeObserver ?? (NoopResizeObserver as unknown as typeof ResizeObserver);
  window.localStorage.clear();
});

describe("no lab surface is reachable when the server reports lab_mode false", () => {
  it("hands back none of them from the rail", () => {
    const labMode = normalizeVersion(PROD_PAYLOAD).labMode;
    expect(labMode).toBe(false);
    const reachable = railSurfaces(labMode);
    // Non-empty, or the harness is passing by rendering nothing.
    expect(reachable.length).toBeGreaterThan(0);
    for (const surface of LAB_ONLY_SURFACES) {
      expect(reachable, `${surface} was reachable from the rail on a production deployment`).not.toContain(surface);
    }
  });

  it("hands back none of them from the command palette", () => {
    const reachable = paletteSurfaces(normalizeVersion(PROD_PAYLOAD).labMode);
    expect(reachable.length).toBeGreaterThan(0);
    for (const surface of LAB_ONLY_SURFACES) {
      expect(reachable, `${surface} was one Ctrl+K away on a production deployment`).not.toContain(surface);
    }
  });

  it("still offers the surfaces an analyst always needs, through both doors", () => {
    // The gate is only worth having if it is narrow. A rail that hid Policies
    // or a palette that dropped Help would "pass" the assertions above.
    expect(railSurfaces(false)).toEqual(expect.arrayContaining(["policies", "fleet", "kprobes", "watchlist"]));
    expect(paletteSurfaces(false)).toEqual(expect.arrayContaining(["policies", "help", "kprobes"]));
  });
});

describe("the same surfaces come back on a deployment the server reports as a lab", () => {
  it("offers every gated surface once lab_mode is true", () => {
    const labMode = normalizeVersion(LAB_PAYLOAD).labMode;
    expect(labMode).toBe(true);
    // Rail and palette between them are the console's two doors; each gated
    // surface has to be reachable through at least one of them, or the gate is
    // hiding a surface the lab is supposed to have.
    const reachable = new Set([...railSurfaces(labMode), ...paletteSurfaces(labMode)]);
    for (const surface of LAB_ONLY_SURFACES) {
      expect(Array.from(reachable), `${surface} is unreachable on a lab deployment`).toContain(surface);
    }
  });

  it("puts the Rule Simulator behind the gate too, not just the two loud ones", () => {
    // The simulator has no palette entry, so it is only ever reachable from the
    // rail — the case the source-grep version of this test was there to cover
    // and the one a reformat would have silently dropped.
    expect(railSurfaces(false)).not.toContain("simulator");
    expect(railSurfaces(true)).toContain("simulator");
    render(
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
    expect(screen.queryByRole("button", { name: /Rule Simulator/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Attack Sim/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Honeypots/ })).toBeNull();
  });

  it("names every gated surface in one list both doors ask", () => {
    // Not a source read: this drives the predicate the rail and the palette
    // both call, so a fourth gated surface added to only one of them shows up
    // as a reachability difference above rather than as a passing grep.
    for (const surface of LAB_ONLY_SURFACES) {
      expect(surfaceOffered(surface, false)).toBe(false);
      expect(surfaceOffered(surface, true)).toBe(true);
    }
    expect(surfaceOffered("policies", false)).toBe(true);
  });
});

describe("an unsteered deployment is treated as production", () => {
  it("gates on the server's word, and a server that says nothing is not a lab", () => {
    // An older engine or control plane sends no lab_mode key at all.
    const labMode = normalizeVersion({ sha: "abc" }).labMode;
    const reachable = new Set([...railSurfaces(labMode), ...paletteSurfaces(labMode)]);
    for (const surface of LAB_ONLY_SURFACES) {
      expect(Array.from(reachable), `${surface} was offered by default`).not.toContain(surface);
    }
    const palette = render(
      <CommandPalette open value="" onValueChange={() => {}} items={paletteCommands(labMode)} onSelect={() => {}} />
    );
    expect(within(palette.container).queryByText("Open attacks")).toBeNull();
    vi.restoreAllMocks();
  });
});
