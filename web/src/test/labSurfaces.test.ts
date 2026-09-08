import { createElement } from "react";
import { cleanup, fireEvent, render, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchSocSnapshot, normalizeVersion } from "../features/soc/api";
import { LAB_ONLY_SURFACES, SocSidebar, surfaceOffered } from "../features/soc/Sidebar";
import type { OpenSurface } from "../features/soc/dashboard";

/**
 * The three demo surfaces are gated because two of them are actively
 * dangerous on a customer estate:
 *
 *  - Attack Sim executes a script AS ROOT on the host the engine is defending,
 *    behind a single shared admin credential (so it is unattributable), and on
 *    the control plane it writes FABRICATED alerts into the tenant's real
 *    telemetry table where alert-stats, MITRE coverage and every export count
 *    them as genuine findings.
 *  - Honeypots on the control plane reports decoy hits from Go constants that
 *    no host produced.
 *  - The Rule Simulator tunes a severity ladder no endpoint can persist.
 *
 * WHAT THIS FILE USED TO BE, AND WHY IT WAS WORTHLESS. It read Sidebar.tsx as
 * text, found `label="Attack Sim"`, and asserted that the 400 characters before
 * it contained "labMode ?". That check has no relationship to what the console
 * does: it passes on a file that has been reformatted or where the conditional
 * belongs to a different entry, it fails on a correctly-gated file whose JSX
 * happens to wrap differently, and a fourth gated surface added with no guard
 * at all would not have moved it. It never rendered anything.
 *
 * WHAT IT ASSERTS NOW. `chrome2LabGateBehaviour.test.tsx` drives the three
 * named surfaces through the rail AND the command palette. This file takes the
 * other half — the shape of the gate rather than its members:
 *
 *  1. Rail ≡ predicate, over EVERY surface the rail can open. The universe is
 *     collected from the rail itself on a lab deployment, so a fourth entry
 *     added to LAB_ONLY_SURFACES and forgotten in the rail's own conditionals,
 *     or an ungated surface accidentally hidden from customers, both show up
 *     here without this file being edited.
 *  2. The surfaces an analyst always needs are reachable BY NAME on a
 *     production rail — the labels an operator looks for, pressed, not grepped.
 *  3. A gated endpoint answering 404 is not routed into the error strip. That
 *     used to be pinned by asserting two source substrings of api.ts; it is now
 *     driven through fetchSocSnapshot against a server that answers the way a
 *     production engine actually answers.
 */

beforeEach(() => {
  window.localStorage.clear();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

/** Render the rail for a deployment and press everything it offers. */
function rail(labMode: boolean): { opened: OpenSurface[]; buttonNames: string[] } {
  const opened: OpenSurface[] = [];
  const { container } = render(
    createElement(SocSidebar, {
      sidebarOpen: true,
      openSurface: null,
      onToggleSidebar: () => {},
      onCloseSidebar: () => {},
      onOpenSurface: (surface: OpenSurface) => opened.push(surface),
      onOpenAssistant: () => {},
      assistantOpen: false,
      assistantAvailable: true,
      watchlistCount: 0,
      labMode,
      notificationBadge: undefined,
      userName: "admin",
    })
  );
  // By role, so what is collected is what a screen reader — and every
  // getByRole in the Playwright suite — can actually find.
  const buttons = within(container).getAllByRole("button");
  const buttonNames = buttons.map((button) => button.textContent?.trim() ?? "");
  // Collected from the handler, not from the labels: an entry that renders but
  // opens nothing, and one that renders hidden but is still clickable, are both
  // things a label-only reading would miss.
  for (const button of buttons) fireEvent.click(button);
  return { opened, buttonNames };
}

describe("the rail offers exactly what the shared predicate says it may", () => {
  it("hides a surface if and only if surfaceOffered says it is lab-only", () => {
    // The universe is what the rail itself hands back on a lab box, so this
    // does not need updating when a surface is added — only when the gate and
    // the rail stop agreeing, which is the defect.
    const inLab = rail(true).opened;
    cleanup();
    const inProduction = new Set(rail(false).opened);
    expect(inLab.length, "the rail opened nothing at all; this test has no subject").toBeGreaterThan(5);

    for (const surface of new Set(inLab)) {
      expect(
        inProduction.has(surface),
        `the rail and surfaceOffered() disagree about ${surface}: rail offers it on production = ${inProduction.has(
          surface
        )}, predicate says ${surfaceOffered(surface, false)}`
      ).toBe(surfaceOffered(surface, false));
    }
  });

  it("puts every LAB_ONLY_SURFACES member behind that gate in the rail, not just the loud two", () => {
    // The Rule Simulator has no command-palette entry, so the rail is its only
    // door — the case a lookback over Sidebar.tsx source could not see.
    const inLab = new Set(rail(true).opened);
    cleanup();
    const inProduction = new Set(rail(false).opened);
    for (const surface of LAB_ONLY_SURFACES) {
      expect(Array.from(inLab), `${surface} is unreachable even on a lab deployment`).toContain(surface);
      expect(Array.from(inProduction), `${surface} was reachable from a production rail`).not.toContain(surface);
    }
  });
});

describe("the gate stays narrow", () => {
  it("leaves the surfaces an analyst always needs on the rail, by the name they look for", () => {
    // A rail that hid Policies or the peer directory would satisfy every
    // assertion above.
    //
    // "Peer Consoles", not "Fleet": the rail item was renamed on 2026-09-07
    // because it opens a browser-local directory of OTHER consoles, not the
    // fleet console at /fleet — which until then was reachable only by typing
    // the URL. The fleet console is a LINK now, not a surface button, so it is
    // asserted by the link case below rather than here.
    const { buttonNames } = rail(false);
    for (const label of ["Watchlist", "Time Machine", "Policies", "Peer Consoles", "Reports", "Sensor Health"]) {
      expect(
        buttonNames.some((name) => name.includes(label)),
        `${label} is not a pressable entry on a production rail`
      ).toBe(true);
    }
  });

  it("shows the operator no lab entry to press on a production deployment", () => {
    const { buttonNames } = rail(false);
    for (const label of ["Attack Sim", "Honeypots", "Rule Simulator"]) {
      expect(buttonNames.join(" | "), `${label} is rendered on a production rail`).not.toContain(label);
    }
  });
});

describe("labMode defaults to off", () => {
  it("treats a server that does not report the field as production", () => {
    // An older control plane or engine has no lab_mode key. Defaulting to true
    // would offer a nav entry whose endpoint answers 404 — or worse, offer the
    // attack runner on a customer box.
    expect(normalizeVersion({ sha: "abc" }).labMode).toBe(false);
    expect(normalizeVersion({}).labMode).toBe(false);
  });

  it("honours an explicit lab_mode", () => {
    expect(normalizeVersion({ sha: "abc", lab_mode: true }).labMode).toBe(true);
    expect(normalizeVersion({ sha: "abc", lab_mode: false }).labMode).toBe(false);
  });

  it("renders the production rail for a version payload that never mentions labs", () => {
    // The whole path a deployment takes: `lab_mode` absent off the wire →
    // normalizeVersion → the rail. Asserted end to end because the two halves
    // were previously pinned separately and neither one saw the join.
    const opened = new Set(rail(normalizeVersion({ sha: "abc" }).labMode).opened);
    for (const surface of LAB_ONLY_SURFACES) {
      expect(Array.from(opened), `${surface} was offered by default`).not.toContain(surface);
    }
  });
});

/** Answer every snapshot read 200 except the paths given an explicit status. */
function serverWhere(failing: Record<string, number>): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      const entry = Object.entries(failing).find(([fragment]) => path.includes(fragment));
      const status = entry ? entry[1] : 200;
      const body = status === 200 ? [] : { error: `HTTP ${status}` };
      return new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      });
    })
  );
}

describe("a gated endpoint is not an outage", () => {
  it("does not report the lab endpoints' 404 as an error", async () => {
    // Routing it into `errors` lights the notices strip and the executive
    // band's "telemetry feed down" path over two panels the operator is
    // deliberately not given — an outage invented out of a configuration.
    serverWhere({ "/api/attacks": 404, "/api/honeypots": 404 });
    const read = await fetchSocSnapshot();

    // The stub was actually reached, so an empty `errors` is a decision rather
    // than an accident of nothing having been requested.
    expect(read.statuses.attacks).toBe(404);
    expect(read.statuses.honeypots).toBe(404);
    expect(Object.keys(read.errors)).toEqual([]);
  });

  it("still reports any other failure on those same endpoints", async () => {
    // "Not offered" is a 404 and nothing else. A lab endpoint that 500s is a
    // broken server, and swallowing that would hide a real fault behind the
    // exemption written for a deliberate omission.
    serverWhere({ "/api/attacks": 500, "/api/honeypots": 503 });
    const read = await fetchSocSnapshot();
    expect(Object.keys(read.errors).sort()).toEqual(["attacks", "honeypots"]);
  });

  it("still reports a 404 on an endpoint the console is not allowed to lose", async () => {
    // The exemption is scoped to the two lab feeds. A policies endpoint that
    // has gone missing is an outage, and the console must say so.
    serverWhere({ "/api/policies": 404 });
    const read = await fetchSocSnapshot();
    expect(Object.keys(read.errors)).toContain("policies");
  });
});
