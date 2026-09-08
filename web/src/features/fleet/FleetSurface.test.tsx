/**
 * WHO DECIDES WHETHER THE FLEET WRITE RAIL IS ARMED, NOW THAT THE FLEET VIEW IS
 * A SURFACE INSIDE THE SOC CONSOLE.
 *
 * It used to decide for itself: its own /api/whoami read, its own
 * `canRespond`/`identityResolved` pair, its own rule for what a missing
 * `can_respond` meant. That is exactly the second source of truth that armed a
 * refused control on three other surfaces before it was centralised, so the
 * surface now reads features/soc/api.ts's shared authority store like every
 * other containment surface — and the claims that used to be pinned on the read
 * path (useFleetSnapshot.test.ts) are pinned here instead, over the same four
 * states:
 *
 *   "loading" — nobody has answered. NOTHING is armed, and the rail says it is
 *               CHECKING rather than calling the account read-only, which would
 *               be its own lie for the operator who turns out to be a responder.
 *   false     — the server refused. Read-only account.
 *   null      — the server ANSWERED and published no `can_respond`: the
 *               single-tenant engine, which has no such permission model.
 *               PERMITTED. Reading it as denial takes the emergency controls
 *               away from every operator on that engine.
 *   true      — permitted.
 *
 * THE API HANDED TO THE SURFACE BELOW HAS NO WHOAMI SOURCE AT ALL — `FleetApi`
 * no longer has one — so nothing here can pass by the surface quietly asking a
 * second time. Every arming decision under test comes from the shared store.
 *
 * ORDER MATTERS IN THIS FILE. The store starts at "loading" and only
 * `recordResponseAuthority` moves it off, with no way back, so the in-flight
 * case is FIRST and nothing before it may record an answer.
 */
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { setSelectedTenant } from "../../lib/tenantScope";

import { ConfirmModal } from "./ConfirmModal";
import { FleetSurface } from "./FleetSurface";
import { recordResponseAuthority } from "../soc/api";
import type { FleetApi } from "./fleetApi";
import type { FleetPeer } from "./types";

const PEERS: FleetPeer[] = [
  { name: "alpha-edge", url: "http://alpha" },
  { name: "bravo-edge", url: "http://bravo" }
];

/**
 * A fleet that is up: two configured peers, both answering. The rail's OTHER
 * refusals (fleet mode disabled, no peers configured) must not be the reason
 * anything below is disabled, or the permission assertions prove nothing.
 */
function fakeApi(): FleetApi {
  return {
    fetchSnapshot: async () => ({
      peers: PEERS as never,
      states: {
        hosts: PEERS.map((peer) => ({
          name: peer.name,
          ok: true,
          data: { mode: "enforcing", tracked: 0 }
        }))
      } as never,
      cgroups: { hosts: [] } as never,
      decisions: { hosts: [] } as never,
      alerts: { hosts: [] } as never,
      devices: { hosts: [] } as never
    }),
    applyPreset: async () => ({}),
    applyThresholds: async () => ({}),
    setKillSwitch: async () => ({}),
    thaw: async () => ({}),
    isDisabled: () => false,
    errorMessage: (e) => String(e)
  };
}

/** Mounted open, with a poll long enough that only the first read ever runs. */
async function renderSurface() {
  const view = render(<FleetSurface open api={fakeApi()} pollMs={60_000} />);
  // The rail is only meaningfully armed once the peers are in: until then
  // `totalHosts === 0` disables it for a reason that is not about permission.
  await waitFor(() => expect(screen.getByRole("row", { name: /alpha-edge/ })).toBeTruthy());
  return view;
}

/** The estate-wide kill-switch: the widest-blast-radius control on the rail. */
function killSwitch(): HTMLButtonElement {
  return screen.getByRole("button", { name: "Kill-switch on" }) as HTMLButtonElement;
}

describe("the fleet surface takes its write authority from the shared store", () => {
  it("arms nothing while the answer is in flight, and says it is checking", async () => {
    // FIRST TEST IN THE FILE, deliberately: the store starts at "loading" and
    // there is no way back to it.
    const view = await renderSurface();

    expect(
      killSwitch().disabled,
      "a read-only principal gets a live estate-wide kill-switch until whoami lands"
    ).toBe(true);
    expect(screen.getByText(/Checking your response rights with the server/i)).toBeTruthy();
    // NOT the read-only sentence: telling a responder their account is
    // read-only for the first second of a session is its own false statement.
    expect(screen.queryByText(/account is read-only/i)).toBeNull();
    view.unmount();
  });

  it("arms when the server answers without can_respond — the single-tenant engine", async () => {
    // null is "the server published no such field", which must read as
    // PERMITTED. Reading it as denial strips the emergency controls from every
    // operator on an engine that has no permission model to consult.
    act(() => recordResponseAuthority(null));
    const view = await renderSurface();

    expect(
      killSwitch().disabled,
      "the single-tenant engine's operator lost the emergency controls over a field their server never sends"
    ).toBe(false);
    expect(screen.queryByText(/Checking your response rights/i)).toBeNull();
    expect(screen.queryByText(/account is read-only/i)).toBeNull();
    view.unmount();
  });

  it("refuses, and says why, when the server says this account may not respond", async () => {
    act(() => recordResponseAuthority(false));
    const view = await renderSurface();

    expect(killSwitch().disabled, "a refused account was handed the estate-wide kill-switch").toBe(true);
    expect(screen.getByText(/read-only/i)).toBeTruthy();
    // The permission refusal, not the in-flight one — the operator has to know
    // which of the two it is: one is theirs to escalate, one ends by itself.
    expect(screen.queryByText(/Checking your response rights/i)).toBeNull();
    view.unmount();
  });

  it("arms when the server says this account may respond", async () => {
    act(() => recordResponseAuthority(true));
    const view = await renderSurface();

    expect(killSwitch().disabled).toBe(false);
    expect(screen.queryByText(/read-only/i)).toBeNull();
    view.unmount();
  });
});

/**
 * THE SECOND CHROME IS GONE.
 *
 * The whole point of the move: one console, one set of chrome. The fleet view
 * used to carry its own brand line ("Choke Fleet Console"), its own four-entry
 * console nav and its own sign-out, a few pixels under the SOC shell's — and
 * its brand line captioned a DIFFERENT customer than the shell's banner did,
 * because it was built from an unscoped whoami. None of it may come back.
 *
 * THE CUSTOMER CAPTION IS NOT PART OF THAT CHROME and is asserted PRESENT
 * further down this file. It went out with the topbar and had to come back:
 * this surface covers the whole viewport, so no caption behind it is visible,
 * and it was the only thing on screen naming the customer whose estate the
 * kill-switch below reaches. What made the old one wrong was its SOURCE — an
 * unscoped whoami — not that the page said whose hosts these were.
 */
describe("the surface renders no console chrome of its own", () => {
  it("has no brand line, no console nav and no sign-out", async () => {
    const view = await renderSurface();

    expect(screen.queryByText("Choke Fleet Console")).toBeNull();
    expect(screen.queryByRole("navigation", { name: "Console navigation" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Sign out" })).toBeNull();
    view.unmount();
  });

  it("keeps the one readout that was its own: the fan-out's health", async () => {
    // Nothing in the SOC chrome reports this. The shell's live pill watches the
    // SSE stream; this surface has no stream, only the five-second poll.
    const view = await renderSurface();

    expect(screen.getByText("connected")).toBeTruthy();
    expect(screen.getByText("auto-refresh 60s")).toBeTruthy();
    view.unmount();
  });
});

/**
 * ESCAPE, NOW THAT THERE IS SOMETHING BEHIND THE CONFIRM.
 *
 * The fleet view is a surface inside the SOC console, and that console closes
 * whatever surface is open on Escape — a window-level handler in SocRoute. The
 * fleet confirm listens on window too, so both used to run: escaping out of
 * "apply containment to the estate?" dismissed the confirm AND shut the fleet
 * view behind it, dropping the operator back on the dashboard mid-incident with
 * no way to tell whether the write had gone.
 *
 * The console's handler is stood in for here rather than mounting SocRoute: the
 * claim is about the EVENT — that a keydown the confirm answers never reaches a
 * window listener behind it — and a stand-in registered exactly as SocRoute
 * registers its own is the whole of what that needs.
 */
describe("the confirm owns Escape while it is up", () => {
  it("closes itself and does not let the surface behind it close too", () => {
    const behind = vi.fn();
    // Registered exactly as SocRoute registers its own: window, bubble phase.
    window.addEventListener("keydown", behind);
    const onClose = vi.fn();
    const view = render(
      <ConfirmModal
        state={{
          title: "Apply containment preset?",
          body: "Containment lowers thresholds across targeted hosts.",
          tone: "danger",
          confirmLabel: "Apply preset",
          reasonLabel: "Audit reason",
          reasonRequired: true,
          onConfirm: async () => undefined
        }}
        onClose={onClose}
      />
    );

    fireEvent.keyDown(window, { key: "Escape" });

    expect(onClose, "Escape did not dismiss the confirm").toHaveBeenCalledTimes(1);
    expect(
      behind,
      "Escape reached the console behind the confirm, which would have closed the fleet surface as well"
    ).not.toHaveBeenCalled();

    window.removeEventListener("keydown", behind);
    view.unmount();
  });

  it("gives Escape back the moment it is gone", () => {
    const behind = vi.fn();
    window.addEventListener("keydown", behind);
    const view = render(
      <ConfirmModal
        state={{ title: "t", body: "b", onConfirm: async () => undefined }}
        onClose={() => {}}
      />
    );
    view.unmount();

    fireEvent.keyDown(window, { key: "Escape" });
    expect(
      behind,
      "the confirm kept swallowing Escape after it was dismissed, so the surface could never be closed"
    ).toHaveBeenCalledTimes(1);
    window.removeEventListener("keydown", behind);
  });
});

/**
 * THE CUSTOMER IS NAMED ON THE SURFACE, BECAUSE NOTHING BEHIND IT IS VISIBLE.
 *
 * The move deleted the topbar that carried this caption, and nothing replaced
 * it. The surface is mounted full screen: .soc-modal-back.is-fullscreen is a
 * fixed, opaque, viewport-filling layer, so the SOC route's own in-flow scope
 * banner is covered, and the shell banner that entry mounts is
 * TenantScopeBanner in "dashboard" mode, which renders nothing unless the scope
 * is unconfirmed. For a while an MSSP operator pointed at customer B could
 * therefore open this surface, read customer B's hosts, and arm the
 * estate-wide kill-switch below with no customer named anywhere on screen.
 *
 * WHICH customer, and every one of the caption's states, is pinned on the
 * caption itself (src/test/fleetCaptionScope.test.tsx). What is pinned HERE is
 * that the surface mounts it at all — the failure was a missing mount, not a
 * wrong string.
 */
describe("the surface names the customer its kill-switch reaches", () => {
  afterEach(() => {
    setSelectedTenant(null);
  });

  it("captions the selected customer above the rail", async () => {
    setSelectedTenant("beta-industries");
    const view = await renderSurface();

    const caption = view.container.querySelector(".fleet-scope-caption");
    expect(caption, "the fleet surface renders no customer caption at all").toBeTruthy();
    expect(
      (caption as HTMLElement).textContent,
      "the estate-wide kill-switch is armed on a surface that names no customer"
    ).toMatch(/beta-industries/);
    view.unmount();
  });

  it("puts the caption above the kill-switch, not below it", async () => {
    setSelectedTenant("beta-industries");
    const view = await renderSurface();

    const caption = view.container.querySelector(".fleet-scope-caption") as HTMLElement;
    // An operator reaching for the widest-blast-radius control on the platform
    // must have read whose estate it is on the way there.
    expect(
      caption.compareDocumentPosition(killSwitch()) & Node.DOCUMENT_POSITION_FOLLOWING,
      "the customer is named below the control it qualifies"
    ).toBeTruthy();
    view.unmount();
  });
});

/**
 * AND IT IS VISIBLE AT EVERY WIDTH.
 *
 * The caption and the poll readout are the surface's only two statements about
 * what is on screen and whose it is, and neither may be hidden by a media
 * query. This is not hypothetical: the old topbar packed five things into one
 * grid row, so under 1260px the stylesheet hid the status readout and the
 * console nav to make room. The nav is gone and the readout is on its own
 * full-width line — keeping that rule would have taken the fan-out's health
 * away from every laptop narrower than 1260px, and it would take the customer's
 * name with it the day the caption joined that selector list.
 *
 * Read from the stylesheet because jsdom applies neither media queries nor this
 * sheet; there is no rendered fact to assert against.
 */
describe("the surface's own captions are not hidden by width", () => {
  it("has no rule that hides the scope caption or the poll readout", () => {
    const css = readFileSync(resolve("src/features/fleet/fleet.css"), "utf8").replace(
      /\/\*[\s\S]*?\*\//g,
      ""
    );
    const hiding = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)].filter(([, , body]) =>
      /display\s*:\s*none/.test(body)
    );
    for (const [, selectors] of hiding) {
      for (const selector of selectors.split(",")) {
        const trimmed = selector.trim();
        expect(
          trimmed === ".fleet-status" ||
            trimmed === ".fleet-surface-status" ||
            trimmed === ".fleet-scope-caption",
          `${trimmed} is hidden, and it is one of the two things this surface says about itself`
        ).toBe(false);
      }
    }
  });
});
