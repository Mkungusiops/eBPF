import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AUTHORITY_UNREACHABLE_REASON, DevicesRoute } from "../features/devices/DevicesRoute";
import { AUTHORITY_PENDING_REASON, responseAuthorityNow } from "../features/soc/api";
import type { DevicesApi, DevicesWhoami } from "../features/devices/api";

/**
 * ONE FAILED /api/whoami USED TO DISARM THE DEVICE PLANE FOR THE WHOLE SESSION.
 *
 * The permission read ran once per mount and swallowed its rejection, so a
 * single dropped request left the shared authority store at "loading" — which
 * withholds — with nothing left in the session able to move it. The
 * kill-switch, the mode toggle, the bulk Choke/Thaw bar and every row rung
 * stayed disabled under "Checking what this account may do" until the operator
 * reloaded the page. Refresh did not help: it re-read the table only.
 *
 * ORDERING MATTERS. The authority store (features/soc/api.ts) starts at
 * "loading" and only an ANSWERED whoami moves it, with no way back. So every
 * test that needs the unanswered state runs before the one that lets an answer
 * land, and the first expectation pins that precondition rather than assuming
 * it.
 *
 * The assistant is mocked out: it opens its own conversation on mount and has
 * nothing to do with permissions.
 */
vi.mock("../features/assistant", () => ({
  AssistantPanel: () => null
}));

const DEVICE = {
  mac: "aa:bb:cc:dd:ee:ff",
  last_ip: "10.0.0.9",
  hostname: "victim-device",
  state: "pristine"
};

function fakeApi(whoami: () => Promise<DevicesWhoami>): DevicesApi {
  return {
    fetchState: async () => ({ enforcing: true, kill_switched: false, links_attached: 1 }) as never,
    fetchDevices: async () => [DEVICE] as never,
    fetchFlows: async () => ({ flows: [] }) as never,
    jailDevices: async () => ({ results: [] }) as never,
    thawDevices: async () => ({ results: [] }) as never,
    setMode: async () => ({ mode: "enforcing" }) as never,
    setKillSwitch: async () => ({ engaged: true }) as never,
    fetchWhoami: whoami
  };
}

function control(selector: string): HTMLButtonElement {
  const button = document.querySelector<HTMLButtonElement>(selector);
  if (!button) throw new Error(`no control matched ${selector}`);
  return button;
}

function withheldNote(): string {
  return document.querySelector('[data-panel="containment-command-withheld"]')?.textContent ?? "";
}

describe("the device console keeps asking what the account may do", () => {
  it("starts at loading — the precondition every assertion below rests on", () => {
    expect(responseAuthorityNow()).toBe("loading");
  });

  it("says it is still ASKING while the read is in flight, not that it was refused", async () => {
    const api = fakeApi(() => new Promise<DevicesWhoami>(() => {}));
    render(<DevicesRoute api={api} pollMs={60_000} />);
    await screen.findByText(/Bulk actions/i);

    expect(withheldNote()).toBe(AUTHORITY_PENDING_REASON);
    expect(document.body.textContent).not.toMatch(/read-only/i);
  });

  it("says the server could not be REACHED once the read has actually failed", async () => {
    // Distinct from the sentence above: "still checking" stops being true the
    // moment the request came back as a failure, and an operator whose console
    // is wedged needs to know the control plane is the thing that is down.
    const api = fakeApi(async () => {
      throw new Error("whoami unreachable");
    });
    render(<DevicesRoute api={api} pollMs={60_000} />);
    await screen.findByText(/Bulk actions/i);

    await waitFor(() => expect(withheldNote()).toBe(AUTHORITY_UNREACHABLE_REASON));
    expect(withheldNote()).not.toBe(AUTHORITY_PENDING_REASON);
    // Still withheld: an unanswered question is not permission.
    expect(control("button.cc-ctl-kill").disabled).toBe(true);
    expect(document.body.textContent).not.toMatch(/read-only/i);
  });

  it("arms the controls when a retry answers, with no remount", async () => {
    let attempts = 0;
    const api = fakeApi(async () => {
      attempts += 1;
      if (attempts === 1) throw new Error("whoami unreachable");
      return { canRespond: true };
    });
    render(<DevicesRoute api={api} pollMs={60_000} />);
    await screen.findByText(/Bulk actions/i);

    // The first read failed and disarmed everything.
    await waitFor(() => expect(attempts).toBe(1));
    expect(control("button.cc-ctl-kill").disabled).toBe(true);

    // Nothing is remounted and nobody clicks Refresh: the bounded backoff
    // re-asks on its own, and the second answer settles the controls.
    await waitFor(() => expect(responseAuthorityNow()).toBe(true), { timeout: 5000 });
    await waitFor(() => expect(control("button.cc-ctl-kill").disabled).toBe(false));
    expect(control("button.cc-ctl-mode").disabled).toBe(false);
    const choke = screen.getByRole("button", { name: "Choke" }) as HTMLButtonElement;
    expect(choke.disabled).toBe(false);
    expect(withheldNote()).toBe("");
  });

  it("still reports a refusal as a refusal", async () => {
    const api = fakeApi(async () => ({ canRespond: false }));
    render(<DevicesRoute api={api} pollMs={60_000} />);
    await waitFor(() => expect(responseAuthorityNow()).toBe(false));

    await waitFor(() => expect(withheldNote()).toMatch(/read-only/i));
    expect(withheldNote()).not.toBe(AUTHORITY_PENDING_REASON);
    expect(withheldNote()).not.toBe(AUTHORITY_UNREACHABLE_REASON);
    expect(control("button.cc-ctl-kill").disabled).toBe(true);
  });
});
