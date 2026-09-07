import { act, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { DevicesRoute } from "../features/devices/DevicesRoute";
import { ThresholdPanel } from "../features/choke/panels";
import { AUTHORITY_PENDING_REASON, responseAuthorityNow } from "../features/soc/api";
import type { DevicesApi, DevicesWhoami } from "../features/devices/api";
import type { CircuitEntry } from "../features/choke/types";

/**
 * LOADING IS NOT PERMISSION.
 *
 * The first pass at this gate read whoami's `can_respond` and treated its
 * ABSENCE as "the server did not publish the field", which means permitted —
 * correct for the single-tenant engine, and wrong for the window between first
 * paint and the first whoami landing, where the field is absent because nobody
 * has answered yet. Both choke planes therefore armed every containment control
 * for that window: a read-only operator's console painted a live device
 * kill-switch, sever and bulk-choke surface until the poll came back.
 *
 * ORDERING MATTERS IN THIS FILE. The shared authority store
 * (features/soc/api.ts) starts at "loading" and only recordResponseAuthority
 * moves it off — there is no way back. So every test that needs the in-flight
 * state runs before any test that lets a whoami answer, and the first
 * expectation below pins that precondition rather than assuming it.
 *
 * The assistant is mocked out: it opens its own network conversation on mount
 * and has nothing to do with permissions.
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

describe("the device plane arms nothing while whoami is in flight", () => {
  it("starts at loading — the precondition every assertion below rests on", () => {
    expect(responseAuthorityNow()).toBe("loading");
  });

  it("draws the kill-switch, the mode toggle and the bulk writes disabled", async () => {
    // A whoami that never settles is exactly the window under test.
    const api = fakeApi(() => new Promise<DevicesWhoami>(() => {}));
    render(<DevicesRoute api={api} pollMs={60_000} />);
    await screen.findByText(/Bulk actions/i);

    expect(control("button.cc-ctl-kill").disabled).toBe(true);
    expect(control("button.cc-ctl-mode").disabled).toBe(true);
    const choke = screen.getByRole("button", { name: "Choke" }) as HTMLButtonElement;
    expect(choke.disabled).toBe(true);
  });

  it("says it is still checking, and does NOT claim the account is read-only", async () => {
    const api = fakeApi(() => new Promise<DevicesWhoami>(() => {}));
    render(<DevicesRoute api={api} pollMs={60_000} />);
    await screen.findByText(/Bulk actions/i);

    const note = document.querySelector('[data-panel="containment-command-withheld"]');
    expect(note?.textContent).toBe(AUTHORITY_PENDING_REASON);
    // Telling a responder their account is read-only for the first second of
    // every session is its own false statement — and the one they would report.
    // Nowhere on the page, banner included — the whole document is checked
    // rather than one selector, so moving the sentence cannot hide the lie.
    expect(document.body.textContent).not.toMatch(/read-only/i);
  });
});

describe("a read-only device operator is told why, on the control", () => {
  it("puts the permission sentence on the withheld write buttons", async () => {
    const api = fakeApi(async () => ({ canRespond: false }));
    render(<DevicesRoute api={api} pollMs={60_000} />);
    await waitFor(() => expect(responseAuthorityNow()).toBe(false));

    const choke = (await screen.findByRole("button", { name: "Choke" })) as HTMLButtonElement;
    await waitFor(() => expect(choke.disabled).toBe(true));
    // The reason is ON the control, not only in the page banner: an operator
    // reaching for a disabled button mid-incident reads the button.
    expect(choke.title).toMatch(/read-only/i);
    expect(choke.title).not.toMatch(/unavailable|offline|not enabled/i);

    const note = document.querySelector('[data-panel="containment-command-withheld"]');
    expect(note?.textContent).toMatch(/read-only/i);
  });
});

describe("the threshold simulation belongs to the reader, not the writer", () => {
  const CIRCUITS = [
    { exec_id: "a", pid: 1, binary: "/bin/a", score: 30, state: "throttled" },
    { exec_id: "b", pid: 2, binary: "/bin/b", score: 75, state: "quarantined" }
  ] as CircuitEntry[];

  it("keeps the sliders and number inputs live for a read-only account, and only withholds the commit", async () => {
    render(
      <ThresholdPanel
        dataPanel="thresholds-panel"
        thresholds={{ throttle_at: 20, tarpit_at: 40, quarantine_at: 60, sever_at: 80 }}
        circuits={CIRCUITS}
        disabled
        disabledReason="Your account is read-only: it can watch this gateway, but not contain or reconfigure it."
        onCommit={async () => {}}
      />
    );

    const slider = screen.getByLabelText("sever_at") as HTMLInputElement;
    expect(slider.disabled).toBe(false);
    const numbers = Array.from(
      document.querySelectorAll<HTMLInputElement>('.choke-threshold-inputs input[type="number"]')
    );
    expect(numbers).toHaveLength(4);
    expect(numbers.some((input) => input.disabled)).toBe(false);

    // The point of the panel: moving a threshold re-buckets the tracked
    // snapshot in the browser so an operator can read the blast radius BEFORE
    // asking someone with response rights to commit it. Reading what WOULD
    // happen is exactly what a read-only role exists for.
    const before = document.querySelector(".choke-blast")?.textContent;
    await act(async () => {
      slider.focus();
      const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")?.set;
      setter?.call(slider, "70");
      slider.dispatchEvent(new Event("input", { bubbles: true }));
    });
    expect(document.querySelector(".choke-blast")?.textContent).not.toBe(before);

    // The WRITE is still withheld, and still says why on the button.
    const commit = screen.getByRole("button", { name: /commit thresholds/i }) as HTMLButtonElement;
    expect(commit.disabled).toBe(true);
    expect(commit.title).toMatch(/read-only/i);
  });
});
