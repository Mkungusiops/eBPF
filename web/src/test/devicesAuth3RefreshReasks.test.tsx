import { act, renderHook, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { DevicesRoute } from "../features/devices/DevicesRoute";
import { useDeviceInventory } from "../features/devices/useDeviceInventory";
import type { DevicesApi, DevicesWhoami } from "../features/devices/api";

/**
 * REFRESH IS THE OPERATOR'S MANUAL WAY OUT.
 *
 * When the permission read has failed, the console withholds every containment
 * control — correctly. The Refresh control used to re-read the device table
 * only, so an operator watching a wedged kill-switch could press it forever
 * and never re-ask the one question that was actually blocking them; the only
 * cure was a page reload.
 *
 * Refresh and the backoff timer both end in another whoami, so the test has to
 * rule the timer out or it proves nothing. It does that by CONSTRUCTION rather
 * than by racing: the retry base is handed in as a minute, so the timer cannot
 * fire inside the test at all and a second attempt can only have come from
 * Refresh. Racing the real 750ms base instead made this fail under a loaded
 * full-suite run and pass in isolation — which is the worst of both, because it
 * would also pass for the wrong reason on a slow machine.
 */
const NEVER_IN_THIS_TEST = 60_000;
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

describe("Refresh re-asks the permission question", () => {
  it("sends another whoami from the inventory's refresh, inside the backoff window", async () => {
    let attempts = 0;
    const api = fakeApi(async () => {
      attempts += 1;
      throw new Error("whoami unreachable");
    });
    const { result } = renderHook(() => useDeviceInventory(api, 60_000, { whoamiRetryBaseMs: NEVER_IN_THIS_TEST }));

    // Waited for, not read synchronously after the attempt counter: the counter
    // increments when the request is ISSUED, and the status is set when it
    // settles — a hop that grew when the read went on a deadline. Reading the
    // status immediately after the counter raced that hop.
    await waitFor(() => expect(result.current.whoamiStatus).toBe("unanswered"));
    expect(attempts).toBe(1);

    act(() => {
      result.current.refresh();
    });
    await waitFor(() => expect(attempts).toBe(2));
  });

  it("settles the console's state from the answer Refresh brought back", async () => {
    let attempts = 0;
    const api = fakeApi(async () => {
      attempts += 1;
      if (attempts === 1) throw new Error("whoami unreachable");
      return { canRespond: false };
    });
    const { result } = renderHook(() => useDeviceInventory(api, 60_000, { whoamiRetryBaseMs: NEVER_IN_THIS_TEST }));

    await waitFor(() => expect(result.current.whoamiStatus).toBe("unanswered"));
    expect(result.current.canRespond).toBeNull();

    act(() => {
      result.current.refresh();
    });
    await waitFor(() => expect(result.current.whoamiStatus).toBe("answered"));
    // The second answer is the one that stands — a refusal, honoured without a
    // remount.
    expect(result.current.canRespond).toBe(false);
  });

  it("is wired to the button an operator actually presses", async () => {
    // The two assertions above are about the hook; this one traces the same
    // recovery to the call site, because the previous rounds of this fix
    // stopped one layer short of it.
    let attempts = 0;
    const api = fakeApi(async () => {
      attempts += 1;
      throw new Error("whoami unreachable");
    });
    render(<DevicesRoute api={api} pollMs={60_000} whoamiRetryBaseMs={NEVER_IN_THIS_TEST} />);
    await screen.findByText(/Bulk actions/i);
    await waitFor(() => expect(attempts).toBe(1));

    const refresh = screen.getByRole("button", { name: /refresh/i });
    await userEvent.click(refresh);
    // Exactly two: the timer is a minute away, so the button is the only thing
    // that can have asked again. A >= here would have passed on the retry alone.
    await waitFor(() => expect(attempts).toBe(2));
  });
});
