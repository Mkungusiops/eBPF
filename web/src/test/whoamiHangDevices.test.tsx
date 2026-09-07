import { act, render, renderHook, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { AUTHORITY_UNREACHABLE_REASON, DevicesRoute } from "../features/devices/DevicesRoute";
import { useDeviceInventory } from "../features/devices/useDeviceInventory";
import type { DevicesApi, DevicesWhoami } from "../features/devices/api";

/**
 * A WHOAMI THAT HANGS MUST NOT WEDGE THE CONSOLE EITHER.
 *
 * The previous round taught this route to survive a permission read that
 * REJECTS. It did not survive one that never settles — and that is the more
 * common outage: a half-open TCP connection through a load balancer answers
 * nothing, ever. The in-flight guard that stops three callers asking at once
 * was the trap: a read that never settles never releases it, so the backoff
 * timer, the poll tick and the operator's Refresh all bailed out on it for the
 * rest of the session, `whoamiStatus` stayed `pending`, the shared authority
 * store stayed "loading", and every containment control stayed disabled — the
 * identical permanent wedge, reached through the front door.
 *
 * So the read is on a deadline, and these tests pin what the deadline buys:
 * silence becomes "could not be reached" rather than "still asking", Refresh
 * can ask again afterwards, and the answer that finally arrives settles the
 * controls — all with no remount.
 *
 * Timings are injected, never waited on: the deadline is handed in as a few
 * milliseconds, and the automatic retry base as a minute, so anything that
 * happens after the timeout can only have come from the path under test.
 */
const HANG_DEADLINE_MS = 20;
const RETRY_NEVER_IN_THIS_TEST = 60_000;

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

/** A request that never settles, the way a half-open connection never does. */
function hang(): Promise<never> {
  return new Promise<never>(() => {});
}

describe("a whoami that never answers", () => {
  it("ends as 'could not be reached' instead of sitting on 'still asking' forever", async () => {
    let attempts = 0;
    const api = fakeApi(() => {
      attempts += 1;
      return hang();
    });
    const { result } = renderHook(() =>
      useDeviceInventory(api, 60_000, {
        whoamiRetryBaseMs: RETRY_NEVER_IN_THIS_TEST,
        whoamiTimeoutMs: HANG_DEADLINE_MS
      })
    );

    await waitFor(() => expect(attempts).toBe(1));
    // Before the deadline this is honestly "still asking".
    expect(result.current.whoamiStatus).toBe("pending");

    await waitFor(() => expect(result.current.whoamiStatus).toBe("unanswered"));
    // Withholding is unchanged and must stay so: an unanswered question never
    // arms containment on a guess.
    expect(result.current.canRespond).toBeNull();
  });

  it("lets Refresh re-ask after the deadline, where before it was silently inert", async () => {
    let attempts = 0;
    const api = fakeApi(() => {
      attempts += 1;
      return hang();
    });
    const { result } = renderHook(() =>
      useDeviceInventory(api, 60_000, {
        whoamiRetryBaseMs: RETRY_NEVER_IN_THIS_TEST,
        whoamiTimeoutMs: HANG_DEADLINE_MS
      })
    );

    await waitFor(() => expect(result.current.whoamiStatus).toBe("unanswered"));
    act(() => {
      result.current.refresh();
    });
    // The automatic retry base is a minute away, so a second attempt can only
    // be Refresh's. Without the deadline the in-flight flag was still set and
    // this stayed at 1 forever.
    await waitFor(() => expect(attempts).toBe(2));
  });

  it("settles the controls from the answer that finally arrives, with no remount", async () => {
    let attempts = 0;
    const api = fakeApi(() => {
      attempts += 1;
      if (attempts === 1) return hang();
      return Promise.resolve({ canRespond: false });
    });
    const { result } = renderHook(() =>
      useDeviceInventory(api, 60_000, {
        whoamiRetryBaseMs: RETRY_NEVER_IN_THIS_TEST,
        whoamiTimeoutMs: HANG_DEADLINE_MS
      })
    );

    await waitFor(() => expect(result.current.whoamiStatus).toBe("unanswered"));
    act(() => {
      result.current.refresh();
    });
    await waitFor(() => expect(result.current.whoamiStatus).toBe("answered"));
    // The refusal stands, from the same mounted hook.
    expect(result.current.canRespond).toBe(false);
  });

  it("keeps 'answers without the field' meaning permitted, even after a hang", async () => {
    let attempts = 0;
    const api = fakeApi(() => {
      attempts += 1;
      if (attempts === 1) return hang();
      // The single-tenant engine publishes no can_respond. That is an ANSWER,
      // and it means permitted — the rule the deadline must not disturb.
      return Promise.resolve({ canRespond: null });
    });
    const { result } = renderHook(() =>
      useDeviceInventory(api, 60_000, {
        whoamiRetryBaseMs: RETRY_NEVER_IN_THIS_TEST,
        whoamiTimeoutMs: HANG_DEADLINE_MS
      })
    );

    await waitFor(() => expect(result.current.whoamiStatus).toBe("unanswered"));
    act(() => {
      result.current.refreshWhoami();
    });
    await waitFor(() => expect(result.current.whoamiStatus).toBe("answered"));
    expect(result.current.canRespond).toBeNull();
  });

  it("tells the operator which of the three states the console is in, and Refresh still asks", async () => {
    // The route, not just the hook: the sentence beside the dead kill-switch is
    // the whole point of distinguishing "asked and could not be reached" from
    // "still asking", and the previous rounds of this fix stopped one layer
    // short of the button an operator actually presses.
    let attempts = 0;
    const api = fakeApi(() => {
      attempts += 1;
      return hang();
    });
    render(
      <DevicesRoute
        api={api}
        pollMs={60_000}
        whoamiRetryBaseMs={RETRY_NEVER_IN_THIS_TEST}
        whoamiTimeoutMs={HANG_DEADLINE_MS}
      />
    );
    await screen.findByText(/Bulk actions/i);
    await waitFor(() => expect(attempts).toBe(1));

    // Both the command cluster and the bulk bar carry the sentence, hence
    // findAll: the assertion is that the console says "could not be reached"
    // rather than "still checking", not how many places it says it.
    const notes = await screen.findAllByText(AUTHORITY_UNREACHABLE_REASON);
    expect(notes.length).toBeGreaterThan(0);

    await userEvent.click(screen.getByRole("button", { name: /refresh/i }));
    await waitFor(() => expect(attempts).toBe(2));
  });
});
