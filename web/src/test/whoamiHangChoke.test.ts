import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useChokeData } from "../features/choke/useChokeData";
import type { useStream } from "../lib/stream";

/**
 * THE SAME HANG, CHECKED ON THE CHOKE ROUTE.
 *
 * The device route's permission read could be wedged forever by a whoami that
 * never settles; this route has the same identity read, so it was worth asking
 * whether it wedges the same way. Its authority gate does not — the retry here
 * is a self-disarming interval that keeps firing regardless of whether the last
 * request ever came back. But `refreshAll` AWAITS the identity read, and
 * `refreshing` disables the Refresh button (sections.tsx), so a hung whoami
 * left the operator's only manual recovery spinning and unpressable for the
 * rest of the session — the same permanent wedge one control over.
 *
 * So the read is on an injectable deadline, and this pins it: silence settles
 * as a failure, the Refresh control comes back, the authority stays withheld
 * while unanswered, and a later answer lands with no remount.
 */

const FAKE_STREAM = {
  state: "live",
  retries: 0,
  messageCount: 0,
  lastMessageAt: 0,
  lastEventAt: 0,
  frames: [],
  latestBatch: [],
  batchId: 0,
  reconnect: () => {},
} as unknown as ReturnType<typeof useStream>;

// Stable across renders: a fresh callback each render churns the refreshers'
// identities and re-fires the mount effect on a loop.
const PUSH_TOAST = () => {};

const HANG_DEADLINE_MS = 20;

let whoamiHangs = true;
let whoamiCalls = 0;

beforeEach(() => {
  whoamiHangs = true;
  whoamiCalls = 0;
  vi.stubGlobal("fetch", async (path: string, init: RequestInit = {}) => {
    const url = String(path);
    // Only the real identity read (through lib/api, which sends credentials)
    // hangs. The reachability probe GETs the same path every 8s and throws the
    // body away; hanging that too would prove nothing about the authority.
    if (url.startsWith("/api/whoami") && init.credentials === "same-origin") {
      whoamiCalls += 1;
      if (whoamiHangs) return new Promise<Response>(() => {});
      return new Response(JSON.stringify({ user: "analyst", can_respond: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response(JSON.stringify(url.includes("/api/choke/state") ? { mode: "detect-only" } : []), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("a choke whoami that never answers", () => {
  it("does not leave Refresh spinning forever", async () => {
    const hook = renderHook(() =>
      useChokeData({ pushToast: PUSH_TOAST, sharedStream: FAKE_STREAM, whoamiTimeoutMs: HANG_DEADLINE_MS }),
    );
    await waitFor(() => expect(whoamiCalls).toBeGreaterThan(0));
    // Without the deadline, refreshAll's await never returns and this stays
    // true — the button reads "Refreshing" and is disabled for the session.
    await waitFor(() => expect(hook.result.current.refreshing).toBe(false));
    // Withholding is unchanged: no answer, no authority, containment stays off.
    expect(hook.result.current.whoami).toBeNull();
  });

  it("still takes the answer when the server finally speaks, with no remount", async () => {
    const hook = renderHook(() =>
      useChokeData({ pushToast: PUSH_TOAST, sharedStream: FAKE_STREAM, whoamiTimeoutMs: HANG_DEADLINE_MS }),
    );
    await waitFor(() => expect(hook.result.current.refreshing).toBe(false));
    expect(hook.result.current.whoami).toBeNull();

    whoamiHangs = false;
    await act(async () => {
      await hook.result.current.refreshAll();
    });
    await waitFor(() => expect(hook.result.current.whoami).toEqual({ user: "analyst", can_respond: true }));
    expect(hook.result.current.refreshing).toBe(false);
  });
});
