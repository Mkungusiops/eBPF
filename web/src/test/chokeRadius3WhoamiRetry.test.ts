import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useChokeData } from "../features/choke/useChokeData";
import type { useStream } from "../lib/stream";

/**
 * A FAILED whoami MUST RECOVER ON ITS OWN.
 *
 * whoami is this route's AUTHORITY read: ChokeRoute publishes its `can_respond`
 * into the shared authority store, and a null whoami is published as "the
 * question is still open", which withholds every containment control. But
 * whoami ran only inside refreshAll — it was on none of the staggered snapshot
 * polls. So one failed read (a restart, a proxy blip) left the console's
 * containment surface disabled indefinitely, and the only ways back were the
 * operator noticing and pressing Refresh, or the tab losing and regaining
 * visibility. During an incident neither is a recovery path.
 *
 * The retry is a self-disarming interval rather than a ninth permanent poll, so
 * this test pins both halves: that a failure recovers by itself, and that a
 * session which has been answered stops asking.
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

// Stable across renders on purpose. useChokeData's refreshers close over this,
// so a fresh function each render would churn their identities and re-fire the
// mount effect — the loop this hook's chokeStateRef comment already records.
const PUSH_TOAST = () => {};

let whoamiCalls = 0;
let whoamiFails = true;

beforeEach(() => {
  whoamiCalls = 0;
  whoamiFails = true;
  // Only the clock the polls run on. Faking the microtask queue too (sinon's
  // default set) deadlocks React's act(), which schedules its flush there.
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval"] });
  vi.stubGlobal("fetch", async (path: string, init: RequestInit = {}) => {
    const url = String(path);
    if (url.startsWith("/api/whoami")) {
      // The reachability probe (pingHost -> probeEndpoint) also GETs
      // /api/whoami every 8s and THROWS THE BODY AWAY — it only wants a status
      // code. That probe is why "whoami is already being polled" looks true and
      // is not: it never populates the authority, so it must not be counted.
      //
      // The discriminator is the INIT OBJECT, not the wire. probeEndpoint calls
      // fetch(path, {method, cache, signal}) and never names `credentials`,
      // while lib/api's funnel sets `credentials: "same-origin"` explicitly on
      // every request it sends. On the wire the two are identical — same-origin
      // IS the Fetch default, so the probe carries the session cookie too — but
      // only the funnel's init has the key, which is all this stub needs to tell
      // the authority read from the probe. Do not "simplify" this to a check on
      // the URL or the method: both reads are a GET of the same path, and the
      // count would then include the probe and stop meaning anything.
      if (init.credentials === "same-origin") whoamiCalls += 1;
      if (whoamiFails) return new Response("upstream unavailable", { status: 502 });
      return new Response(JSON.stringify({ user: "analyst", can_respond: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    // Everything else this hook polls answers empty; only the identity read is
    // under test here.
    return new Response(JSON.stringify(url.includes("/api/choke/state") ? { mode: "detect-only" } : []), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  });
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

// Drains the hook's in-flight reads: every refresh is a promise chain several
// awaits deep, so one microtask turn is not enough to see its result.
async function settle(ms = 0): Promise<void> {
  await act(async () => {
    if (ms > 0) vi.advanceTimersByTime(ms);
    for (let i = 0; i < 20; i += 1) await Promise.resolve();
  });
}

describe("the choke route's authority read retries itself", () => {
  it("recovers a failed whoami with no reload, refresh press or tab switch", async () => {
    const hook = renderHook(() => useChokeData({ pushToast: PUSH_TOAST, sharedStream: FAKE_STREAM }));
    await settle();
    // Precondition: the read failed, so the route has no authority and every
    // containment control is withheld.
    expect(whoamiCalls).toBeGreaterThan(0);
    expect(hook.result.current.whoami).toBeNull();

    // Nobody touches the page. The server comes back.
    whoamiFails = false;
    await settle(6000);
    await settle();

    expect(hook.result.current.whoami).toEqual({ user: "analyst", can_respond: true });
  });

  it("stops asking once whoami has answered, rather than adding a ninth poll", async () => {
    whoamiFails = false;
    const hook = renderHook(() => useChokeData({ pushToast: PUSH_TOAST, sharedStream: FAKE_STREAM }));
    await settle();
    expect(hook.result.current.whoami).not.toBeNull();

    const answered = whoamiCalls;
    await settle(60000);
    await settle();
    // A healthy session must not add a per-minute identity poll of its own; the
    // retry exists for the unanswered case only.
    expect(whoamiCalls).toBe(answered);
  });
});
