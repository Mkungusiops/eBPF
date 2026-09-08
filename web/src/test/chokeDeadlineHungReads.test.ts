import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ChokeTimeoutError, getChokeState, isTimeoutError } from "../features/choke/api";
import { useChokeData } from "../features/choke/useChokeData";
import type { useStream } from "../lib/stream";

/**
 * A CHOKE READ THAT NEVER ANSWERS.
 *
 * The identity read on this route was already bounded; nothing else was. So the
 * same permanent wedge was still reachable through `/api/choke/state`, which
 * `refreshAll` awaited on its own line ahead of every other read, with
 * `setRefreshing(false)` in the finally — the flag that disables the Refresh
 * button (sections.tsx). One hung state read therefore took the operator's only
 * manual recovery away for the life of the session, prevented the other seven
 * reads from being issued at all, and left the route sitting on "loading"
 * forever, which reads as "still asking" rather than "could not be reached".
 *
 * The fetch stubbed here IGNORES the abort signal, on purpose: that is what a
 * half-open connection through a load balancer does, and it is why the deadline
 * has to be a race and not only an abort.
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

// Far shorter than the eight-second default so the deadline can be driven
// without fake timers, which deadlock the act() flush these async reads run
// through, and far shorter than waitFor's own budget so a real timeout is what
// the assertions observe.
const HANG_DEADLINE_MS = 120;

const CIRCUIT = { exec_id: "e-1", binary: "/usr/bin/curl", score: 42, state: "pristine" };
const DECISION = { id: "d-1", action: "observe", binary: "/usr/bin/curl", at: "2026-09-07T00:00:00Z" };

let stateHangs = true;
let stateCalls = 0;

function jsonFor(url: string): unknown {
  if (url.includes("/api/choke/circuits")) return [CIRCUIT];
  if (url.includes("/api/decisions")) return [DECISION];
  if (url.includes("/api/whoami")) return { user: "analyst", can_respond: true };
  if (url.includes("/api/choke/cgroups")) return {};
  return [];
}

beforeEach(() => {
  stateHangs = true;
  stateCalls = 0;
  vi.stubGlobal("fetch", async (path: string) => {
    const url = String(path);
    if (url.startsWith("/api/choke/state")) {
      stateCalls += 1;
      // No signal handling at all — the request simply never comes back.
      if (stateHangs) return new Promise<Response>(() => {});
      return new Response(JSON.stringify({ mode: "detect-only", tracked: 3 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response(JSON.stringify(jsonFor(url)), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function mount() {
  return renderHook(() =>
    useChokeData({
      pushToast: PUSH_TOAST,
      sharedStream: FAKE_STREAM,
      readTimeoutMs: HANG_DEADLINE_MS,
      whoamiTimeoutMs: HANG_DEADLINE_MS,
    }),
  );
}

describe("the choke read client", () => {
  it("ends a hung read as a timeout, and cancels the request behind it", async () => {
    let seen: AbortSignal | undefined;
    vi.stubGlobal("fetch", async (_path: string, init: RequestInit = {}) => {
      seen = init.signal ?? undefined;
      return new Promise<Response>(() => {});
    });
    const caught = await getChokeState({ timeoutMs: 20 }).catch((error: unknown) => error);
    expect(isTimeoutError(caught)).toBe(true);
    expect((caught as ChokeTimeoutError).message).toContain("unreachable");
    expect((caught as ChokeTimeoutError).message).toContain("/api/choke/state");
    // The socket is not left open behind the abandoned await.
    expect(seen?.aborted).toBe(true);
  });

  it("relays a caller's abort as an abort, not as a fabricated timeout", async () => {
    vi.stubGlobal("fetch", async (_path: string, init: RequestInit = {}) => {
      return new Promise<Response>((_, reject) => {
        init.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      });
    });
    const controller = new AbortController();
    const pending = getChokeState({ signal: controller.signal, timeoutMs: 5000 }).catch((error: unknown) => error);
    controller.abort();
    const caught = await pending;
    expect(isTimeoutError(caught)).toBe(false);
    expect((caught as Error).name).toBe("AbortError");
  });
});

describe("a choke state read that never answers", () => {
  it("settles as unreachable within the deadline instead of pending forever", async () => {
    const hook = mount();
    await waitFor(() => expect(stateCalls).toBeGreaterThan(0));
    // "Could not be reached" is its own sentence: not the loading state it used
    // to sit in forever, and not the disabled banner, which claims the gateway
    // answered and said it is switched off.
    await waitFor(() => expect(hook.result.current.loadState.kind).toBe("error"));
    const message = (hook.result.current.loadState as { message: string }).message;
    expect(message).toContain("unreachable");
    expect(hook.result.current.chokeState).toBeNull();
  });

  it("returns the Refresh control to the operator", async () => {
    const hook = mount();
    // Without a deadline this stays true — the button reads "Refreshing" and is
    // disabled for the rest of the session.
    await waitFor(() => expect(hook.result.current.refreshing).toBe(false));
  });

  it("does not hold back the reads that would have answered", async () => {
    const hook = mount();
    // These used to sit behind the awaited state read and never be issued at
    // all, so a single slow endpoint emptied every panel on the route.
    await waitFor(() => expect(hook.result.current.circuits).toHaveLength(1));
    expect(hook.result.current.decisions).toHaveLength(1);
    expect(hook.result.current.chokeState).toBeNull();
  });

  it("recovers on Refresh once the gateway starts answering again", async () => {
    const hook = mount();
    await waitFor(() => expect(hook.result.current.loadState.kind).toBe("error"));
    expect(hook.result.current.refreshing).toBe(false);

    stateHangs = false;
    await act(async () => {
      await hook.result.current.refreshAll();
    });
    await waitFor(() => expect(hook.result.current.loadState.kind).toBe("ready"));
    expect(hook.result.current.chokeState).toEqual({ mode: "detect-only", tracked: 3 });
    expect(hook.result.current.refreshing).toBe(false);
  });
});
