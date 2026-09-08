import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getWhoami, probeEndpoint } from "../features/choke/api";
import { useChokeData } from "../features/choke/useChokeData";
import { HOST_ENDPOINTS } from "../features/choke/constants";
import type { useStream } from "../lib/stream";

/**
 * THE REACHABILITY PROBE IS A READ LIKE ANY OTHER.
 *
 * The deadline pass bounded the nine snapshot reads and left `pingHost` on a
 * bare fetch: no deadline, no signal. That is the one read whose result is
 * painted on the header pill an operator glances at before firing containment,
 * and against the failure this whole pass exists for — a half-open connection
 * through a load balancer, which this estate has actually seen — an unbounded
 * probe never settles. `hostPings` therefore kept whatever it last held and the
 * pill went on reading "host ok" while every other read on the route had
 * already timed out.
 *
 * The fetch stubs here IGNORE the abort signal wherever they hang, on purpose:
 * that is what a half-open connection does, and it is why the deadline has to
 * be a race and not only an abort.
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

// Far shorter than the eight-second default so a deadline can be driven without
// fake timers, which deadlock the act() flush these async reads run through.
const HANG_DEADLINE_MS = 120;

// Long enough that a probe which never settles is still open when we look, and
// well clear of the deadline above so a bounded one has certainly landed.
const SETTLE_BUDGET_MS = 900;

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

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

/** Did the promise settle inside the budget, or is it still open? */
async function settledWithin<T>(promise: Promise<T>, budgetMs: number): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const verdict = await Promise.race([
    promise.then(() => true, () => true),
    new Promise<boolean>((resolve) => {
      timer = setTimeout(() => resolve(false), budgetMs);
    }),
  ]);
  if (timer) clearTimeout(timer);
  return verdict;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the host reachability probe", () => {
  beforeEach(() => {
    // Every endpoint hangs — the half-open gateway.
    vi.stubGlobal("fetch", async () => new Promise<Response>(() => {}));
  });

  it("settles as unreachable instead of leaving the pill on its last reading", async () => {
    const hook = mount();
    let ping!: Promise<void>;
    await act(async () => {
      ping = hook.result.current.pingHost();
      expect(await settledWithin(ping, SETTLE_BUDGET_MS)).toBe(true);
    });
    await waitFor(() => expect(hook.result.current.hostPings).toHaveLength(HOST_ENDPOINTS.length));
    for (const result of hook.result.current.hostPings) {
      expect(result.ok).toBe(false);
      expect(String(result.error)).toContain("unreachable");
    }
  });

  it("hands the probe a signal so teardown cancels it", async () => {
    const signals: Array<AbortSignal | undefined> = [];
    vi.stubGlobal("fetch", async (_path: string, init: RequestInit = {}) => {
      signals.push(init.signal ?? undefined);
      return new Promise<Response>(() => {});
    });
    const hook = mount();
    await act(async () => {
      void hook.result.current.pingHost();
      await Promise.resolve();
    });
    await waitFor(() => expect(signals.length).toBeGreaterThanOrEqual(HOST_ENDPOINTS.length));
    hook.unmount();
    // A socket held open on a gateway that is already struggling is exactly
    // what the unbounded probe left behind, four endpoints at a time, every
    // eight seconds for the life of the tab.
    expect(signals.every((signal) => signal !== undefined)).toBe(true);
    expect(signals.every((signal) => signal?.aborted)).toBe(true);
  });
});

describe("a probe the caller cancelled", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", async (path: string) => json(String(path).includes("/api/choke/cgroups") ? {} : []));
  });

  it("leaves the last real reading standing rather than painting the host down", async () => {
    const hook = mount();
    await act(async () => {
      await hook.result.current.pingHost();
    });
    await waitFor(() => expect(hook.result.current.hostPings).toHaveLength(HOST_ENDPOINTS.length));
    expect(hook.result.current.hostPings.every((result) => result.ok)).toBe(true);

    // An abort is a teardown or a navigation, not an answer about the host.
    // Reporting it as one would flash "host down" in the operator's face on the
    // way out of the route — and, worse, on the way back in.
    vi.stubGlobal("fetch", async () => {
      throw new DOMException("aborted", "AbortError");
    });
    await act(async () => {
      await hook.result.current.pingHost();
    });
    expect(hook.result.current.hostPings.every((result) => result.ok)).toBe(true);
  });
});

describe("the probe and the authority read are still telling apart", () => {
  it("leaves credentials unset on the probe while the real identity read opts in", async () => {
    // Both GET /api/whoami, and only the explicit credentials mode separates
    // them: the route's self-disarming whoami retry is pinned by counting the
    // identity reads that carry it (chokeRadius3WhoamiRetry), so a probe that
    // opts in reads as an answered authority read and the retry's "a healthy
    // session adds no ninth poll" check starts counting seven probes a minute.
    const seen: Array<{ url: string; credentials?: RequestCredentials }> = [];
    vi.stubGlobal("fetch", async (path: string, init: RequestInit = {}) => {
      seen.push({ url: String(path), credentials: init.credentials });
      return json({ user: "analyst" });
    });

    await probeEndpoint("/api/whoami");
    await getWhoami();

    const [probe, authority] = seen;
    expect(probe.url).toContain("/api/whoami");
    expect(probe.credentials).toBeUndefined();
    expect(authority.credentials).toBe("same-origin");
  });
});
