/**
 * The Tier 1A exit criterion for fleet: renders with a fake API and ZERO
 * network. Before the injection this hook could only be tested by stubbing
 * global fetch, which is why it had no test at all.
 *
 * WHAT MOVED OUT OF HERE. This hook used to read /api/whoami as well, and the
 * claims about that read — an answered whoami with no `can_respond` means
 * PERMITTED, and nothing is armed while the answer is in flight — were pinned
 * on it. The fleet view is a surface inside the SOC console now and takes both
 * from the shared authority store every other containment surface reads, so
 * those claims are pinned on the surface instead (FleetSurface.test.tsx). They
 * are the same claims, over the same four states, asserted against the thing
 * that now decides them.
 */
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useFleetSnapshot } from "./useFleetSnapshot";
import type { FleetApi } from "./fleetApi";

afterEach(() => {
  vi.unstubAllGlobals();
});

function fakeApi(over: Partial<FleetApi> = {}): FleetApi {
  return {
    fetchSnapshot: async () => ({
      peers: [{ host: "h1" }] as never,
      states: { hosts: [] } as never,
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
    errorMessage: (e) => String(e),
    ...over
  };
}

describe("useFleetSnapshot", () => {
  it("loads a snapshot with no network", async () => {
    const { result } = renderHook(() => useFleetSnapshot(60_000, { api: fakeApi() }));
    await waitFor(() => expect(result.current.pollStatus).toBe("connected"));
    expect(result.current.snapshot.peers).toHaveLength(1);
  });

  it("reports 'disabled' distinctly from an error", async () => {
    // A fleet that is switched off is not a fault; conflating the two would
    // show an operator a red error for a deliberate configuration.
    const api = fakeApi({
      fetchSnapshot: async () => { throw new Error("fleet off"); },
      isDisabled: () => true,
      errorMessage: () => "fleet console is not enabled"
    });
    const { result } = renderHook(() => useFleetSnapshot(60_000, { api }));
    await waitFor(() => expect(result.current.pollStatus).toBe("disabled"));
    expect(result.current.disabledMessage).toBe("fleet console is not enabled");
    expect(result.current.pollError).toBe("");
  });

  it("passes an AbortSignal on every poll", async () => {
    // The bug this conversion was asked to fix: polls outliving the component.
    const fetchSnapshot = vi.fn().mockResolvedValue({
      peers: [], states: { hosts: [] }, cgroups: { hosts: [] },
      decisions: { hosts: [] }, alerts: { hosts: [] }, devices: { hosts: [] }
    });
    // Hoisted, NOT built inline in the render callback. `api` is a dependency of
    // the poll effect, so a fresh object each render re-triggers the poll and
    // aborts the previous one — which looks like the abort-on-unmount assertion
    // failing. Production passes the module-level default, which is stable; a
    // caller that constructs one inline needs useMemo.
    const api = fakeApi({ fetchSnapshot });
    const { unmount } = renderHook(() => useFleetSnapshot(60_000, { api }));
    await waitFor(() => expect(fetchSnapshot).toHaveBeenCalled());
    expect(fetchSnapshot.mock.calls[0][0]?.signal).toBeInstanceOf(AbortSignal);
    expect(fetchSnapshot.mock.calls[0][0].signal.aborted).toBe(false);
    unmount();
    expect(fetchSnapshot.mock.calls[0][0].signal.aborted).toBe(true);
  });
});

/**
 * A CLOSED SURFACE MUST NOT POLL, and "mounted" no longer means "on screen".
 *
 * The fleet view is a ModalShell body now, and ModalShell keeps a body mounted
 * once the operator has opened it — deliberately, so a scrolled list and a
 * half-typed audit reason survive a close. That trade is only affordable
 * because THIS read path stops: six requests across every configured peer every
 * five seconds, running behind a dialog the operator shut, for the rest of the
 * shift.
 *
 * `active: false` is asserted on the FIRST read as well as on the interval,
 * because a hook that skipped only the timer would still fan out once per
 * mount — which is the whole cost on a console that is opened and closed.
 */
describe("the poll follows the surface, not the mount", () => {
  it("issues nothing at all while the surface is closed", async () => {
    const fetchSnapshot = vi.fn().mockResolvedValue({
      peers: [], states: { hosts: [] }, cgroups: { hosts: [] },
      decisions: { hosts: [] }, alerts: { hosts: [] }, devices: { hosts: [] }
    });
    const api = fakeApi({ fetchSnapshot });
    const { result } = renderHook(() => useFleetSnapshot(60_000, { api, active: false }));

    // Give the effect a turn: a poll that fires late still fires.
    await act(async () => { await Promise.resolve(); });
    expect(
      fetchSnapshot,
      "a closed fleet surface fanned out across every peer"
    ).not.toHaveBeenCalled();
    // And it says so rather than claiming a healthy connection it never made.
    expect(result.current.pollStatus).toBe("idle");
  });

  it("starts polling when the surface opens and stops when it closes", async () => {
    const fetchSnapshot = vi.fn().mockResolvedValue({
      peers: [], states: { hosts: [] }, cgroups: { hosts: [] },
      decisions: { hosts: [] }, alerts: { hosts: [] }, devices: { hosts: [] }
    });
    const api = fakeApi({ fetchSnapshot });
    const { rerender } = renderHook(
      ({ active }: { active: boolean }) => useFleetSnapshot(60_000, { api, active }),
      { initialProps: { active: false } }
    );

    rerender({ active: true });
    await waitFor(() => expect(fetchSnapshot).toHaveBeenCalledTimes(1));
    // The in-flight request is abandoned on close, not merely un-timered.
    const signal = fetchSnapshot.mock.calls[0][0].signal as AbortSignal;
    expect(signal.aborted).toBe(false);

    rerender({ active: false });
    expect(signal.aborted, "closing the surface left its fan-out in flight").toBe(true);
    await act(async () => { await Promise.resolve(); });
    expect(
      fetchSnapshot,
      "the fleet kept polling after the operator closed the surface"
    ).toHaveBeenCalledTimes(1);
  });
});

/**
 * THE ABORT HAS TO REACH THE WIRE, AND THE FAKE API CANNOT PROVE THAT.
 *
 * Every test above hands the hook a fake whose `fetchSnapshot` records the
 * options it was given, so "the signal was passed" was true of the seam and of
 * nothing further. It was not true of the real client: `createFleetApi` called
 * `readFleetSnapshot()` with no arguments and readFleetSnapshot passed no
 * signal to any of its six getJSON calls, so closing the surface aborted a
 * controller nothing was listening to and the fan-out ran to completion across
 * every configured peer. This test uses the DEFAULT api — no injection — and
 * looks at what `fetch` was actually handed.
 */
describe("the abort reaches fetch, not just the seam", () => {
  it("hands the poll's signal to every request the browser makes", async () => {
    const calls: Array<{ path: string; signal: AbortSignal | undefined }> = [];
    // The peer list answers, so the other five fan-out requests are issued;
    // those never resolve, which is what leaves an abort something to cancel.
    vi.stubGlobal("fetch", (path: string, init: RequestInit) => {
      calls.push({ path, signal: init?.signal ?? undefined });
      if (path === "/api/fleet/hosts") {
        return Promise.resolve(
          new Response(JSON.stringify({ hosts: [{ name: "alpha-edge", url: "http://alpha" }] }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          })
        );
      }
      return new Promise<Response>(() => {});
    });

    // No `api` option: the module-level client, the one production uses.
    const { unmount } = renderHook(() => useFleetSnapshot(60_000));
    // All six: the peer list, then state, cgroups, decisions, alerts, devices.
    await waitFor(() => expect(calls.length).toBe(6));

    expect(calls[0].path).toBe("/api/fleet/hosts");
    for (const call of calls) {
      expect(
        call.signal,
        `${call.path} went out with no signal, so nothing could cancel it`
      ).toBeInstanceOf(AbortSignal);
      expect(call.signal?.aborted).toBe(false);
    }

    unmount();
    for (const call of calls) {
      expect(
        call.signal?.aborted,
        `the surface closed and ${call.path} was still running`
      ).toBe(true);
    }
  });
});

/**
 * CLOSING THE SURFACE MUST NOT LEAVE ITS OWN FAILURE BEHIND.
 *
 * The cleanup aborts the in-flight poll, which rejects it — and an AbortError
 * is not a disabled fleet, so it used to fall through to `degraded` and a poll
 * error, set on a body ModalShell keeps mounted. Re-opening the surface then
 * painted the red banner and a degraded dot for the failure that closing it had
 * caused, until the next poll resolved. Only observable now that the abort
 * actually reaches something; before that the request was never cancelled and
 * never rejected.
 */
describe("an abort is not a fault", () => {
  it("leaves no degraded status or error banner behind when the surface closes", async () => {
    const started: AbortSignal[] = [];
    const api = fakeApi({
      fetchSnapshot: (options) =>
        new Promise((_resolve, reject) => {
          const signal = options?.signal;
          if (!signal) throw new Error("the hook polled with no signal");
          started.push(signal);
          // What the browser does to a cancelled request.
          signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
        })
    });

    const { result, rerender } = renderHook(
      ({ active }: { active: boolean }) => useFleetSnapshot(60_000, { api, active }),
      { initialProps: { active: true } }
    );
    await waitFor(() => expect(started).toHaveLength(1));
    expect(result.current.pollStatus).toBe("loading");

    await act(async () => {
      rerender({ active: false });
      await Promise.resolve();
    });

    expect(
      result.current.pollStatus,
      "closing the surface reported the fleet as degraded"
    ).not.toBe("degraded");
    expect(
      result.current.pollError,
      "re-opening the surface would paint the error that closing it caused"
    ).toBe("");
  });
});

/**
 * A SLOW FAN-OUT MUST STILL LAND.
 *
 * The engine gives its peer fan-out a 6s HTTP timeout
 * (engine/internal/api/fleet.go) and this hook polls every 5s, so one hung peer
 * makes /api/fleet/state answer LATER than the next tick fires. That is not an
 * edge case; it is what a degraded estate looks like, and it is the state an
 * operator most needs the fleet view for.
 *
 * refresh() used to abort the previous poll on every call. While the signal
 * went nowhere that was a harmless tie-breaker — a slow fan-out merely landed
 * late. Once the signal reached fetch it became starvation: every tick killed
 * the request in flight, the next inherited the same hung peer, and the surface
 * sat at "connecting" with an empty host table indefinitely. Silently, too,
 * because an abort is deliberately not reported as a fault — so the console
 * showed no error, no degraded dot, and no rows.
 *
 * The timer now yields to a poll already in flight. An operator's own re-read
 * still supersedes, because a Refresh press and the read after a containment
 * write must produce fresh rows and neither repeats on a timer.
 */
describe("a poll slower than the interval", () => {
  it("lands, instead of being cancelled by the next tick for ever", async () => {
    let started = 0;
    const api = fakeApi({
      fetchSnapshot: (options?: { signal?: AbortSignal }) => {
        started += 1;
        return new Promise((resolve, reject) => {
          // Slower than the poll interval below — the hung-peer case.
          const timer = setTimeout(
            () =>
              resolve({
                peers: [{ name: "slow-peer", url: "http://slow" }] as never,
                states: { hosts: [] } as never,
                cgroups: { hosts: [] } as never,
                decisions: { hosts: [] } as never,
                alerts: { hosts: [] } as never,
                devices: { hosts: [] } as never
              }),
            120
          );
          options?.signal?.addEventListener("abort", () => {
            clearTimeout(timer);
            reject(new DOMException("aborted", "AbortError"));
          });
        });
      }
    });

    const { result } = renderHook(() => useFleetSnapshot(30, { api }));

    await waitFor(
      () => {
        expect(
          result.current.pollStatus,
          `the fleet never connected after ${started} polls — every tick cancelled the one in flight`
        ).toBe("connected");
      },
      { timeout: 2000 }
    );
    expect(result.current.snapshot.peers.map((peer) => peer.name)).toContain("slow-peer");
    // And the ticks that fired while it was in flight did not each start their
    // own fan-out: yielding, not stacking.
    expect(started, "a tick started a second fan-out while one was still out").toBeLessThan(4);
  });
});
