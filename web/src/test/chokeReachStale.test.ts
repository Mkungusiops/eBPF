import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useChokeData } from "../features/choke/useChokeData";
import { useChokePosture } from "../features/choke/useChokePosture";
import type { HostPingResult, LoadState } from "../features/choke/types";
import type { StreamInfo } from "../features/choke/constants";
import type { useStream } from "../lib/stream";

/**
 * "UNREACHABLE" HAS TO SURVIVE PAST THE FIRST SUCCESSFUL READ.
 *
 * The deadline pass made a hung gateway visible only on COLD START: the route
 * error banner is raised from `handleFailure`, which sets it just when no
 * snapshot has ever arrived. Once one state read had landed, a gateway that
 * then stopped answering was signalled by toasts alone — they fade — while the
 * persistent surface went on rendering the last good snapshot: the same counts,
 * the same mode, the same posture as a gateway that is perfectly healthy.
 *
 * That is the reading an operator consults before firing containment, so the
 * staleness has to be on screen next to it and stay there. The SOC route
 * already says this in the console's own vocabulary with its stale-stream
 * banner ("Stream silent for Ns. Dashboard snapshots remain available."); this
 * is the choke route's equivalent for a gateway that has gone quiet.
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

const PUSH_TOAST = () => {};
const HANG_DEADLINE_MS = 120;

const STATE_SNAPSHOT = { mode: "detect-only", tracked: 3 };

let stateHangs = false;

function jsonFor(url: string): unknown {
  if (url.includes("/api/whoami")) return { user: "analyst", can_respond: true };
  if (url.includes("/api/choke/cgroups")) return {};
  return [];
}

function stubFetch() {
  vi.stubGlobal("fetch", async (path: string) => {
    const url = String(path);
    if (url.startsWith("/api/choke/state")) {
      // No signal handling at all — the half-open connection, which answers
      // once and then simply stops coming back.
      if (stateHangs) return new Promise<Response>(() => {});
      return new Response(JSON.stringify(STATE_SNAPSHOT), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response(JSON.stringify(jsonFor(url)), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  stateHangs = false;
});

describe("a gateway that goes quiet mid-session", () => {
  it("says so on the persistent surface, not only in a toast that fades", async () => {
    stateHangs = false;
    stubFetch();
    const hook = renderHook(() =>
      useChokeData({
        pushToast: PUSH_TOAST,
        sharedStream: FAKE_STREAM,
        readTimeoutMs: HANG_DEADLINE_MS,
        whoamiTimeoutMs: HANG_DEADLINE_MS,
      }),
    );
    await waitFor(() => expect(hook.result.current.loadState.kind).toBe("ready"));
    expect(hook.result.current.chokeState).toEqual(STATE_SNAPSHOT);

    stateHangs = true;
    await act(async () => {
      await hook.result.current.refreshState();
    });

    await waitFor(() => expect(hook.result.current.loadState.kind).toBe("error"));
    const message = (hook.result.current.loadState as { message: string }).message;
    expect(message).toContain("unreachable");
    // The banner must say what the panels under it are, or an operator reads
    // the old counts as current ones.
    expect(message).toContain("last good");
    // And the last good snapshot stays on screen: blanking it would trade one
    // wrong reading for another, and lose the evidence they were looking at.
    expect(hook.result.current.chokeState).toEqual(STATE_SNAPSHOT);
  });

  it("clears the banner when the gateway starts answering again", async () => {
    stateHangs = true;
    stubFetch();
    const hook = renderHook(() =>
      useChokeData({
        pushToast: PUSH_TOAST,
        sharedStream: FAKE_STREAM,
        readTimeoutMs: HANG_DEADLINE_MS,
        whoamiTimeoutMs: HANG_DEADLINE_MS,
      }),
    );
    await waitFor(() => expect(hook.result.current.loadState.kind).toBe("error"));
    stateHangs = false;
    await act(async () => {
      await hook.result.current.refreshState();
    });
    await waitFor(() => expect(hook.result.current.loadState.kind).toBe("ready"));
  });
});

function ping(path: string, ok: boolean, rtt: number): HostPingResult {
  return { path, ok, status: ok ? 200 : 0, rtt_ms: rtt, checked_at: Date.now() };
}

function posture(hostPings: HostPingResult[], loadState: LoadState = { kind: "ready" }) {
  return renderHook(() =>
    useChokePosture({
      chokeState: null,
      circuits: [],
      approvals: [],
      whoami: null,
      hostPings,
      streamInfo: { state: "live", retries: 0, lastMessageAt: 0, totalMessages: 0, messagesByMinute: [] } as StreamInfo,
      loadState,
      now: Date.now(),
      windowMin: 60,
      currentWindowDecisions: [],
    }),
  ).result.current;
}

describe("the header host pill", () => {
  it("reads down when any probed endpoint failed, not just the first", () => {
    // The identity endpoint answering says nothing about the state and circuit
    // endpoints an operator is actually reading — and under a half-open gateway
    // it is exactly the split that left the pill green.
    expect(posture([ping("/api/whoami", true, 20), ping("/api/choke/state", false, 120)]).hostState).toBe("down");
  });

  it("reads down before the first probe lands if the route already knows the gateway is unreachable", () => {
    // The probe runs on an eight-second interval, so there is a window at first
    // paint with no reading at all. Claiming "ok" there while the route's own
    // reads have already timed out is the confident-green lie in miniature.
    expect(posture([], { kind: "error", message: "choke gateway unreachable: /api/choke/state" }).hostState).toBe("down");
  });

  it("still reads ok and slow when the host is answering", () => {
    expect(posture([ping("/api/whoami", true, 20), ping("/api/choke/state", true, 30)]).hostState).toBe("ok");
    expect(posture([ping("/api/whoami", true, 20), ping("/api/choke/state", true, 900)]).hostState).toBe("slow");
    expect(posture([]).hostState).toBe("ok");
  });
});
