/**
 * Two ways the fleet console can state something the server did not.
 *
 * 1. COVERAGE. The control plane may answer a fan-out with a target `total` and
 *    no `applied` — it knows how many agents it addressed before it knows how
 *    many acked. `applied ?? 0` rendered that as "0/3 succeeded", a specific
 *    claim of total failure nobody made, sitting one line away from the 0/0-as-
 *    success defect the same function was written to kill. Unknown reads as
 *    unknown.
 *
 * 2. PERMISSION. `canRespond === null` is two different facts — "the single-
 *    tenant engine publishes no can_respond" and "whoami has not come back
 *    yet" — and the rail treated both as permitted. /api/whoami routinely
 *    loses the race with the fleet snapshot, so a read-only principal was
 *    handed a live estate-wide kill-switch for the length of that request.
 */
import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { readFanout, summarizeFanout } from "../features/fleet/fleetLogic";
import { useFleetControls } from "../features/fleet/useFleetControls";
import type { ConfirmState, FleetPeer, ToastMessage } from "../features/fleet/types";

const { writeKillSwitch, writePreset, writeThaw, writeThresholds } = vi.hoisted(() => ({
  writeKillSwitch: vi.fn(),
  writePreset: vi.fn(),
  writeThaw: vi.fn(),
  writeThresholds: vi.fn()
}));

vi.mock("../features/fleet/api", () => ({
  writeKillSwitch,
  writePreset,
  writeThaw,
  writeThresholds
}));

const PEERS: FleetPeer[] = [
  { name: "alpha-edge", url: "http://alpha" },
  { name: "bravo-edge", url: "http://bravo" }
];

type Toast = [ToastMessage["kind"], string, string?];

function setup(canRespond: boolean | null, identityResolved: boolean) {
  const toasts: Toast[] = [];
  const confirms: ConfirmState[] = [];
  const view = renderHook(() =>
    useFleetControls({
      peers: PEERS,
      totalHosts: PEERS.length,
      majorityThresholds: null,
      pollStatus: "connected",
      canRespond,
      identityResolved,
      pushToast: (kind, title, body) => toasts.push([kind, title, body]),
      refresh: async () => undefined,
      setConfirmState: (state) => {
        if (state) confirms.push(state);
      }
    })
  );
  return { view, toasts, confirms };
}

beforeEach(() => {
  vi.clearAllMocks();
  for (const write of [writeKillSwitch, writePreset, writeThaw, writeThresholds]) {
    write.mockResolvedValue({ hosts: [{ name: "alpha-edge", ok: true, status: 200 }] });
  }
});

describe("a fan-out that states a total but no applied count", () => {
  it("does not fabricate a success count the server never stated", () => {
    const summary = summarizeFanout("Preset default", readFanout({ ok: true, total: 3 }));

    expect(summary.ok).toBe(false);
    expect(
      summary.body,
      "the console asserted 0/3 succeeded — a total-failure claim the server did not make"
    ).not.toContain("0/3");
    expect(summary.title).toBe("Preset default: coverage unknown");
    expect(summary.body).toMatch(/3 hosts/);
    expect(summary.body).toMatch(/did not say how many took it/i);
  });

  it("keeps the detail the server did send", () => {
    const summary = summarizeFanout(
      "Thaw",
      readFanout({ ok: true, total: 1, detail: "dispatched to 1 agent" })
    );

    expect(summary.ok).toBe(false);
    expect(summary.body).toContain("dispatched to 1 agent");
    // Singular, because "1 hosts" reads as a template that was never finished.
    expect(summary.body).toContain("targeted 1 host ");
  });

  it("still reports a stated zero-applied as the partial it is", () => {
    // applied: 0 IS a fact. Only the absent field is unknown, and conflating
    // the two in the other direction would hide a genuine total failure.
    const summary = summarizeFanout("Thresholds", readFanout({ ok: true, applied: 0, total: 3 }));

    expect(summary.ok).toBe(false);
    expect(summary.title).toBe("Thresholds: partial");
    expect(summary.body).toContain("0/3");
  });
});

describe("the write rail while whoami is in flight", () => {
  it("is not armed before the server has answered", async () => {
    const { view, toasts } = setup(null, false);

    expect(
      view.result.current.writesDisabled,
      "a read-only principal gets a live estate-wide kill-switch until whoami lands"
    ).toBe(true);
    expect(view.result.current.writesDisabledReason).toMatch(/checking your response rights/i);

    // And the guard holds at write time too, not only in the rail's styling.
    await act(async () => {
      await view.result.current.applyThresholds();
    });
    expect(writeThresholds).not.toHaveBeenCalled();
    expect(toasts.at(-1)?.[0]).toBe("warn");
  });

  it("arms once whoami answers without can_respond — the single-tenant engine", async () => {
    const { view } = setup(null, true);

    expect(view.result.current.writesDisabled).toBe(false);
    expect(view.result.current.writesDisabledReason).toBe("");

    await act(async () => {
      await view.result.current.applyThresholds();
    });
    expect(writeThresholds).toHaveBeenCalledTimes(1);
  });

  it("stays disabled when whoami answers false", async () => {
    const { view, toasts } = setup(false, true);

    expect(view.result.current.writesDisabled).toBe(true);
    expect(view.result.current.writesDisabledReason).toMatch(/read-only/i);

    await act(async () => {
      await view.result.current.applyThresholds();
    });
    expect(writeThresholds).not.toHaveBeenCalled();
    expect(toasts.at(-1)?.[1]).toBe("Read-only account");
  });
});
