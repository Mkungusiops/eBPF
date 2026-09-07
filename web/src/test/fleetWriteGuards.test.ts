/**
 * The guards standing in front of a fleet write: may this account write at all,
 * and does the widest-blast-radius toggle on the platform record why it was
 * thrown.
 *
 * Both were missing. `writesDisabled` was computed from three facts about the
 * ESTATE (poll status, a write in flight, host count) and none about the
 * operator, so an account the control plane reports `can_respond: false` for was
 * offered a fully armed rail — including the estate-wide kill-switch — and found
 * out mid-incident by pressing it and watching the server refuse. And the
 * kill-switch confirm collected no audit reason at all, though the engine's
 * `handleChokeKillSwitch` decodes and audits one, so the audit row for
 * bypassing enforcement across the whole estate recorded who and when but never
 * why.
 *
 * These run against the hook rather than the page because the claims are about
 * the request the hook builds and the state it exposes; the browser suite pins
 * that the button an operator can actually reach is bound to it.
 */
import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

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

/** Both peers took the write — the shape the single-tenant engine returns. */
const APPLIED_EVERYWHERE = {
  hosts: [
    { name: "alpha-edge", ok: true, status: 200 },
    { name: "bravo-edge", ok: true, status: 200 }
  ]
};

type Toast = [ToastMessage["kind"], string, string?];

function setup(canRespond: boolean | null, identityResolved = true) {
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
    write.mockResolvedValue(APPLIED_EVERYWHERE);
  }
});

describe("the fleet kill-switch audit reason", () => {
  it("collects a required reason and sends it with the engage", async () => {
    const { view, confirms } = setup(null);

    act(() => view.result.current.requestKillSwitchOn());

    const confirm = confirms.at(-1)!;
    expect(confirm.reasonLabel, "the confirm renders no reason field at all without a label").toBe(
      "Audit reason"
    );
    expect(
      confirm.reasonRequired,
      "thaw — a recovery action — requires a reason; bypassing enforcement estate-wide must too"
    ).toBe(true);

    await act(async () => {
      await confirm.onConfirm("ransomware canary tripped; enforcement is killing the recovery job");
    });

    expect(writeKillSwitch).toHaveBeenCalledWith(
      true,
      null,
      "ransomware canary tripped; enforcement is killing the recovery job"
    );
  });

  it("still records where an unedited engage came from", async () => {
    const { view, confirms } = setup(null);
    act(() => view.result.current.requestKillSwitchOn());
    const confirm = confirms.at(-1)!;

    // The prefilled default is provenance, not a justification — but an empty
    // string in the engine's audit row would be neither.
    expect(confirm.defaultReason?.trim()).not.toBe("");
    await act(async () => {
      await confirm.onConfirm(confirm.defaultReason ?? "");
    });

    const [, , reason] = writeKillSwitch.mock.calls[0];
    expect(reason.trim()).not.toBe("");
  });

  it("carries a reason on the ungated disengage too", async () => {
    const { view } = setup(null);

    await act(async () => {
      view.result.current.disengageKillSwitch();
    });

    await waitFor(() => expect(writeKillSwitch).toHaveBeenCalled());
    const [on, targets, reason] = writeKillSwitch.mock.calls[0];
    expect(on, "disengaging must send on:false, not a second engage").toBe(false);
    expect(targets).toBeNull();
    expect(reason.trim(), "the engine audits this transition too").not.toBe("");
  });
});

describe("the fleet write rail and can_respond", () => {
  it("disables every write for a read-only account, and says so as a permission", () => {
    const { view } = setup(false);

    expect(view.result.current.writesDisabled).toBe(true);
    const reason = view.result.current.writesDisabledReason;
    expect(reason, "a disabled control that says nothing reads as a broken one").not.toBe("");
    expect(reason, "the reason must be stated as a permission").toMatch(/read-only/i);
    expect(
      reason,
      "an outage or a missing feature is a different claim, and the wrong one to make here"
    ).not.toMatch(/unavailable|not enabled|failed|error|outage/i);
  });

  it("refuses a read-only account's write instead of sending it", async () => {
    const { view, toasts } = setup(false);

    await act(async () => {
      view.result.current.requestPreset("default");
      view.result.current.disengageKillSwitch();
      view.result.current.requestThaw();
      await view.result.current.applyThresholds();
    });

    expect(writePreset, "a read-only account's preset reached the server").not.toHaveBeenCalled();
    expect(writeKillSwitch).not.toHaveBeenCalled();
    expect(writeThresholds).not.toHaveBeenCalled();
    expect(
      toasts.some(([, title]) => /read-only/i.test(title)),
      "the write was dropped with no explanation, which is indistinguishable from a dead control"
    ).toBe(true);
  });

  it("leaves the rail armed when the server publishes no can_respond", async () => {
    // The single-tenant engine has no permission model. Reading its silence as
    // `false` would take the emergency controls away from every operator on it.
    const { view } = setup(null);

    expect(view.result.current.writesDisabled).toBe(false);
    expect(view.result.current.writesDisabledReason).toBe("");

    await act(async () => {
      view.result.current.requestPreset("default");
    });
    await waitFor(() => expect(writePreset).toHaveBeenCalled());
  });

  it("leaves the rail armed for an operator the server says may respond", () => {
    const { view } = setup(true);

    expect(view.result.current.writesDisabled).toBe(false);
    expect(view.result.current.writesDisabledReason).toBe("");
  });
});

describe("what the operator is told about a fleet write", () => {
  it("does not report a write that reached no hosts as applied", async () => {
    writePreset.mockResolvedValue({ hosts: [] });
    const { view, toasts } = setup(null);

    await act(async () => {
      view.result.current.requestPreset("default");
    });
    await waitFor(() => expect(toasts.length).toBeGreaterThan(0));

    const [kind, title, body] = toasts.at(-1)!;
    expect(kind, "a fan-out that touched no host was toned as routine confirmation").toBe("err");
    expect(title).toMatch(/no hosts/i);
    expect(body).not.toMatch(/^0\/0 hosts succeeded/);
  });

  it("reports the coverage a control-plane envelope stated", async () => {
    // No `hosts` key: the shape that used to render "0/0 hosts succeeded".
    writePreset.mockResolvedValue({ ok: true, preset: "default", applied: 2, total: 2, detail: "" });
    const { view, toasts } = setup(null);

    await act(async () => {
      view.result.current.requestPreset("default");
    });
    await waitFor(() => expect(toasts.length).toBeGreaterThan(0));

    const [kind, title, body] = toasts.at(-1)!;
    expect(kind).toBe("ok");
    expect(title).toMatch(/applied/i);
    expect(body).toContain("2/2");
    expect(body, "the control plane said this reached every agent").not.toContain("0/0");
  });
});
