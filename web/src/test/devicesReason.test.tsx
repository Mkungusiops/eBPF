import { act, renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { useDeviceActions } from "../features/devices/useDeviceActions";
import type { DevicesApi } from "../features/devices/api";
import type { ConfirmOptions } from "../features/devices/ConfirmModal";
import type { DeviceJailRequest, DeviceThawRequest } from "../features/devices/types";

/**
 * The audit reason on a device write is the operator's sentence or it is
 * nothing at all.
 *
 * A jail with an empty reason never reaches the wire; a release with an empty
 * reason goes out with the field omitted. What is then recorded depends on
 * which server the console is pointed at, and it cannot tell:
 *
 *   - The single-tenant engine (engine/internal/api/devchoke.go) refuses ANY
 *     device-jail with an empty reason, and substitutes its own
 *     "operator thaw (no reason stated)" marker on a release — the only thing
 *     in that row telling a later reader nobody actually justified it.
 *   - The multi-tenant control plane (engine/internal/controlplane/choke.go)
 *     demands a reason only for quarantine and sever, and on a device release
 *     decodes the field and discards it: the Thaw command on the wire has no
 *     reason at all, so the row carries none.
 *
 * A console literal filled in for an empty box is wrong against both. It
 * overwrites the marker on the one and manufactures a justification on the
 * other, and a row reading as though an operator typed a reason is worse than
 * one plainly missing. Omission is the only honest answer the console can give
 * without knowing which server is on the far end.
 *
 * These tests watch the wire, not the UI copy, because the wire is what the
 * audit row is written from.
 */
const MAC = "aa:bb:cc:dd:ee:ff";

interface Wire {
  jail: DeviceJailRequest[];
  thaw: DeviceThawRequest[];
  mode: Array<{ enforcing: boolean; reason: string }>;
  confirms: ConfirmOptions[];
}

function harness(options: {
  reason: string;
  /** What the operator types into the confirm modal, or null for a cancel. */
  confirmReason?: string | null;
}) {
  const wire: Wire = { jail: [], thaw: [], mode: [], confirms: [] };
  const toasts: string[] = [];
  const api: DevicesApi = {
    fetchState: async () => ({ enforcing: false, kill_switched: false }) as never,
    fetchDevices: async () => [],
    fetchFlows: async () => ({ flows: [] }) as never,
    jailDevices: async (body) => {
      wire.jail.push(body);
      return { results: [{ mac: MAC, ok: true }] } as never;
    },
    thawDevices: async (body) => {
      wire.thaw.push(body);
      return { results: [{ mac: MAC, ok: true }] } as never;
    },
    setMode: async (enforcing, reason) => {
      wire.mode.push({ enforcing, reason });
      return { mode: enforcing ? "enforcing" : "detect-only" } as never;
    },
    setKillSwitch: async () => ({ engaged: true }) as never
  };
  const hook = renderHook(() =>
    useDeviceActions({
      api,
      state: { enforcing: false, kill_switched: false, dry_run: false } as never,
      selected: new Set([MAC]),
      action: "quarantine",
      reason: options.reason,
      revertAfter: "",
      pushToast: (message) => toasts.push(message),
      setDisabledMessage: () => {},
      requestConfirm: async (confirmOptions) => {
        wire.confirms.push(confirmOptions);
        // Stand in for the modal's own gate: a required reason that was left
        // empty never resolves a result, exactly as ConfirmModal refuses to
        // confirm until one is typed.
        const typed = options.confirmReason ?? null;
        if (typed === null) return null;
        if (confirmOptions.requireReason && typed.trim() === "") return null;
        return { reason: typed.trim() };
      },
      refresh: () => {},
      clearSelection: () => {},
      canRespond: null
    })
  );
  return { actions: hook.result.current, wire, toasts };
}

describe("an empty reason box never becomes a fabricated reason", () => {
  it("omits the field entirely on a bulk thaw", async () => {
    const { actions, wire } = harness({ reason: "   " });
    await act(async () => {
      await actions.thawSelected();
    });
    expect(wire.thaw).toHaveLength(1);
    // Not "", not "operator thaw" — absent, so each server records its own
    // honest answer for an unjustified release (a no-reason-stated marker on
    // the single-tenant engine, no reason at all on the control plane) rather
    // than an invented sentence.
    expect(Object.hasOwn(wire.thaw[0], "reason")).toBe(false);
  });

  it("omits the field entirely on a per-device release", async () => {
    const { actions, wire } = harness({ reason: "" });
    let outcome: { ok: boolean; detail: string } | null = null;
    await act(async () => {
      outcome = await actions.applyToDevice(MAC, "pristine", "");
    });
    expect(outcome!.ok).toBe(true);
    expect(wire.thaw).toHaveLength(1);
    expect(Object.hasOwn(wire.thaw[0], "reason")).toBe(false);
  });

  it("offers the mode confirm no prefilled reason to ship on an Enter press", async () => {
    // The modal pre-selects any defaultReason and Enter confirms, so a default
    // here is a justification the operator never wrote.
    const { actions, wire } = harness({ reason: "", confirmReason: "planned maintenance" });
    await act(async () => {
      await actions.toggleMode();
    });
    expect(wire.confirms).toHaveLength(1);
    expect(wire.confirms[0].requireReason).toBe(true);
    expect(wire.confirms[0].defaultReason).toBeUndefined();
  });
});

describe("a required-reason action cannot be fired without one", () => {
  it("refuses a bulk choke and sends nothing", async () => {
    const { actions, wire, toasts } = harness({ reason: "   " });
    await act(async () => {
      await actions.jailSelected();
    });
    expect(wire.jail).toEqual([]);
    expect(toasts).toEqual(["reason is required for the audit log"]);
  });

  it("refuses every per-device jail rung, throttle included", async () => {
    const { actions, wire } = harness({ reason: "" });
    const outcomes: Array<{ ok: boolean; detail: string }> = [];
    await act(async () => {
      for (const rung of ["throttled", "tarpit", "quarantined", "severed"] as const) {
        outcomes.push(await actions.applyToDevice(MAC, rung, "  "));
      }
    });
    expect(wire.jail).toEqual([]);
    for (const outcome of outcomes) {
      expect(outcome.ok).toBe(false);
      expect(outcome.detail).toMatch(/reason is required/i);
    }
  });

  it("sends no mode change when the confirm resolves without a reason", async () => {
    const { actions, wire } = harness({ reason: "", confirmReason: "" });
    await act(async () => {
      await actions.toggleMode();
    });
    expect(wire.mode).toEqual([]);
  });
});

describe("a supplied reason reaches the wire verbatim", () => {
  it("carries the operator's sentence on a bulk choke, trimmed of nothing but its edges", async () => {
    const { actions, wire } = harness({ reason: "  contained per IR-4412: beaconing to 5.188.x  " });
    await act(async () => {
      await actions.jailSelected();
    });
    expect(wire.jail[0].reason).toBe("contained per IR-4412: beaconing to 5.188.x");
    expect(wire.jail[0].action).toBe("quarantine");
    // One operator sentence applied to the whole selection is fine; an
    // invented one is not.
    expect(wire.jail[0].macs).toEqual([MAC]);
  });

  it("carries it on a bulk thaw", async () => {
    const { actions, wire } = harness({ reason: "cleared by IR-4412 after reimage" });
    await act(async () => {
      await actions.thawSelected();
    });
    expect(wire.thaw[0].reason).toBe("cleared by IR-4412 after reimage");
  });

  it("carries it on a per-device jail and a per-device release", async () => {
    const { actions, wire } = harness({ reason: "" });
    await act(async () => {
      await actions.applyToDevice(MAC, "severed", "sever: confirmed C2");
      await actions.applyToDevice(MAC, "pristine", "false positive, host is clean");
    });
    expect(wire.jail[0].reason).toBe("sever: confirmed C2");
    expect(wire.thaw[0].reason).toBe("false positive, host is clean");
  });

  it("carries the reason the mode confirm collected", async () => {
    const { actions, wire } = harness({ reason: "", confirmReason: " arming for the maintenance window " });
    await act(async () => {
      await actions.toggleMode();
    });
    expect(wire.mode).toEqual([{ enforcing: true, reason: "arming for the maintenance window" }]);
  });
});
