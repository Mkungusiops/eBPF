import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createDevicesApi, type DevicesApi } from "../features/devices/api";
import type { ConfirmOptions } from "../features/devices/ConfirmModal";
import { useDeviceActions } from "../features/devices/useDeviceActions";
import { setSelectedTenant } from "../lib/tenantScope";

/**
 * THE DEVICE KILL-SWITCH ENGAGES WITH A REASON, OR NOT AT ALL.
 *
 * Engaging it halts EVERY device containment on the plane — including a
 * quarantine an operator deliberately applied to a compromised box — so the
 * single-tenant engine (engine/internal/api/devchoke.go,
 * handleChokeDeviceKillSwitch) refuses an engage whose reason is empty. The
 * console posted `{on}` and nothing else, so shipping that engine against it
 * turns the Engage button into a 400 naming a field no operator was shown.
 *
 * The reason is collected through the confirm modal this route already uses for
 * the mode switch, rather than a second kind of prompt — the modal is what
 * refuses to resolve until a required reason is typed, so an unanswered
 * confirmation cannot become an empty one.
 *
 * A DISENGAGE stays ungated, deliberately. Both servers accept it without a
 * reason and the engine records its own "kill-switch released (no reason
 * stated)" marker; demanding a typed justification before enforcement can be
 * restored is friction in the one moment nobody has time for it, and an
 * invented stand-in in that row would be worse than a plainly absent one.
 */

const MAC = "02:00:00:00:00:01";

interface Wire {
  kill: Array<{ on: boolean; reason: string }>;
  confirms: ConfirmOptions[];
}

function harness(options: { engaged: boolean; confirmReason?: string | null }) {
  const wire: Wire = { kill: [], confirms: [] };
  const toasts: string[] = [];
  const api: DevicesApi = {
    fetchState: async () => ({}) as never,
    fetchDevices: async () => [],
    fetchFlows: async () => ({ flows: [] }) as never,
    jailDevices: async () => ({ results: [{ mac: MAC, ok: true }] }) as never,
    thawDevices: async () => ({ results: [{ mac: MAC, ok: true }] }) as never,
    setMode: async () => ({ mode: "enforcing" }) as never,
    setKillSwitch: async (on, reason) => {
      wire.kill.push({ on, reason });
      return { engaged: on } as never;
    }
  };
  const hook = renderHook(() =>
    useDeviceActions({
      api,
      state: { enforcing: true, kill_switched: options.engaged, dry_run: false } as never,
      selected: new Set([MAC]),
      action: "quarantine",
      reason: "",
      revertAfter: "",
      pushToast: (message) => toasts.push(message),
      setDisabledMessage: () => {},
      requestConfirm: async (confirmOptions) => {
        wire.confirms.push(confirmOptions);
        // Stand in for the modal's own gate: a required reason left empty never
        // resolves a result, exactly as ConfirmModal refuses to confirm until
        // one is typed, and a cancel resolves null.
        const typed = options.confirmReason ?? null;
        if (typed === null) return null;
        if (confirmOptions.requireReason && typed.trim() === "") return null;
        return { reason: confirmOptions.requireReason ? typed.trim() : "" };
      },
      refresh: () => {},
      clearSelection: () => {},
      canRespond: null
    })
  );
  return { actions: hook.result.current, wire, toasts };
}

describe("engaging the device kill-switch collects and sends an audit reason", () => {
  it("asks for one and puts the operator's sentence on the wire", async () => {
    const { actions, wire } = harness({
      engaged: false,
      confirmReason: "  halting device plane: bridge flapping, IR-4412  "
    });

    await act(async () => {
      await actions.toggleKillSwitch();
    });

    expect(wire.confirms).toHaveLength(1);
    expect(wire.confirms[0].requireReason, "the engage confirm accepted an empty reason").toBe(true);
    // No prefill: the modal pre-selects whatever it is given and Enter
    // confirms, so a default ships as a justification nobody wrote.
    expect(wire.confirms[0].defaultReason).toBeUndefined();
    expect(wire.kill).toEqual([
      { on: true, reason: "halting device plane: bridge flapping, IR-4412" }
    ]);
  });

  it("sends nothing when the confirmation is abandoned without one", async () => {
    const { actions, wire } = harness({ engaged: false, confirmReason: "   " });

    await act(async () => {
      await actions.toggleKillSwitch();
    });

    expect(wire.kill, "an engage went out with no reason for the server to refuse").toEqual([]);
  });

  it("does not gate the disengage, and states no reason the operator never gave", async () => {
    const { actions, wire } = harness({ engaged: true, confirmReason: "" });

    await act(async () => {
      await actions.toggleKillSwitch();
    });

    expect(wire.confirms).toHaveLength(1);
    expect(wire.confirms[0].requireReason).toBe(false);
    expect(wire.kill).toEqual([{ on: false, reason: "" }]);
  });
});

describe("what the kill-switch request itself carries", () => {
  const sent: Array<{ url: string; body: Record<string, unknown> }> = [];

  beforeEach(() => {
    sent.length = 0;
    window.localStorage.clear();
    setSelectedTenant(null);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
        sent.push({
          url: String(input),
          body: typeof init.body === "string" ? JSON.parse(init.body) : {}
        });
        return new Response(JSON.stringify({ engaged: true }), {
          status: 200,
          headers: { "content-type": "application/json" }
        });
      })
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    setSelectedTenant(null);
    window.localStorage.clear();
  });

  it("posts the reason beside `on`, at the customer the console is showing", async () => {
    setSelectedTenant("globex");

    await createDevicesApi().setKillSwitch(true, "halting device plane for IR-4412");

    expect(sent).toEqual([
      {
        url: "/api/choke/device-kill-switch?tenant=globex",
        body: { on: true, reason: "halting device plane for IR-4412" }
      }
    ]);
  });

  it("omits the field entirely rather than posting an empty one", async () => {
    // Absent, not "": the engine substitutes its own no-reason-stated marker
    // for a release, and that marker is the only thing in the row telling a
    // later reader that nobody justified it. A field the operator never filled
    // in has no business on the wire.
    await createDevicesApi().setKillSwitch(false, "   ");

    expect(sent[0].body).toEqual({ on: false });
    expect(Object.hasOwn(sent[0].body, "reason")).toBe(false);
  });
});
