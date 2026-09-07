import { act, render, renderHook, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { DevicesBulkBar } from "../features/devices/DevicesBulkBar";
import { DevicesTable } from "../features/devices/DevicesTable";
import { useDeviceActions } from "../features/devices/useDeviceActions";
import { useDeviceInventory } from "../features/devices/useDeviceInventory";
import type { DevicesApi } from "../features/devices/api";
import type { DeviceEntry } from "../features/devices/types";

/**
 * The device choke arms independently of the process choke — a device sever is
 * a TC drop rule on the data plane, a process sever is a SIGKILL, and they
 * travel as different commands to different enforcers. So the device console
 * asks whoami the permission question for itself rather than inheriting the
 * Choke Gateway's answer: if the two ever diverge, this route reports what it
 * was told instead of what it assumed.
 *
 * Same three-valued contract, pinned for the same reason: only an explicit
 * `false` withholds. `null` is the single-tenant engine, which publishes no
 * `can_respond` at all, and reading its silence as a refusal would take the
 * device kill-switch away from an operator who legitimately owns it.
 */
const DEVICE: DeviceEntry = {
  mac: "aa:bb:cc:dd:ee:ff",
  last_ip: "10.0.0.9",
  hostname: "victim-device",
  state: "pristine"
} as DeviceEntry;

function fakeApi(overrides: Partial<DevicesApi> = {}): DevicesApi {
  return {
    fetchState: async () => ({ enforcing: false, kill_switched: false }) as never,
    fetchDevices: async () => [DEVICE],
    fetchFlows: async () => ({ flows: [] }) as never,
    jailDevices: async () => ({ results: [{ mac: DEVICE.mac, ok: true }] }) as never,
    thawDevices: async () => ({ results: [{ mac: DEVICE.mac, ok: true }] }) as never,
    setMode: async () => ({ mode: "enforcing" }) as never,
    setKillSwitch: async () => ({ engaged: true }) as never,
    ...overrides
  };
}

describe("the device inventory reads whoami's can_respond", () => {
  it("carries an explicit false through", async () => {
    const { result } = renderHook(() =>
      useDeviceInventory(fakeApi({ fetchWhoami: async () => ({ canRespond: false }) }), 60_000)
    );
    await waitFor(() => expect(result.current.canRespond).toBe(false));
  });

  it("stays null — permitted — when the deployment publishes no field", async () => {
    const { result } = renderHook(() =>
      useDeviceInventory(fakeApi({ fetchWhoami: async () => ({ canRespond: null }) }), 60_000)
    );
    await waitFor(() => expect(result.current.devices).toHaveLength(1));
    expect(result.current.canRespond).toBeNull();
  });

  it("stays null when whoami itself fails", async () => {
    // An auxiliary request that did not come back is not a refusal. Treating it
    // as one would strip the emergency controls off a working console.
    const { result } = renderHook(() =>
      useDeviceInventory(
        fakeApi({
          fetchWhoami: async () => {
            throw new Error("whoami unreachable");
          }
        }),
        60_000
      )
    );
    await waitFor(() => expect(result.current.devices).toHaveLength(1));
    expect(result.current.canRespond).toBeNull();
  });
});

describe("every device write refuses for a read-only account", () => {
  function actions(canRespond: boolean | null) {
    const sent: string[] = [];
    const toasts: Array<{ message: string; tone: string }> = [];
    const api = fakeApi({
      jailDevices: async () => {
        sent.push("jail");
        return { results: [{ mac: DEVICE.mac, ok: true }] } as never;
      },
      thawDevices: async () => {
        sent.push("thaw");
        return { results: [{ mac: DEVICE.mac, ok: true }] } as never;
      },
      setMode: async () => {
        sent.push("mode");
        return { mode: "enforcing" } as never;
      },
      setKillSwitch: async () => {
        sent.push("kill-switch");
        return { engaged: true } as never;
      }
    });
    const hook = renderHook(() =>
      useDeviceActions({
        api,
        state: { enforcing: false, kill_switched: false, dry_run: false } as never,
        selected: new Set([DEVICE.mac]),
        action: "quarantine",
        reason: "containment drill",
        revertAfter: "",
        pushToast: (message, tone) => toasts.push({ message, tone }),
        setDisabledMessage: () => {},
        // A confirm that always says yes: the point of this test is that the
        // write never reaches the confirm, let alone the wire.
        requestConfirm: async () => ({ reason: "containment drill" }),
        refresh: () => {},
        clearSelection: () => {},
        canRespond
      })
    );
    return { api: hook.result.current, sent, toasts };
  }

  it("sends nothing on any device write, and says it is the account", async () => {
    const { api, sent, toasts } = actions(false);
    await act(async () => {
      await api.jailSelected();
      await api.thawSelected();
      await api.toggleMode();
      await api.toggleKillSwitch();
    });
    expect(sent).toEqual([]);
    expect(toasts).toHaveLength(4);
    for (const toast of toasts) {
      expect(toast.message).toMatch(/read-only/i);
      expect(toast.message).not.toMatch(/unavailable|not enabled|offline/i);
    }
  });

  it("refuses a per-device ladder rung with the permission reason, not a rejection", async () => {
    const { api, sent } = actions(false);
    let outcome: { ok: boolean; detail: string } | null = null;
    await act(async () => {
      outcome = await api.applyToDevice(DEVICE.mac, "quarantined", "drill");
    });
    expect(sent).toEqual([]);
    expect(outcome!.ok).toBe(false);
    expect(outcome!.detail).toMatch(/read-only/i);
  });

  it("sends the write when the server published no can_respond", async () => {
    const { api, sent, toasts } = actions(null);
    await act(async () => {
      await api.jailSelected();
    });
    expect(sent).toEqual(["jail"]);
    expect(toasts.every((toast) => !/read-only/i.test(toast.message))).toBe(true);
  });
});

describe("the device containment controls are drawn disabled, not drawn armed", () => {
  const REASON = "Your account is read-only: it can watch the device plane, but not contain or reconfigure it.";

  it("disables Choke and Thaw and states the permission reason", () => {
    render(
      <DevicesBulkBar
        selectedCount={1}
        action="quarantine"
        reason=""
        revertAfter=""
        toast={null}
        loading={false}
        refreshing={false}
        disabled
        blockedReason={REASON}
        onAction={() => {}}
        onReason={() => {}}
        onRevertAfter={() => {}}
        onRefresh={() => {}}
        onChoke={() => {}}
        onThaw={() => {}}
      />
    );
    expect((screen.getByRole("button", { name: /^choke$/i }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: /^thaw$/i }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/read-only/i)).toBeTruthy();
    // Refresh is a read and stays available: a read-only operator still has to
    // be able to watch the plane they cannot change.
    expect((screen.getByRole("button", { name: /refresh/i }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("withholds the per-device ladder while still showing where the device sits on it", () => {
    const { container } = render(
      <DevicesTable
        devices={[DEVICE]}
        deviceCount={1}
        selected={new Set()}
        expanded={new Set([DEVICE.mac])}
        flows={{}}
        allSelected={false}
        disabled
        blockedReason={REASON}
        loading={false}
        query=""
        searchTerm=""
        rungFilter={null}
        now={() => 0}
        onSelect={() => {}}
        onSelectAll={() => {}}
        onToggleFlows={() => {}}
        onApply={async () => ({ ok: true, detail: "" })}
        onReadState={async () => undefined}
        onSettled={() => {}}
      />
    );
    const fieldset = container.querySelector<HTMLFieldSetElement>(".devices-permission-fieldset");
    expect(fieldset).toBeTruthy();
    expect(fieldset!.disabled).toBe(true);
    // fieldset[disabled] is what actually withholds the shared ladder, which
    // takes no disabled prop of its own. Asserted with `:disabled` rather than
    // the `disabled` property: the property reflects a control's OWN attribute
    // and stays false inside a disabled fieldset, while `:disabled` — and the
    // click handling, and the browser's rendering — follow the real state.
    const rungs = Array.from(fieldset!.querySelectorAll("button"));
    expect(rungs.length).toBeGreaterThan(0);
    expect(rungs.every((button) => button.matches(":disabled"))).toBe(true);
    // The row itself is still readable — the rung a device is on is evidence.
    expect(container.textContent).toContain(DEVICE.mac);
  });

  it("leaves the ladder armed when no reason is given", () => {
    const { container } = render(
      <DevicesTable
        devices={[DEVICE]}
        deviceCount={1}
        selected={new Set()}
        expanded={new Set([DEVICE.mac])}
        flows={{}}
        allSelected={false}
        disabled={false}
        loading={false}
        query=""
        searchTerm=""
        rungFilter={null}
        now={() => 0}
        onSelect={() => {}}
        onSelectAll={() => {}}
        onToggleFlows={() => {}}
        onApply={async () => ({ ok: true, detail: "" })}
        onReadState={async () => undefined}
        onSettled={() => {}}
      />
    );
    const fieldset = container.querySelector<HTMLFieldSetElement>(".devices-permission-fieldset");
    expect(fieldset!.disabled).toBe(false);
    // Not "none disabled": the ladder disables its own rungs for its own
    // reasons — the current rung, a backwards move, a missing audit reason. The
    // claim here is only that PERMISSION is not one of them.
    const rungs = Array.from(fieldset!.querySelectorAll("button"));
    expect(rungs.some((button) => !button.matches(":disabled"))).toBe(true);
  });
});
