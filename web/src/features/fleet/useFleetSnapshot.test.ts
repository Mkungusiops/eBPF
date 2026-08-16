/**
 * The Tier 1A exit criterion for fleet: renders with a fake API and ZERO
 * network. Before the injection this hook could only be tested by stubbing
 * global fetch, which is why it had no test at all.
 */
import { renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { useFleetSnapshot } from "./useFleetSnapshot";
import type { FleetApi } from "./fleetApi";

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
    fetchWhoami: async () => ({ user: "op-adanian" }),
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
    const { result } = renderHook(() => useFleetSnapshot(60_000, fakeApi()));
    await waitFor(() => expect(result.current.pollStatus).toBe("connected"));
    expect(result.current.who).toBe("op-adanian");
  });

  it("reports 'disabled' distinctly from an error", async () => {
    // A fleet that is switched off is not a fault; conflating the two would
    // show an operator a red error for a deliberate configuration.
    const api = fakeApi({
      fetchSnapshot: async () => { throw new Error("fleet off"); },
      isDisabled: () => true,
      errorMessage: () => "fleet console is not enabled"
    });
    const { result } = renderHook(() => useFleetSnapshot(60_000, api));
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
    const { unmount } = renderHook(() => useFleetSnapshot(60_000, api));
    await waitFor(() => expect(fetchSnapshot).toHaveBeenCalled());
    expect(fetchSnapshot.mock.calls[0][0]?.signal).toBeInstanceOf(AbortSignal);
    expect(fetchSnapshot.mock.calls[0][0].signal.aborted).toBe(false);
    unmount();
    expect(fetchSnapshot.mock.calls[0][0].signal.aborted).toBe(true);
  });
});
