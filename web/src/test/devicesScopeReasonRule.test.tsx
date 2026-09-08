import { act, render, renderHook, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { DevicesApi } from "../features/devices/api";
import { DevicesTable } from "../features/devices/DevicesTable";
import { useDeviceActions } from "../features/devices/useDeviceActions";
import { DEVICE_REASON_NOTE, deviceRungNeedsReason } from "../features/devices/utils";
import { LADDER, REASON_REQUIRED, type Rung } from "../features/common/enforcement";
import type { DeviceJailRequest } from "../features/devices/types";

/**
 * THE REASON RULE THE DEVICE CONSOLE STATES IS THE ONE IT ENFORCES.
 *
 * The console refuses every device jail rung without an audit reason, throttle
 * and tarpit included. That is stricter than the control plane
 * (engine/internal/controlplane/choke.go, requireReasonForDestructive, which
 * insists only for quarantine and sever) and exactly matches the single-tenant
 * engine (engine/internal/api/devchoke.go, handleChokeDeviceJail, which 400s
 * any device-jail with an empty reason). It is kept as a deliberate policy —
 * the console cannot tell which of the two servers it is pointed at, and
 * relaxing to the looser one would send the stricter server a write it always
 * refuses, then hand the operator its bare 400 about a field the console had
 * just called optional.
 *
 * What made that a defect rather than a policy was the copy. The shared
 * EnforcementLadder's reason box says "required to quarantine or sever" — the
 * PROCESS plane's rule, and the only one it can render, since it takes no prop
 * for another — so the device surface told the operator that throttle needed no
 * reason and then refused their throttle for want of one. The rule now lives in
 * ONE place (deviceRungNeedsReason) and is printed beside the ladder from the
 * same module, which is what these tests hold together: copy on one side, the
 * gate that actually stops the write on the other.
 */

const MAC = "02:00:00:00:00:01";

function actions(wire: DeviceJailRequest[]) {
  const api: DevicesApi = {
    fetchState: async () => ({}) as never,
    fetchDevices: async () => [],
    fetchFlows: async () => ({ flows: [] }) as never,
    jailDevices: async (body) => {
      wire.push(body);
      return { results: [{ mac: MAC, ok: true }] } as never;
    },
    thawDevices: async () => ({ results: [{ mac: MAC, ok: true }] }) as never,
    setMode: async () => ({ mode: "enforcing" }) as never,
    setKillSwitch: async () => ({ engaged: true }) as never
  };
  return renderHook(() =>
    useDeviceActions({
      api,
      state: { enforcing: true, kill_switched: false, dry_run: false } as never,
      selected: new Set([MAC]),
      action: "quarantine",
      reason: "",
      revertAfter: "",
      pushToast: () => {},
      setDisabledMessage: () => {},
      requestConfirm: async () => null,
      refresh: () => {},
      clearSelection: () => {},
      canRespond: null
    })
  ).result.current;
}

function renderTable() {
  return render(
    <DevicesTable
      devices={[{ mac: MAC, state: "pristine", hostname: "cam-01" }]}
      deviceCount={1}
      selected={new Set()}
      // Expanded, because the ladder and its rule only exist on an opened row.
      expanded={new Set([MAC])}
      flows={{}}
      allSelected={false}
      disabled={false}
      loading={false}
      query=""
      searchTerm=""
      rungFilter={null}
      now={() => Date.now()}
      onSelect={() => {}}
      onSelectAll={() => {}}
      onToggleFlows={() => {}}
      onApply={async () => ({ ok: true, detail: "" })}
      onReadState={async () => undefined}
      onSettled={() => {}}
    />
  );
}

describe("the rung gate and the rung copy come from one rule", () => {
  it("refuses exactly the rungs the rule names, and no others", async () => {
    const wire: DeviceJailRequest[] = [];
    const deviceActions = actions(wire);
    const refused: Rung[] = [];

    await act(async () => {
      for (const rung of LADDER) {
        const outcome = await deviceActions.applyToDevice(MAC, rung, "   ");
        if (!outcome.ok && /reason is required/i.test(outcome.detail)) refused.push(rung);
      }
    });

    expect(refused).toEqual(LADDER.filter(deviceRungNeedsReason));
    // A release is not on the list: both servers accept it reason-less, and
    // the engine writes its own no-reason-stated marker.
    expect(deviceRungNeedsReason("pristine")).toBe(false);
    // Nothing reached the wire for a refused rung — the point of refusing here
    // rather than posting an empty reason and relaying a 400.
    expect(wire).toEqual([]);
  });

  it("names on screen every rung the shared ladder leaves out", async () => {
    // The gap between the two rules: the rungs this plane refuses that the
    // ladder's own copy does not mark required. If the note stops naming one
    // of them, the operator is being told something the code contradicts.
    const unstated = LADDER.filter((rung) => deviceRungNeedsReason(rung) && !REASON_REQUIRED.has(rung));
    expect(unstated, "the two rules no longer differ — this test is the wrong shape now").toEqual([
      "throttled",
      "tarpit"
    ]);

    renderTable();
    const note = await screen.findByText(DEVICE_REASON_NOTE);

    for (const rung of unstated) {
      // "throttled" is the rung; "throttle" is the verb the operator presses.
      expect(note.textContent?.toLowerCase()).toContain(rung.replace(/d$/, ""));
    }
  });

  it("prints the rule beside the ladder it corrects, not only in a tooltip", () => {
    renderTable();

    const note = screen.getByText(DEVICE_REASON_NOTE);
    const ladder = document.querySelector('[data-panel="enforcement-ladder"]');
    expect(ladder, "no ladder on the opened row — the note would be correcting nothing").toBeTruthy();
    // The ladder's reason box states the DEVICE plane's rule, because the rule
    // is a prop now (EnforcementLadder's ReasonRule) rather than a constant the
    // ladder owns. Until 2026-09-07 the box said "required to quarantine or
    // sever" on a surface that refuses every rung without a reason, and this
    // note existed to correct it. One definition feeds the gate and the copy, so
    // there is nothing left to contradict — the note now adds what a placeholder
    // has no room for rather than apologising for it.
    expect(
      screen.getByPlaceholderText("Reason (required for every choke — throttle and tarpit included)"),
      "the ladder is not stating the device plane's own rule"
    ).toBeTruthy();
    expect(note.compareDocumentPosition(ladder!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });
});
