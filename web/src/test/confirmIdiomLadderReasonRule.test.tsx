import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { DEFAULT_REASON_RULE, EnforcementLadder } from "../features/common/EnforcementLadder";
import { DEVICE_TERMINAL, LADDER, PROCESS_TERMINAL, REASON_REQUIRED } from "../features/common/enforcement";
import { DevicesTable } from "../features/devices/DevicesTable";
import { DEVICE_REASON_RULE, deviceRungNeedsReason } from "../features/devices/utils";

/**
 * THE SURFACE THAT ENFORCES THE RULE IS THE SURFACE THAT STATES IT.
 *
 * The shared ladder used to hard-code the process plane's policy — reason
 * required to quarantine or sever — while the device plane refuses EVERY jail
 * rung without one. The device console therefore printed "required to
 * quarantine or sever" above a throttle button it would then refuse for want
 * of a reason, and the only correction available was a paragraph of prose
 * beside it. The rule is now a prop: one object carrying the rungs, the
 * placeholder and the tooltip, so the gate and the copy cannot say different
 * things.
 */

const target = { id: "exec-1", label: "/usr/bin/nc", pid: 4242, host: "web-01" };
const MAC = "02:00:00:00:00:01";

function ladder(overrides: Partial<React.ComponentProps<typeof EnforcementLadder>> = {}) {
  render(
    <EnforcementLadder
      target={target}
      state="pristine"
      policy={PROCESS_TERMINAL}
      apply={vi.fn(async () => ({ ok: true, detail: "accepted" }))}
      readState={vi.fn(async () => "throttled")}
      confirmIntervalMs={1}
      {...overrides}
    />
  );
}

const btn = (name: string) => screen.getByRole("button", { name }) as HTMLButtonElement;
const reasonBox = () => screen.getByLabelText(/reason for this enforcement action/i);

describe("the ladder takes its reason rule from the surface", () => {
  it("defaults to the process plane's rule when no surface states one", () => {
    ladder();
    expect((reasonBox() as HTMLInputElement).placeholder).toBe(DEFAULT_REASON_RULE.placeholder);
    // Throttle and tarpit are free on this plane; both servers accept them
    // reason-less for a process.
    expect(btn("Throttle").disabled).toBe(false);
    expect(btn("Tarpit").disabled).toBe(false);
    expect(btn("Quarantine").disabled).toBe(true);
    expect(btn("Quarantine").title).toMatch(/A reason is required/);
  });

  it("closes the lower rungs too when the surface's rule is stricter", () => {
    ladder({ reasonRule: DEVICE_REASON_RULE, policy: DEVICE_TERMINAL });

    expect(btn("Throttle").disabled, "the device plane refuses a reasonless throttle").toBe(true);
    expect(btn("Throttle").title).toMatch(/A reason is required to throttle/);
    expect(btn("Tarpit").disabled).toBe(true);
    expect(btn("Quarantine").disabled).toBe(true);

    fireEvent.change(reasonBox(), { target: { value: "camera beaconing, INC-4471" } });
    expect(btn("Throttle").disabled).toBe(false);
    expect(btn("Tarpit").disabled).toBe(false);
    expect(btn("Quarantine").disabled).toBe(false);
  });

  it("states the stricter rule where the operator reads it, not only in a tooltip", () => {
    ladder({ reasonRule: DEVICE_REASON_RULE, policy: DEVICE_TERMINAL });
    const placeholder = (reasonBox() as HTMLInputElement).placeholder;
    // The two rungs the process plane's copy leaves out are exactly the two the
    // operator was previously told were free.
    for (const rung of LADDER.filter((r) => deviceRungNeedsReason(r) && !REASON_REQUIRED.has(r))) {
      expect(placeholder.toLowerCase(), `the box does not mention ${rung}`).toContain(rung.replace(/d$/, ""));
    }
    expect(placeholder).not.toBe(DEFAULT_REASON_RULE.placeholder);
  });

  it("leaves a release open — both servers accept one reason-less", () => {
    ladder({ reasonRule: DEVICE_REASON_RULE, policy: DEVICE_TERMINAL, state: "quarantined" });
    expect(btn("Pristine").disabled).toBe(false);
  });

  it("derives the device rungs from the predicate that refuses the write", () => {
    // Not a restatement: if deviceRungNeedsReason changes, the copy and the
    // gate move with it. A hand-written set here is how they drifted before.
    expect([...DEVICE_REASON_RULE.rungs].sort()).toEqual(LADDER.filter(deviceRungNeedsReason).slice().sort());
  });
});

describe("the device table hands the ladder that rule", () => {
  it("gates throttle and prints the device wording on an opened row", () => {
    render(
      <DevicesTable
        devices={[{ mac: MAC, state: "pristine", hostname: "cam-01" }]}
        deviceCount={1}
        selected={new Set()}
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

    expect((reasonBox() as HTMLInputElement).placeholder).toBe(DEVICE_REASON_RULE.placeholder);
    expect(btn("Throttle").disabled, "the device ladder still ran the process plane's rule").toBe(true);
  });
});
