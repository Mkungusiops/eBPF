import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { EnforcementLadder } from "../features/common/EnforcementLadder";
import { DEVICE_TERMINAL, PROCESS_TERMINAL } from "../features/common/enforcement";

const target = { id: "exec-1", label: "/usr/bin/nc", pid: 4242, host: "web-01" };

function setup(overrides: Partial<React.ComponentProps<typeof EnforcementLadder>> = {}) {
  const apply = vi.fn(async () => ({ ok: true, detail: "accepted" }));
  const readState = vi.fn(async () => "throttled");
  render(
    <EnforcementLadder
      target={target}
      state="pristine"
      policy={PROCESS_TERMINAL}
      apply={apply}
      readState={readState}
      confirmIntervalMs={1}
      {...overrides}
    />
  );
  return { apply, readState };
}

const btn = (name: string) => screen.getByRole("button", { name }) as HTMLButtonElement;

describe("EnforcementLadder", () => {
  it("only climbs: rungs at or below the current one are disabled, with the reason given", () => {
    setup({ state: "tarpit" });
    expect(btn("Throttle").disabled).toBe(true);
    expect(btn("Throttle").title).toMatch(/only climbs/i);
    expect(btn("Tarpit").disabled).toBe(true);
    expect(btn("Tarpit").title).toMatch(/already tarpit/i);
    // Release stays open from any rung.
    expect(btn("Pristine").disabled).toBe(false);
    // Quarantine is upward, so it is gated on the reason rather than the
    // direction — the distinction the title has to make correctly.
    expect(btn("Quarantine").title).toMatch(/reason is required/i);
    fireEvent.change(screen.getByLabelText(/reason for this enforcement action/i), {
      target: { value: "lateral movement" }
    });
    expect(btn("Quarantine").disabled).toBe(false);
    // …and a reason must not unlock a downward move.
    expect(btn("Throttle").disabled).toBe(true);
  });

  it("requires a reason for quarantine and sever, but not for the lower rungs", () => {
    setup();
    expect(btn("Throttle").disabled).toBe(false);
    expect(btn("Quarantine").disabled).toBe(true);
    expect(btn("Quarantine").title).toMatch(/reason is required/i);

    fireEvent.change(screen.getByLabelText(/reason for this enforcement action/i), {
      target: { value: "confirmed beaconing" }
    });
    expect(btn("Quarantine").disabled).toBe(false);
  });

  it("takes a second press to sever, naming the pid and host first", () => {
    const { apply } = setup();
    fireEvent.change(screen.getByLabelText(/reason for this enforcement action/i), {
      target: { value: "confirmed c2" }
    });
    fireEvent.click(btn("Sever"));
    expect(apply).not.toHaveBeenCalled();
    expect(screen.getByText(/pid 4242/)).toBeTruthy();
    expect(screen.getByText(/web-01/)).toBeTruthy();

    fireEvent.click(btn("Confirm"));
    expect(apply).toHaveBeenCalledOnce();
  });

  // A severed PROCESS took a SIGKILL: thaw is accepted by the API and changes
  // nothing, which would read as a successful action that silently did nothing.
  it("disables the whole ladder once a process is severed", () => {
    setup({ state: "severed" });
    for (const label of ["Throttle", "Tarpit", "Quarantine", "Sever", "Pristine"]) {
      expect(btn(label).disabled).toBe(true);
    }
    expect(screen.getByText(/terminal state/i)).toBeTruthy();
  });

  // A severed DEVICE is a reversible drop rule — verified against the live
  // engine (sever -> severed, thaw -> pristine). Copying the process rule here
  // would disable a release that genuinely works.
  it("keeps release available on a severed device", () => {
    setup({ state: "severed", policy: DEVICE_TERMINAL, target: { id: "aa:bb", label: "printer" } });
    expect(btn("Pristine").disabled).toBe(false);
    expect(screen.queryByText(/terminal state/i)).toBeNull();
  });

  it("reports dispatched, then confirmed only once the rung actually changes", async () => {
    const apply = vi.fn(async () => ({ ok: true, detail: "accepted" }));
    // Two polls still pristine, then the agent reports the new rung.
    const readState = vi
      .fn<() => Promise<string | undefined>>()
      .mockResolvedValueOnce("pristine")
      .mockResolvedValueOnce("pristine")
      .mockResolvedValue("throttled");
    render(
      <EnforcementLadder
        target={target}
        state="pristine"
        policy={PROCESS_TERMINAL}
        apply={apply}
        readState={readState}
        confirmIntervalMs={1}
      />
    );
    await act(async () => {
      fireEvent.click(btn("Throttle"));
    });
    await waitFor(() => expect(screen.getByText(/throttle confirmed — now throttled/i)).toBeTruthy());
    expect(readState).toHaveBeenCalledTimes(3);
  });

  it("does not claim success when the agent never reports the new rung", async () => {
    const apply = vi.fn(async () => ({ ok: true, detail: "accepted" }));
    const readState = vi.fn(async () => "pristine");
    render(
      <EnforcementLadder
        target={target}
        state="pristine"
        policy={PROCESS_TERMINAL}
        apply={apply}
        readState={readState}
        confirmAttempts={2}
        confirmIntervalMs={1}
      />
    );
    await act(async () => {
      fireEvent.click(btn("Throttle"));
    });
    await waitFor(() => expect(screen.getByText(/has not reported the new state/i)).toBeTruthy());
  });

  // The control plane drops a released process from its tracked set rather than
  // reporting it as pristine, so waiting for "pristine" would fail a release
  // that actually worked.
  it("treats a vanished circuit as a confirmed release", async () => {
    const apply = vi.fn(async () => ({ ok: true, detail: "accepted" }));
    const readState = vi.fn(async () => undefined);
    render(
      <EnforcementLadder
        target={target}
        state="quarantined"
        policy={PROCESS_TERMINAL}
        apply={apply}
        readState={readState}
        confirmIntervalMs={1}
      />
    );
    await act(async () => {
      fireEvent.click(btn("Pristine"));
    });
    await waitFor(() => expect(screen.getByText(/release confirmed — no longer choked/i)).toBeTruthy());
  });

  it("surfaces a rejected action instead of reporting success", async () => {
    const apply = vi.fn(async () => ({ ok: false, detail: "reason is required for the audit row" }));
    const readState = vi.fn(async () => "pristine");
    render(
      <EnforcementLadder
        target={target}
        state="pristine"
        policy={PROCESS_TERMINAL}
        apply={apply}
        readState={readState}
        confirmIntervalMs={1}
      />
    );
    await act(async () => {
      fireEvent.click(btn("Throttle"));
    });
    await waitFor(() => expect(screen.getByText(/reason is required for the audit row/i)).toBeTruthy());
    expect(readState).not.toHaveBeenCalled();
  });
});
