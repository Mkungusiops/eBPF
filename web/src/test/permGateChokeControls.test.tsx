import { render, renderHook, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ChokeBanners } from "../features/choke/sections";
import { ProcessTable } from "../features/choke/ProcessTable";
import { ThresholdPanel } from "../features/choke/panels";
import { useChokeActions } from "../features/choke/useChokeActions";
import { useChokePosture } from "../features/choke/useChokePosture";
import type { CircuitEntry, ConfirmRequest, ToastMessage } from "../features/choke/types";

/**
 * The Choke Gateway must not arm containment for a principal the server will
 * refuse.
 *
 * The control plane publishes `can_respond` from whoami (authz.CanRespond, whose
 * own comment says the console uses it to enable and disable action controls)
 * and this route read none of it: `disabled` came from `loadState`, which is
 * about whether the DEPLOYMENT is serving, never about who is asking. So a
 * read-only operator was shown a live sever/jail/kill-switch surface and found
 * out by pressing it on a real host — the server answers 404, the fan-out
 * summary reports what it reached, which is nothing, and the operator walks
 * away believing enforcement was bypassed.
 *
 * All three values of the contract are pinned, because the third is where this
 * goes wrong in the other direction: `null` means the server did not publish
 * the field at all, which is the single-tenant engine, which has no permission
 * model. Reading that silence as a refusal would strip the emergency controls
 * off every single-tenant console.
 *
 * The tracked-process table is virtualised, and jsdom gives its scroll element
 * no height, so tanstack-virtual renders zero rows. VirtualList is replaced
 * here with a plain map — the rows under test are ProcessTable's, not the
 * virtualiser's.
 */
vi.mock("../components/VirtualList", () => ({
  VirtualList: <T,>({
    items,
    renderItem,
    before
  }: {
    items: T[];
    renderItem: (item: T, index: number) => unknown;
    before?: unknown;
  }) => (
    <div>
      {before as never}
      {items.map((item, index) => (
        <div key={index}>{renderItem(item, index) as never}</div>
      ))}
    </div>
  )
}));

const STREAM = { state: "live" as const, retries: 0, lastMessageAt: 0, totalMessages: 0, messagesByMinute: [] };

function posture(whoami: Record<string, unknown> | null) {
  return renderHook(() =>
    useChokePosture({
      chokeState: null,
      circuits: [],
      approvals: [],
      whoami,
      hostPings: [],
      streamInfo: STREAM,
      loadState: { kind: "ready" } as never,
      now: 0,
      windowMin: 30,
      currentWindowDecisions: []
    })
  ).result.current;
}

describe("the choke posture reads whoami's can_respond, and only false withholds", () => {
  it("withholds containment and names the reason as permission when can_respond is false", () => {
    const readOnly = posture({ user: "viewer", can_respond: false });
    expect(readOnly.canRespond).toBe(false);
    expect(readOnly.readOnlyAccount).toBe(true);
    expect(readOnly.containmentDisabled).toBe(true);
    // In the language of permission, not of outage. An operator told the
    // gateway is "unavailable" goes looking for a broken estate.
    expect(readOnly.containmentBlockedReason).toMatch(/read-only/i);
    expect(readOnly.containmentBlockedReason).not.toMatch(/unavailable|not enabled|disabled|offline/i);
  });

  it("leaves containment armed when the server publishes no can_respond", () => {
    // The single-tenant engine. It has no such concept, and must not lose its
    // controls to a permission model it does not implement.
    const single = posture({ user: "admin", hostname: "engine-01" });
    expect(single.canRespond).toBeNull();
    expect(single.readOnlyAccount).toBe(false);
    expect(single.containmentDisabled).toBe(false);
    expect(single.containmentBlockedReason).toBe("");

    // Same for a whoami that never arrived at all.
    expect(posture(null).containmentDisabled).toBe(false);
  });

  it("leaves containment armed when can_respond is true", () => {
    const analyst = posture({ user: "analyst", can_respond: true });
    expect(analyst.canRespond).toBe(true);
    expect(analyst.containmentDisabled).toBe(false);
    expect(analyst.containmentBlockedReason).toBe("");
  });
});

describe("every choke write refuses at the action layer for a read-only account", () => {
  function actions(canRespond: boolean | null) {
    const confirms: Array<ConfirmRequest | null> = [];
    const toasts: Array<{ message: string; kind?: ToastMessage["kind"] }> = [];
    const entry = { exec_id: "exec-1", pid: 42, binary: "/bin/sh" } as CircuitEntry;
    const hook = renderHook(() =>
      useChokeActions({
        chokeState: { kill_switched: false } as never,
        setChokeState: () => {},
        selectedEntries: [entry],
        selectedExecs: new Set(["exec-1"]),
        setSelectedExecs: () => {},
        setConfirm: ((value: ConfirmRequest | null) => confirms.push(value)) as never,
        pushToast: (message, kind) => toasts.push({ message, kind }),
        refreshAll: async () => {},
        refreshState: async () => {},
        refreshApprovals: async () => {},
        canRespond
      })
    );
    return { api: hook.result.current, confirms, toasts, entry };
  }

  it("stages nothing and says why, for every containment opener", () => {
    const { api, confirms, toasts, entry } = actions(false);
    api.openKillSwitchConfirm();
    api.openModeConfirm(true);
    api.openPresetConfirm("containment");
    api.openThawConfirm();
    api.openManualConfirm(entry, "sever");
    api.openBulkConfirm("sever");
    api.openBulkForgetConfirm();

    // Nothing was staged: no confirm dialog, so no path to the network.
    expect(confirms).toEqual([]);
    // And it refused LOUDLY. A control that silently does nothing is
    // indistinguishable from a broken one.
    expect(toasts).toHaveLength(7);
    for (const toast of toasts) {
      expect(toast.message).toMatch(/read-only/i);
      expect(toast.kind).toBe("warn");
    }
  });

  it("stages the write when the server published no can_respond", () => {
    const { api, confirms, toasts } = actions(null);
    api.openKillSwitchConfirm();
    expect(confirms).toHaveLength(1);
    expect(toasts).toEqual([]);
  });
});

describe("the choke controls themselves are drawn disabled, not drawn armed", () => {
  const ROW = {
    exec_id: "exec-1",
    pid: 42,
    binary: "/bin/sh",
    score: 88,
    state: "pristine"
  } as CircuitEntry;

  function renderTable(readOnly: boolean) {
    return render(
      <ProcessTable
        rows={[ROW]}
        selected={new Set()}
        density="normal"
        alertCounts={new Map()}
        truncated={false}
        total={1}
        onSelect={() => {}}
        onSelectAll={() => {}}
        onClear={() => {}}
        onAction={() => {}}
        onDrill={() => {}}
        onFilterBinary={() => {}}
        onFilterExec={() => {}}
        onCopy={() => {}}
        readOnly={readOnly}
      />
    );
  }

  it("disables the per-process sever and quarantine buttons", () => {
    const { container } = renderTable(true);
    const actions = Array.from(container.querySelectorAll<HTMLButtonElement>(".choke-row-actions button"));
    const escalations = actions.filter((button) => /^(thr|tar|qua|sev)$/.test(button.textContent || ""));
    expect(escalations).toHaveLength(4);
    expect(escalations.every((button) => button.disabled)).toBe(true);
    // The tape filter is a READ. Taking investigation away from an operator who
    // is allowed to investigate would be a second defect, not a stricter fix.
    const tape = actions.find((button) => button.textContent === "tape");
    expect(tape?.disabled).toBe(false);
  });

  it("leaves them armed when the server published no can_respond", () => {
    const { container } = renderTable(false);
    const actions = Array.from(container.querySelectorAll<HTMLButtonElement>(".choke-row-actions button"));
    expect(actions.some((button) => button.disabled)).toBe(false);
  });

  it("disables the threshold commit and states the permission reason", () => {
    render(
      <ThresholdPanel
        dataPanel="thresholds-panel"
        thresholds={{ throttle_at: 20, tarpit_at: 40, quarantine_at: 60, sever_at: 80 }}
        circuits={[]}
        disabled
        disabledReason="Your account is read-only: it can watch this gateway, but not contain or reconfigure it."
        onCommit={async () => {}}
      />
    );
    const commit = screen.getByRole("button", { name: /commit thresholds/i }) as HTMLButtonElement;
    expect(commit.disabled).toBe(true);
    expect(screen.getByText(/read-only/i)).toBeTruthy();
  });

  it("states the read-only account once, at the top of the page", () => {
    render(
      <ChokeBanners
        loadState={{ kind: "ready" } as never}
        staleSeconds={0}
        onReconnect={() => {}}
        mode="detect-only"
        divergedAgents={[]}
        kernelFired={0}
        readOnlyReason="Your account is read-only: it can watch this gateway, but not contain or reconfigure it."
      />
    );
    const banner = document.querySelector('[data-panel="read-only-account-banner"]');
    expect(banner).toBeTruthy();
    expect(banner?.textContent).toMatch(/read-only/i);
  });

  it("draws no read-only banner when the server said nothing", () => {
    render(
      <ChokeBanners
        loadState={{ kind: "ready" } as never}
        staleSeconds={0}
        onReconnect={() => {}}
        mode="detect-only"
        divergedAgents={[]}
        kernelFired={0}
      />
    );
    expect(document.querySelector('[data-panel="read-only-account-banner"]')).toBeNull();
  });
});
