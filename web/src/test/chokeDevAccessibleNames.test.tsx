import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ChokeTopBar } from "../features/choke/sections";
import { CommandView } from "../features/choke/CommandView";
import { useChokeFilters } from "../features/choke/useChokeFilters";
import { useChokePosture } from "../features/choke/useChokePosture";
import type { ChokeData } from "../features/choke/useChokeData";
import { DevicesBulkBar } from "../features/devices/DevicesBulkBar";

/**
 * Every containment input announces itself.
 *
 * A `placeholder` is not an accessible name. A screen reader reads a
 * placeholder-only field as "edit text, blank", and for everyone else the hint
 * disappears the instant a character is typed — so the operator typing the
 * audit reason a containment is recorded under has nothing telling them which
 * box they are in.
 *
 * The browser suite (web/e2e/a11y.spec.ts) is what proves the COMPUTED name,
 * because only a real engine runs the aria-label → label → text fallback
 * chain. This file guards the markup those controls are rendered from, so a
 * name cannot be dropped in a refactor without a fast unit failure.
 */

const STREAM = { state: "live" as const, retries: 0, lastMessageAt: 0, totalMessages: 0, messagesByMinute: [] };

function renderTopBar() {
  render(
    <ChokeTopBar
      isFleetConsole={false}
      globalSearch=""
      onGlobalSearch={() => {}}
      mode="detect-only"
      popover={null}
      onPopover={() => {}}
      hostState="up"
      chokeState={null}
      streamInfo={STREAM}
      alertsActive={false}
      alertBadgeEnabled={false}
      decisions={[]}
      ackedDecisionIds={new Set()}
      alertsClearedAt={0}
      onToggleNotifications={() => {}}
      onToggleProfile={() => {}}
      userLabel="operator"
      windowOptions={[5, 30]}
      windowMin={30}
      onWindowMin={() => {}}
      disabled={false}
      onPreset={() => {}}
      trackedCount={0}
      refreshing={false}
      onRefreshAll={() => {}}
      onJail={() => {}}
    />,
  );
}

/**
 * The Command lens is a projection of the route's hooks, so it is mounted
 * through the real ones over empty data rather than through a hand-built
 * imitation of their return shapes — an imitation would keep passing after the
 * view stopped reading the field the name hangs off.
 */
function CommandHarness() {
  const filters = useChokeFilters({
    windowOptions: [5, 30],
    circuits: [],
    decisions: [],
    alerts: [],
    now: 0,
    ackedDecisionIds: new Set(),
  });
  const posture = useChokePosture({
    chokeState: null,
    circuits: [],
    approvals: [],
    whoami: null,
    hostPings: [],
    streamInfo: STREAM,
    loadState: { kind: "ready" } as never,
    now: 0,
    windowMin: filters.windowMin,
    currentWindowDecisions: [],
  });
  const data = {
    loadState: { kind: "ready" },
    chokeState: null,
    circuits: [],
    buckets: [],
    cgroups: {},
    decisions: [],
    alerts: [],
    systemHealth: null,
    whoami: null,
    approvals: [],
    hostPings: [],
    streamInfo: STREAM,
    now: 0,
    refreshing: false,
  } as unknown as ChokeData;
  return (
    <CommandView
      data={data}
      filters={filters}
      posture={posture}
      // The operator gate is a REQUIRED prop, and stays required: every real
      // caller decides it once in ChokeRoute and hands it down, and a default
      // here would let a future view mount with writes armed simply by
      // forgetting to pass it — the first-paint arming defect, reintroduced
      // through a prop signature. This harness is asking "are the inputs
      // named?", so it withholds nothing and states no reason.
      writesWithheld={false}
      commitWithheld={false}
      withheldReason=""
      density="normal"
      acked={new Set()}
      onDensity={() => {}}
      onCopy={() => {}}
      onAck={() => {}}
      onUnack={() => {}}
      onManualAction={() => {}}
      onBulkAction={() => {}}
      onBulkForget={() => {}}
      onDrill={() => {}}
      onCommitThresholds={async () => {}}
    />
  );
}

describe("the choke gateway's search boxes are named, not just hinted", () => {
  it("names the global search box", () => {
    renderTopBar();
    expect(screen.getByRole("textbox", { name: /search processes, decisions and policies/i })).toBeTruthy();
  });

  it("names the tracked-process filter and the decision-tape search", () => {
    render(<CommandHarness />);
    expect(screen.getByRole("textbox", { name: /filter tracked processes/i })).toBeTruthy();
    expect(screen.getByRole("textbox", { name: /search the decision tape/i })).toBeTruthy();
  });

  it("leaves no visible choke input relying on its placeholder alone", () => {
    const { container } = render(<CommandHarness />);
    const unnamed = Array.from(container.querySelectorAll("input")).filter(
      (input) => !input.getAttribute("aria-label") && !input.getAttribute("aria-labelledby") && !input.labels?.length,
    );
    expect(unnamed.map((input) => input.outerHTML)).toEqual([]);
  });
});

describe("the device bulk bar names the fields an audit depends on", () => {
  function renderBulkBar() {
    render(
      <DevicesBulkBar
        selectedCount={2}
        action="quarantine"
        reason=""
        revertAfter=""
        toast={null}
        loading={false}
        refreshing={false}
        disabled={false}
        onAction={() => {}}
        onReason={() => {}}
        onRevertAfter={() => {}}
        onRefresh={() => {}}
        onChoke={() => {}}
        onThaw={() => {}}
      />,
    );
  }

  it("names the audit-reason field", () => {
    renderBulkBar();
    expect(screen.getByRole("textbox", { name: /audit reason for this containment/i })).toBeTruthy();
  });

  it("names the auto-revert field", () => {
    renderBulkBar();
    expect(screen.getByRole("spinbutton", { name: /auto-revert after, in seconds/i })).toBeTruthy();
  });
});
