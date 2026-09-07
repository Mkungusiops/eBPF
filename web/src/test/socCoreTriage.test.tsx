import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { AlertQueue, queueEmptyState } from "../features/soc/AlertQueue";
import { groupAckState, groupAlertList } from "../features/soc/analytics";
import type { AlertGroup } from "../features/soc/dashboard";
import type { SocAlert } from "../features/soc/types";

/**
 * The triage queue's two claims about itself: what a row's buttons reach, and
 * why the list is empty. Both were wrong in the same direction — the panel
 * stated something stronger than it had done.
 */
function alert(id: string, overrides: Partial<SocAlert> = {}): SocAlert {
  return {
    id,
    title: "Credential file read",
    description: "One of two identical criticals the queue collapses into one row",
    severity: "critical",
    score: 44,
    timestamp: "2026-06-25T09:00:00Z",
    policyName: "override-credential-read",
    process: "cat",
    raw: undefined,
    ...overrides
  };
}

function renderQueue(alerts: AlertGroup[], overrides: Partial<Parameters<typeof AlertQueue>[0]> = {}) {
  const onAck = vi.fn();
  const onPin = vi.fn();
  render(
    <AlertQueue
      alerts={alerts}
      coverage={{ short: false, coveredMs: 0 }}
      query=""
      windowAlertCount={alerts.reduce((n, group) => n + group.members.length, 0)}
      excluded={{ query: 0, baseline: 0, unacked: 0 }}
      beyondWindow={0}
      hideBaseline={false}
      onHideBaseline={() => {}}
      filterUnack={false}
      onFilterUnack={() => {}}
      grouped
      onGrouped={() => {}}
      sortField="time"
      onSortField={() => {}}
      selectedIds={new Set()}
      onToggleSelected={() => {}}
      onClearSelection={() => {}}
      onBulkAck={() => {}}
      ackStates={{}}
      pinnedAlerts={[]}
      onOpen={() => {}}
      onAck={onAck}
      onPin={onPin}
      onContext={() => {}}
      onHover={() => {}}
      onLeave={() => {}}
      {...overrides}
    />
  );
  return { onAck, onPin };
}

describe("a grouped row acts on every alert it stands for", () => {
  /**
   * groupAlertList spreads members[0], so the row's id is one member's id while
   * the row draws "×2". Acking it wrote a single entry into soc.alertStates:
   * the row said "Ack'd" and its sibling came straight back under "Unacked
   * only" — the console claiming the work was both done and outstanding, two
   * inches apart.
   */
  const group = groupAlertList([alert("alert-dup-1"), alert("alert-dup-2", { execId: "exec-2" })]);

  it("is a ×2 row, or this test is about nothing", () => {
    expect(group).toHaveLength(1);
    expect(group[0].groupCount).toBe(2);
    expect(group[0].id, "the row carries the first member's id").toBe("alert-dup-1");
  });

  it("acks both members from the row's Ack button", async () => {
    const { onAck } = renderQueue(group);
    await userEvent.click(screen.getByRole("button", { name: "Ack" }));
    expect(onAck).toHaveBeenCalledWith(["alert-dup-1", "alert-dup-2"], "ack");
  });

  it("resolves both members from the row's Resolve button", async () => {
    const { onAck } = renderQueue(group);
    await userEvent.click(screen.getByRole("button", { name: "Resolve" }));
    expect(onAck).toHaveBeenCalledWith(["alert-dup-1", "alert-dup-2"], "resolved");
  });

  it("pins both members, so the group cannot shed rows to the sort", async () => {
    const { onPin } = renderQueue(group);
    await userEvent.click(screen.getByRole("button", { name: "Pin" }));
    expect(onPin).toHaveBeenCalledWith(["alert-dup-1", "alert-dup-2"]);
  });

  it("only reads as acknowledged once every member is", () => {
    expect(groupAckState(group[0].members, { "alert-dup-1": "ack" })).toBe("new");
    expect(groupAckState(group[0].members, { "alert-dup-1": "ack", "alert-dup-2": "ack" })).toBe("ack");
    // A group with one alert still open is outstanding work, whatever the other
    // member's state says.
    expect(groupAckState(group[0].members, { "alert-dup-1": "resolved", "alert-dup-2": "ack" })).toBe("ack");
  });

  it("shows the row as new while a member is unacknowledged", () => {
    renderQueue(group, { ackStates: { "alert-dup-1": "ack" } });
    expect(screen.getByText("New")).toBeTruthy();
  });
});

describe("an empty queue says which kind of empty it is", () => {
  /**
   * One hard-coded "No alerts match current filters" served both readings. An
   * analyst with no query and no chip engaged went loosening filters that were
   * not set, and never learned the feed was dry; the inverse is worse, because
   * someone who has learned those words mean "quiet" reads them the same way on
   * the day a stray query is hiding real alerts.
   */
  it("blames the filters only when there was something for them to exclude", () => {
    const filtered = queueEmptyState({
      query: "no-such-alert-anywhere",
      windowAlertCount: 4,
      beyondWindow: 0,
      excluded: { query: 4, baseline: 0, unacked: 0 }
    });
    expect(filtered.title).toMatch(/match current filters/i);
    expect(filtered.detail, "the analyst is told WHICH filter excluded them").toContain("no-such-alert-anywhere");
    expect(filtered.detail).toContain("4 alerts");
  });

  it("does not blame filters on an estate that produced nothing", () => {
    const quiet = queueEmptyState({
      query: "",
      windowAlertCount: 0,
      beyondWindow: 0,
      // hideBaseline is ON by default, so a naive "any chip engaged" test would
      // still blame it here. Nothing arrived; nothing was excluded.
      excluded: { query: 0, baseline: 0, unacked: 0 }
    });
    expect(quiet.title).not.toMatch(/match current filters/i);
    expect(quiet.detail).not.toMatch(/match current filters/i);
    expect(quiet.title).toMatch(/recorded on this estate/i);
  });

  it("points at the range when the alerts are outside the window", () => {
    const windowed = queueEmptyState({
      query: "",
      windowAlertCount: 0,
      beyondWindow: 1839,
      excluded: { query: 0, baseline: 0, unacked: 0 }
    });
    expect(windowed.detail).toContain("1,839 alerts");
    expect(windowed.detail).toMatch(/Widen the range/);
  });

  it("renders the two as different text", () => {
    const filtered = queueEmptyState({
      query: "x",
      windowAlertCount: 4,
      beyondWindow: 0,
      excluded: { query: 4, baseline: 0, unacked: 0 }
    });
    const quiet = queueEmptyState({ query: "", windowAlertCount: 0, beyondWindow: 0, excluded: { query: 0, baseline: 0, unacked: 0 } });
    expect(`${filtered.title} ${filtered.detail}`).not.toEqual(`${quiet.title} ${quiet.detail}`);
  });

  it("puts the honest copy on the panel", () => {
    renderQueue([], { windowAlertCount: 0 });
    expect(screen.getByText(/recorded on this estate/i)).toBeTruthy();
    expect(screen.queryByText(/match current filters/i)).toBeNull();
  });
});
