import { render, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SocAlert, SocSnapshot } from "../features/soc/types";

/**
 * WHERE A ROW'S TRIAGE ACTUALLY LANDS — tested through the route, not through
 * the handler in isolation.
 *
 * The previous pass fixed the row button and the bulk bar and stopped there:
 * the drill panel, the keyboard shortcuts and the context menu still wrote a
 * single member of a ×2 row. Because the row derives its state from its
 * LEAST-PROGRESSED member, that produced two contradictory readings on one
 * screen — a drill panel reporting the alert acknowledged above a row still
 * marked "New". A unit test over the handler would have passed throughout;
 * only rendering the route reaches the call sites that were wrong.
 */

const ALERT_A = "alert-dup-1";
const ALERT_B = "alert-dup-2";

function duplicateAlert(id: string, execId: string): SocAlert {
  return {
    id,
    title: "Credential file read",
    description: "One of two identical criticals the queue collapses into one row",
    severity: "critical",
    score: 44,
    // Fixed, recent-relative timestamps are set per test so the default window
    // contains them whatever the clock says when the suite runs.
    timestamp: new Date(Date.now() - 60_000).toISOString(),
    policyName: "override-credential-read",
    process: "/usr/bin/cat",
    execId,
    raw: { id, exec_id: execId }
  };
}

const snapshot = vi.hoisted(() => ({ current: null as SocSnapshot | null }));

vi.mock("../lib/stream", () => ({
  useStream: () => ({
    state: "live" as const,
    retries: 0,
    messageCount: 0,
    lastMessageAt: Date.now(),
    lastEventAt: Date.now(),
    frames: [],
    latestBatch: [],
    batchId: 0,
    reconnect: () => {}
  })
}));

// D3 owns the graph's DOM and has nothing to do with triage; rendering it in
// jsdom only buys flakiness.
vi.mock("../features/soc/CorrelationGraph", () => ({ CorrelationGraph: () => null }));

vi.mock("../features/soc/api", async () => {
  const actual = await vi.importActual<typeof import("../features/soc/api")>("../features/soc/api");
  return {
    ...actual,
    fetchSocSnapshot: async () => ({
      snapshot: snapshot.current ?? actual.EMPTY_SOC_SNAPSHOT,
      truncated: { alerts: false, events: false },
      errors: {},
      statuses: {}
    }),
    // Null keeps the dashboard on its buffer-derived counts; the server-stats
    // path is not what these tests are about.
    fetchAlertStats: async () => null,
    fetchDecisionStats: async () => null,
    fetchProcessDetail: async () => ({ ok: false as const, error: "not under test" })
  };
});

// The drill is a <aside class="soc-slide-over">, not a dialog role, so it is
// found the way the e2e suite finds it: by the panel it is.
async function openDrill(): Promise<HTMLElement> {
  await waitFor(() => {
    const panel = document.querySelector(".soc-slide-over.is-open");
    expect(panel, "the drill slide-over never opened").not.toBeNull();
  });
  return document.querySelector(".soc-slide-over.is-open") as HTMLElement;
}

function ackStates(): Record<string, string> {
  return JSON.parse(window.localStorage.getItem("soc.alertStates") || "{}");
}

function pinned(): string[] {
  return JSON.parse(window.localStorage.getItem("soc.pinnedAlerts") || "[]");
}

async function renderRoute() {
  const { SocRoute } = await import("../features/soc/SocRoute");
  render(<SocRoute />);
  // The grouped row is the proof the snapshot landed; every test below acts on it.
  await waitFor(() => expect(document.querySelector(".soc-group-count")).not.toBeNull());
  return document.querySelector(".soc-alert-row") as HTMLElement;
}

beforeEach(() => {
  window.localStorage.clear();
  snapshot.current = null;
});

describe("every surface that triages a ×2 row acts on both of its alerts", () => {
  beforeEach(async () => {
    const { EMPTY_SOC_SNAPSHOT } = await import("../features/soc/api");
    snapshot.current = {
      ...EMPTY_SOC_SNAPSHOT,
      alerts: [duplicateAlert(ALERT_A, "exec-a"), duplicateAlert(ALERT_B, "exec-b")]
    };
  });

  it("groups the two alerts into one row, or these tests are about nothing", async () => {
    const row = await renderRoute();
    expect(within(row).getByText("×2")).toBeTruthy();
  });

  it("acknowledges both from the drill panel's Acknowledge button", async () => {
    const row = await renderRoute();
    await userEvent.click(within(row).getByRole("button", { name: /Credential file read/ }));
    const drill = await openDrill();
    await userEvent.click(within(drill).getByRole("button", { name: "Acknowledge" }));

    await waitFor(() => expect(ackStates()).toEqual({ [ALERT_A]: "ack", [ALERT_B]: "ack" }));
    // And the row must agree with the panel that just reported the work done.
    expect(within(row).queryByText("New"), "the row still read New after the drill acknowledged it").toBeNull();
  });

  it("resolves both from the drill panel's Resolve button", async () => {
    const row = await renderRoute();
    await userEvent.click(within(row).getByRole("button", { name: /Credential file read/ }));
    const drill = await openDrill();
    await userEvent.click(within(drill).getByRole("button", { name: "Resolve" }));

    await waitFor(() => expect(ackStates()).toEqual({ [ALERT_A]: "resolved", [ALERT_B]: "resolved" }));
  });

  it("acknowledges both from the 'a' keyboard shortcut", async () => {
    const row = await renderRoute();
    await userEvent.click(within(row).getByRole("button", { name: /Credential file read/ }));
    await openDrill();
    // The shortcut is a document-level listener, so it is fired at the body the
    // way the operator's keystroke reaches it.
    await userEvent.keyboard("a");

    await waitFor(() => expect(ackStates()).toEqual({ [ALERT_A]: "ack", [ALERT_B]: "ack" }));
  });

  it("resolves both from the 'r' keyboard shortcut", async () => {
    const row = await renderRoute();
    await userEvent.click(within(row).getByRole("button", { name: /Credential file read/ }));
    await openDrill();
    await userEvent.keyboard("r");

    await waitFor(() => expect(ackStates()).toEqual({ [ALERT_A]: "resolved", [ALERT_B]: "resolved" }));
  });

  it("acknowledges both from the row's context menu", async () => {
    const row = await renderRoute();
    await userEvent.pointer({ target: row, keys: "[MouseRight]" });
    const menu = document.querySelector(".soc-context-menu") as HTMLElement;
    await userEvent.click(within(menu).getByRole("button", { name: "Acknowledge" }));

    await waitFor(() => expect(ackStates()).toEqual({ [ALERT_A]: "ack", [ALERT_B]: "ack" }));
  });

  it("resolves both from the row's context menu", async () => {
    const row = await renderRoute();
    await userEvent.pointer({ target: row, keys: "[MouseRight]" });
    const menu = document.querySelector(".soc-context-menu") as HTMLElement;
    await userEvent.click(within(menu).getByRole("button", { name: "Resolve" }));

    await waitFor(() => expect(ackStates()).toEqual({ [ALERT_A]: "resolved", [ALERT_B]: "resolved" }));
  });

  it("pins both from the row's context menu, so the sort cannot split the group", async () => {
    const row = await renderRoute();
    await userEvent.pointer({ target: row, keys: "[MouseRight]" });
    const menu = document.querySelector(".soc-context-menu") as HTMLElement;
    await userEvent.click(within(menu).getByRole("button", { name: "Toggle pin" }));

    await waitFor(() => expect(pinned().sort()).toEqual([ALERT_A, ALERT_B]));
  });
});
