import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { StreamProvider } from "../lib/stream";
import { ChokeRoute } from "../features/choke/ChokeRoute";
import { AUTHORITY_PENDING_REASON, responseAuthorityNow } from "../features/soc/api";
import type { Whoami } from "../features/choke/types";

/**
 * The Choke Gateway's half of "loading is not permission".
 *
 * useChokeData holds `whoami` as `Whoami | null`, and useChokePosture turns
 * null into `canRespond: null` — the single-tenant engine's "the server
 * published no such field", which reads as PERMITTED. That is right for the
 * engine and wrong for the first paint of a control-plane session, where the
 * field is missing because the request has not come back. So this route drew a
 * live kill-switch, mode toggle, threshold commit and per-process sever for
 * every read-only operator until the first poll landed.
 *
 * useChokeData is mocked rather than the network, because what is under test is
 * the ROUTE's gate: given a whoami that has not answered, does this file arm
 * anything? Nine polling endpoints and an SSE catch-up would only add ways for
 * the test to fail for reasons that are not the defect.
 *
 * The virtualiser is replaced for the same reason it is in
 * permGateChokeControls.test.tsx: jsdom gives its scroll element no height, so
 * it renders zero rows and the per-process controls under test never exist.
 *
 * ORDERING MATTERS. The shared authority store starts at "loading" and only
 * recordResponseAuthority moves it off, with no way back, so the in-flight case
 * runs first and pins that precondition before asserting on it.
 */
const whoamiHolder = vi.hoisted(() => ({ current: null as Whoami | null }));

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

vi.mock("../features/choke/useChokeData", () => ({
  useChokeData: () => ({
    loadState: { kind: "ready" },
    chokeState: {
      mode: "enforcing",
      kill_switched: false,
      tracked: 1,
      thresholds: { throttle_at: 20, tarpit_at: 40, quarantine_at: 60, sever_at: 80 }
    },
    setChokeState: () => {},
    // "throttled" rather than "pristine": the table's default state chips
    // exclude pristine, and a row that is filtered out cannot show whether its
    // escalations were armed.
    circuits: [{ exec_id: "exec-1", pid: 42, binary: "/bin/sh", score: 88, state: "throttled" }],
    buckets: [],
    cgroups: {},
    decisions: [],
    alerts: [],
    systemHealth: null,
    whoami: whoamiHolder.current,
    approvals: [],
    hostPings: [],
    streamInfo: { state: "live", retries: 0, lastMessageAt: 0, totalMessages: 0, messagesByMinute: [] },
    now: 0,
    refreshing: false,
    refreshAll: async () => {},
    refreshState: async () => {},
    refreshCircuits: async () => {},
    refreshApprovals: async () => {},
    pingHost: async () => {}
  })
}));

function renderRoute() {
  return render(
    <StreamProvider>
      <ChokeRoute />
    </StreamProvider>
  );
}

function control(selector: string): HTMLButtonElement {
  const button = document.querySelector<HTMLButtonElement>(selector);
  if (!button) throw new Error(`no control matched ${selector}`);
  return button;
}

describe("the Choke Gateway arms nothing while whoami is in flight", () => {
  it("starts at loading — the precondition the assertions below rest on", () => {
    expect(responseAuthorityNow()).toBe("loading");
  });

  it("withholds the kill-switch, the mode toggle, the threshold commit and the row escalations", async () => {
    whoamiHolder.current = null; // the poll has not answered yet
    renderRoute();
    await screen.findByText(/Containment Command/i);

    expect(control("button.cc-ctl-kill").disabled).toBe(true);
    expect(control("button.cc-ctl-mode").disabled).toBe(true);

    const commit = screen.getByRole("button", { name: /commit thresholds/i }) as HTMLButtonElement;
    expect(commit.disabled).toBe(true);

    const escalations = Array.from(
      document.querySelectorAll<HTMLButtonElement>('[data-panel="tracked-processes-list"] .choke-row-actions button')
    ).filter((button) => /^(thr|tar|qua|sev)$/.test(button.textContent || ""));
    expect(escalations).toHaveLength(4);
    expect(escalations.every((button) => button.disabled)).toBe(true);
  });

  it("says it is checking, on the control — and never calls the operator read-only", async () => {
    whoamiHolder.current = null;
    renderRoute();
    await screen.findByText(/Containment Command/i);

    const note = document.querySelector('[data-panel="containment-command-withheld"]');
    expect(note?.textContent).toBe(AUTHORITY_PENDING_REASON);
    const commit = screen.getByRole("button", { name: /commit thresholds/i }) as HTMLButtonElement;
    expect(commit.title).toBe(AUTHORITY_PENDING_REASON);
    // Nowhere on the page, banner included. Telling a responder their account is
    // read-only for the first second of every session is a different false
    // statement, and the one they would report as a bug.
    expect(document.body.textContent).not.toMatch(/read-only/i);
  });
});

describe("once whoami answers, the route reports what it was told", () => {
  it("withholds and names permission for an account the server refused", async () => {
    whoamiHolder.current = { user: "viewer", can_respond: false } as unknown as Whoami;
    renderRoute();
    await waitFor(() => expect(responseAuthorityNow()).toBe(false));

    expect(control("button.cc-ctl-kill").disabled).toBe(true);
    const note = document.querySelector('[data-panel="containment-command-withheld"]');
    expect(note?.textContent).toMatch(/read-only/i);
    // The reason reaches the control, not only the page banner.
    const escalation = Array.from(
      document.querySelectorAll<HTMLButtonElement>('[data-panel="tracked-processes-list"] .choke-row-actions button')
    ).find((button) => button.textContent === "sev");
    expect(escalation?.disabled).toBe(true);
    expect(escalation?.title).toMatch(/read-only/i);
  });

  it("arms containment when the server answers without the field — the single-tenant engine", async () => {
    whoamiHolder.current = { user: "admin", hostname: "engine-01" } as unknown as Whoami;
    renderRoute();
    await waitFor(() => expect(responseAuthorityNow()).toBeNull());

    expect(control("button.cc-ctl-kill").disabled).toBe(false);
    expect(control("button.cc-ctl-mode").disabled).toBe(false);
    expect(document.querySelector('[data-panel="containment-command-withheld"]')).toBeNull();
  });
});
