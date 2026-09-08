import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FleetHostsPanel } from "../features/fleet/FleetTable";
import { deriveFleet } from "../features/fleet/fleetLogic";
import type { ChokeState, FleetPeer, HostResult } from "../features/fleet/types";

/**
 * The row half of the three-state kill-switch.
 *
 * The KPI strip counting an unknown separately is worth nothing if the row
 * still paints it. `kill_switched: null` — which is every host on the
 * multi-tenant control plane, because no heartbeat field carries the agent's
 * switch — used to render the same green "live" pill as a host that answered
 * "off": the console asserting enforcement is armed on a host that never said
 * so.
 */

const THRESHOLDS = { throttle_at: 10, tarpit_at: 30, quarantine_at: 60, sever_at: 100 };

const PEERS: FleetPeer[] = [
  { name: "reported-off", url: "http://a" },
  { name: "silent", url: "http://b" }
];

function host(name: string, killSwitched: boolean | null): HostResult<ChokeState> {
  return {
    name,
    ok: true,
    data: {
      mode: "enforcing",
      kill_switched: killSwitched,
      tracked: 0,
      counts: {},
      thresholds: THRESHOLDS,
      audit: { ok: false, supported: false }
    }
  };
}

function panel(states: Array<HostResult<ChokeState>>) {
  const derived = deriveFleet(PEERS, states);
  return render(
    <FleetHostsPanel
      rows={derived.rows}
      kpis={derived.kpis}
      selected={new Set<string>()}
      onSelect={() => undefined}
      onSelectAll={() => undefined}
      onClear={() => undefined}
      onRefresh={() => undefined}
      loading={false}
    />
  );
}

describe("a host row states the kill-switch it was told, and nothing more", () => {
  it("renders 'not reported' rather than a state for a host that reported none", () => {
    panel([host("reported-off", false), host("silent", null)]);

    // One host said off, and it keeps its "live" pill.
    expect(screen.getAllByText("live")).toHaveLength(1);
    // The other said nothing, and gets a reading of its own — not a second
    // green pill.
    expect(screen.getAllByText("not reported").length).toBeGreaterThan(0);
  });

  it("counts the silent host in the panel summary instead of hiding it in the zero", () => {
    panel([host("reported-off", false), host("silent", null)]);
    expect(screen.getByText(/1 kill state not reported/)).toBeTruthy();
  });

  it("calls a broken chain broken even when the host named no offending index", () => {
    // {ok: false} with no `bad_at`. The KPI strip counts this host as
    // auditBroken; the row used to decide "broken" on `bad_at != null` alone
    // and rendered "not maintained" — the row saying this host keeps no
    // tamper-evidence while the tile above said its evidence had failed. Both
    // now read the same classifier.
    panel([
      { name: "reported-off", ok: true, data: { ...host("reported-off", false).data, audit: { ok: false } } },
      host("silent", null)
    ]);

    expect(screen.getByText("broken")).toBeTruthy();
    expect(screen.getAllByText("not maintained")).toHaveLength(1);
  });

  it("withholds the drift reading until two hosts have reported", () => {
    const derived = deriveFleet([PEERS[0]], [host("reported-off", false)]);
    render(
      <FleetHostsPanel
        rows={derived.rows}
        kpis={derived.kpis}
        selected={new Set<string>()}
        onSelect={() => undefined}
        onSelectAll={() => undefined}
        onClear={() => undefined}
        onRefresh={() => undefined}
        loading={false}
      />
    );
    expect(
      screen.queryByText(/drift/i),
      "a drift reading over one host is a host compared with itself"
    ).toBeNull();
  });
});
