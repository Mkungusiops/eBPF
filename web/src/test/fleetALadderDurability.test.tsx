import { render, screen } from "@testing-library/react";
import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { FleetControlRail } from "../features/fleet/FleetControlRail";
import { readLadderPersistence } from "../features/fleet/fleetLogic";
import { useFleetControls } from "../features/fleet/useFleetControls";
import type { ConfirmState, FleetPeer, ToastMessage } from "../features/fleet/types";

/**
 * A TARGETED LADDER WRITE REPORTS SUCCESS AND IS THEN SILENTLY REVERTED.
 *
 * The control plane behaves correctly and says so. `handleChokeThresholds`
 * (engine/internal/controlplane/choke.go) stores a ladder as the TENANT's
 * policy only when the write named no targets — a per-host ladder must not
 * quietly become the policy every future agent inherits — and reports which it
 * did in `stored_for_tenant`. Then `reconcileLadders`
 * (engine/internal/controlplane/ladderreconcile.go) pushes the tenant ladder
 * back over every agent whose reported ladder differs from it, every two
 * minutes. Its own comment describes the operator who "watches it revert
 * within two minutes with nothing anywhere saying why".
 *
 * Nothing in web/src read the field. So "Apply to selected hosts" raised the
 * same green "Thresholds applied · 1/1 hosts succeeded" as an estate-wide
 * write, and the estate did not stay in that state. Both halves of that toast
 * were individually true and together they misinformed.
 *
 * WHAT IS PINNED HERE:
 *   1. a targeted write whose response says `stored_for_tenant: false` is NOT
 *      reported as plain success — the tone changes and the revert is named;
 *   2. an untargeted write that WAS stored still reports success;
 *   3. a server that says nothing about durability (the single-tenant engine,
 *      which has no tenant policy and no reconciler) has no caveat invented
 *      for it;
 *   4. the caveat outlives its toast, on the rail, because the revert happens
 *      minutes after the toast has gone.
 */

const { writeKillSwitch, writePreset, writeThaw, writeThresholds } = vi.hoisted(() => ({
  writeKillSwitch: vi.fn(),
  writePreset: vi.fn(),
  writeThaw: vi.fn(),
  writeThresholds: vi.fn()
}));

vi.mock("../features/fleet/api", () => ({
  writeKillSwitch,
  writePreset,
  writeThaw,
  writeThresholds
}));

const PEERS: FleetPeer[] = [
  { name: "alpha-edge", url: "http://alpha" },
  { name: "bravo-edge", url: "http://bravo" }
];

const LADDER = { throttle_at: 6, tarpit_at: 12, quarantine_at: 24, sever_at: 48 };

type Toast = [ToastMessage["kind"], string, string?];

function setup() {
  const toasts: Toast[] = [];
  const view = renderHook(() =>
    useFleetControls({
      peers: PEERS,
      totalHosts: PEERS.length,
      majorityThresholds: null,
      pollStatus: "connected",
      canRespond: true,
      identityResolved: true,
      pushToast: (kind, title, body) => toasts.push([kind, title, body]),
      refresh: async () => undefined,
      setConfirmState: (_state: ConfirmState | null) => undefined
    })
  );
  return { view, toasts };
}

/** Edit the draft so Apply has something to send, then send it. */
async function applyLadder(view: ReturnType<typeof setup>["view"]) {
  act(() => {
    view.result.current.setThreshold("throttle_at", String(LADDER.throttle_at));
    view.result.current.setThreshold("tarpit_at", String(LADDER.tarpit_at));
    view.result.current.setThreshold("quarantine_at", String(LADDER.quarantine_at));
    view.result.current.setThreshold("sever_at", String(LADDER.sever_at));
  });
  await act(async () => {
    await view.result.current.applyThresholds();
  });
}

/** Select one host, which is what puts a host list on the wire. */
function selectOne(view: ReturnType<typeof setup>["view"]) {
  act(() => {
    view.result.current.selectHost("alpha-edge", true);
  });
}

describe("a ladder the server did not store is not reported as applied and done", () => {
  it("refuses a success tone for a targeted write the tenant policy will overwrite", async () => {
    // The live control-plane response: the agent took it, and it is not the
    // tenant's ladder.
    writeThresholds.mockResolvedValue({
      ok: true,
      applied: 1,
      total: 1,
      detail: "",
      hosts: [{ name: "alpha-edge", ok: true, status: "APPLIED" }],
      stored_for_tenant: false
    });

    const { view, toasts } = setup();
    selectOne(view);
    await applyLadder(view);

    await waitFor(() => expect(toasts.length).toBe(1));
    const [kind, title, body] = toasts[0];

    expect(kind, "a write that will be reverted was toned as an unqualified success").not.toBe("ok");
    // The fan-out fact survives — the hosts DID take it — but the toast may not
    // stop there.
    expect(`${title} ${body}`).toMatch(/1\/1/);
    expect(body, "the operator is not told the ladder was not stored").toMatch(/not stored/i);
    expect(body, "the revert window the reconciler runs on is not named").toMatch(/two minutes/i);
    expect(body, "the operator is not told how to make the change stick").toMatch(/apply to all hosts/i);
    expect(view.result.current.ladderTemporary).toBe(true);
  });

  it("still reports success when the write became the tenant's ladder", async () => {
    writeThresholds.mockResolvedValue({
      ok: true,
      applied: 2,
      total: 2,
      detail: "",
      hosts: [
        { name: "alpha-edge", ok: true, status: "APPLIED" },
        { name: "bravo-edge", ok: true, status: "APPLIED" }
      ],
      stored_for_tenant: true
    });

    const { view, toasts } = setup();
    await applyLadder(view);

    await waitFor(() => expect(toasts.length).toBe(1));
    const [kind, , body] = toasts[0];
    expect(kind, "an estate-wide ladder that WAS stored was demoted to a warning").toBe("ok");
    expect(body).toMatch(/enrols later inherits it/i);
    expect(view.result.current.ladderTemporary).toBe(false);
  });

  it("invents no durability caveat for a server that reported none", async () => {
    // The single-tenant engine: a per-host `hosts` array and no
    // `stored_for_tenant` at all. It has no tenant policy and no reconciler, so
    // a revert warning here would be as untrue as the missing one was.
    writeThresholds.mockResolvedValue({
      hosts: [
        { name: "alpha-edge", ok: true, status: 200 },
        { name: "bravo-edge", ok: true, status: 200 }
      ]
    });

    const { view, toasts } = setup();
    selectOne(view);
    await applyLadder(view);

    await waitFor(() => expect(toasts.length).toBe(1));
    const [kind, , body] = toasts[0];
    expect(kind).toBe("ok");
    expect(body).not.toMatch(/revert|not stored/i);
    expect(view.result.current.ladderNote).toBe("");
  });

  it("keeps a failed fan-out reported as a failure, caveat or not", async () => {
    // Durability is a second fact, not a replacement for the first: a write
    // that half-landed must still read as a partial.
    writeThresholds.mockResolvedValue({
      applied: 1,
      total: 2,
      detail: "",
      hosts: [
        { name: "alpha-edge", ok: true, status: "APPLIED" },
        { name: "bravo-edge", ok: false, status: "timeout" }
      ],
      stored_for_tenant: false
    });

    const { view, toasts } = setup();
    selectOne(view);
    await applyLadder(view);

    await waitFor(() => expect(toasts.length).toBe(1));
    const [kind, title, body] = toasts[0];
    expect(kind).toBe("err");
    expect(title).toMatch(/partial/i);
    expect(body).toMatch(/bravo-edge/);
    expect(body, "the durability caveat was dropped because the fan-out failed").toMatch(/not stored/i);
  });
});

describe("readLadderPersistence reads only what the server said", () => {
  it("treats a non-boolean stored_for_tenant as no statement at all", () => {
    expect(readLadderPersistence({}, ["alpha-edge"])).toEqual({ temporary: false, note: "" });
    expect(readLadderPersistence({ stored_for_tenant: null }, ["alpha-edge"]).note).toBe("");
    expect(readLadderPersistence("not an object", null).note).toBe("");
  });

  it("does not promise a revert it cannot know about", () => {
    // `stored_for_tenant: false` says this ladder is not the tenant's. It does
    // NOT say the tenant has one — reconcileLadders skips a tenant with no
    // stored ladder — so the revert is stated as conditional on that.
    const { note, temporary } = readLadderPersistence({ stored_for_tenant: false }, ["alpha-edge"]);
    expect(temporary).toBe(true);
    expect(note).toMatch(/if this tenant has a stored ladder/i);
  });

  it("warns about the NEXT agent, not this write, when an untargeted write was not stored", () => {
    // Untargeted and unstored: the live agents took it and nothing reverts it,
    // because there is no stored policy to reconcile against. Toning this as a
    // failure would be its own false reading.
    const { note, temporary } = readLadderPersistence({ stored_for_tenant: false }, null);
    expect(temporary).toBe(false);
    expect(note).toMatch(/enrols later/i);
  });
});

describe("the caveat outlives the toast", () => {
  it("stands on the rail, where the operator looks when the numbers move back", () => {
    render(
      <FleetControlRail
        applyMode="sel"
        onApplyMode={() => undefined}
        selectedCount={1}
        writesDisabled={false}
        writesDisabledReason=""
        onPreset={() => undefined}
        thresholdDraft={LADDER}
        thresholdDirty={false}
        majorityThresholds={LADDER}
        reportingHosts={1}
        ladderNote="Applied to the 1 selected host only, and NOT stored as this tenant's ladder."
        ladderTemporary
        onThreshold={() => undefined}
        onApplyThresholds={() => undefined}
        targetCount={1}
        onKillSwitchOn={() => undefined}
        onKillSwitchOff={() => undefined}
        onThaw={() => undefined}
      />
    );

    expect(screen.getByText(/NOT stored as this tenant's ladder/)).toBeTruthy();
    // And the reading above it does not call one host's ladder a fleet
    // majority while it is at it.
    expect(screen.getByText("One host reporting · 6/12/24/48")).toBeTruthy();
  });
});
