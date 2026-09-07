import { renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useChokeActions } from "../features/choke/useChokeActions";
import type { ApprovalRequest } from "../features/choke/api";
import type { CircuitEntry, ConfirmRequest, ToastMessage } from "../features/choke/types";

/**
 * A CONTAINMENT CONTROL MUST STATE ITS REAL BLAST RADIUS BEFORE IT FIRES.
 *
 * Two ways this page told the operator the wrong reach, in opposite directions:
 *
 *  1. "Thaw quarantined cgroup — frozen processes resume." That wording came
 *     from the agent-local engine, where a reason-only thaw unfreezes ONE
 *     host's quarantine tier. On the control plane the identical POST used to
 *     400 (a dead control) and now releases every contained process on every
 *     agent in the tenant. Thaw is deliberately never approval-gated, so the
 *     confirm dialog is the ONLY thing between one click and un-containing the
 *     estate — and it named neither the hosts, nor the count, nor the tenant.
 *
 *  2. Every fleet-scoped approval said "<requester> asked to <action> the
 *     entire tenant", hardcoded. The server publishes `targets` and `radius` on
 *     each row precisely so the approver can see what they are approving, and
 *     the console read neither: the approver of an "agent-a only" containment
 *     was told, in the sentence they must click through, that they were arming
 *     the whole estate.
 *
 * The confirms are inspected as staged, and the fetch is real (stubbed at the
 * transport, not at the api module) so the assertions land on the body that
 * actually goes on the wire — the previous passes stopped one layer short of
 * exactly that.
 */

const CALLS: Array<{ path: string; body: Record<string, unknown> }> = [];
let response: Record<string, unknown> = { ok: true };

beforeEach(() => {
  CALLS.length = 0;
  response = { ok: true };
  vi.stubGlobal("fetch", async (path: string, init: RequestInit = {}) => {
    CALLS.push({ path: String(path), body: JSON.parse(String(init.body || "{}")) });
    return new Response(JSON.stringify(response), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function contained(agent: string | undefined, execId: string, state = "quarantined"): CircuitEntry {
  return { exec_id: execId, agent, pid: 100, binary: "/bin/sh", state } as CircuitEntry;
}

function harness(options: { circuits?: CircuitEntry[]; isFleetConsole?: boolean } = {}) {
  const confirms: ConfirmRequest[] = [];
  const toasts: Array<{ message: string; kind?: ToastMessage["kind"] }> = [];
  const hook = renderHook(() =>
    useChokeActions({
      chokeState: { kill_switched: false } as never,
      setChokeState: () => {},
      selectedEntries: [],
      selectedExecs: new Set<string>(),
      setSelectedExecs: () => {},
      setConfirm: ((value: ConfirmRequest) => confirms.push(value)) as never,
      pushToast: (message, kind) => toasts.push({ message, kind }),
      refreshAll: async () => {},
      refreshState: async () => {},
      refreshApprovals: async () => {},
      canRespond: true,
      circuits: options.circuits || [],
      isFleetConsole: options.isFleetConsole ?? false,
    }),
  );
  return { api: hook.result.current, confirms, toasts };
}

describe("the thaw control states how far it reaches", () => {
  it("says every agent in the tenant when a fleet release cannot be narrowed", async () => {
    // Fleet console, nothing on screen naming a host: the POST goes out with no
    // targets, which the control plane resolves as the whole tenant.
    const { api, confirms } = harness({ isFleetConsole: true, circuits: [] });
    api.openThawConfirm();
    const confirm = confirms[0];

    expect(`${confirm.title} ${confirm.body}`).toMatch(/every agent in this tenant/i);
    expect(confirm.body).toMatch(/EVERY contained process/);
    // A tenant-scale release with no second operator behind it is a dangerous
    // act and is drawn as one.
    expect(confirm.danger).toBe(true);
    // And it must not still be wearing the single-host wording.
    expect(confirm.title).not.toMatch(/quarantined cgroup/i);

    await confirm.onConfirm({ reason: "incident closed" });
    expect(CALLS).toEqual([{ path: "/api/choke/thaw", body: { reason: "incident closed" } }]);
  });

  it("scopes the release to the hosts on screen and names them", async () => {
    const { api, confirms } = harness({
      isFleetConsole: true,
      circuits: [
        contained("agent-a", "exec-1"),
        contained("agent-a", "exec-2", "tarpit"),
        contained("agent-b", "exec-3"),
        // Not contained: a high-scoring but pristine row is a process nobody has
        // acted on, and its host must not be dragged into the release.
        { exec_id: "exec-4", agent: "agent-c", state: "pristine", score: 99 } as CircuitEntry,
        // Severed is gone, not held — "released" would be a claim about a dead
        // process.
        contained("agent-d", "exec-5", "severed"),
      ],
    });
    api.openThawConfirm();
    const confirm = confirms[0];

    expect(confirm.body).toMatch(/agent-a, agent-b/);
    expect(confirm.body).not.toMatch(/agent-c|agent-d/);
    expect(confirm.body).toMatch(/3 contained processes tracked on them right now/);
    expect(confirm.title).toMatch(/2 hosts/);
    // The narrow release must not describe itself with the wide sentence.
    expect(confirm.body).not.toMatch(/every agent in this tenant/i);

    await confirm.onConfirm({ reason: "false positive" });
    // Traced to the wire: the hosts named in the confirm are the hosts sent.
    expect(CALLS).toEqual([
      { path: "/api/choke/thaw", body: { reason: "false positive", targets: ["agent-a", "agent-b"] } },
    ]);
  });

  it("keeps the single-host wording on the engine, where that is what happens", async () => {
    // The single-tenant engine puts no `agent` on a circuit, so there is nothing
    // to scope to — and nothing to scope, because the same POST releases that
    // one host's quarantine tier. Saying "the tenant" there would be its own lie.
    const { api, confirms } = harness({ isFleetConsole: false, circuits: [contained(undefined, "exec-1")] });
    api.openThawConfirm();
    const confirm = confirms[0];

    expect(`${confirm.title} ${confirm.body}`).toMatch(/this host/i);
    expect(confirm.body).not.toMatch(/tenant/i);

    await confirm.onConfirm({ reason: "drill over" });
    expect(CALLS[0].body).toEqual({ reason: "drill over" });
  });

  it("reports what the fleet actually released, not a blanket success", async () => {
    response = { ok: false, status: "PARTIAL", detail: "released 0 of 4 contained process(es)" };
    const { api, confirms, toasts } = harness({
      isFleetConsole: true,
      circuits: [contained("agent-a", "exec-1")],
    });
    api.openThawConfirm();
    await confirms[0].onConfirm({ reason: "r" });
    expect(toasts[0].kind).toBe("err");
    expect(toasts[0].message).toMatch(/NOT applied/);

    response = { ok: true, released: 3, contained: 4, total: 2 };
    api.openThawConfirm();
    await confirms[1].onConfirm({ reason: "r" });
    expect(toasts[1].kind).toBe("ok");
    expect(toasts[1].message).toMatch(/released 3 of 4 contained process\(es\) across 2 host\(s\)/);
  });
});

describe("the approver is told the radius the request actually asks for", () => {
  function request(extra: Partial<ApprovalRequest>): ApprovalRequest {
    return {
      id: "req-1",
      action: "quarantine",
      requester: "alice",
      status: "pending",
      reason: "beaconing",
      ...extra,
    } as ApprovalRequest;
  }

  it("names the targeted hosts instead of the whole tenant", async () => {
    const { api, confirms } = harness({ isFleetConsole: true });
    await api.decideOnApproval(request({ scope: "fleet", targets: ["agent-a"], radius: "agent-a" }), true);
    const confirm = confirms[0];

    expect(confirm.body).toMatch(/agent-a \(1 host\)/);
    // The whole point: this approver is NOT approving the estate.
    expect(confirm.body).not.toMatch(/entire tenant/i);
    expect(confirm.body).toMatch(/alice asked to quarantine/);
  });

  it("says the entire tenant only when the request really is untargeted", async () => {
    const { api, confirms } = harness({ isFleetConsole: true });
    // Untargeted: the server omits `targets` and states the radius in words.
    await api.decideOnApproval(request({ scope: "fleet", radius: "the whole tenant" }), true);
    expect(confirms[0].body).toMatch(/the entire tenant/i);
  });

  it("does not invent a radius the server no longer knows", async () => {
    // The control plane's radius ledger is bounded: when a request's radius has
    // aged out it publishes neither field rather than claim one. Printing "the
    // entire tenant" there would be a fact the server refused to assert.
    const { api, confirms } = harness({ isFleetConsole: true });
    await api.decideOnApproval(request({ scope: "fleet" }), true);
    expect(confirms[0].body).toMatch(/did not report/i);
  });

  it("still names the single process for a targeted request", async () => {
    const { api, confirms } = harness({ isFleetConsole: true });
    await api.decideOnApproval(request({ scope: "target", exec_id: "abcdef0123456789", pid: 42 }), true);
    expect(confirms[0].body).toMatch(/abcdef012345\.\.\. \(pid 42\)/);
    expect(confirms[0].body).not.toMatch(/tenant/i);
  });
});
