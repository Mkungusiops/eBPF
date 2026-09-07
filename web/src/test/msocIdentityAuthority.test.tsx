import { render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * LOADING IS NOT PERMISSION.
 *
 * `can_respond` is three-valued on the wire — yes, no, and "this deployment has
 * no such concept" (the single-tenant engine, whose silence must read as
 * permitted). The console collapsed a FOURTH state into that last one: nobody
 * has answered yet. The module state started at `null`, `null` means permitted,
 * and so every containment surface — soc, choke and devices — painted armed for
 * a read-only account for as long as the first whoami took. The operator's first
 * evidence that they may not contain was pressing sever on a live host.
 *
 * So the predicate now starts at "loading", which withholds, and only a whoami
 * that actually ANSWERED can move it. The distinction between the two withheld
 * states is load-bearing in the other direction too: telling a responder their
 * account is read-only for the first second of every session is its own false
 * statement, so `readOnlyAccount` stays strictly "the server said no" and
 * `pending` carries the other reason.
 *
 * The last two tests are the ones that make this end-to-end rather than a
 * rendering convention: the gate is enforced on the containment REQUEST, in the
 * one place every jail passes through, so a surface that gated on the wrong
 * flag still cannot fire one.
 */

type Api = typeof import("../features/soc/api");

/** A fresh module instance, so the pre-answer state is observable. */
async function freshApi(): Promise<Api> {
  vi.resetModules();
  return import("../features/soc/api");
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function stubWhoami(whoami: Record<string, unknown> | { fail: true }): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.startsWith("/api/whoami")) {
        return "fail" in whoami ? jsonResponse({ error: "upstream" }, 503) : jsonResponse(whoami);
      }
      if (path.startsWith("/api/version") || path.startsWith("/api/health")) return jsonResponse({});
      return jsonResponse([]);
    })
  );
}

/** Render the hook and report what it told the surface. */
function readAuthority(api: Api): {
  pending: boolean;
  withheld: boolean;
  readOnlyAccount: boolean;
  withheldReason: string | null;
} {
  let seen = {} as ReturnType<Api["useResponseAuthority"]>;
  function Probe() {
    seen = api.useResponseAuthority();
    return null;
  }
  render(<Probe />);
  return {
    pending: seen.pending,
    withheld: seen.withheld,
    readOnlyAccount: seen.readOnlyAccount,
    withheldReason: seen.withheldReason
  };
}

beforeEach(() => {
  vi.unstubAllGlobals();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the response-authority predicate before whoami has answered", () => {
  it("reports loading, and withholds while it does", async () => {
    const api = await freshApi();
    expect(api.responseAuthorityNow(), "the console starts by assuming permission").toBe("loading");

    const gate = readAuthority(api);
    expect(gate.pending).toBe(true);
    expect(gate.withheld, "every containment control paints armed before the server has answered").toBe(true);
    // …but not by claiming the account is read-only, which for a responder is
    // simply untrue.
    expect(gate.readOnlyAccount).toBe(false);
    expect(gate.withheldReason).toBe(api.AUTHORITY_PENDING_REASON);
  });

  it("stays withheld when the first whoami fails outright", async () => {
    const api = await freshApi();
    stubWhoami({ fail: true });
    await api.fetchSocSnapshot();
    // A console whose whoami never succeeded does not know what this account
    // may do. Not knowing is not permission.
    expect(api.responseAuthorityNow()).toBe("loading");
  });
});

describe("the response-authority predicate after whoami answers", () => {
  it("treats a server that never mentions the field as permitted", async () => {
    const api = await freshApi();
    // The single-tenant engine: no principals to refuse, so it publishes
    // nothing. Reading that as denial would strip a working console of controls
    // it legitimately owns.
    stubWhoami({ user: "operator", host: "sensor-1" });
    await api.fetchSocSnapshot();

    expect(api.responseAuthorityNow()).toBeNull();
    const gate = readAuthority(api);
    expect(gate.pending).toBe(false);
    expect(gate.withheld).toBe(false);
    expect(gate.withheldReason).toBeNull();
  });

  it("refuses when can_respond is false, in the language of permission", async () => {
    const api = await freshApi();
    stubWhoami({ user: "viewer@acme", host: "cp", can_respond: false });
    await api.fetchSocSnapshot();

    const gate = readAuthority(api);
    expect(gate.readOnlyAccount).toBe(true);
    expect(gate.withheld).toBe(true);
    expect(gate.withheldReason).toBe(api.READ_ONLY_ACCOUNT_REASON);
  });
});

describe("the gate reaches the request, not only the button", () => {
  it("does not send a jail while the answer is still in flight", async () => {
    const api = await freshApi();
    const sent = vi.fn(async () => jsonResponse({}));
    vi.stubGlobal("fetch", sent);

    const alert = api.normalizeAlert({ exec_id: "ZXhlYy0x", severity: "critical", title: "t", description: "d" });
    await expect(
      api.jailSocAlert({ alert, action: "sever", reason: "because", descendants: false })
    ).rejects.toThrow(/Checking what this account may do/);
    expect(sent, "a containment request left the console before whoami answered").not.toHaveBeenCalled();
  });

  it("does not send a ladder action for an account the server refused", async () => {
    const api = await freshApi();
    stubWhoami({ user: "viewer@acme", host: "cp", can_respond: false });
    await api.fetchSocSnapshot();

    const sent = vi.fn(async () => jsonResponse({ ok: true }));
    vi.stubGlobal("fetch", sent);
    const result = await api.applyChokeAction("sever", { execId: "exec-1" }, "because");

    expect(result.ok).toBe(false);
    expect(result.detail).toBe(api.READ_ONLY_ACCOUNT_REASON);
    expect(sent, "a read-only account's ladder action reached the control plane").not.toHaveBeenCalled();
  });
});
