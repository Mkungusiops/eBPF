import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  fetchSocSnapshot,
  recordResponseAuthority,
  responseAuthorityNow
} from "../features/soc/api";

/**
 * `can_respond` is the control plane's answer to "may THIS principal contain
 * anything?", and until 2026-09-02 normalizeWhoami threw it away.
 *
 * The cost was measured live by the persona probes: an operator the control
 * plane 404s on every containment route was shown a fully armed kill-switch
 * surface, and found out they were read-only by pressing sever on a live host
 * and watching nothing happen. A kill-switch that does nothing is worse than
 * no kill-switch — the operator believes enforcement is bypassed.
 *
 * The three-valued contract is the whole subtlety, so all three are pinned
 * here: true (armed), false (withheld, in the language of permission), and
 * null — the single-tenant engine, which has no notion of an operator who may
 * not contain and therefore publishes no field at all. Reading that silence as
 * denial would strip a working console of controls it legitimately owns.
 */
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" }
  });
}

function stubEstate(whoami: Record<string, unknown> | { fail: true }): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.startsWith("/api/whoami")) {
        return "fail" in whoami ? jsonResponse({ error: "upstream" }, 503) : jsonResponse(whoami);
      }
      if (path.startsWith("/api/version") || path.startsWith("/api/health")) {
        return jsonResponse({});
      }
      return jsonResponse([]);
    })
  );
}

beforeEach(() => {
  // The authority is module state shared by every surface, so each test starts
  // from "the server has not said".
  recordResponseAuthority(null);
});

afterEach(() => {
  vi.unstubAllGlobals();
  recordResponseAuthority(null);
});

describe("whoami's can_respond survives normalisation", () => {
  it("carries a read-only operator's refusal through to the console", async () => {
    stubEstate({ user: "viewer@acme", host: "cp", can_respond: false, can_push_policy: false });
    const read = await fetchSocSnapshot();
    expect((read.snapshot.whoami as { canRespond?: boolean | null }).canRespond).toBe(false);
    expect(responseAuthorityNow()).toBe(false);
  });

  it("carries a responder's permission through", async () => {
    stubEstate({ user: "analyst@acme", host: "cp", can_respond: true, can_push_policy: true });
    const read = await fetchSocSnapshot();
    expect((read.snapshot.whoami as { canRespond?: boolean | null }).canRespond).toBe(true);
    expect(responseAuthorityNow()).toBe(true);
  });

  it("reads a server that never mentions the field as null, not as a refusal", async () => {
    // The single-tenant engine. It has no principals to refuse, so absence must
    // leave every control it owns exactly where it was.
    stubEstate({ user: "operator", host: "sensor-1" });
    const read = await fetchSocSnapshot();
    expect((read.snapshot.whoami as { canRespond?: boolean | null }).canRespond).toBeNull();
    expect(responseAuthorityNow()).toBeNull();
  });

  it("does not re-arm containment for a read-only account when whoami fails", async () => {
    stubEstate({ user: "viewer@acme", host: "cp", can_respond: false });
    await fetchSocSnapshot();
    expect(responseAuthorityNow()).toBe(false);

    // A 503 normalises to the empty whoami, whose canRespond is null. Publishing
    // that would read as "the server did not say" — permitted — so one flaky
    // poll would rearm the kill-switch for an account the server refuses.
    stubEstate({ fail: true });
    await fetchSocSnapshot();
    expect(responseAuthorityNow()).toBe(false);
  });
});
