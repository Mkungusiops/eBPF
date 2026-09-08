import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * EVERY ENTRY LEARNS WHICH CUSTOMER IT IS SHOWING — not just the dashboard.
 *
 * The customer switcher was hydrated inside the SOC route: it read the roster,
 * adopted the persisted selection, and only then did the request funnel have a
 * tenant to name. This console ships FIVE HTML entries (vite.config.ts's rollup
 * input) and each boots its own React tree, so on /choke, /devices and /fleet —
 * the pages where containment is actually fired — nothing ever hydrated the
 * selection. Every read and every write went out tenant-less, which the control
 * plane resolves to the account's default customer (authz.DefaultTenant), with
 * no banner on screen saying so.
 *
 * These tests drive the SHELL's hydration (app/tenantHydration.ts, started by
 * app/render.tsx on every entry) over a stubbed fetch, and pin the URLs that
 * actually leave the console — including the ones that must NOT leave.
 *
 * Modules are re-imported per test because the barrier is module state that
 * exists once per page load, and a test that inherited a settled barrier from
 * the previous one would prove nothing about the window this closes.
 */

interface Call {
  url: string;
  method: string;
}

interface Stub {
  calls: Call[];
  urls: () => string[];
}

/** Answers whoami/tenants like a provider account, everything else with `{}`. */
function stubProviderServer(options: { crossTenant?: boolean; offered?: string[] } = {}): Stub {
  const calls: Call[] = [];
  const crossTenant = options.crossTenant ?? true;
  const offered = options.offered ?? ["acme-corp", "globex"];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({ url, method: (init?.method ?? "GET").toUpperCase() });
      const body =
        url === "/api/whoami"
          ? { user: "msoc", cross_tenant: crossTenant, viewing_tenant: "acme-corp" }
          : url === "/api/tenants"
            ? { tenants: offered.map((tenantId) => ({ tenant_id: tenantId, agents: 1, agents_fresh: 1 })) }
            : { ok: true };
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    })
  );
  return { calls, urls: () => calls.map((call) => call.url) };
}

/** A fresh console: the store, the funnel and the shell's boot driver. */
async function loadConsole() {
  vi.resetModules();
  const scope = await import("../lib/tenantScope");
  const api = await import("../lib/api");
  const hydration = await import("../app/tenantHydration");
  return { scope, api, hydration };
}

beforeEach(() => {
  window.localStorage.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe("a provider's selection reaches a page that is not the dashboard", () => {
  it("names the remembered customer on the first read /choke issues", async () => {
    // The blocker, in one test. The operator switched to globex on the
    // dashboard last session; this is the choke gateway booting.
    window.localStorage.setItem("soc.selectedTenant", JSON.stringify("globex"));
    const stub = stubProviderServer();
    const { api, hydration } = await loadConsole();

    // Exactly what the shell does (app/render.tsx) and then what the route's
    // first effect does, in the same tick — the route does not wait for the
    // shell, and must not have to.
    void hydration.startTenantScopeHydration();
    await api.getJSON("/api/choke/circuits");

    expect(
      stub.urls(),
      "the choke gateway read the account's default customer while the console was pointed at globex"
    ).toEqual(["/api/whoami", "/api/tenants", "/api/choke/circuits?tenant=globex"]);
  });

  it("holds the page's reads until the roster has confirmed the customer", async () => {
    // The confirmation is two sequential round trips. Anything issued inside
    // that window and NOT held would go out tenant-less and come back as the
    // default customer's rows, under a banner about to name another one.
    window.localStorage.setItem("soc.selectedTenant", JSON.stringify("globex"));
    const stub = stubProviderServer();
    const { api, hydration } = await loadConsole();

    void hydration.startTenantScopeHydration();
    const read = api.getJSON("/api/alerts?limit=50");
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(
      stub.urls(),
      "a page read escaped while the console still did not know which customer it was for"
    ).not.toContain("/api/alerts?limit=50");

    await read;
    expect(stub.urls()).toContain("/api/alerts?limit=50&tenant=globex");
  });

  it("forgets a remembered customer the roster no longer offers, and scopes nothing", async () => {
    // Grants are revoked and customers are offboarded. Scoping to a customer
    // this account cannot reach reads back 404, which the console renders as an
    // empty page — indistinguishable from a quiet customer.
    window.localStorage.setItem("soc.selectedTenant", JSON.stringify("offboarded-corp"));
    const stub = stubProviderServer({ offered: ["acme-corp"] });
    const { api, scope, hydration } = await loadConsole();

    await hydration.startTenantScopeHydration();
    await api.getJSON("/api/choke/circuits");

    expect(scope.selectedTenantNow()).toBeNull();
    expect(stub.urls()).toEqual(["/api/whoami", "/api/tenants", "/api/choke/circuits"]);
    // Forgetting is an ANSWER, so containment is not held back afterwards: the
    // console is honestly pointed at the customer the server resolves for it.
    expect(scope.tenantScopeRefusal()).toBeNull();
  });
});

describe("a tenant-bound operator's console is untouched", () => {
  it("asks nothing at boot and sends the URLs it always sent", async () => {
    // No remembered customer — every single-tenant console, and every operator
    // who has never been offered a switcher. There is no claim to confirm, so
    // the shell must not add a whoami to every page, must not ask for a roster
    // the control plane refuses by design, and must not open a barrier that
    // delays the page's first paint.
    const stub = stubProviderServer();
    const { api, hydration } = await loadConsole();

    await hydration.startTenantScopeHydration();
    await api.getJSON("/api/choke/circuits");
    await api.postJSON("/api/choke/jail", { pids: [4242], action: "sever" });

    expect(stub.urls(), "the shell added requests to a console that had nothing to hydrate").toEqual([
      "/api/choke/circuits",
      "/api/choke/jail"
    ]);
  });

  it("never asks for the roster when whoami says the account is not cross-tenant", async () => {
    // A shared browser profile: a provider's remembered customer, and a
    // tenant-bound operator signing in on the same machine. The claim cannot
    // apply to them, and /api/tenants would be a 404 in the network log of a
    // console that is working perfectly.
    window.localStorage.setItem("soc.selectedTenant", JSON.stringify("globex"));
    const stub = stubProviderServer({ crossTenant: false });
    const { api, scope, hydration } = await loadConsole();

    await hydration.startTenantScopeHydration();
    await api.getJSON("/api/choke/circuits");

    expect(stub.urls()).toEqual(["/api/whoami", "/api/choke/circuits"]);
    expect(scope.selectedTenantNow(), "a tenant-bound operator was scoped to another account's customer").toBeNull();
    expect(scope.tenantScopeRefusal(), "a tenant-bound operator's writes were held").toBeNull();
  });
});
