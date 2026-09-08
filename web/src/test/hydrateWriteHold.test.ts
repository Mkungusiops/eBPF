import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * A WRITE MAY NOT LEAVE WHILE THE CONSOLE CANNOT SAY WHOSE HOST IT REACHES.
 *
 * Hydration is asynchronous: confirming the customer this browser remembers
 * takes a whoami and a roster read. A containment write issued inside that
 * window carries no tenant, and the control plane resolves a tenant-less write
 * to the account's DEFAULT customer (authorizeRespondAs) — a sever, a jail or a
 * fleet kill switch landing on a host nobody named, which is the defect this
 * whole line of work exists to prevent.
 *
 * The rule these tests pin, in the two halves it has:
 *
 *   WHILE THE ANSWER IS COMING, the write WAITS. It is not refused: nothing has
 *   gone wrong, the operator's intent is unambiguous, and one round trip later
 *   the request goes out naming the right customer. Refusing here would make a
 *   correct console reject correct containment for the first second of its life.
 *
 *   WHEN THE ANSWER NEVER COMES, the write is REFUSED. Reads are released
 *   unscoped at that point — the server's own default is a real scope, the
 *   shell banner says the remembered customer could not be confirmed, and a page
 *   showing nothing teaches an operator nothing — but there is no honest
 *   version of firing containment at whichever customer the server picks for a
 *   console that was told to point somewhere else.
 */

interface Deferred {
  resolve: (body: unknown) => void;
  reject: (error: Error) => void;
}

interface Stub {
  urls: () => string[];
  /** Hold the next answer for `path` until the test releases it. */
  defer: (path: string) => Deferred;
}

function stubServer(routes: Record<string, unknown> = {}): Stub {
  const urls: string[] = [];
  const deferred = new Map<string, Deferred>();
  const bodyFor = (url: string): unknown => {
    if (url in routes) return routes[url];
    if (url === "/api/whoami") return { user: "msoc", cross_tenant: true, viewing_tenant: "acme-corp" };
    if (url === "/api/tenants") return { tenants: [{ tenant_id: "globex", agents: 1, agents_fresh: 1 }] };
    return { ok: true };
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      urls.push(url);
      const hold = deferred.get(url);
      const body = hold
        ? await new Promise<unknown>((resolve, reject) => {
            deferred.set(url, { resolve, reject });
            hold.resolve(undefined);
          })
        : bodyFor(url);
      const status = body && typeof body === "object" && "__status" in (body as Record<string, unknown>)
        ? Number((body as Record<string, unknown>).__status)
        : 200;
      return new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" }
      });
    })
  );
  return {
    urls: () => urls,
    defer: (path: string) => {
      // The placeholder is replaced by the real deferred the moment the request
      // arrives; until then its resolve() is the "request has landed" signal.
      const placeholder: Deferred = { resolve: () => {}, reject: () => {} };
      deferred.set(path, placeholder);
      return {
        resolve: (body: unknown) => deferred.get(path)?.resolve(body),
        reject: (error: Error) => deferred.get(path)?.reject(error)
      };
    }
  };
}

async function loadConsole() {
  vi.resetModules();
  const scope = await import("../lib/tenantScope");
  const api = await import("../lib/api");
  const hydration = await import("../app/tenantHydration");
  return { scope, api, hydration };
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

beforeEach(() => {
  window.localStorage.clear();
  window.localStorage.setItem("soc.selectedTenant", JSON.stringify("globex"));
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  window.localStorage.clear();
});

describe("containment fired while the customer is still being confirmed", () => {
  it("waits, and then names the customer the console was pointed at", async () => {
    const stub = stubServer();
    const whoami = stub.defer("/api/whoami");
    const { api, hydration } = await loadConsole();

    void hydration.startTenantScopeHydration();
    // The operator was already on /choke and pressed sever before the roster
    // came back — the drill panel does not know a barrier exists.
    const sever = api.postJSON("/api/choke/jail", { pids: [4242], action: "sever" });
    await settle();

    expect(
      stub.urls(),
      "a containment write left the console while it still did not know which customer it was for"
    ).toEqual(["/api/whoami"]);

    whoami.resolve({ user: "msoc", cross_tenant: true, viewing_tenant: "acme-corp" });
    await sever;

    expect(stub.urls()).toEqual(["/api/whoami", "/api/tenants", "/api/choke/jail?tenant=globex"]);
  });
});

describe("containment fired when the customer could not be confirmed", () => {
  it("is refused rather than sent to whichever customer the server defaults to", async () => {
    // The roster answered 500. adoptPersistedTenant neither adopts nor forgets
    // on an answer like this (a flaky poll must not silently drop a working
    // selection), so the console is left remembering globex and scoping
    // nothing — exactly the state in which a tenant-less sever would land on
    // the account's default customer.
    const stub = stubServer({ "/api/tenants": { __status: 500, error: "boom" } });
    const { api, hydration } = await loadConsole();

    await hydration.startTenantScopeHydration();

    await expect(api.postJSON("/api/choke/jail", { pids: [4242], action: "sever" })).rejects.toThrow(
      /cannot confirm which customer/
    );
    expect(stub.urls(), "the refused containment was sent anyway").not.toContain("/api/choke/jail");

    // Reads are NOT refused: an unreadable page tells the operator nothing, and
    // the shell banner says the scope is unconfirmed above every row it shows.
    await api.getJSON("/api/alerts?limit=50");
    expect(stub.urls()).toContain("/api/alerts?limit=50");
  });

  it("sends the containment once an operator names a customer themselves", async () => {
    // The way out of the hold. Naming a customer is an answer, so the write is
    // released — and it is released to the customer that was named, not to the
    // one this browser remembered and could not confirm.
    const stub = stubServer({ "/api/tenants": { __status: 500, error: "boom" } });
    const { api, scope, hydration } = await loadConsole();

    await hydration.startTenantScopeHydration();
    scope.setSelectedTenant("acme-corp");
    await api.postJSON("/api/choke/jail", { pids: [4242], action: "sever" });

    expect(stub.urls()).toContain("/api/choke/jail?tenant=acme-corp");
  });

  it("refuses the write when the confirming reads never answer at all", async () => {
    // A hung control plane. The barrier is bounded (TENANT_HYDRATION_DEADLINE_MS)
    // so the page is not held blank forever, and the release is asymmetric:
    // reads go out unscoped, writes stay refused.
    vi.useFakeTimers();
    const stub = stubServer();
    stub.defer("/api/whoami");
    const { api, hydration } = await loadConsole();

    void hydration.startTenantScopeHydration();
    const sever = api.postJSON("/api/choke/jail", { pids: [4242], action: "sever" });
    const refused = expect(sever).rejects.toThrow(/cannot confirm which customer/);
    await vi.advanceTimersByTimeAsync(hydration.TENANT_HYDRATION_DEADLINE_MS + 1);
    await refused;

    expect(stub.urls()).toEqual(["/api/whoami"]);
  });
});
