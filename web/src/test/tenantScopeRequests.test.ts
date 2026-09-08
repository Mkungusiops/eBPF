import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  adoptPersistedTenant,
  applyChokeAction,
  fetchSocSnapshot,
  jailSocAlert,
  normalizeAlert,
  recordResponseAuthority,
  selectedTenantNow,
  setSelectedTenant,
  tenantScopedPath
} from "../features/soc/api";

/**
 * WHICH CUSTOMER EVERY REQUEST IS ABOUT.
 *
 * A cross-tenant (provider) account belongs to no tenant, so the control plane
 * resolves each tenant-less request to the ONE customer stamped on the account
 * (authz.DefaultTenant). Both the read plane (authorizeRead) and the write
 * plane (authorizeRespondAs) read `?tenant=` from the query string, and until
 * the switcher existed the console named a tenant on no request it made:
 * `grep -rn "tenant=" web/src` found nothing.
 *
 * The dangerous half is not the dashboard. A console that re-scopes its panels
 * but sends containment unscoped kills a process for a customer nobody is
 * looking at, and reports success — which is the failure the cross-tenant
 * responder persona probe was written for. So reads and writes are pinned here
 * together, against the ONE accessor both go through: if they could drift, the
 * screen and the kill-switch could be aimed at two different customers.
 */

interface Recorded {
  paths: string[];
}

function mockApi(handler: (path: string) => unknown = () => []): Recorded {
  const recorded: Recorded = { paths: [] };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      recorded.paths.push(path);
      return new Response(JSON.stringify(handler(path)), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    })
  );
  return recorded;
}

const PROVIDER_WHOAMI = {
  user: "msoc@provider",
  host: "all tenants",
  cross_tenant: true,
  tenants: [],
  viewing_tenant: "acme-corp",
  can_respond: true
};

beforeEach(() => {
  window.localStorage.clear();
  setSelectedTenant(null);
  // Containment is refused while the console does not know what the account
  // may do, so an unanswered authority would make the write tests pass for the
  // wrong reason — no request at all rather than a correctly scoped one.
  recordResponseAuthority(true);
});

afterEach(() => {
  vi.unstubAllGlobals();
  setSelectedTenant(null);
  window.localStorage.clear();
});

describe("the selected customer travels on the request, not in the payload", () => {
  it("leaves every path untouched when no customer has been selected", () => {
    // The single-tenant engine has no tenants at all, and a tenant-bound
    // operator on the control plane holds exactly one. Both must keep sending
    // the requests they always sent.
    expect(tenantScopedPath("/api/alerts?limit=1000")).toBe("/api/alerts?limit=1000");
    expect(tenantScopedPath("/api/choke/jail")).toBe("/api/choke/jail");
  });

  it("names the customer on a bare path and on one that already has a query", () => {
    setSelectedTenant("globex");
    expect(tenantScopedPath("/api/choke/jail")).toBe("/api/choke/jail?tenant=globex");
    expect(tenantScopedPath("/api/alerts?limit=1000")).toBe("/api/alerts?limit=1000&tenant=globex");
  });

  it("never scopes the reads that describe the session rather than a customer", () => {
    // whoami answers about the principal, version about the build, and
    // /api/tenants about which customers this account may reach. None is
    // tenant-scoped server-side, so a tenant on them would state a scope the
    // endpoint does not honour.
    setSelectedTenant("globex");
    expect(tenantScopedPath("/api/whoami")).toBe("/api/whoami");
    expect(tenantScopedPath("/api/version")).toBe("/api/version");
    expect(tenantScopedPath("/api/tenants")).toBe("/api/tenants");
  });
});

describe("a snapshot poll reads the customer on screen", () => {
  it("names the selected customer on every feed", async () => {
    setSelectedTenant("globex");
    const recorded = mockApi((path) => (path.includes("/api/whoami") ? PROVIDER_WHOAMI : []));
    await fetchSocSnapshot();

    for (const feed of ["/api/alerts", "/api/events", "/api/decisions", "/api/policies", "/api/system-health"]) {
      const asked = recorded.paths.find((path) => path.startsWith(feed));
      expect(asked, `${feed} was never read`).toBeDefined();
      expect(asked, `${feed} was read without naming the customer on screen`).toContain("tenant=globex");
    }
  });

  it("captions the snapshot with the customer its rows were read for", async () => {
    // The banner, the host pill and every exported artefact read this field.
    // Taking it from the wire alone would caption a switched console with the
    // server's default customer while showing another customer's rows.
    setSelectedTenant("globex");
    mockApi((path) => (path.includes("/api/whoami") ? PROVIDER_WHOAMI : []));
    const read = await fetchSocSnapshot();

    expect((read.snapshot.whoami as { viewingTenant?: string }).viewingTenant).toBe("globex");
    // The server's own answer survives untouched beside it: it is how the
    // route knows what an UNSCOPED connection — the SSE tail — is carrying.
    expect((read.snapshot.whoami as { serverTenant?: string }).serverTenant).toBe("acme-corp");
  });

  it("drops a poll that was answered for the customer the operator just left", async () => {
    // The caller merges a poll into the buffer the live stream is filling
    // (mergeSocSnapshot), so rows handed over here are ADDED to whatever the
    // newly selected customer already has. One customer's alerts sitting in
    // another customer's queue are not merely a wrong tile: they are
    // selectable, and containment fired from one is aimed by this console at
    // the customer now selected.
    setSelectedTenant("acme-corp");
    mockApi((path) => {
      if (path.includes("/api/whoami")) return PROVIDER_WHOAMI;
      if (path.startsWith("/api/alerts")) {
        // The switch lands while the poll is in flight.
        setSelectedTenant("globex");
        return [{ severity: "critical", title: "acme incident", exec_id: "e1", timestamp: new Date().toISOString() }];
      }
      return [];
    });

    const read = await fetchSocSnapshot();

    expect(read.snapshot.alerts, "the previous customer's alerts were handed to the new customer's dashboard").toHaveLength(0);
    // Identity survives — dropping it would flash "localhost" over the top bar
    // on every switch — and is captioned with the customer now selected.
    expect(read.snapshot.whoami.user).toBe("msoc@provider");
    expect((read.snapshot.whoami as { viewingTenant?: string }).viewingTenant).toBe("globex");
    // Nothing failed, so nothing may be reported as an outage: a notices strip
    // lighting up on a customer switch is a false alarm.
    expect(read.errors).toEqual({});
  });
});

describe("containment is aimed at the customer on screen", () => {
  it("names the selected customer on a jail fired from an alert", async () => {
    setSelectedTenant("globex");
    const recorded = mockApi(() => ({ ok: true }));
    await jailSocAlert({
      alert: normalizeAlert({ exec_id: "YWJj", severity: "critical", title: "t", timestamp: new Date().toISOString() }),
      action: "sever",
      reason: "pinned by test",
      descendants: false
    });

    expect(recorded.paths).toContain("/api/choke/jail?tenant=globex");
  });

  it("names the selected customer on every rung of the ladder, release included", async () => {
    setSelectedTenant("globex");
    const recorded = mockApi(() => ({ ok: true, detail: "applied" }));
    await applyChokeAction("quarantine", { execId: "abc" }, "pinned by test");
    await applyChokeAction("pristine", { execId: "abc" }, "pinned by test");

    expect(recorded.paths).toContain("/api/choke/manual?tenant=globex");
    expect(recorded.paths).toContain("/api/choke/thaw?tenant=globex");
  });

  it("sends the unscoped write a single-tenant deployment expects", async () => {
    // The engine has no tenants and the control plane resolves a tenant-less
    // write to the operator's own default. A stray parameter here would be a
    // scope claim on a console that never offered a switcher.
    const recorded = mockApi(() => ({ ok: true, detail: "applied" }));
    await applyChokeAction("throttle", { execId: "abc" }, "pinned by test");

    expect(recorded.paths).toContain("/api/choke/manual");
  });
});

describe("a persisted customer is trusted only against a roster that answered", () => {
  it("adopts a stored customer the roster still offers", () => {
    window.localStorage.setItem("soc.selectedTenant", JSON.stringify("globex"));
    adoptPersistedTenant({
      answered: true,
      offered: [
        { tenantId: "acme-corp", agents: 2, agentsFresh: 2 },
        { tenantId: "globex", agents: 1, agentsFresh: 0 }
      ]
    });

    expect(selectedTenantNow()).toBe("globex");
  });

  it("forgets a stored customer the roster no longer offers, and scopes nothing", () => {
    // Grants are revoked and customers are offboarded. Scoping to a customer
    // this account can no longer reach reads back as 404 — which the console
    // renders as an empty dashboard, indistinguishable from a quiet customer.
    window.localStorage.setItem("soc.selectedTenant", JSON.stringify("offboarded-corp"));
    adoptPersistedTenant({ answered: true, offered: [{ tenantId: "acme-corp", agents: 2, agentsFresh: 2 }] });

    expect(selectedTenantNow(), "a customer that is no longer offered still scoped the console").toBeNull();
    expect(tenantScopedPath("/api/alerts")).toBe("/api/alerts");
    expect(
      window.localStorage.getItem("soc.selectedTenant"),
      "the unreachable customer was left to be adopted by a later read"
    ).toBeNull();
  });

  it("neither adopts nor forgets when the roster did not answer", () => {
    // A refusal, a 500 or an aborted read is no evidence either way. Dropping
    // a working selection on a flaky poll would silently move the console to
    // another customer mid-shift.
    window.localStorage.setItem("soc.selectedTenant", JSON.stringify("globex"));
    adoptPersistedTenant({ answered: false, offered: [] });

    expect(selectedTenantNow()).toBeNull();
    expect(window.localStorage.getItem("soc.selectedTenant")).toBe(JSON.stringify("globex"));
  });
});
