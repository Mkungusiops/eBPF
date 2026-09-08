import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getJSON, putJSON } from "../lib/api";
import { setSelectedTenant } from "../lib/tenantScope";
import { getCircuits, jailProcesses } from "../features/choke/api";
import { writeKillSwitch } from "../features/fleet/api";
import { fetchEstateSummary } from "../features/soc/estate";

/**
 * ONE PLACE NAMES THE CUSTOMER, AND IT NAMES IT ON EVERYTHING.
 *
 * The customer switcher was built inside the SOC feature, and only that
 * feature's own reads carried the selection. Every other surface on the same
 * route — the choke gateway, devices, fleet, settings — kept issuing both its
 * reads AND ITS WRITES unscoped, which the control plane resolves to the
 * operator's default customer (authz.DefaultTenant, via authorizeRead and
 * authorizeRespondAs). So a provider could select customer B, read B's alerts
 * under a banner promising that "any containment fired from this console lands
 * there", press sever, and contain a process belonging to customer A. Scoping
 * the reads while leaving the writes unscoped is worse than scoping neither:
 * the operator has been given a reason to trust the aim.
 *
 * The fix is the one that cannot be forgotten by the next endpoint: the scope
 * is applied in lib/api.ts's request funnel, which every one of those features
 * goes through, rather than at each call site. These tests drive the REAL
 * feature functions over a stubbed fetch so what is pinned is the URL that
 * actually leaves the console — not a helper that a caller may or may not have
 * remembered to use.
 */

function recordPaths(body: unknown = {}): string[] {
  const paths: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      paths.push(String(input));
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    })
  );
  return paths;
}

beforeEach(() => {
  window.localStorage.clear();
  setSelectedTenant(null);
});

afterEach(() => {
  vi.unstubAllGlobals();
  setSelectedTenant(null);
  window.localStorage.clear();
});

describe("the selected customer reaches every feature's requests, reads and writes alike", () => {
  it("names the customer on a read issued by a feature that has never heard of the switcher", async () => {
    setSelectedTenant("globex");
    const paths = recordPaths([]);

    await getCircuits();

    expect(
      paths,
      "the choke gateway read the ladder for the operator's default customer while the console showed another"
    ).toEqual(["/api/choke/circuits?tenant=globex"]);
  });

  it("names the customer on the containment those same features fire", async () => {
    // THE BLOCKER. These are real enforcement: a jail kills or freezes a
    // process on a real host, and the fleet kill switch does it to every host
    // in one customer's estate at once. Which customer that is comes from the
    // URL and from nowhere else — the write handlers do not read a tenant out
    // of the body.
    setSelectedTenant("globex");
    const paths = recordPaths({ ok: true });

    await jailProcesses({ pids: [4242], action: "sever", reason: "pinned by test" });
    await writeKillSwitch(true, null, "pinned by test");
    await putJSON("/api/settings/retention", { days: 30 });

    expect(paths).toEqual([
      "/api/choke/jail?tenant=globex",
      "/api/fleet/kill-switch?tenant=globex",
      "/api/settings/retention?tenant=globex"
    ]);
  });

  it("keeps the customer out of the requests that are about the account or the whole estate", async () => {
    setSelectedTenant("globex");
    const paths = recordPaths({});

    await getJSON("/api/whoami");
    await getJSON("/api/version");
    await getJSON("/api/tenants");
    await fetchEstateSummary(1440);

    expect(paths).toEqual([
      // The principal, the build, and the roster of customers this ACCOUNT may
      // reach: none is tenant-scoped server-side, and a tenant on the roster
      // would narrow the list you switch with to the customer you already
      // switched to.
      "/api/whoami",
      "/api/version",
      "/api/tenants",
      // The one that matters most. The estate summary reads EVERY customer this
      // principal can reach; scoped to one it would be a single customer's
      // numbers wearing an estate label, directly above the per-customer
      // breakdown that says otherwise.
      "/api/estate/summary?window_min=1440"
    ]);
  });

  it("leaves a tenant-bound operator's requests exactly as they were", async () => {
    // No selection: the single-tenant engine, which has no tenants at all, and
    // every tenant-bound operator on the control plane, whose one tenant the
    // server resolves for them. A stray parameter here would be a scope claim
    // from a console that never offered a switcher.
    const paths = recordPaths({ ok: true });

    await getCircuits();
    await jailProcesses({ pids: [4242], action: "sever", reason: "pinned by test" });
    await writeKillSwitch(true, null, "pinned by test");
    await getJSON("/api/whoami");

    expect(paths).toEqual([
      "/api/choke/circuits",
      "/api/choke/jail",
      "/api/fleet/kill-switch",
      "/api/whoami"
    ]);
  });
});

describe("a switch that lands while a write is being prepared", () => {
  it("cannot send the containment to the customer the operator has left", async () => {
    // Between deciding to contain and the request going out there is always a
    // gap — a confirmation dialog, a reason typed into a modal, an await on the
    // process detail the drill panel is still fetching. If the tenant were
    // captured when the surface opened, a switch inside that gap would leave
    // the request aimed at the customer no longer on screen while the console
    // has already re-scoped, re-polled and cleared its selection state around
    // the new one. The funnel reads the selection as the request leaves, so the
    // only customer a write can reach is the one the console is showing.
    setSelectedTenant("acme-corp");
    const paths = recordPaths({ ok: true });

    let confirm: () => void = () => {};
    const operatorConfirmed = new Promise<void>((resolve) => {
      confirm = resolve;
    });
    const pending = operatorConfirmed.then(() =>
      jailProcesses({ pids: [4242], action: "sever", reason: "pinned by test" })
    );

    setSelectedTenant("globex");
    confirm();
    await pending;

    expect(paths).toEqual(["/api/choke/jail?tenant=globex"]);
    expect(paths.join(" "), "the containment was aimed at the customer the operator had left").not.toContain(
      "acme-corp"
    );
  });
});
