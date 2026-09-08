import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setSelectedTenant } from "../lib/tenantScope";
import { forensicSnapshot, probeEndpoint } from "../features/choke/api";

/**
 * THE EVIDENCE FILE MUST NAME THE CUSTOMER THE CONSOLE IS SHOWING.
 *
 * The forensic snapshot is downloaded with a raw fetch, because its answer is a
 * blob and lib/api's funnel parses every response into JSON or text. That made
 * it the one request on this route that skipped the funnel's tenant scoping, so
 * a provider looking at customer B pressed "snapshot" and got the OPERATOR'S
 * DEFAULT customer's bundle — the control plane resolves a tenant-less request
 * to authz.DefaultTenant. Worse than a wrong reading on screen: a file that has
 * left the building carries no banner to correct it, and this estate has
 * already shipped that exact shape once (a PDF headed "all tenants" over one
 * customer's rows).
 *
 * These drive the real exported functions over a stubbed fetch, so what is
 * pinned is the URL that actually leaves the console.
 */
function recordPaths(): string[] {
  const paths: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      paths.push(String(input));
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
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

describe("the forensic snapshot is scoped to the customer on screen", () => {
  it("names the selected customer on the snapshot request", async () => {
    setSelectedTenant("globex");
    const paths = recordPaths();

    await forensicSnapshot();

    // Stated as the request contract it is, not as a leak it prevents today:
    // the control plane answers this path with a 501 stub and the single-tenant
    // engine has one tenant, so no server in this tree can currently hand back
    // another customer's bundle. The claim under test is that this helper names
    // the customer the console is showing, so it cannot drift from the funnel
    // it mirrors before the control plane implements the endpoint.
    expect(
      paths,
      "the snapshot request did not name the customer the console was showing"
    ).toEqual(["/api/choke/forensic-snapshot?tenant=globex"]);
  });

  it("leaves a tenant-bound operator's request byte for byte what it always was", async () => {
    // No selection is the single-tenant engine and every tenant-bound operator
    // on the control plane. Appending a tenant there would be a scope claim
    // nobody made.
    const paths = recordPaths();

    await forensicSnapshot();

    expect(paths).toEqual(["/api/choke/forensic-snapshot"]);
  });

  it("leaves the reachability probe unscoped, because it is exempt by design", async () => {
    // probeEndpoint IS an authenticated request — it names no credentials mode
    // and the Fetch default for a same-origin GET is `same-origin`, so it
    // carries the session cookie — but it never reads the response BODY, only
    // whether one arrived and with what status. No customer's rows reach the
    // operator through it, so there is nothing for a ?tenant= to mis-attribute;
    // and /api/whoami, one of the four HOST_ENDPOINTS it is called over, is in
    // tenantScope's UNSCOPED_PATHS because scoping it would ask the endpoint
    // that reports the server's own default to echo the console's guess back.
    // Pinned so the next reader tidying up raw fetches does not "fix" it.
    setSelectedTenant("globex");
    const paths = recordPaths();

    await probeEndpoint("/api/whoami");
    await probeEndpoint("/api/choke/state");

    expect(paths).toEqual(["/api/whoami", "/api/choke/state"]);
  });
});
