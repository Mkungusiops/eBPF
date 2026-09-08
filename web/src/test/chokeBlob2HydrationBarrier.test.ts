import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { beginTenantHydration, setSelectedTenant } from "../lib/tenantScope";
import { forensicSnapshot } from "../features/choke/api";

/**
 * THE EVIDENCE BUNDLE MUST WAIT FOR THE CONSOLE TO KNOW WHOSE IT IS.
 *
 * chokeBlobScope pins that the snapshot NAMES the selected customer. That is
 * only half of what lib/api.ts does for every other request: the selection
 * takes two round trips (whoami, then the roster) to become trustworthy, and
 * the funnel HOLDS a scoped request until the boot driver has settled it. The
 * snapshot re-implements the scoping with a raw fetch — its answer is a blob,
 * which the funnel would have parsed — and so was not held: pressed inside that
 * window it went out tenant-less, which the control plane resolves to
 * authz.DefaultTenant, and the operator was handed the DEFAULT customer's
 * evidence file. Scoping without the barrier closes the defect only for the
 * presses that happen late enough.
 *
 * A file that has left the building carries no banner to correct it, which is
 * why the window matters more here than anywhere on screen.
 */
function recordPaths(): string[] {
  const paths: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      paths.push(String(input));
      return new Response("evidence", { status: 200 });
    })
  );
  return paths;
}

/** Lets the pending fetch (or the absence of one) reach the recorder. */
async function drain(): Promise<void> {
  for (let i = 0; i < 5; i += 1) await Promise.resolve();
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

describe("the forensic snapshot waits for the boot driver, as every other request does", () => {
  it("sends nothing while hydration is still deciding which customer this console shows", async () => {
    let settleDriver!: () => void;
    const driverAnswered = new Promise<void>((resolve) => {
      settleDriver = resolve;
    });
    // `retry` because a barrier has already run in this module's lifetime for
    // any earlier test — beginTenantHydration starts exactly one otherwise.
    void beginTenantHydration(async () => {
      await driverAnswered;
      // What the driver decides: this browser's remembered customer is still
      // offered, so the console points at it (adoptPersistedTenant's effect).
      setSelectedTenant("globex");
      return true;
    }, true);

    const paths = recordPaths();
    const download = forensicSnapshot();
    await drain();

    expect(
      paths,
      "the snapshot left before the console knew which customer it was showing — tenant-less, so the control plane answers with the operator's DEFAULT customer's evidence"
    ).toEqual([]);

    settleDriver();
    await download;

    expect(paths).toEqual(["/api/choke/forensic-snapshot?tenant=globex"]);
  });

  it("still holds nothing back on a console that started no hydration", async () => {
    // The single-tenant engine and every tenant-bound operator: no remembered
    // customer, so no driver, so no barrier — the request is the one this
    // console always sent.
    const paths = recordPaths();
    await forensicSnapshot();
    expect(paths).toEqual(["/api/choke/forensic-snapshot"]);
  });
});
