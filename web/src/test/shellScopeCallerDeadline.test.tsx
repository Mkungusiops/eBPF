import { act, cleanup } from "@testing-library/react";
import { useEffect } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * THE HYDRATION WAIT IS NOT SPENT OUT OF A READ'S OWN DEADLINE.
 *
 * The funnel holds a scoped request until the console knows which customer it
 * is for (lib/api.ts). The clients that issue those requests put each read
 * under a deadline of their own — features/choke/api.ts gives every read eight
 * seconds, and the deadline starts when the read is CALLED, not when it reaches
 * the wire. Those two facts together were a lie on screen: with the route
 * mounted before the barrier settled, a slow control plane spent a read's
 * entire budget inside the hold, and the route reported "choke gateway
 * unreachable: /api/choke/state did not answer within 8s" for a request the
 * console had never sent. Every panel on /choke, blaming a gateway that was
 * never asked anything.
 *
 * So the shell does not mount the route until the barrier settles. What is
 * pinned here is the consequence a refactor could silently lose: at the moment
 * a route's first effect runs, there is NO barrier left to wait on, so the read
 * it issues starts its own clock with its whole budget in front of it. Nothing
 * here lengthens or suppresses a read deadline — a gateway that is genuinely
 * slow is timed from the moment its request goes out, exactly as before.
 */

interface Deferred {
  release: (body: unknown) => void;
}

function stubServer(): { urls: () => string[]; defer: (path: string) => Deferred } {
  const urls: string[] = [];
  const held = new Map<string, (body: unknown) => void>();
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      urls.push(url);
      const body = held.has(url)
        ? await new Promise<unknown>((resolve) => held.set(url, resolve))
        : url === "/api/whoami"
          ? { user: "msoc", cross_tenant: true, viewing_tenant: "acme-corp" }
          : url === "/api/tenants"
            ? { tenants: [{ tenant_id: "globex", agents: 1, agents_fresh: 1 }] }
            : { ok: true };
      return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    })
  );
  return {
    // The shell also mounts the assistant provider, whose own probe is none of
    // this test's business; the scope reads and the route's read are.
    urls: () => urls.filter((url) => !url.startsWith("/api/assistant")),
    defer: (path: string) => {
      held.set(path, () => {});
      return { release: (body: unknown) => held.get(path)?.(body) };
    }
  };
}

async function loadShell() {
  vi.resetModules();
  const scope = await import("../lib/tenantScope");
  const api = await import("../lib/api");
  const render = await import("../app/render");
  return { scope, api, renderApp: render.renderApp };
}

function mountPoint(): HTMLElement {
  const root = document.createElement("div");
  root.id = "root";
  document.body.appendChild(root);
  return root;
}

beforeEach(() => {
  window.localStorage.clear();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.localStorage.clear();
  document.body.innerHTML = "";
});

describe("a route's read deadline starts when the route can read", () => {
  it("mounts the route only once the barrier is gone, so its first read holds for nothing", async () => {
    window.localStorage.setItem("soc.selectedTenant", JSON.stringify("globex"));
    const stub = stubServer();
    const whoami = stub.defer("/api/whoami");
    const { scope, api, renderApp } = await loadShell();

    // What every route does on mount, and the two facts that matter about the
    // moment it does it: was a barrier still standing, and did the read it
    // issued reach the wire without waiting on one.
    const barrierAtMount: (Promise<void> | null)[] = [];
    let mounts = 0;
    function Route() {
      useEffect(() => {
        mounts += 1;
        barrierAtMount.push(scope.pendingTenantHydration());
        void api.getJSON("/api/choke/state").catch(() => undefined);
      }, []);
      return <div>choke gateway</div>;
    }

    const root = mountPoint();
    await act(async () => {
      renderApp(<Route />, "the choke gateway");
    });

    // The control plane has not answered yet. Nothing of the route is on
    // screen, and — the point — nothing of the route has started a clock.
    expect(mounts, "the route mounted and began timing its reads while the customer was unknown").toBe(0);
    expect(root.textContent).toContain("Confirming");
    expect(stub.urls()).toEqual(["/api/whoami"]);

    await act(async () => {
      whoami.release({ user: "msoc", cross_tenant: true, viewing_tenant: "acme-corp" });
    });

    expect(root.textContent).toContain("choke gateway");
    expect(mounts).toBeGreaterThan(0);
    expect(
      barrierAtMount.filter((barrier) => barrier !== null),
      "the route mounted with the hydration barrier still standing: its read deadline pays for the wait"
    ).toEqual([]);
    // And the read it issued went out named, in that same flush — no hold.
    expect(stub.urls()).toContain("/api/choke/state?tenant=globex");
  });

  it("still refuses to guess: the route mounts when the deadline expires, not before", async () => {
    // A hung control plane. The wait is bounded, so the page arrives; it
    // arrives unscoped and captioned as unconfirmed, which is the honest
    // reading — but it does not arrive early, because a route mounted early is
    // a route timing its reads against a barrier again.
    vi.useFakeTimers();
    window.localStorage.setItem("soc.selectedTenant", JSON.stringify("globex"));
    const stub = stubServer();
    stub.defer("/api/whoami");
    const { api, renderApp } = await loadShell();
    const hydration = await import("../app/tenantHydration");

    let mounts = 0;
    function Route() {
      useEffect(() => {
        mounts += 1;
        void api.getJSON("/api/choke/state").catch(() => undefined);
      }, []);
      return <div>choke gateway</div>;
    }

    const root = mountPoint();
    await act(async () => {
      renderApp(<Route />, "the choke gateway");
    });
    expect(mounts).toBe(0);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(hydration.TENANT_HYDRATION_DEADLINE_MS + 1);
    });

    // StrictMode double-invokes the effect; one mount is one mount.
    expect(mounts, "the page was withheld past the deadline that guarantees it arrives").toBeGreaterThan(0);
    expect(root.textContent).toContain("could not confirm");
    expect(stub.urls()).toContain("/api/choke/state");
    vi.useRealTimers();
  });

  it("mounts a console with nothing to confirm in the same call, with no extra render", async () => {
    // Every tenant-bound operator and the single-tenant engine. There is no
    // claim to check, so no barrier is opened and nothing is deferred: the page
    // is exactly the page it was before any of this existed.
    const stub = stubServer();
    const { renderApp } = await loadShell();

    let mounts = 0;
    function Route() {
      useEffect(() => {
        mounts += 1;
      }, []);
      return <div>choke gateway</div>;
    }

    const root = mountPoint();
    await act(async () => {
      renderApp(<Route />, "the choke gateway");
    });

    expect(root.textContent).toContain("choke gateway");
    // StrictMode double-invokes effects; what matters is that the route was
    // never rendered as absent and then rendered again.
    expect(mounts).toBeGreaterThan(0);
    expect(stub.urls().filter((url) => url === "/api/whoami" || url === "/api/tenants")).toEqual([]);
  });
});
