import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";

/**
 * THE PAGE SAYS WHOSE ESTATE IT IS SHOWING, ON EVERY ENTRY.
 *
 * The dashboard has had a provider banner since the switcher shipped, and it is
 * the sentence the whole feature rests on: "every panel below is this
 * customer's data only, and any containment fired from this console lands
 * there". /choke, /devices and /fleet are separate HTML entries with separate
 * React trees and had NO such sentence — so the pages carrying the ladder, the
 * device jails and the fleet kill switch were the pages that named no customer
 * at all.
 *
 * The banner lives in the shell (app/render.tsx mounts it) rather than in each
 * feature, so a fourth page cannot ship without one. These tests pin what it
 * says in each state, and that a tenant-bound operator is shown nothing.
 */

async function loadShell() {
  vi.resetModules();
  const scope = await import("../lib/tenantScope");
  const banner = await import("../app/TenantScopeBanner");
  const render = await import("../app/render");
  return { scope, TenantScopeBanner: banner.TenantScopeBanner, renderApp: render.renderApp };
}

function stubServer(handler?: (url: string) => unknown): string[] {
  const urls: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      urls.push(url);
      const body =
        handler?.(url) ??
        (url === "/api/whoami"
          ? { user: "msoc", cross_tenant: true, viewing_tenant: "acme-corp" }
          : url === "/api/tenants"
            ? { tenants: [{ tenant_id: "globex", agents: 1, agents_fresh: 1 }] }
            : { ok: true });
      return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    })
  );
  return urls;
}

/** The boot driver's two reads, picked out of whatever else the shell mounts. */
function scopeReads(urls: string[]): string[] {
  return urls.filter((url) => url === "/api/whoami" || url === "/api/tenants");
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

describe("the shell banner names the customer a non-dashboard page is showing", () => {
  it("names the selected customer, and says containment lands there", async () => {
    const { scope, TenantScopeBanner } = await loadShell();
    scope.setSelectedTenant("globex");

    render(<TenantScopeBanner mode="shell" />);

    const banner = screen.getByRole("status");
    expect(banner).toHaveTextContent("globex");
    expect(
      banner.textContent,
      "the page named a customer without saying that containment fired here reaches it"
    ).toMatch(/containment fired from this page lands there/i);
  });

  it("names the customer the server resolves to when the provider has picked nobody", async () => {
    // Not an error state — but "your account's default" is still ONE customer,
    // and the numbers on this page are not the whole book of business.
    const { scope, TenantScopeBanner } = await loadShell();
    scope.noteScopeFromResponse("/api/whoami", { cross_tenant: true, viewing_tenant: "acme-corp" });

    render(<TenantScopeBanner mode="shell" />);

    expect(screen.getByRole("status")).toHaveTextContent("acme-corp");
  });

  it("shows a tenant-bound operator nothing at all", async () => {
    // One customer, no switcher, no claim. Their page must be exactly what it
    // was before any of this existed.
    const { scope, TenantScopeBanner } = await loadShell();
    scope.noteScopeFromResponse("/api/whoami", { cross_tenant: false, viewing_tenant: "acme-corp" });

    const { container } = render(<TenantScopeBanner mode="shell" />);

    expect(container.textContent, "a tenant-bound operator was told they are a provider").toBe("");
  });

  it("says the scope is unconfirmed, on the dashboard too, when writes are being held", async () => {
    // The dashboard renders its own provider banner beside the switcher, so the
    // shell stays quiet there — EXCEPT for this state, which that banner cannot
    // describe: containment is being refused by the funnel, and a refusal the
    // operator cannot see reads as a broken console.
    window.localStorage.setItem("soc.selectedTenant", JSON.stringify("globex"));
    const { scope, TenantScopeBanner } = await loadShell();
    await act(async () => {
      await scope.beginTenantHydration(async () => false);
    });

    render(<TenantScopeBanner mode="dashboard" />);

    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("globex");
    expect(alert.textContent).toMatch(/Containment is being refused/i);
  });

  it("stays quiet on the dashboard while the dashboard's own banner is doing the naming", async () => {
    const { scope, TenantScopeBanner } = await loadShell();
    scope.setSelectedTenant("globex");

    const { container } = render(<TenantScopeBanner mode="dashboard" />);

    expect(container.textContent, "the dashboard rendered two provider banners").toBe("");
  });
});

describe("every entry mounts it, because the shell does", () => {
  it("captions a page that has never heard of the customer switcher", async () => {
    // What /choke, /devices and /fleet do: renderApp with no scope option. The
    // route itself is a bare div here — the point is that the caption and the
    // hydration come from the shell, not from anything the feature remembered
    // to do.
    window.localStorage.setItem("soc.selectedTenant", JSON.stringify("globex"));
    const urls = stubServer();
    const { renderApp } = await loadShell();
    const root = document.createElement("div");
    root.id = "root";
    document.body.appendChild(root);

    await act(async () => {
      renderApp(<div>the choke gateway</div>, "the choke gateway");
    });

    await waitFor(() => expect(root.textContent).toContain("globex"));
    expect(root.textContent).toContain("the choke gateway");
    // Filtered to the scope reads: the shell also mounts the assistant
    // provider, whose own probe is none of this test's business.
    expect(scopeReads(urls), "the shell did not confirm the remembered customer before mounting").toEqual([
      "/api/whoami",
      "/api/tenants"
    ]);
  });

  it("adds neither banner nor boot requests to the login page", async () => {
    // Nobody is signed in: whoami would answer 401 and the roster is not a
    // question an unauthenticated page may ask.
    window.localStorage.setItem("soc.selectedTenant", JSON.stringify("globex"));
    const urls = stubServer();
    const { renderApp } = await loadShell();
    const root = document.createElement("div");
    root.id = "root";
    document.body.appendChild(root);

    await act(async () => {
      renderApp(<div>sign in</div>, "the login page", { tenantScope: "none" });
    });

    expect(root.textContent).toBe("sign in");
    expect(scopeReads(urls), "the login page asked who is signed in before anyone was").toEqual([]);
  });
});
