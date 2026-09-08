import { act, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * THE LIVE TAIL WAITS FOR THE CUSTOMER TOO.
 *
 * /api/stream is the one request that does not go through lib/api.ts: an
 * EventSource is opened directly, so the funnel's hydration barrier never held
 * it. On a provider console booting with a remembered customer, the socket was
 * therefore opened before the selection landed, named nobody, and the control
 * plane resolves a tenant-less read to the account's DEFAULT customer — so the
 * tail delivered THAT customer's alerts into a console on its way to another
 * one, under a "live" pill.
 *
 * Re-opening on the selection (it is a dependency of the connect effect) fixed
 * the URL and the buffer. It did not fix the operator who had already read the
 * frames, which is the whole reason the barrier exists for the panels beside
 * it.
 *
 * Pinned here: no connection while the barrier stands, one connection naming
 * the confirmed customer after it settles, and — the property a "just await it"
 * refactor would quietly cost every single-tenant console — a connection opened
 * in the mount tick when there is no barrier at all.
 */

class RecordingEventSource {
  static opened: RecordingEventSource[] = [];

  url: string;
  closed = false;
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;

  constructor(url: string) {
    this.url = url;
    RecordingEventSource.opened.push(this);
  }

  close(): void {
    this.closed = true;
  }
}

function stubServer(): { release: () => void } {
  let release: () => void = () => {};
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "/api/whoami") {
        await new Promise<void>((resolve) => {
          release = resolve;
        });
        return new Response(JSON.stringify({ user: "msoc", cross_tenant: true, viewing_tenant: "acme-corp" }), {
          status: 200,
          headers: { "content-type": "application/json" }
        });
      }
      const body =
        url === "/api/tenants" ? { tenants: [{ tenant_id: "globex", agents: 1, agents_fresh: 1 }] } : { ok: true };
      return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    })
  );
  return { release: () => release() };
}

async function loadStream() {
  vi.resetModules();
  const scope = await import("../lib/tenantScope");
  const stream = await import("../lib/stream");
  const hydration = await import("../app/tenantHydration");
  return { scope, StreamProvider: stream.StreamProvider, hydration };
}

const urls = () => RecordingEventSource.opened.map((source) => source.url);

beforeEach(() => {
  RecordingEventSource.opened = [];
  window.localStorage.clear();
  vi.stubGlobal("EventSource", RecordingEventSource as unknown as typeof EventSource);
  vi.stubGlobal("requestAnimationFrame", (callback: FrameRequestCallback) => {
    callback(0);
    return 1;
  });
  vi.stubGlobal("cancelAnimationFrame", () => {});
});

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe("the SSE tail does not connect before hydration settles", () => {
  it("opens nothing while the customer is still being confirmed, then names them", async () => {
    window.localStorage.setItem("soc.selectedTenant", JSON.stringify("globex"));
    const server = stubServer();
    const { StreamProvider, hydration } = await loadStream();

    void hydration.startTenantScopeHydration();
    await act(async () => {
      render(
        <StreamProvider>
          <div />
        </StreamProvider>
      );
    });

    expect(
      urls(),
      "the live tail opened unscoped and began delivering the default customer's frames"
    ).toEqual([]);

    await act(async () => {
      server.release();
    });

    expect(urls(), "the tail never opened once the customer was confirmed").toEqual([
      "/api/stream?tenant=globex"
    ]);
  });

  it("connects in the mount tick on a console with no barrier", async () => {
    // No remembered customer: nothing is hydrated, so nothing is deferred and
    // the tail opens exactly as it always did.
    const { StreamProvider } = await loadStream();
    stubServer();

    act(() => {
      render(
        <StreamProvider>
          <div />
        </StreamProvider>
      );
    });

    expect(urls()).toEqual(["/api/stream"]);
  });
});
