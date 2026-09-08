import { act, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { StreamProvider } from "../lib/stream";
import { setSelectedTenant } from "../lib/tenantScope";
import { useStreamStore } from "../stores/stream";

/**
 * THE LIVE TAIL BELONGS TO THE CUSTOMER ON SCREEN.
 *
 * /api/stream is a read like any other — the control plane runs it through
 * authorizeRead and queries the store with the tenant that resolves from, so a
 * connection opened without one keeps delivering the account's DEFAULT customer
 * for as long as it stays open. Until this was scoped, a provider who switched
 * customers had a socket still tailing the customer they had left, and the
 * console had to throw its frames away to keep them out of the new customer's
 * queue: the dashboard only moved when the 30-second poll landed, under a "live"
 * pill, which is how an operator reads a busy customer as a quiet one.
 *
 * Two things are pinned here, and the second is the one a re-render could
 * silently lose: the URL carries the selection, and CHANGING the selection tears
 * the connection down and opens a new one. A scoped URL evaluated once at mount
 * is the same defect with a tenant parameter on it.
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

  /** Deliver one frame the way the browser would. */
  emit(frame: unknown): void {
    this.onmessage?.({ data: JSON.stringify(frame) });
  }

  close(): void {
    this.closed = true;
  }
}

function sources(): RecordingEventSource[] {
  return RecordingEventSource.opened;
}

function urls(): string[] {
  return sources().map((source) => source.url);
}

beforeEach(() => {
  RecordingEventSource.opened = [];
  window.localStorage.clear();
  setSelectedTenant(null);
  vi.stubGlobal("EventSource", RecordingEventSource as unknown as typeof EventSource);
  // The provider batches frames on an animation frame; running the callback
  // immediately keeps the assertions on the same tick as the message.
  vi.stubGlobal("requestAnimationFrame", (callback: FrameRequestCallback) => {
    callback(0);
    return 1;
  });
  vi.stubGlobal("cancelAnimationFrame", () => {});
});

afterEach(() => {
  vi.unstubAllGlobals();
  setSelectedTenant(null);
  window.localStorage.clear();
});

describe("the SSE connection is scoped like every other read", () => {
  it("opens the tail for the customer the console is pointed at", () => {
    setSelectedTenant("globex");
    // Wrapped because mounting the provider resets the shared stream store,
    // which is a state update React must be told about.
    act(() => {
      render(
        <StreamProvider>
          <div />
        </StreamProvider>
      );
    });

    expect(urls(), "the live tail was opened without naming the customer on screen").toEqual([
      "/api/stream?tenant=globex"
    ]);
  });

  it("opens the tail a single-tenant console has always opened when nothing is selected", () => {
    // Wrapped because mounting the provider resets the shared stream store,
    // which is a state update React must be told about.
    act(() => {
      render(
        <StreamProvider>
          <div />
        </StreamProvider>
      );
    });

    expect(urls()).toEqual(["/api/stream"]);
  });

  it("re-opens the tail on a switch instead of tailing the previous customer", () => {
    setSelectedTenant("acme-corp");
    // Wrapped because mounting the provider resets the shared stream store,
    // which is a state update React must be told about.
    act(() => {
      render(
        <StreamProvider>
          <div />
        </StreamProvider>
      );
    });

    // A frame from the customer being left, already in the shared buffer.
    act(() => {
      sources()[0].emit({ type: "alert", data: { title: "acme incident" } });
    });
    expect(useStreamStore.getState().frames.length).toBe(1);

    act(() => {
      setSelectedTenant("globex");
    });

    expect(urls(), "the switch did not open a connection for the customer now on screen").toEqual([
      "/api/stream?tenant=acme-corp",
      "/api/stream?tenant=globex"
    ]);
    expect(sources()[0].closed, "the previous customer's socket was left open and still delivering").toBe(true);
    expect(
      useStreamStore.getState().frames,
      "the previous customer's frames survived into the new customer's buffer"
    ).toEqual([]);
  });
});
