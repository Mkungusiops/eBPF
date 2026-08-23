import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ChatSidebar } from "../features/assistant/ChatSidebar";
import type { AssistantApi } from "../features/assistant/api";
import type { Chat, ChatApi } from "../features/assistant/chatApi";
import { enrichmentSummaryText } from "../features/common/enrichmentSummary";

/**
 * Behaviour & Intel left the side menu, so the assistant is now its entry
 * point. That is only safe while the sidebar keeps stating the one thing a
 * conversation will not volunteer: whether the detector is actually running.
 */
const chat: Chat = {
  id: "c1", title: "t", mode: "chat",
  created_at: "2026-08-21T10:00:00Z", updated_at: "2026-08-21T10:00:00Z"
};

function apis(): { chatApi: ChatApi; assistantApi: AssistantApi } {
  return {
    chatApi: {
      listChats: async () => [chat],
      createChat: async () => chat,
      listMessages: async () => [],
      renameChat: async () => undefined,
      pinChat: async () => undefined,
      deleteChat: async () => undefined
    },
    assistantApi: {
      capability: async () => ({ enabled: true, model: "m", agents: [{ id: "ask", title: "Ask", conversational: true }] }),
      ask: async () => ({ agent: "ask", content: "ok", steps: [], model: "m", duration: "1s", grounded: true })
    }
  };
}

function mockEnrichment(baseline: unknown, intel: unknown) {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.startsWith("/api/baseline")) return Promise.resolve(new Response(JSON.stringify(baseline), { status: 200 }));
    if (url.startsWith("/api/intel")) return Promise.resolve(new Response(JSON.stringify(intel), { status: 200 }));
    return Promise.resolve(new Response("{}", { status: 503 }));
  }));
}

afterEach(() => vi.unstubAllGlobals());

const ready = { enabled: true, status: { ready: true, observations: 9000, need_observations: 500, span_seconds: 90000, need_span_seconds: 1800 } };
const warming = { enabled: true, status: { ready: false, observations: 250, need_observations: 500, span_seconds: 900, need_span_seconds: 1800 } };

describe("enrichment strip in the assistant", () => {
  it("states a healthy detector and offers the findings", async () => {
    mockEnrichment(ready, { status: { loaded: true, indicators: 414 } });
    const onOpenFindings = vi.fn();
    render(<ChatSidebar open onClose={() => {}} onOpenFindings={onOpenFindings} {...apis()} />);

    expect(await screen.findByText(/Baseline ready/)).toBeTruthy();
    expect(screen.getByText(/414 indicators/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: /View the findings/ }));
    expect(onOpenFindings).toHaveBeenCalled();
  });

  it("says the baseline is still learning rather than staying silent", async () => {
    mockEnrichment(warming, { status: { loaded: true, indicators: 414 } });
    render(<ChatSidebar open onClose={() => {}} onOpenFindings={() => {}} {...apis()} />);
    // "Still learning" is NOT "nothing unusual", and the sidebar is now the
    // only place an analyst sees the difference without asking.
    expect(await screen.findByText(/still learning/i)).toBeTruthy();
  });

  it("says when no indicators are loaded", async () => {
    mockEnrichment(ready, { status: { loaded: false, indicators: 0 } });
    render(<ChatSidebar open onClose={() => {}} onOpenFindings={() => {}} {...apis()} />);
    expect(await screen.findByText(/no threat-intel indicators loaded/i)).toBeTruthy();
  });

  it("offers no findings link on a route that has no panel", async () => {
    mockEnrichment(ready, { status: { loaded: true, indicators: 10 } });
    render(<ChatSidebar open onClose={() => {}} {...apis()} />);
    await waitFor(() => expect(screen.getByText(/Baseline ready/)).toBeTruthy());
    // Offered-and-inert is worse than not offered.
    expect(screen.queryByRole("button", { name: /View the findings/ })).toBeNull();
  });
});

describe("enrichmentSummaryText", () => {
  it("distinguishes the three empty-list causes", () => {
    expect(enrichmentSummaryText({ baselineReady: null, baselineProgress: null, indicators: null, unavailable: true }))
      .toMatch(/not enabled/i);
    expect(enrichmentSummaryText({ baselineReady: false, baselineProgress: 0.5, indicators: 414, unavailable: false }))
      .toMatch(/still learning/i);
    expect(enrichmentSummaryText({ baselineReady: true, baselineProgress: 1, indicators: 0, unavailable: false }))
      .toMatch(/no threat-intel indicators/i);
  });
});
