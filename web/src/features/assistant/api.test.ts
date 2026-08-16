/**
 * Tests for the REAL client, not an injected fake.
 *
 * The panel tests all inject an AssistantApi, so defaultRequest was never
 * exercised and a missing CSRF header shipped to production: the panel
 * rendered, the buttons worked, and every ask returned "csrf token missing or
 * invalid". Injection makes components testable; it also means the transport
 * needs its own tests or nothing covers it.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAssistantApi } from "./api";

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

describe("createAssistantApi", () => {
  beforeEach(() => {
    document.cookie = "csrf_token=tok-123";
  });

  it("sends the CSRF token on ask (an unsafe method)", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ agent: "a", content: "", steps: [] }));
    const api = createAssistantApi();
    vi.stubGlobal("fetch", fetchMock);

    await api.ask({ agent: "summarise-incident" });

    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(new Headers(init.headers).get("X-CSRF-Token")).toBe("tok-123");
    vi.unstubAllGlobals();
  });

  it("does not send it on the capability GET", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ enabled: false, agents: [] }));
    vi.stubGlobal("fetch", fetchMock);

    await createAssistantApi().capability();

    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(new Headers(init?.headers).get("X-CSRF-Token")).toBeNull();
    vi.unstubAllGlobals();
  });

  it("reports capability as unavailable rather than throwing", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("nope", { status: 502 })));
    const cap = await createAssistantApi().capability();
    // The assistant must never take the drill panel down with it.
    expect(cap.enabled).toBe(false);
    expect(cap.reason).toContain("502");
    vi.unstubAllGlobals();
  });
});
