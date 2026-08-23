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

  // ── streaming ────────────────────────────────────────────────────────────

  /**
   * Feeds the SSE body in DELIBERATELY AWKWARD chunks — split mid-frame, mid
   * JSON, and with two frames in one chunk.
   *
   * This is the whole risk in the streaming client. A per-chunk parser works
   * perfectly on loopback, where frames arrive whole, and corrupts under any
   * real latency or any proxy that repacks the stream. The bug would surface as
   * missing progress lines in production and a green test suite locally.
   */
  function streamResponse(chunks: string[], status = 200) {
    const encoder = new TextEncoder();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        for (const c of chunks) controller.enqueue(encoder.encode(c));
        controller.close();
      }
    });
    return new Response(body, { status, headers: { "Content-Type": "text/event-stream" } });
  }

  it("reassembles SSE frames split across chunk boundaries", async () => {
    const answer = { agent: "ask", content: "quiet", steps: [], model: "m", duration: "1s", grounded: true };
    const fetchMock = vi.fn().mockResolvedValue(
      streamResponse([
        'event: step\ndata: {"tool":"list_aler',           // split mid-JSON
        'ts","path":"/api/alerts","bytes":9,"duration":"3ms"}\n\nevent: st',
        'ep\ndata: {"tool":"fleet_state","path":"/api/fleet/state","bytes":4,"duration":"2ms"}\n\n',
        `event: answer\ndata: ${JSON.stringify(answer)}\n\n`
      ])
    );
    vi.stubGlobal("fetch", fetchMock);
    const api = createAssistantApi();

    const steps: string[] = [];
    const got = await api.askStream!({
      agent: "ask",
      question: "how is it?",
      surface: "kpi-drill",
      onStep: (s) => steps.push(s.tool)
    });

    expect(steps).toEqual(["list_alerts", "fleet_state"]);
    expect(got.content).toBe("quiet");
    // The surface must reach the server, or the model does not know which panel asked.
    expect(JSON.parse(String((fetchMock.mock.calls[0][1] as RequestInit).body)).surface).toBe("kpi-drill");
    vi.unstubAllGlobals();
  });

  it("treats a stream that ends without an answer as a failure", async () => {
    // Silence must never read as success. Rendering an empty answer would look
    // exactly like the assistant having found nothing to say.
    const fetchMock = vi.fn().mockResolvedValue(
      streamResponse(['event: step\ndata: {"tool":"list_alerts","path":"/api/alerts","bytes":2,"duration":"1ms"}\n\n'])
    );
    vi.stubGlobal("fetch", fetchMock);
    const api = createAssistantApi();

    await expect(
      api.askStream!({ agent: "ask", onStep: () => {} })
    ).rejects.toThrow(/without an answer/);
    vi.unstubAllGlobals();
  });

  it("surfaces a streamed error event as a thrown error", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      streamResponse(['event: error\ndata: {"error":"the assistant could not complete this request"}\n\n'])
    );
    vi.stubGlobal("fetch", fetchMock);
    const api = createAssistantApi();

    await expect(api.askStream!({ agent: "ask", onStep: () => {} })).rejects.toThrow(
      /could not complete/
    );
    vi.unstubAllGlobals();
  });
});
