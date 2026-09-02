import { describe, expect, it, vi } from "vitest";
import { createAssistantApi } from "../features/assistant/api";

/**
 * A deployment may answer drill panels from a fast model and sustained sidebar
 * conversations from a stronger one. The client's only job is to say which
 * kind of exchange this is — and to say it on BOTH transports, because the
 * sidebar streams by default and a flag that only rides the non-streaming path
 * would be dead on arrival.
 */
function captureBody() {
  const calls: Array<Record<string, unknown>> = [];
  vi.stubGlobal("fetch", vi.fn(async (_u: RequestInfo | URL, init?: RequestInit) => {
    calls.push(JSON.parse(String(init?.body ?? "{}")));
    return new Response(JSON.stringify({ content: "ok", grounded: true, steps: [] }), {
      status: 200, headers: { "Content-Type": "application/json" }
    });
  }));
  return calls;
}

describe("the conversation flag reaches the server", () => {
  it("rides the non-streaming ask", async () => {
    const calls = captureBody();
    await createAssistantApi().ask({ agent: "soc", question: "q", conversation: true });
    expect(calls[0].conversation).toBe(true);
  });

  it("rides the STREAMING ask, which is the sidebar's default path", async () => {
    // The bug this pins: askStream destructured every other field and dropped
    // this one, so the flag never left the browser on the path that matters.
    const calls = captureBody();
    const api = createAssistantApi();
    // The stub answers with JSON rather than SSE, so the stream parser
    // rightly rejects it. Irrelevant here: the request body is captured
    // before any of that, and the body is the whole claim.
    await api.askStream?.({ agent: "soc", question: "q", conversation: true, onStep: () => {} }).catch(() => {});
    expect(calls[0].conversation).toBe(true);
  });

  it("is absent for a drill panel, which never sets it", async () => {
    const calls = captureBody();
    await createAssistantApi().ask({ agent: "soc", question: "q" });
    expect(calls[0].conversation).toBeUndefined();
  });
});
