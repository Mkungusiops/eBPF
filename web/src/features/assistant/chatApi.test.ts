import { describe, expect, it } from "vitest";
import { createChatApi, parseSteps } from "./chatApi";
import { AssistantError } from "./api";

/**
 * These drive the REAL transport, not a fake.
 *
 * The reason is on the record: the assistant's CSRF bug shipped past seven green
 * tests because every one of them injected a fake api object, so defaultRequest
 * — the only code that actually talks to the console — was never executed once.
 * The panel rendered, the buttons worked, and every ask came back "csrf token
 * missing or invalid".
 *
 * So: a captured Requester, exercising the paths and bodies this module builds.
 */

function capture(response: () => Response) {
  const calls: Array<{ path: string; init?: RequestInit }> = [];
  const api = createChatApi((path, init) => {
    calls.push({ path, init });
    return Promise.resolve(response());
  });
  return { api, calls };
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

describe("chatApi transport", () => {
  it("sends the search term as ?q= and unwraps the envelope", async () => {
    const { api, calls } = capture(() => json({ chats: [{ id: "c1", title: "curl" }] }));
    const chats = await api.listChats("etc/shadow");
    expect(calls[0].path).toBe("/api/assistant/chats?q=etc%2Fshadow");
    expect(chats).toHaveLength(1);
  });

  it("lists without a query string when there is no search", async () => {
    const { api, calls } = capture(() => json({ chats: [] }));
    await api.listChats();
    expect(calls[0].path).toBe("/api/assistant/chats");
  });

  it("tolerates a response with no chats key rather than throwing", async () => {
    // An empty history is the normal first-run state. If this threw, every new
    // operator would meet an error banner on their first open.
    const { api } = capture(() => json({}));
    await expect(api.listChats()).resolves.toEqual([]);
  });

  it("escapes the chat id in the path", async () => {
    // Ids come from the server today, but a path built by concatenation is a
    // traversal waiting for the day one does not.
    const { api, calls } = capture(() => json({ messages: [] }));
    await api.listMessages("../../admin");
    expect(calls[0].path).toBe("/api/assistant/chats/..%2F..%2Fadmin");
    expect(calls[0].path).not.toContain("/../");
  });

  it("uses PATCH for rename and pin, and DELETE for delete", async () => {
    const { api, calls } = capture(() => json({ status: "ok" }));
    await api.renameChat("c1", "Renamed");
    await api.pinChat("c1", true);
    await api.deleteChat("c1");
    expect(calls.map((c) => (c.init?.method ?? "GET").toUpperCase())).toEqual(["PATCH", "PATCH", "DELETE"]);
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ title: "Renamed" });
    expect(JSON.parse(String(calls[1].init?.body))).toEqual({ pinned: true });
  });

  it("surfaces the server's message and status on failure", async () => {
    const { api } = capture(() => json({ error: "chat history is not enabled" }, 503));
    await expect(api.listChats()).rejects.toMatchObject({
      message: "chat history is not enabled",
      status: 503
    });
  });

  it("keeps the status when the error body is not JSON", async () => {
    const { api } = capture(() => new Response("<html>502</html>", { status: 502 }));
    const err = await api.listChats().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AssistantError);
    expect((err as AssistantError).status).toBe(502);
  });
});

describe("parseSteps", () => {
  it("recovers a stored trace", () => {
    expect(parseSteps('[{"tool":"soc_alerts","path":"/api/alerts"}]')).toHaveLength(1);
  });

  it("degrades to empty rather than throwing on unusable input", () => {
    // The answer is still the answer. A trace that will not parse must not cost
    // the analyst the message it belongs to.
    expect(parseSteps("not json")).toEqual([]);
    expect(parseSteps('{"not":"an array"}')).toEqual([]);
    expect(parseSteps(undefined)).toEqual([]);
    expect(parseSteps("")).toEqual([]);
  });
});
