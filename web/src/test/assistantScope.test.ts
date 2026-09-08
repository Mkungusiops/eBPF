import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { beginTenantHydration, setSelectedTenant } from "../lib/tenantScope";
import { AssistantError, assistantRequest, createAssistantApi } from "../features/assistant/api";
import { createChatApi } from "../features/assistant/chatApi";

/**
 * THE ASSISTANT MUST ANSWER ABOUT THE CUSTOMER THE CONSOLE IS POINTED AT.
 *
 * The assistant client issued its own fetches — it borrowed only readCookie
 * from lib/api — so no ask, no stream and no history read carried the
 * selection. The control plane resolves a request that names no tenant to the
 * account's DEFAULT customer, so a provider who had switched the console to
 * customer B asked a question and got a fluent, confident paragraph assembled
 * out of customer A's telemetry. Worse than a wrong table: prose carries no
 * column header, and it is the surface an analyst pastes into a handover.
 *
 * These drive the REAL transport over a stubbed fetch, because the thing under
 * test is the URL that actually leaves the console. Every panel test injects a
 * fake requester, which is exactly how this client's missing CSRF header
 * shipped past seven green tests.
 */
function recordPaths(body = "{}"): string[] {
  const paths: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      paths.push(String(input));
      return new Response(body, { status: 200, headers: { "content-type": "application/json" } });
    })
  );
  return paths;
}

/** Lets a pending request (or the absence of one) reach the recorder. */
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

describe("every assistant request names the customer on screen", () => {
  it("names it on the ask", async () => {
    setSelectedTenant("globex");
    const paths = recordPaths(JSON.stringify({ agent: "ask", content: "quiet", steps: [] }));

    await createAssistantApi().ask({ agent: "ask", question: "anything on fire?" });

    expect(
      paths,
      "the ask went out naming no customer, so the control plane answered it about the account's default one"
    ).toEqual(["/api/assistant/ask?tenant=globex"]);
  });

  it("names it on the streamed ask", async () => {
    setSelectedTenant("globex");
    const answer = { agent: "ask", content: "quiet", steps: [], model: "m", duration: "1s", grounded: true };
    const paths: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        paths.push(String(input));
        return new Response(`event: answer\ndata: ${JSON.stringify(answer)}\n\n`, {
          status: 200,
          headers: { "content-type": "text/event-stream" }
        });
      })
    );

    await createAssistantApi().askStream!({ agent: "ask", onStep: () => {} });

    expect(paths).toEqual(["/api/assistant/stream?tenant=globex"]);
  });

  it("names it on the capability read and on the history endpoints", async () => {
    setSelectedTenant("globex");
    const paths = recordPaths(JSON.stringify({ enabled: true, agents: [], chats: [], messages: [] }));

    await createAssistantApi().capability("devices");
    await assistantRequest("/api/assistant");
    const chats = createChatApi();
    await chats.listChats("etc/shadow");
    await chats.createChat("New", "deep");
    await chats.listMessages("c1");
    await chats.renameChat("c1", "Renamed");
    await chats.deleteChat("c1");

    // The customer is appended to a query the caller already built, never
    // instead of it — a search that lost its ?q= would answer with the whole
    // list under a banner naming the search.
    expect(paths).toEqual([
      "/api/assistant?surface=devices&tenant=globex",
      "/api/assistant?tenant=globex",
      "/api/assistant/chats?q=etc%2Fshadow&tenant=globex",
      "/api/assistant/chats?tenant=globex",
      "/api/assistant/chats/c1?tenant=globex",
      "/api/assistant/chats/c1?tenant=globex",
      "/api/assistant/chats/c1?tenant=globex"
    ]);
  });

  it("leaves a tenant-bound operator's requests byte for byte what they always were", async () => {
    // No selection is the single-tenant engine and every tenant-bound operator
    // on the control plane. A tenant appended there would be a scope claim
    // nobody made, against a server that resolves these reads correctly today.
    const paths = recordPaths(JSON.stringify({ agent: "ask", content: "", steps: [], chats: [] }));

    await createAssistantApi().ask({ agent: "ask", question: "anything on fire?" });
    await createChatApi().listChats();

    expect(paths).toEqual(["/api/assistant/ask", "/api/assistant/chats"]);
  });
});

describe("an ask waits for the console to know whose question it is", () => {
  it("sends nothing while the boot driver is still deciding", async () => {
    let settleDriver!: () => void;
    const driverAnswered = new Promise<void>((resolve) => {
      settleDriver = resolve;
    });
    // `retry`, because a barrier has already run in this module's lifetime for
    // any earlier test — beginTenantHydration starts exactly one otherwise.
    void beginTenantHydration(async () => {
      await driverAnswered;
      // What the driver decides: this browser's remembered customer is still
      // offered, so the console points at it (adoptPersistedTenant's effect).
      setSelectedTenant("globex");
      return true;
    }, true);

    const paths = recordPaths(JSON.stringify({ agent: "ask", content: "quiet", steps: [] }));
    const asked = createAssistantApi().ask({ agent: "ask", question: "anything on fire?" });
    await drain();

    expect(
      paths,
      "the ask left before the console knew which customer it was about — tenant-less, so the answer is built out of the operator's DEFAULT customer's telemetry"
    ).toEqual([]);

    settleDriver();
    await asked;

    expect(paths).toEqual(["/api/assistant/ask?tenant=globex"]);
  });

  it("refuses the ask outright when the customer could not be confirmed", async () => {
    // Hydration settled and still cannot say which customer this console is
    // pointed at. A history GET may go out — the server's default is a real
    // scope and the shell banner says it is not the remembered one — but an ask
    // may not: it spends a customer's inference budget and returns a paragraph
    // an analyst quotes, and there is no honest caption for "about whichever
    // customer the server picked for a console that was told to point
    // elsewhere". Same rule lib/api.ts applies to every other unsafe method.
    window.localStorage.setItem("soc.selectedTenant", JSON.stringify("globex"));
    await beginTenantHydration(async () => false, true);

    const paths = recordPaths(JSON.stringify({ chats: [] }));
    const failure = await createAssistantApi()
      .ask({ agent: "ask", question: "anything on fire?" })
      .catch((err: unknown) => err);

    expect(failure).toBeInstanceOf(AssistantError);
    expect(String((failure as AssistantError).message)).toContain("cannot confirm which customer");
    // The operator is told which customer the console last showed, so the
    // sentence names something they can act on.
    expect(String((failure as AssistantError).message)).toContain("globex");
    expect(paths, "a request left the browser after the refusal").toEqual([]);

    // The reads beside it are not refused; they go out unscoped, as every panel
    // read does in the same state.
    await createChatApi().listChats();
    expect(paths).toEqual(["/api/assistant/chats"]);
  });
});
