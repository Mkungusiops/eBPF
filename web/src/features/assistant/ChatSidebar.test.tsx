/**
 * Behaviour of the platform assistant sidebar, driven entirely through injected
 * object literals — no network, no stubbing, no Vite proxy.
 *
 * The states these pin are the ones a real deployment will actually hit: no
 * chat store at all (every engine deployment without Postgres), a store that is
 * configured but down, and an answer the engine could not ground.
 */
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ChatSidebar } from "./ChatSidebar";
import { AssistantError } from "./api";
import type { AssistantApi, AssistantAnswer, AssistantAskRequest } from "./api";
import type { Chat, ChatApi, ChatMessage } from "./chatApi";

const chat: Chat = {
  id: "c1",
  title: "curl on host-3",
  mode: "chat",
  created_at: "2026-08-16T10:00:00Z",
  updated_at: "2026-08-16T10:00:00Z"
};

const answer: AssistantAnswer = {
  agent: "triage",
  content: "curl read /etc/shadow at 10:04.",
  steps: [{ tool: "soc_alerts", args: "{}", path: "/api/alerts", bytes: 400, duration: "20ms" }],
  model: "gpt-oss:120b",
  duration: "2s",
  grounded: true
};

function fakeChatApi(over: Partial<ChatApi> = {}): ChatApi {
  return {
    listChats: async () => [chat],
    createChat: async () => chat,
    listMessages: async () => [],
    renameChat: async () => undefined,
    pinChat: async () => undefined,
    deleteChat: async () => undefined,
    ...over
  };
}

function fakeAssistantApi(over: Partial<AssistantApi> = {}): AssistantApi {
  return {
    capability: async () => ({ enabled: true, model: "gpt-oss:120b", agents: [{ id: "triage", title: "Triage" }] }),
    ask: async () => answer,
    ...over
  };
}

function open(props: Partial<React.ComponentProps<typeof ChatSidebar>> = {}) {
  return render(
    <ChatSidebar
      open
      onClose={() => {}}
      chatApi={fakeChatApi()}
      assistantApi={fakeAssistantApi()}
      {...props}
    />
  );
}

describe("ChatSidebar", () => {
  it("renders nothing when closed", () => {
    const { container } = render(
      <ChatSidebar open={false} onClose={() => {}} chatApi={fakeChatApi()} assistantApi={fakeAssistantApi()} />
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("lists conversations and states the read-only guarantee", async () => {
    open();
    expect(await screen.findByText("curl on host-3")).toBeTruthy();
    expect(screen.getByText("Read-only")).toBeTruthy();
  });

  it("says history is OFF without dressing it as a fault", async () => {
    // A deployment with no Postgres is the common case, not a broken one. It
    // must not get error styling: spending the incident colour on a
    // non-incident is how operators learn to ignore it.
    open({
      chatApi: fakeChatApi({
        listChats: async () => {
          throw new AssistantError("chat history is not enabled", 503);
        }
      })
    });
    const note = await screen.findByText(/History is off on this deployment/);
    expect(note.className).not.toContain("warn");
    expect(screen.queryByRole("alert")).toBeNull();
    // And the composer still works — no history does not mean no assistant.
    expect(screen.getByLabelText("Ask the assistant")).toBeTruthy();
  });

  it("distinguishes a store that is DOWN from one that is off", async () => {
    open({
      chatApi: fakeChatApi({
        listChats: async () => {
          throw new AssistantError("chat store unavailable", 500);
        }
      })
    });
    expect(await screen.findByText(/Past conversations could not be loaded/)).toBeTruthy();
    // Distinct from the disabled copy — the two must never collapse into one
    // message, because one is an action for an operator and the other is not.
    expect(screen.queryByText(/History is off on this deployment/)).toBeNull();
  });

  it("creates a conversation and records the ask against it", async () => {
    const ask = vi.fn(async (_req: AssistantAskRequest) => answer);
    const createChat = vi.fn(async () => chat);
    open({ chatApi: fakeChatApi({ createChat }), assistantApi: fakeAssistantApi({ ask }) });

    await screen.findByText("curl on host-3");
    await userEvent.type(screen.getByLabelText("Ask the assistant"), "what happened?");
    await userEvent.click(screen.getByRole("button", { name: /send/i }));

    await waitFor(() => expect(ask).toHaveBeenCalled());
    expect(createChat).toHaveBeenCalled();
    expect(ask.mock.calls[0][0]).toMatchObject({ chatId: "c1", question: "what happened?" });
  });

  it("asks INCOGNITO when there is no history to record into", async () => {
    // The safe default for an unclassified question is to leave no record. With
    // no store, the ask must still go out — and must carry no chat id.
    const ask = vi.fn(async (_req: AssistantAskRequest) => answer);
    open({
      chatApi: fakeChatApi({
        listChats: async () => {
          throw new AssistantError("chat history is not enabled", 503);
        }
      }),
      assistantApi: fakeAssistantApi({ ask })
    });

    await screen.findByText(/History is off/);
    await userEvent.type(screen.getByLabelText("Ask the assistant"), "is this a breach?");
    await userEvent.click(screen.getByRole("button", { name: /send/i }));

    await waitFor(() => expect(ask).toHaveBeenCalled());
    expect(ask.mock.calls[0][0].chatId).toBeUndefined();
  });

  it("marks an answer the engine could not ground", async () => {
    // Measured behaviour, not theory: under urgent framing the model invented an
    // entire incident. The badge is the only thing standing between that and an
    // analyst acting on it.
    open({
      chatApi: fakeChatApi({
        listMessages: async (): Promise<ChatMessage[]> => [
          {
            id: "m1",
            chat_id: "c1",
            role: "assistant",
            content: "host-9 was compromised",
            grounded: false,
            created_at: "2026-08-16T10:05:00Z"
          }
        ]
      })
    });
    await userEvent.click(await screen.findByRole("button", { name: "curl on host-3" }));
    expect(await screen.findByText(/Not grounded in telemetry/)).toBeTruthy();
  });

  it("discloses how many sources an answer was built from", async () => {
    open({
      chatApi: fakeChatApi({
        listMessages: async (): Promise<ChatMessage[]> => [
          {
            id: "m1",
            chat_id: "c1",
            role: "assistant",
            content: "two alerts",
            steps: JSON.stringify([
              { tool: "soc_alerts", path: "/api/alerts", bytes: 1, duration: "1ms" },
              { tool: "soc_hosts", path: "/api/hosts", bytes: 2, duration: "2ms" }
            ]),
            grounded: true,
            created_at: "2026-08-16T10:05:00Z"
          }
        ]
      })
    });
    await userEvent.click(await screen.findByRole("button", { name: "curl on host-3" }));
    expect(await screen.findByText("2 sources consulted")).toBeTruthy();
  });

  it("sends a handed-over question exactly once, carrying its subject", async () => {
    // Continuity from a drill panel. Sending twice would double-charge an
    // inference call and duplicate the turn in the stored transcript.
    const ask = vi.fn(async (_req: AssistantAskRequest) => answer);
    const { rerender } = render(
      <ChatSidebar
        open
        onClose={() => {}}
        execId="exec-abc123456789"
        initialQuestion="explain this chain"
        chatApi={fakeChatApi()}
        assistantApi={fakeAssistantApi({ ask })}
      />
    );
    await waitFor(() => expect(ask).toHaveBeenCalledTimes(1));
    expect(ask.mock.calls[0][0]).toMatchObject({
      question: "explain this chain",
      execId: "exec-abc123456789"
    });

    rerender(
      <ChatSidebar
        open
        onClose={() => {}}
        execId="exec-abc123456789"
        initialQuestion="explain this chain"
        chatApi={fakeChatApi()}
        assistantApi={fakeAssistantApi({ ask })}
      />
    );
    await waitFor(() => expect(ask).toHaveBeenCalledTimes(1));
  });

  it("only ever asks for an agent the SERVER advertised", async () => {
    // THE BUG THIS PINS: the sidebar shipped hardcoding agent "triage", which
    // has never existed — the registry defines explain-chain and
    // summarise-incident. Every question failed with "the assistant could not
    // complete this request", and nothing in the frontend could catch it
    // because an invented string type-checks perfectly.
    const ask = vi.fn(async (_req: AssistantAskRequest) => answer);
    const advertised = [{ id: "explain-chain", title: "Explain" }];
    open({
      assistantApi: fakeAssistantApi({
        ask,
        capability: async () => ({ enabled: true, model: "m", agents: advertised })
      })
    });

    await screen.findByText("curl on host-3");
    await userEvent.type(screen.getByLabelText("Ask the assistant"), "what happened?");
    await userEvent.click(screen.getByRole("button", { name: "Send" }));

    await waitFor(() => expect(ask).toHaveBeenCalled());
    const used = ask.mock.calls[0][0].agent;
    expect(
      advertised.map((a) => a.id),
      `the sidebar asked for agent "${used}", which the server never advertised`
    ).toContain(used);
  });

  it("refuses to ask at all when the deployment advertises no agent", async () => {
    // Better a clear message than a request the server will reject with a
    // generic failure the analyst cannot act on. The server SAID it is off, so
    // this is the one case allowed to name the deployment; the states where the
    // console merely failed to read the server say something else, and
    // assistantChats3CapabilityStates covers all four.
    const ask = vi.fn(async (_req: AssistantAskRequest) => answer);
    open({
      assistantApi: fakeAssistantApi({
        ask,
        capability: async () => ({ enabled: false, agents: [], reason: "no model configured" })
      })
    });

    await screen.findByText("curl on host-3");
    await userEvent.type(screen.getByLabelText("Ask the assistant"), "what happened?");
    await userEvent.click(screen.getByRole("button", { name: "Send" }));

    await screen.findByText(/Not configured on this deployment/);
    expect(ask).not.toHaveBeenCalled();
  });

  it("closes on Escape", async () => {
    // A slide-over that traps an analyst is worse than no slide-over.
    const onClose = vi.fn();
    open({ onClose });
    await userEvent.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalled();
  });

  it("keeps the analyst's question visible while the answer is in flight", async () => {
    // A composer that empties into nothing for twenty seconds reads as a
    // dropped message.
    let release: (a: AssistantAnswer) => void = () => {};
    const ask = vi.fn((_req: AssistantAskRequest) => new Promise<AssistantAnswer>((res) => (release = res)));
    open({ assistantApi: fakeAssistantApi({ ask }) });

    await screen.findByText("curl on host-3");
    await userEvent.type(screen.getByLabelText("Ask the assistant"), "what happened?");
    await userEvent.click(screen.getByRole("button", { name: /send/i }));

    expect(await screen.findByText("what happened?")).toBeTruthy();
    expect(screen.getByText("Reading the console…")).toBeTruthy();
    release(answer);
    await waitFor(() => expect(screen.queryByText("Reading the console…")).toBeNull());
  });
});

/**
 * A follow-up that restates an already-grounded conversation must NOT wear the
 * red unverified banner.
 *
 * The red banner means "this may be fabricated". Firing it at an analyst who
 * asked "are you sure?" trains them to ignore red — which is the one thing that
 * banner cannot afford to lose. The weaker, true statement goes in its place.
 */
describe("derived answers", () => {
  it("labels a restatement instead of calling it unverified", async () => {
    open({
      chatApi: fakeChatApi({
        listMessages: async (): Promise<ChatMessage[]> => [
          {
            id: "m1",
            chat_id: "c1",
            role: "assistant",
            content: "Yes — 6 indicators, as I said a moment ago.",
            grounded: false,
            derived: true,
            created_at: "2026-08-16T10:05:00Z"
          }
        ]
      })
    });
    await userEvent.click(await screen.findByRole("button", { name: "curl on host-3" }));
    expect(await screen.findByText(/From earlier in this conversation/)).toBeTruthy();
    expect(screen.queryByText(/Not grounded in telemetry/)).toBeNull();
  });

  it("still flags an answer with nothing behind it at all", async () => {
    open({
      chatApi: fakeChatApi({
        listMessages: async (): Promise<ChatMessage[]> => [
          {
            id: "m1",
            chat_id: "c1",
            role: "assistant",
            content: "There are 14 critical alerts on web-01.",
            grounded: false,
            created_at: "2026-08-16T10:05:00Z"
          }
        ]
      })
    });
    await userEvent.click(await screen.findByRole("button", { name: "curl on host-3" }));
    expect(await screen.findByText(/Not grounded in telemetry/)).toBeTruthy();
    expect(screen.queryByText(/From earlier in this conversation/)).toBeNull();
  });
});

/**
 * A greeting must not wear the red "unverified" banner.
 *
 * "Unverified" and "nothing to verify" are different states. Warning an analyst
 * that a greeting might be fabricated teaches them to ignore the banner that
 * exists for genuinely ungrounded claims — which is the one thing it cannot
 * afford to lose.
 */
describe("no-claim replies", () => {
  it("shows no warning on a greeting", async () => {
    open({
      chatApi: fakeChatApi({
        listMessages: async (): Promise<ChatMessage[]> => [
          {
            id: "m1",
            chat_id: "c1",
            role: "assistant",
            content: "Hi — quiet here right now. What do you need?",
            grounded: false,
            no_claim: true,
            created_at: "2026-08-21T10:05:00Z"
          }
        ]
      })
    });
    await userEvent.click(await screen.findByRole("button", { name: "curl on host-3" }));
    expect(await screen.findByText(/quiet here right now/)).toBeTruthy();
    expect(screen.queryByText(/Not grounded in telemetry/)).toBeNull();
    expect(screen.queryByText(/From earlier in this conversation/)).toBeNull();
  });
});
