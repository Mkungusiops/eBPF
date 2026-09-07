/**
 * The chat sidebar must say WHICH reason there is no agent to ask.
 *
 * The drill panel was taught this distinction in an earlier sweep and the
 * finding was reported closed — but the sidebar kept its own single sentence,
 * "No assistant agent is available on this deployment.", produced by
 * `capability().then((cap) => cap.agents ?? []).catch(() => [])` in useChats.
 * That collapse is the expensive direction of the mistake, and worse here than
 * in the panel: this is the box an operator types into mid-incident, and on an
 * assistant-enabled deployment it is also the only entry point to Behaviour &
 * Intel. Told the deployment has no assistant, they call a platform team that
 * has nothing to fix, while the real fault — a failed read, a degraded 502, a
 * body of the wrong shape — goes unlooked-for.
 *
 * So: a failed read, a 200 with `agents: []` and a 200 with no `agents` key
 * each produce a DIFFERENT message, and only the state where the SERVER said
 * the assistant is off is allowed to name the deployment.
 */
import { render, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ChatSidebar } from "../features/assistant/ChatSidebar";
import type { AssistantApi, AssistantAnswer, AssistantAskRequest } from "../features/assistant/api";
import type { Chat, ChatApi } from "../features/assistant/chatApi";

const chat: Chat = {
  id: "c1",
  title: "curl on host-3",
  mode: "chat",
  created_at: "2026-08-16T10:00:00Z",
  updated_at: "2026-08-16T10:00:00Z"
};

const answer: AssistantAnswer = {
  agent: "ask",
  content: "nothing to report",
  steps: [],
  model: "gpt-oss:120b",
  duration: "1s",
  grounded: true
};

function fakeChatApi(): ChatApi {
  return {
    listChats: async () => [chat],
    createChat: async () => chat,
    listMessages: async () => [],
    renameChat: async () => undefined,
    pinChat: async () => undefined,
    deleteChat: async () => undefined
  };
}

/** Opens the sidebar over a capability client, types a question, sends it. */
async function askWith(capability: AssistantApi["capability"]) {
  const ask = vi.fn(async (_req: AssistantAskRequest) => answer);
  const assistantApi: AssistantApi = { capability, ask };
  const view = render(
    <ChatSidebar open onClose={() => {}} chatApi={fakeChatApi()} assistantApi={assistantApi} />
  );
  const ui = within(view.baseElement as HTMLElement);
  await ui.findByText("curl on host-3");
  await userEvent.type(ui.getByLabelText("Ask the assistant"), "is host-3 compromised?");
  await userEvent.click(ui.getByRole("button", { name: "Send" }));
  const alert = await ui.findByRole("alert");
  const text = alert.textContent ?? "";
  // Unmounted before returning, so a test may compare several states without
  // the queries colliding across two mounted sidebars.
  view.unmount();
  return { text, ask };
}

/** The claim that must never be made from a fault of this console's own. */
const BLAMES_DEPLOYMENT = /Not configured on this deployment/;

describe("the chat sidebar names WHICH state left it with no agent", () => {
  it("does not blame the deployment when the capability read never completed", async () => {
    const { text, ask } = await askWith(async () => {
      throw new Error("network down");
    });

    expect(text).not.toMatch(BLAMES_DEPLOYMENT);
    expect(text).toMatch(/could not reach the assistant service/i);
    // The honest part: we never got an answer, so we do not know.
    expect(text).toMatch(/unknown/i);
    expect(ask).not.toHaveBeenCalled();
  });

  it("does not blame the deployment for a 502 the client degraded", async () => {
    // createAssistantApi turns a non-ok capability read into this body rather
    // than throwing, so the verdict has to survive normalisation in useChats —
    // the layer the previous pass stopped short of.
    const { text } = await askWith(async () => ({
      enabled: false,
      agents: [],
      availability: "unreachable" as const,
      reason: "unavailable (HTTP 502)"
    }));

    expect(text).not.toMatch(BLAMES_DEPLOYMENT);
    expect(text).toMatch(/could not reach the assistant service/i);
    // The status is carried through, because it is the actionable part.
    expect(text).toMatch(/502/);
  });

  it("says enabled-but-nothing-published for a 200 with an empty agent list", async () => {
    const { text } = await askWith(async () => ({ enabled: true, model: "gpt-oss:120b", agents: [] }));

    expect(text).not.toMatch(BLAMES_DEPLOYMENT);
    expect(text).not.toMatch(/could not reach|does not understand/i);
    expect(text).toMatch(/no assistant agents published/i);
  });

  it("says enabled-but-nothing-published for an explicit `agents: null`", async () => {
    // Both servers marshal a nil slice as an explicit null (no `omitempty`), so
    // this is the real wire shape of "on, and this surface publishes nothing".
    const { text } = await askWith(
      async () => ({ enabled: true, model: "gpt-oss:120b", agents: null }) as never
    );

    expect(text).not.toMatch(BLAMES_DEPLOYMENT);
    expect(text).toMatch(/no assistant agents published/i);
  });

  it("says the body was not understood when a 200 omits the agent list", async () => {
    const { text } = await askWith(async () => ({ enabled: true, model: "gpt-oss:120b" }) as never);

    expect(text).not.toMatch(BLAMES_DEPLOYMENT);
    expect(text).not.toMatch(/could not reach/i);
    expect(text).toMatch(/does not understand/i);
    expect(text).toMatch(/omits the agent list/i);
  });

  it("gives the three states three DIFFERENT sentences", async () => {
    // The regression this file exists for is not any one wording — it is the
    // collapse. Whatever the sentences say, they must not be the same sentence.
    const failed = await askWith(async () => {
      throw new Error("network down");
    });
    const empty = await askWith(async () => ({ enabled: true, agents: [] }));
    const missing = await askWith(async () => ({ enabled: true }) as never);

    const said = new Set([failed.text, empty.text, missing.text]);
    expect(said.size, `the sidebar printed the same message for different states: ${[...said].join(" | ")}`).toBe(3);
  });

  it("still names the deployment when the SERVER said the assistant is off", async () => {
    // The distinction cuts both ways: the one state that IS a settings gap must
    // still send the operator to their platform team.
    const { text } = await askWith(async () => ({
      enabled: false,
      agents: [],
      reason: "no model configured"
    }));

    expect(text).toMatch(BLAMES_DEPLOYMENT);
    expect(text).toMatch(/no model configured/);
  });
});
