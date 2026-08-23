/**
 * The point of these tests is not coverage — it is that they exist AT ALL
 * without a network stub.
 *
 * The audit found one of four routes unit-testable without stubbing, and it was
 * the only route with a route-level test. These run against an object literal
 * because AssistantApi names no transport type. That is the whole argument for
 * the Tier 1 DI work, demonstrated on the newest code in the tree.
 */
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { AssistantPanel } from "./AssistantPanel";
import type { AssistantApi, AssistantAnswer, AssistantAskRequest, AssistantSurface } from "./api";

const answer: AssistantAnswer = {
  agent: "explain-chain",
  content: "curl was launched by bash from an SSH session. Consistent with an operator.",
  steps: [
    { tool: "process_tree", args: '{"exec_id":"abc"}', path: "/api/process/", bytes: 812, duration: "31ms" }
  ],
  model: "openai-compatible:gpt-oss:20b",
  duration: "2.1s"
};

function fakeApi(over: Partial<AssistantApi> = {}): AssistantApi {
  return {
    capability: async () => ({
      enabled: true,
      model: "gpt-oss:20b",
      agents: [
        // Ordered and flagged the way the server orders and flags them:
        // conversational first. A fake that does not match the contract tests
        // nothing about the contract.
        { id: "ask", title: "Ask a question", conversational: true },
        { id: "explain-chain", title: "Explain this process chain" },
        { id: "summarise-incident", title: "Summarise this incident" }
      ]
    }),
    ask: async () => answer,
    ...over
  };
}

describe("AssistantPanel", () => {
  it("renders the read-only guarantee where the analyst can see it", async () => {
    render(<AssistantPanel api={fakeApi()} />);
    // Not a nice-to-have: three engine layers make containment impossible, and
    // none of them are worth anything to an operator who cannot see the claim.
    expect(await screen.findByText("Read-only")).toBeInTheDocument();
  });

  it("offers named tasks rather than a blank prompt", async () => {
    render(<AssistantPanel api={fakeApi()} />);
    expect(await screen.findByRole("button", { name: /Explain this process chain/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Summarise this incident/ })).toBeInTheDocument();
  });

  it("shows the answer and the sources it was built from", async () => {
    const user = userEvent.setup();
    render(<AssistantPanel api={fakeApi()} execId="abc" />);
    await user.click(await screen.findByRole("button", { name: /Explain this process chain/ }));

    expect(await screen.findByText(/Consistent with an operator/)).toBeInTheDocument();

    // Provenance is collapsed by default and must be reachable: an answer an
    // analyst cannot verify is not evidence.
    const toggle = screen.getByRole("button", { name: /1 source consulted/ });
    await user.click(toggle);
    expect(screen.getByText("process_tree")).toBeInTheDocument();
    expect(screen.getByText("/api/process/")).toBeInTheDocument();
  });

  it("passes the exec id under investigation to the agent", async () => {
    const ask = vi.fn().mockResolvedValue(answer);
    const user = userEvent.setup();
    render(<AssistantPanel api={fakeApi({ ask })} execId="exec-42" />);
    await user.click(await screen.findByRole("button", { name: /Explain this process chain/ }));
    await waitFor(() =>
      expect(ask).toHaveBeenCalledWith(expect.objectContaining({ agent: "explain-chain", execId: "exec-42" }))
    );
  });

  it("warns when the answer came from a partial investigation", async () => {
    const user = userEvent.setup();
    render(<AssistantPanel api={fakeApi({ ask: async () => ({ ...answer, truncated: true }) })} />);
    await user.click(await screen.findByRole("button", { name: /Explain this process chain/ }));
    // Surfaced, never hidden: an answer built on an incomplete investigation
    // that presents as complete is how a wrong conclusion gets anchored.
    expect(await screen.findByText(/partial investigation/)).toBeInTheDocument();
  });

  it("explains an unconfigured deployment instead of erroring", async () => {
    render(
      <AssistantPanel
        api={fakeApi({
          capability: async () => ({ enabled: false, agents: [], reason: "no model configured" })
        })}
      />
    );
    expect(await screen.findByText(/Not configured/)).toBeInTheDocument();
    // An optional feature that is switched off is not a fault.
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("surfaces a failure without taking the panel down", async () => {
    const user = userEvent.setup();
    render(<AssistantPanel api={fakeApi({ ask: async () => { throw new Error("provider unreachable"); } })} />);
    await user.click(await screen.findByRole("button", { name: /Explain this process chain/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent("provider unreachable");
    // The actions remain usable — the assistant failing must not strand the
    // analyst inside their own investigation.
    expect(screen.getByRole("button", { name: /Summarise this incident/ })).toBeEnabled();
  });

  it("routes a typed question to the conversational agent, not a fixed-task button", async () => {
    // THE BUG THIS PINS. The panel hard-coded `summarise-incident` for free
    // text, so every typed question on all eight surfaces came back as an
    // incident summary — ask "is this host compromised?" and receive a shift
    // handover. It is the same defect that was found and fixed in the sidebar,
    // which had hard-coded a different agent; only the sidebar was fixed.
    const user = userEvent.setup();
    const ask = vi.fn(async (_req: AssistantAskRequest) => answer);
    render(<AssistantPanel api={fakeApi({ ask })} />);

    const input = await screen.findByRole("textbox", { name: /Ask the analyst assistant/ });
    await user.type(input, "is this host compromised?");
    await user.click(screen.getByRole("button", { name: /Send question/ }));

    await waitFor(() => expect(ask).toHaveBeenCalled());
    expect(ask.mock.calls[0][0]).toMatchObject({
      agent: "ask",
      question: "is this host compromised?"
    });
  });

  it("tells the engine which panel it is mounted on", async () => {
    // subjectLabel is for the analyst and never leaves the browser; `surface`
    // is for the model. Conflating them is how a panel could announce
    // "Investigating the device fleet" above an assistant that did not know it
    // was looking at devices.
    const user = userEvent.setup();
    const ask = vi.fn(async (_req: AssistantAskRequest) => answer);
    const capability = vi.fn(async (_surface?: AssistantSurface) => ({
      enabled: true,
      model: "gpt-oss:20b",
      agents: [
        { id: "ask", title: "Ask a question", conversational: true },
        { id: "assess-device-exposure", title: "Assess device exposure" }
      ]
    }));
    render(<AssistantPanel api={fakeApi({ ask, capability })} surface="devices-assurance" />);

    // The capability call is scoped, so the panel is offered the buttons that
    // can actually be answered there.
    await waitFor(() => expect(capability).toHaveBeenCalled());
    expect(capability.mock.calls[0][0]).toBe("devices-assurance");

    await user.click(await screen.findByRole("button", { name: /Assess device exposure/ }));
    await waitFor(() => expect(ask).toHaveBeenCalled());
    expect(ask.mock.calls[0][0]).toMatchObject({ surface: "devices-assurance" });
  });
});
