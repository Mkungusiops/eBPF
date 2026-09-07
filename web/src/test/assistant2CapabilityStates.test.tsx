/**
 * Four server answers, four different things an operator is told.
 *
 * The first fix sweep guarded the crash (a capability body without `agents` no
 * longer throws) and then printed the SAME sentence for every degraded state:
 * "Not configured on this deployment." That is the defect class this whole
 * sweep exists to remove — one state reported as a different state — and here
 * it is the expensive direction of the mistake. "Not configured" is a claim
 * about the deployment: an operator who reads it stops investigating and asks
 * their platform team for a setting. When the truth is that the console could
 * not READ the server, or could not REACH it, that operator has been sent to
 * the wrong team with a wrong fact, mid-incident.
 *
 * `agents: null` is the case worth naming: both servers marshal a nil slice as
 * an explicit null (no `omitempty`), so `{enabled: true, agents: null}` is a
 * healthy, reachable server saying "the assistant is on and this surface
 * publishes nothing". Reporting that as unreadable sends an operator hunting a
 * transport fault that does not exist.
 */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AssistantPanel } from "../features/assistant/AssistantPanel";
import type { AssistantApi } from "../features/assistant/api";

/** A client whose capability call resolves with `body`, whatever shape it is. */
function apiReturning(body: unknown): AssistantApi {
  return {
    capability: async () => body as never,
    ask: async () => {
      throw new Error("not expected in these tests");
    }
  };
}

/** A client whose capability call REJECTS — the read never completed at all. */
const apiThatFails: AssistantApi = {
  capability: async () => {
    throw new Error("network down");
  },
  ask: async () => {
    throw new Error("not expected in these tests");
  }
};

async function panelFor(api: AssistantApi) {
  render(<AssistantPanel api={api} />);
  const region = await screen.findByRole("region", { name: "Analyst assistant" });
  return region;
}

describe("the assistant panel names WHICH degraded state it is in", () => {
  it("says not-configured only when the server said the assistant is off", async () => {
    const panel = await panelFor(apiReturning({ enabled: false, agents: [], reason: "no model configured" }));

    expect(panel).toHaveAttribute("data-assistant-state", "disabled");
    expect(panel.textContent).toMatch(/Not configured on this deployment/);
    // The server's own explanation is carried through verbatim; it is the part
    // the platform team can act on.
    expect(panel.textContent).toMatch(/no model configured/);
    // Off is not broken.
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("says the response was not understood when a 200 omits the agent list", async () => {
    // An older engine, or a proxy that rewrote the JSON: it claims the
    // assistant is running and then withholds the one field needed to run it.
    const panel = await panelFor(apiReturning({ enabled: true, model: "gpt-oss:20b" }));

    expect(panel).toHaveAttribute("data-assistant-state", "unreadable");
    expect(panel.textContent).not.toMatch(/Not configured on this deployment/);
    expect(panel.textContent).toMatch(/does not understand|could not read/i);
    // And it says what actually happened, so the defect can be reported.
    expect(panel.textContent).toMatch(/omits the agent list/i);
  });

  it("says enabled-but-no-agents-here for an explicit `agents: null`", async () => {
    const panel = await panelFor(apiReturning({ enabled: true, model: "gpt-oss:20b", agents: null }));

    expect(panel).toHaveAttribute("data-assistant-state", "no-agents");
    // Not a settings gap and not a fault: reachable, on, nothing for this panel.
    expect(panel.textContent).not.toMatch(/Not configured on this deployment/);
    expect(panel.textContent).not.toMatch(/could not read|does not understand|could not reach/i);
    expect(panel.textContent).toMatch(/no assistant agents published/i);
    // Nothing to click, so no composer that promises an answer it cannot give.
    expect(screen.queryByLabelText("Ask the analyst assistant a question")).toBeNull();
  });

  it("says the service could not be reached when the capability read itself fails", async () => {
    const panel = await panelFor(apiThatFails);

    expect(panel).toHaveAttribute("data-assistant-state", "unreachable");
    // The one thing it must never claim: that this deployment has no assistant.
    // We never got an answer, so we do not know.
    expect(panel.textContent).not.toMatch(/Not configured on this deployment/);
    expect(panel.textContent).toMatch(/could not reach/i);
    expect(panel.textContent).toMatch(/unknown/i);
  });

  it("keeps an HTTP failure from the real client out of the not-configured state", async () => {
    // createAssistantApi() degrades a non-ok capability read into a body rather
    // than throwing; that body must survive normalisation as unreachable, or
    // the whole distinction is lost one layer below the renderer.
    const panel = await panelFor(
      apiReturning({ enabled: false, agents: [], availability: "unreachable", reason: "unavailable (HTTP 502)" })
    );

    expect(panel).toHaveAttribute("data-assistant-state", "unreachable");
    expect(panel.textContent).not.toMatch(/Not configured on this deployment/);
    expect(panel.textContent).toMatch(/502/);
  });

  it("still renders the working panel when agents are published", async () => {
    // The guard must not swallow the good path.
    const panel = await panelFor(
      apiReturning({
        enabled: true,
        model: "gpt-oss:20b",
        agents: [
          { id: "ask", title: "Ask a question", conversational: true },
          { id: "explain-chain", title: "Explain this process chain" }
        ]
      })
    );

    expect(panel).not.toHaveAttribute("data-assistant-state");
    expect(screen.getByRole("button", { name: /Explain this process chain/ })).toBeTruthy();
  });
});
