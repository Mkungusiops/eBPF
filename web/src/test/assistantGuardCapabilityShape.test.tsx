/**
 * The capability body is the one assistant response nothing validates.
 *
 * `AssistantApi.capability` casts the parsed JSON straight to the interface, so
 * the TYPE promised `agents: AssistantAgent[]` while the VALUE was whatever the
 * server sent. `useAssistant` then read `capability.agents.find(...)` behind an
 * optional chain that guarded only the OUTER object, so a 200 that omitted
 * `agents` threw during render and took the whole SOC route down — from the
 * code path whose own comment promises the assistant "must never take the drill
 * panel down with it". Both servers happen to send `agents: []` today, which is
 * the only reason it was latent rather than live.
 *
 * Pinned end-to-end in web/e2e/resilience.spec.ts; this is the unit-level
 * version, and it also covers the states that spec cannot easily reach.
 */
import { renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { useAssistant } from "../features/assistant/useAssistant";
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

async function capabilityOf(body: unknown) {
  const { result } = renderHook(() => useAssistant({ api: apiReturning(body) }));
  await waitFor(() => expect(result.current.capability).not.toBeNull());
  return result.current;
}

describe("useAssistant survives a capability body it did not expect", () => {
  it("degrades instead of throwing when a 200 body omits `agents`", async () => {
    const state = await capabilityOf({ enabled: false, reason: "older server, no agents field" });

    // The dereference that used to crash the route.
    expect(state.conversationalAgent).toBeNull();
    expect(state.capability?.agents).toEqual([]);
    // The server's own explanation is kept: it told us why it is off, and that
    // is more useful to an operator than a generic degraded message.
    expect(state.capability?.reason).toBe("older server, no agents field");
  });

  it("renders the panel rather than crashing when consumers filter the agent list", async () => {
    // AssistantPanel does `capability.agents.filter(...)`. Guarding only the
    // hook's own derivation would move the crash one component along, so the
    // hook normalises what it EXPOSES, not just what it reads.
    const state = await capabilityOf({ enabled: false, reason: "no model configured" });
    expect(() => state.capability?.agents.filter((a) => !a.conversational)).not.toThrow();
  });

  it("says the capability could not be read when it claims enabled with no agent list", async () => {
    const state = await capabilityOf({ enabled: true, model: "gpt-oss:20b" });

    // "Not configured" and "we could not understand the answer" are different
    // facts and an operator acts on them differently, so the reason must not be
    // silently reused for both.
    expect(state.capability?.enabled).toBe(false);
    expect(state.capability?.reason).toMatch(/could not be read/i);
    expect(state.conversationalAgent).toBeNull();
  });

  it("treats a body that is not an object, or lacks `enabled`, as unreadable", async () => {
    for (const body of [null, 42, "enabled", [], { agents: [{ id: "ask" }] }]) {
      const state = await capabilityOf(body);
      expect(state.capability?.enabled, JSON.stringify(body)).toBe(false);
      expect(state.capability?.reason, JSON.stringify(body)).toMatch(/could not be read/i);
    }
  });

  it("drops agent entries with no usable id rather than offering a nameless button", async () => {
    const state = await capabilityOf({
      enabled: true,
      agents: [{ id: "ask", title: "Ask", conversational: true }, null, { title: "no id" }, { id: "" }]
    });

    expect(state.capability?.enabled).toBe(true);
    expect(state.capability?.agents.map((a) => a.id)).toEqual(["ask"]);
    expect(state.conversationalAgent).toBe("ask");
  });

  it("still selects the conversational agent by flag on a well-formed body", async () => {
    // The guard must not change the good path: picking agents[0] is what once
    // turned "Hello" into a process-chain analysis.
    const state = await capabilityOf({
      enabled: true,
      agents: [
        { id: "explain-chain", title: "Explain this process chain" },
        { id: "ask", title: "Ask a question", conversational: true }
      ]
    });

    expect(state.conversationalAgent).toBe("ask");
  });
});
