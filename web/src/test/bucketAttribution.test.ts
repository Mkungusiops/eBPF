import { describe, expect, it } from "vitest";
import { shortAgent } from "../features/choke/utils";

/**
 * The control plane has always sent `agent` on every kernel bucket and the
 * console's type never declared it, so it was dropped. PIDs are per-host and
 * collide across a fleet, which made the fleet's kernel map not merely
 * unattributed but ambiguous — and the row key omitted the agent too, so two
 * hosts throttling the same PID rendered as one row and the other vanished.
 */
describe("kernel bucket rows are attributed to a host", () => {
  it("keeps the distinguishing tail of an agent id", () => {
    // The "agent-" prefix is identical on every agent, so the head carries no
    // information and would push the numbers that matter off the row.
    expect(shortAgent("agent-f8c76126681c5a63559223b61f888c29")).toBe("…1f888c29");
  });

  it("renders a short id whole", () => {
    expect(shortAgent("agent-abc123")).toBe("abc123");
  });

  it("is empty rather than misleading when there is no agent", () => {
    // The single-host engine sends none: there is only one answer, and
    // inventing a label would imply a fleet that does not exist.
    expect(shortAgent(undefined)).toBe("");
    expect(shortAgent("")).toBe("");
  });

  it("gives two hosts sharing a PID distinct row keys", () => {
    // The collision that dropped a row. Same pid, same flags, different host.
    const key = (b: { agent?: string; pid: number; flags: number }) =>
      `${b.agent || "host"}-${b.pid}-${b.flags}`;
    const a = key({ agent: "agent-aaa", pid: 1156421, flags: 1 });
    const b = key({ agent: "agent-bbb", pid: 1156421, flags: 1 });
    expect(a).not.toBe(b);
  });
});
