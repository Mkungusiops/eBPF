import { describe, expect, it } from "vitest";
import { buildCorrelationGraph } from "../features/soc/SocRoute";
import type { SocAlert, SocEvent } from "../features/soc/types";

const alert = (o: Partial<SocAlert>): SocAlert => ({
  id: "a", title: "t", description: "", severity: "high", score: 30,
  timestamp: "2026-07-22T10:00:00Z", raw: {}, ...o
});
const event = (o: Partial<SocEvent>): SocEvent => ({
  id: "e", eventType: "process_exec", timestamp: "2026-07-22T10:00:00Z", raw: {}, ...o
});

describe("buildCorrelationGraph process instances", () => {
  it("keeps every exec_id behind a binary node so enforcement has a target", () => {
    // Two DIFFERENT processes of the same binary must not collapse into one:
    // the node is keyed by binary, but you enforce against an exec_id.
    const g = buildCorrelationGraph(
      [alert({ execId: "X1", pid: 11, process: "/usr/bin/nc", score: 40, agent: "agent-a" })],
      [
        event({ execId: "X1", pid: 11, process: "/usr/bin/nc", policyName: "reverse-shell", agent: "agent-a" }),
        event({ execId: "X2", pid: 22, process: "/usr/bin/nc", policyName: "reverse-shell", agent: "agent-b" })
      ]
    );
    const node = g.nodes.find((n) => n.group === "process" && n.fullLabel === "/usr/bin/nc");
    expect(node).toBeDefined();
    const ids = (node!.processes ?? []).map((p) => p.execId).sort();
    expect(ids).toEqual(["X1", "X2"]);
  });

  it("carries pid, agent and score onto the instance, worst first", () => {
    const g = buildCorrelationGraph(
      [alert({ execId: "HI", pid: 9, process: "/bin/sh", score: 90, agent: "agent-a" })],
      [
        event({ execId: "HI", pid: 9, process: "/bin/sh", agent: "agent-a" }),
        event({ execId: "LO", pid: 8, process: "/bin/sh", agent: "agent-b" })
      ]
    );
    const node = g.nodes.find((n) => n.group === "process" && n.fullLabel === "/bin/sh")!;
    const [worst] = node.processes!;
    expect(worst.execId).toBe("HI");     // highest score sorts first
    expect(worst.pid).toBe(9);
    expect(worst.agent).toBe("agent-a"); // which host the action would hit
    expect(worst.score).toBe(90);
  });

  it("drops records with no exec_id — there is nothing to enforce against", () => {
    const g = buildCorrelationGraph([], [event({ process: "/usr/bin/curl" })]);
    const node = g.nodes.find((n) => n.group === "process" && n.fullLabel === "/usr/bin/curl");
    expect(node?.processes ?? []).toHaveLength(0);
  });
});

describe("buildCorrelationGraph peer (IP) nodes", () => {
  // A real tcp_connect event carries the destination in args ("ip:port"), not
  // destIp/remoteIp (those are only on the sim path). The graph must still draw
  // an IP peer node and wire it to the process — without this, real outbound
  // connections showed only the policy node, never the peer.
  it("draws a peer node from an IP in args, linked to the process", () => {
    const g = buildCorrelationGraph(
      [alert({ execId: "N1", pid: 5, process: "/usr/bin/nc", score: 40 })],
      [
        event({
          execId: "N1", pid: 5, process: "/usr/bin/nc",
          eventType: "process_kprobe", policyName: "outbound-connections",
          args: "185.220.101.1:4444"
        })
      ]
    );
    const peer = g.nodes.find((n) => n.group === "peer");
    expect(peer, "a peer node exists").toBeDefined();
    expect(peer!.label).toContain("185.220.101.1");

    const proc = g.nodes.find((n) => n.group === "process" && n.fullLabel === "/usr/bin/nc")!;
    const linked = g.links.some((l) => {
      const s = typeof l.source === "object" ? (l.source as { id: string }).id : String(l.source);
      const t = typeof l.target === "object" ? (l.target as { id: string }).id : String(l.target);
      return (s === proc.id && t === peer!.id) || (t === proc.id && s === peer!.id);
    });
    expect(linked, "the process is linked to the peer").toBe(true);
  });

  it("still prefers structured destIp when present (sim path unaffected)", () => {
    // Public IP so this exercises the peer path (a private destIp is a device).
    const g = buildCorrelationGraph(
      [],
      [event({ execId: "S1", pid: 7, process: "/bin/sh", destIp: "203.0.113.9", destPort: 443 })]
    );
    const peer = g.nodes.find((n) => n.group === "peer");
    expect(peer?.label).toContain("203.0.113.9:443");
  });
})

describe("buildCorrelationGraph device nodes", () => {
  // A LAN (RFC1918) destination is a device — the same entity the Devices page
  // inventories — not an external peer. This is what wires devices into the
  // correlation graph, which otherwise knew only about processes.
  it("renders a LAN destination as a device node, linked to the process", () => {
    const g = buildCorrelationGraph(
      [alert({ execId: "L1", pid: 3, process: "/usr/bin/nc", score: 30 })],
      [event({
        execId: "L1", pid: 3, process: "/usr/bin/nc",
        eventType: "process_kprobe", policyName: "outbound-connections",
        args: "192.168.139.126:22"
      })]
    );
    const dev = g.nodes.find((n) => n.group === "device");
    expect(dev, "a device node exists for the LAN IP").toBeDefined();
    expect(dev!.label).toContain("192.168.139.126");
    expect(g.nodes.some((n) => n.group === "peer"), "not misfiled as a peer").toBe(false);
  });

  it("keeps a public destination as an external peer, not a device", () => {
    const g = buildCorrelationGraph(
      [],
      [event({ execId: "P1", pid: 4, process: "/usr/bin/nc", args: "185.220.101.1:4444" })]
    );
    expect(g.nodes.some((n) => n.group === "peer")).toBe(true);
    expect(g.nodes.some((n) => n.group === "device")).toBe(false);
  });
})
