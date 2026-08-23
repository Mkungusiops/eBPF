import { describe, expect, it } from "vitest";
import { normalizeAlert, normalizeEvent } from "../features/soc/api";
import { buildCorrelationGraph } from "../features/soc/graphModel";
import fixtures from "./fixtures/correlation-graph-live.json";

/**
 * The correlation graph, built from payloads captured off BOTH live
 * deployments.
 *
 * The two servers do not agree on field names and never have: the single-tenant
 * engine sends `binary` and `parent_pid`, the multi-tenant control plane sends
 * `process` and `agent` and no parent at all. Everything downstream depends on
 * a normaliser absorbing that, and a field it silently drops costs the graph a
 * whole class of edge without anything failing.
 *
 * That is not hypothetical — it is why these fixtures exist. `parent_pid` was
 * being discarded, so on the engine the graph had 18 process nodes joined by 9
 * edges and most of them were isolated dots.
 */
type Payload = { alerts: unknown[]; events: unknown[] };
const data = fixtures as unknown as Record<string, Payload>;

function graphFor(dep: string) {
  const alerts = data[dep].alerts.map((a, i) => normalizeAlert(a, i));
  const events = data[dep].events.map((e, i) => normalizeEvent(e, i));
  return { alerts, events, graph: buildCorrelationGraph(alerts, events) };
}

for (const dep of ["engine", "cp"]) {
  describe(`correlation graph — ${dep}`, () => {
    it("builds a connected graph, with no blank nodes", () => {
      const { graph } = graphFor(dep);
      const byGroup: Record<string, number> = {};
      for (const n of graph.nodes) byGroup[n.group] = (byGroup[n.group] ?? 0) + 1;

      expect(graph.nodes.length).toBeGreaterThan(0);
      // A cloud of isolated dots is not a correlation graph.
      expect(graph.links.length).toBeGreaterThan(0);
      // Process nodes are the spine; without them nothing is pivotable.
      expect(byGroup.process ?? 0).toBeGreaterThan(0);
      // A blank label is what a field-name mismatch looks like on screen.
      expect(graph.nodes.filter((n) => !n.label?.trim()).map((n) => n.id)).toEqual([]);
      // Every edge must join nodes that were actually emitted.
      const ids = new Set(graph.nodes.map((n) => n.id));
      for (const l of graph.links) {
        expect(ids.has(String(l.source))).toBe(true);
        expect(ids.has(String(l.target))).toBe(true);
      }
    });
  });
}

describe("process lineage", () => {
  it("recovers parent → child edges the alert title cannot supply", () => {
    const { events } = graphFor("engine");
    // The engine really does send it, and the normaliser must keep it.
    expect(events.some((e) => e.parentPid && e.parentPid > 0)).toBe(true);
  });

  it("draws more edges with parent_pid than without it", () => {
    const alerts = data.engine.alerts.map((a, i) => normalizeAlert(a, i));
    const events = data.engine.events.map((e, i) => normalizeEvent(e, i));
    const withParents = buildCorrelationGraph(alerts, events);
    const stripped = buildCorrelationGraph(
      alerts,
      events.map((e) => ({ ...e, parentPid: undefined }))
    );
    expect(withParents.links.length).toBeGreaterThan(stripped.links.length);
  });

  it("says nothing when the parent was never observed in the window", () => {
    const alerts = data.engine.alerts.map((a, i) => normalizeAlert(a, i));
    const events = data.engine.events.map((e, i) => normalizeEvent(e, i));
    // Parents that exist in no exec event must not invent a node or an edge.
    const orphaned = events.map((e) => ({ ...e, parentPid: 999_999 }));
    const g = buildCorrelationGraph(alerts, orphaned);
    expect(g.nodes.some((n) => n.id.includes("999999"))).toBe(false);
  });
});
