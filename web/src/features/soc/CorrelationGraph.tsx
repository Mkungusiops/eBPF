import { Maximize2, Minimize2, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type * as React from "react";
import { applyChokeAction, fetchChokeCircuits, type ChokeAction, type ChokeCircuit } from "./api";
import { ACTION_FOR_RUNG, ladderIndex, type Rung } from "../common/enforcement";
import { EmptyState, InlineNotice, cx } from "./components";
import { SearchField } from "./panels";
import { GraphBrief } from "./GraphBrief";
import { GraphSelectionRail } from "./GraphSelectionRail";
import { ProcessActionModal } from "./ProcessActionModal";
import { MiniBarList } from "./rows";
import { GRAPH_CLASSES, buildCorrelationGraph, filterGraph, graphLinkKey, graphMeta, type CorrelationGraphData, type GraphClass, type GraphControls, type GraphLayout, type GraphLink, type GraphLinkSel, type GraphNode, type GraphNodeSel, type ProcessInstance } from "./graphModel";
import type { SocAlert, SocEvent } from "./types";
import "./soc.css";

// The D3 force-graph bridge for the SOC correlation view.
//
// Split out of SocRoute because it is a genuinely different kind of code: an
// imperative simulation driven by refs and a 17-method handle, sitting inside
// an otherwise declarative tree. Keeping it inline made the route file
// impossible to read past it, and made this hard to reason about on its own.
interface GraphHandle {
  destroy: () => void;
  controls: GraphControls;
  resize: () => void;
  // Incrementally fold the latest correlation data into the running graph,
  // preserving existing node positions and animating in newly-seen processes.
  // Returns the number of brand-new process nodes folded in (drives "LIVE +N").
  update: (data: CorrelationGraphData) => number;
  setLayout: (layout: GraphLayout) => void;
  setSearch: (query: string) => void;
  setSelected: (id: string | null) => void;
  // Mark nodes whose processes are already held on the ladder. Keyed by node id,
  // valued by the HIGHEST rung among that node's processes. Applied through the
  // same restyle pass as selection, so a 5s containment refresh never disturbs
  // the running simulation.
  setContained: (byNode: Map<string, Rung>) => void;
}

// Imperatively render a live D3 force graph into the svg shell: a running
// simulation (so nodes can be dragged), wheel zoom + canvas pan, and a
// fit-to-view so the whole graph is legible at once. React owns the svg element
// but D3 owns its contents, which keeps the simulation off the React render path:
// live data arrives through update(), which diffs by id so existing nodes keep
// their positions (no re-mount/blink) while new processes animate in.
function renderForceGraph(
  svgEl: SVGSVGElement,
  d3: typeof import("d3"),
  data: CorrelationGraphData,
  onSelect: (node: GraphNode | null) => void
): GraphHandle {
  const rect = svgEl.getBoundingClientRect();
  let width = Math.max(320, Math.round(rect.width) || 920);
  let height = Math.max(280, Math.round(rect.height) || 460);

  const svg = d3.select(svgEl);
  svg.selectAll("*").remove();
  svg.attr("viewBox", `0 0 ${width} ${height}`);

  const root = svg.append("g").attr("class", "soc-graph-zoomable");
  const linkLayer = root.append("g").attr("class", "soc-graph-link-layer");
  const nodeLayer = root.append("g").attr("class", "soc-graph-node-layer");

  // Smaller discs + more spacing keep dense graphs (40+ nodes) legible — the
  // old r≤14 made big nodes collide and labels overlap.
  const nodeRadius = (node: GraphNode) => Math.max(4, Math.min(9, 3.5 + node.weight * 0.45));

  let nodes = data.nodes;
  let links = data.links;
  let layout: GraphLayout = "force";
  let selectedId: string | null = null;
  let searchQuery = "";
  let containedByNode = new Map<string, Rung>();

  const searchableNodeText = (node: GraphNode) => `${node.label} ${node.fullLabel || ""}`.toLowerCase();

  // Adjacency, rebuilt on each structural change, powers neighbourhood highlight
  // when a node is selected and the radial grouping order.
  let adjacency = new Map<string, Set<string>>();
  const rebuildAdjacency = () => {
    adjacency = new Map();
    for (const lnk of links) {
      const s = typeof lnk.source === "object" ? lnk.source.id : String(lnk.source);
      const t = typeof lnk.target === "object" ? lnk.target.id : String(lnk.target);
      // get-or-create, so the set is a value the compiler can see rather than a
      // `Map.get(...)!` asserted non-null on the render path.
      const sourceEdges = adjacency.get(s) ?? new Set<string>();
      const targetEdges = adjacency.get(t) ?? new Set<string>();
      adjacency.set(s, sourceEdges);
      adjacency.set(t, targetEdges);
      sourceEdges.add(t);
      targetEdges.add(s);
    }
  };

  const linkForce = d3
    .forceLink<GraphNode, GraphLink>(links)
    .id((node) => node.id)
    .distance(92)
    .strength(0.32);
  const simulation = d3
    .forceSimulation<GraphNode>(nodes)
    .force("link", linkForce)
    .force("charge", d3.forceManyBody<GraphNode>().strength(-340))
    // A generous collision pad (≈ a label's width) keeps node labels from
    // stacking on top of each other.
    .force("collide", d3.forceCollide<GraphNode>().radius((node) => nodeRadius(node) + 26))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("x", d3.forceX<GraphNode>(width / 2).strength(0.045))
    .force("y", d3.forceY<GraphNode>(height / 2).strength(0.045))
    .stop();

  // Switch the active force configuration. Force = organic spread; Radial =
  // concentric rings keyed by node group; Decay = tight, fast-settling cluster
  // (high velocity decay) that reads as a "cooling" snapshot.
  const GROUP_RING: Record<GraphNode["group"], number> = { process: 0.34, policy: 0.6, file: 0.82, device: 0.9, peer: 0.95 };
  const applyLayout = (next: GraphLayout) => {
    layout = next;
    const minDim = Math.min(width, height);
    if (next === "radial") {
      simulation
        .force("charge", d3.forceManyBody<GraphNode>().strength(-120))
        .force("x", null)
        .force("y", null)
        .force(
          "radial",
          d3
            .forceRadial<GraphNode>((node) => GROUP_RING[node.group] * (minDim / 2 - 24), width / 2, height / 2)
            .strength(0.85)
        );
      linkForce.distance(48).strength(0.25);
      simulation.velocityDecay(0.4);
    } else if (next === "decay") {
      simulation
        .force("charge", d3.forceManyBody<GraphNode>().strength(-160))
        .force("radial", null)
        .force("x", d3.forceX<GraphNode>(width / 2).strength(0.11))
        .force("y", d3.forceY<GraphNode>(height / 2).strength(0.11));
      linkForce.distance(58).strength(0.6);
      simulation.velocityDecay(0.75);
    } else {
      simulation
        .force("charge", d3.forceManyBody<GraphNode>().strength(-340))
        .force("radial", null)
        .force("x", d3.forceX<GraphNode>(width / 2).strength(0.045))
        .force("y", d3.forceY<GraphNode>(height / 2).strength(0.045));
      linkForce.distance(92).strength(0.32);
      simulation.velocityDecay(0.4);
    }
    simulation.alpha(0.6).restart();
  };

  const drag = d3
    .drag<SVGGElement, GraphNode>()
    // Use the (zoom-transformed) node layer as the pointer reference so drag
    // coordinates stay aligned with node positions at any zoom level.
    .container(function () {
      return this.parentNode as SVGGElement;
    })
    .on("start", (event, d) => {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    })
    .on("drag", (event, d) => {
      d.fx = event.x;
      d.fy = event.y;
    })
    .on("end", (event, d) => {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    });

  let link: GraphLinkSel = linkLayer.selectAll<SVGLineElement, GraphLink>("line");
  let node: GraphNodeSel = nodeLayer.selectAll<SVGGElement, GraphNode>("g.soc-graph-node");
  let firstRender = true;
  let pulseIds = new Set<string>();

  // A ring that expands and fades behind a node — flags a process that just
  // joined or just produced fresh events, so the live graph reads as alive.
  const pulse = (selection: GraphNodeSel) => {
    selection
      .insert("circle", ":first-child")
      .attr("class", "soc-graph-pulse")
      .attr("r", (d) => nodeRadius(d))
      .style("opacity", 0.5)
      .call((sel) => sel.transition().duration(900).attr("r", (d) => nodeRadius(d) + 16).style("opacity", 0).remove());
  };

  const baseNodeClass = (d: GraphNode) =>
    `soc-graph-node node-${d.group}${d.group === "process" && d.cls ? ` score-${d.cls}` : ""}`;

  const applyJoin = () => {
    link = link
      .data(links, graphLinkKey)
      .join((enter) => enter.append("line"))
      .attr("stroke-width", (d) => Math.max(0.75, Math.min(3, d.weight)));

    node = node.data(nodes, (d) => d.id).join(
      (enter) => {
        const group = enter
          .append("g")
          .attr("class", baseNodeClass)
          .attr("aria-label", (d) => d.fullLabel || d.label)
          .style("cursor", "pointer")
          .on("click", (event: PointerEvent, d) => {
            event.stopPropagation();
            select(selectedId === d.id ? null : d.id);
          });
        const disc = group.append("circle").attr("class", "soc-graph-disc");
        if (firstRender) disc.attr("r", nodeRadius);
        else disc.attr("r", 0).transition().duration(450).attr("r", nodeRadius);
        group
          .append("text")
          .attr("x", (d) => nodeRadius(d) + 4)
          .attr("y", 3)
          .text((d) => d.label);
        // A process appearing after the first paint visibly "joins" the graph.
        if (!firstRender) pulse(group);
        return group;
      },
      (existing) => {
        existing.attr("class", baseNodeClass).attr("aria-label", (d) => d.fullLabel || d.label);
        existing.select<SVGCircleElement>("circle.soc-graph-disc").attr("r", nodeRadius);
        existing
          .select<SVGTextElement>("text")
          .attr("x", (d) => nodeRadius(d) + 4)
          .text((d) => d.label);
        // Already-present processes with fresh activity pulse in place.
        existing.filter((d) => pulseIds.has(d.id)).call(pulse);
        return existing;
      },
      (exit) => exit.call((sel) => sel.transition().duration(300).style("opacity", 0).remove())
    );
    node.call(drag);
    firstRender = false;
    restyle();
  };

  // Apply selection-highlight and search-dim classes without touching the
  // simulation. A selected node lights its neighbourhood; everything else dims.
  const restyle = () => {
    const neighbours = selectedId ? new Set<string>([selectedId, ...(adjacency.get(selectedId) ?? [])]) : null;
    const q = searchQuery.trim().toLowerCase();
    node
      // Containment was previously legible only after clicking a node and
      // reading its process list, so on a graph of any size an operator could
      // not see WHICH processes were already held — the question they ask first
      // during triage. The rung rides on the node as a data attribute so the
      // marker is styled in CSS per rung, in both themes.
      .classed("is-contained", (d) => containedByNode.has(d.id))
      .attr("data-rung", (d) => containedByNode.get(d.id) ?? null)
      .classed("is-selected", (d) => d.id === selectedId)
      .classed("is-neighbour", (d) => Boolean(neighbours && neighbours.has(d.id) && d.id !== selectedId))
      .classed("is-match", (d) => Boolean(q) && searchableNodeText(d).includes(q))
      .classed("is-dim", (d) => {
        if (neighbours && !neighbours.has(d.id)) return true;
        if (q && !searchableNodeText(d).includes(q)) return true;
        return false;
      });
    link.classed("is-active", (d) => {
      if (!neighbours) return false;
      const s = (d.source as GraphNode).id ?? String(d.source);
      const t = (d.target as GraphNode).id ?? String(d.target);
      return neighbours.has(s) && neighbours.has(t);
    });
  };

  const select = (id: string | null) => {
    selectedId = id;
    restyle();
    onSelect(id ? nodes.find((entry) => entry.id === id) ?? null : null);
  };

  // Clicking empty canvas clears the current selection.
  svg.on("click", () => select(null));

  const ticked = () => {
    link
      .attr("x1", (d) => (d.source as GraphNode).x ?? 0)
      .attr("y1", (d) => (d.source as GraphNode).y ?? 0)
      .attr("x2", (d) => (d.target as GraphNode).x ?? 0)
      .attr("y2", (d) => (d.target as GraphNode).y ?? 0);
    node.attr("transform", (d) => `translate(${d.x ?? 0},${d.y ?? 0})`);
  };

  applyJoin();
  rebuildAdjacency();
  simulation.on("tick", ticked);
  simulation.tick(260); // settle once for a stable, non-jumpy initial layout
  ticked();

  const zoom = d3
    .zoom<SVGSVGElement, unknown>()
    .scaleExtent([0.25, 4])
    .on("zoom", (event) => {
      root.attr("transform", event.transform.toString());
    });
  svg.call(zoom).style("cursor", "grab");

  const fit = () => {
    if (!nodes.length) return;
    const xs = nodes.map((entry) => entry.x ?? width / 2);
    const ys = nodes.map((entry) => entry.y ?? height / 2);
    const minX = Math.min(...xs);
    const maxX = Math.max(...xs);
    const minY = Math.min(...ys);
    const maxY = Math.max(...ys);
    const graphWidth = Math.max(1, maxX - minX);
    const graphHeight = Math.max(1, maxY - minY);
    const padding = 70;
    const scale = Math.max(0.25, Math.min(2, Math.min((width - padding) / graphWidth, (height - padding) / graphHeight)));
    const tx = width / 2 - scale * (minX + maxX) / 2;
    const ty = height / 2 - scale * (minY + maxY) / 2;
    svg.transition().duration(350).call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
  };
  fit();

  const resize = () => {
    const nextRect = svgEl.getBoundingClientRect();
    const nextWidth = Math.max(320, Math.round(nextRect.width) || width);
    const nextHeight = Math.max(280, Math.round(nextRect.height) || height);
    if (nextWidth === width && nextHeight === height) {
      fit();
      return;
    }
    width = nextWidth;
    height = nextHeight;
    svg.attr("viewBox", `0 0 ${width} ${height}`);
    simulation.force("center", d3.forceCenter(width / 2, height / 2));
    applyLayout(layout);
    fit();
  };

  const update = (next: CorrelationGraphData): number => {
    const byId = new Map(nodes.map((entry) => [entry.id, entry] as const));
    const prevNodeIds = new Set(byId.keys());
    const prevLinkKeys = new Set(links.map(graphLinkKey));
    pulseIds = new Set();
    let added = 0;

    // Reuse existing node objects so positions/velocities (and any active drag
    // pins) survive; seed brand-new processes near the centre so they fly in.
    nodes = next.nodes.map((entry) => {
      const existing = byId.get(entry.id);
      if (existing) {
        // A heavier weight means new alerts/events landed on this process.
        if (entry.weight > existing.weight + 0.05) pulseIds.add(entry.id);
        existing.weight = entry.weight;
        existing.label = entry.label;
        existing.fullLabel = entry.fullLabel;
        existing.group = entry.group;
        existing.score = entry.score;
        existing.cls = entry.cls;
        return existing;
      }
      if (entry.group === "process") added += 1;
      entry.x = width / 2 + (Math.random() - 0.5) * 60;
      entry.y = height / 2 + (Math.random() - 0.5) * 60;
      return entry;
    });
    links = next.links.map((entry) => ({
      source: typeof entry.source === "object" ? entry.source.id : entry.source,
      target: typeof entry.target === "object" ? entry.target.id : entry.target,
      weight: entry.weight
    }));

    const nodesChanged = nodes.length !== prevNodeIds.size || nodes.some((entry) => !prevNodeIds.has(entry.id));
    const linksChanged = links.length !== prevLinkKeys.size || links.some((entry) => !prevLinkKeys.has(graphLinkKey(entry)));

    // A selected process that aged out of the graph clears the selection panel.
    if (selectedId && !nodes.some((entry) => entry.id === selectedId)) select(null);

    applyJoin();
    rebuildAdjacency();
    simulation.nodes(nodes);
    linkForce.links(links);
    // Re-heat only on structural change, and gently — keep the operator's
    // current pan/zoom and avoid a full re-layout jitter on every tick.
    if (nodesChanged || linksChanged) simulation.alpha(0.3).restart();
    return added;
  };

  return {
    destroy: () => {
      simulation.on("tick", null);
      simulation.stop();
      svg.on(".zoom", null);
      svg.on("click", null);
      svg.selectAll("*").remove();
    },
    resize,
    update,
    setLayout: (next: GraphLayout) => {
      if (next !== layout) applyLayout(next);
    },
    setSearch: (query: string) => {
      searchQuery = query;
      restyle();
    },
    setSelected: (id: string | null) => select(id),
    setContained: (byNode: Map<string, Rung>) => {
      containedByNode = byNode;
      restyle();
    },
    controls: {
      zoomIn: () => void svg.transition().duration(200).call(zoom.scaleBy, 1.3),
      zoomOut: () => void svg.transition().duration(200).call(zoom.scaleBy, 1 / 1.3),
      reset: () => void svg.transition().duration(250).call(zoom.transform, d3.zoomIdentity),
      fit
    }
  };
}

export function CorrelationGraph({
  active,
  alerts,
  events,
  topProcesses
}: {
  active: boolean;
  alerts: SocAlert[];
  events: SocEvent[];
  topProcesses: Array<{ process: string; score: number; count: number; execId?: string }>;
}) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const dataRef = useRef<{ alerts: SocAlert[]; events: SocEvent[] }>({ alerts, events });
  dataRef.current = { alerts, events };
  const lastDataRef = useRef<CorrelationGraphData>({ nodes: [], links: [] });
  const controlsRef = useRef<GraphControls | null>(null);
  const handleRef = useRef<GraphHandle | null>(null);
  const [phase, setPhase] = useState<"loading" | "ready" | "empty" | "error">("loading");
  const [errorMsg, setErrorMsg] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);
  const [live, setLive] = useState(true);
  const [layout, setLayout] = useState<GraphLayout>("force");
  const [show, setShow] = useState<Set<GraphClass>>(() => new Set<GraphClass>(["attack", "threat", "baseline"]));
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [liveAdded, setLiveAdded] = useState(0);
  const [meta, setMeta] = useState({ processes: 0, edges: 0 });
  const [maximized, setMaximized] = useState(false);

  // Refs so the build closure always reads the latest filter without forcing a
  // teardown/rebuild (which blinks) whenever a chip toggles.
  const showRef = useRef(show);
  showRef.current = show;
  const queryRef = useRef(query);
  queryRef.current = query;
  const layoutRef = useRef(layout);
  layoutRef.current = layout;

  const buildFiltered = useCallback(() => {
    const data = filterGraph(
      buildCorrelationGraph(dataRef.current.alerts, dataRef.current.events),
      showRef.current
    );
    lastDataRef.current = data;
    return data;
  }, []);

  // Build the simulation once when the surface opens or the user forces a
  // rebuild — never on every live buffer tick, which is what used to blink.
  useEffect(() => {
    if (!active) return undefined;
    let cancelled = false;
    let raf = 0;
    setPhase("loading");
    setErrorMsg("");
    setSelected(null);
    setLiveAdded(0);
    controlsRef.current = null;
    handleRef.current = null;
    void import("d3")
      .then((d3) => {
        if (cancelled) return;
        const data = buildFiltered();
        if (!data.nodes.length) {
          setPhase("empty");
          return;
        }
        raf = requestAnimationFrame(() => {
          if (cancelled || !svgRef.current) return;
          const handle = renderForceGraph(svgRef.current, d3, data, (node) => setSelected(node));
          handleRef.current = handle;
          controlsRef.current = handle.controls;
          if (layoutRef.current !== "force") handle.setLayout(layoutRef.current);
          if (queryRef.current) handle.setSearch(queryRef.current);
          setMeta(graphMeta(data));
          setPhase("ready");
        });
      })
      .catch((error) => {
        if (!cancelled) {
          setErrorMsg(error instanceof Error ? error.message : String(error));
          setPhase("error");
        }
      });

    return () => {
      cancelled = true;
      if (raf) cancelAnimationFrame(raf);
      handleRef.current?.destroy();
      handleRef.current = null;
    };
  }, [active, refreshKey, buildFiltered]);

  // Live updates: fold the latest data into the running graph (debounced) so new
  // processes animate in. Pausing freezes the current view.
  const liveSignature = `${alerts.length}:${events.length}:${alerts[0]?.id ?? ""}:${events[0]?.id ?? ""}`;
  useEffect(() => {
    if (!active || !live || phase !== "ready") return undefined;
    const timer = window.setTimeout(() => {
      const data = buildFiltered();
      const added = handleRef.current?.update(data) ?? 0;
      if (added > 0) setLiveAdded((value) => value + added);
      setMeta(graphMeta(data));
    }, 700);
    return () => window.clearTimeout(timer);
  }, [active, live, phase, liveSignature, buildFiltered]);

  // Recover from a premature "empty" verdict.
  //
  // The graph is built once, and the live updater above only runs once it is
  // "ready". So if the surface is opened before the alert buffer has landed,
  // the build finds nothing, latches "empty", and stays empty forever — no
  // amount of incoming data brings it back, because nothing re-triggers the
  // build. Opening the graph a few seconds later showed 61 nodes; opening it
  // immediately showed none, permanently. Watch for data arriving and rebuild.
  useEffect(() => {
    if (!active || phase !== "empty") return undefined;
    const timer = window.setTimeout(() => {
      if (buildFiltered().nodes.length > 0) setRefreshKey((key) => key + 1);
    }, 700);
    return () => window.clearTimeout(timer);
  }, [active, phase, liveSignature, buildFiltered]);

  // Filter / layout / search push to the running handle without a rebuild.
  useEffect(() => {
    if (phase !== "ready") return;
    const data = buildFiltered();
    handleRef.current?.update(data);
    setMeta(graphMeta(data));
  }, [show, phase, buildFiltered]);
  useEffect(() => {
    if (phase === "ready") handleRef.current?.setLayout(layout);
  }, [layout, phase]);
  useEffect(() => {
    if (phase === "ready") handleRef.current?.setSearch(query);
  }, [query, phase]);
  useEffect(() => {
    if (phase !== "ready") return undefined;
    let secondFrame = 0;
    const firstFrame = requestAnimationFrame(() => {
      secondFrame = requestAnimationFrame(() => handleRef.current?.resize());
    });
    return () => {
      cancelAnimationFrame(firstFrame);
      if (secondFrame) cancelAnimationFrame(secondFrame);
    };
  }, [maximized, phase]);

  const toggleClass = (key: GraphClass) =>
    setShow((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      // Never let every class be hidden — keep at least one visible.
      return next.size ? next : prev;
    });

  // The drilled-into process (level 2 of the panel). Cleared whenever the
  // selected node changes so you never act on a process from a previous node.
  const [drill, setDrill] = useState<ProcessInstance | null>(null);
  useEffect(() => {
    setDrill(null);
  }, [selected?.id]);

  // Live ladder state, keyed by exec_id. Refreshed while the panel is open so a
  // rung that was just applied (or applied autonomously by the scorer) is
  // reflected rather than the operator acting on a stale picture.
  const [circuits, setCircuits] = useState<Map<string, ChokeCircuit>>(new Map());
  // Q1: a binary node can stand for 50+ processes, most of them identical at a
  // glance. Rather than an arbitrary cap that hides work, the list scrolls and
  // is filterable, and "contained only" answers the question an operator
  // actually has during triage: what is already held, and what is not?
  const [procFilter, setProcFilter] = useState("");
  const [containedOnly, setContainedOnly] = useState(false);

  const refreshCircuits = useCallback(async () => {
    const list = await fetchChokeCircuits();
    setCircuits(new Map(list.map((c) => [c.execId, c])));
  }, []);

  useEffect(() => {
    if (!active) return;
    void refreshCircuits();
    const timer = window.setInterval(() => void refreshCircuits(), 5000);
    return () => window.clearInterval(timer);
  }, [active, refreshCircuits]);

  // Put containment on the CANVAS, not only in the drill-in.
  //
  // The rung was already fetched above and every node already carries its
  // processes, so this is a join rather than another request. Without it the
  // only way to learn which processes are held is to click each node in turn
  // and read its list — on a graph of any size that is the first question an
  // operator has and the slowest one to answer. Pushed through the handle's
  // restyle path (like selection and search) so a 5s refresh re-marks nodes
  // without restarting the force simulation and scattering the layout.
  useEffect(() => {
    if (phase !== "ready") return;
    const byNode = new Map<string, Rung>();
    for (const graphNode of lastDataRef.current.nodes) {
      for (const proc of graphNode.processes ?? []) {
        const state = circuits.get(proc.execId)?.state;
        if (!state || state === "pristine") continue;
        // A binary node stands for many processes; the node reports the most
        // severe rung among them, so a single severed child is never hidden
        // behind a dozen merely-throttled siblings.
        const current = byNode.get(graphNode.id);
        if (!current || ladderIndex(state) > ladderIndex(current)) byNode.set(graphNode.id, state as Rung);
      }
    }
    handleRef.current?.setContained(byNode);
  }, [circuits, phase]);

  useEffect(() => {
    setProcFilter("");
    setContainedOnly(false);
  }, [selected?.id]);

  const drillState = drill ? circuits.get(drill.execId)?.state ?? "pristine" : "pristine";

  // Transport for the shared ladder. The component owns the interaction (reason,
  // confirm, dispatch-vs-confirmed polling); the page owns how a process is
  // addressed and read back.
  const applyToProcess = useCallback(
    async (rung: Rung, why: string) => {
      if (!drill) return { ok: false, detail: "no process selected" };
      return applyChokeAction(
        ACTION_FOR_RUNG[rung] as ChokeAction,
        { execId: drill.execId, pid: drill.pid, binary: drill.binary },
        why
      );
    },
    [drill]
  );

  const readProcessState = useCallback(async () => {
    if (!drill) return undefined;
    const list = await fetchChokeCircuits();
    setCircuits(new Map(list.map((c) => [c.execId, c])));
    // Undefined (rather than "pristine") when the circuit is gone — the ladder
    // reads absence as "released", which is exactly what it means here.
    return list.find((c) => c.execId === drill.execId)?.state;
  }, [drill]);

  const neighbours = useMemo(() => {
    if (!selected) return [];
    const ids = new Set<string>();
    for (const link of lastDataRef.current.links) {
      const s = typeof link.source === "object" ? link.source.id : String(link.source);
      const t = typeof link.target === "object" ? link.target.id : String(link.target);
      if (s === selected.id) ids.add(t);
      if (t === selected.id) ids.add(s);
    }
    return lastDataRef.current.nodes.filter((node) => ids.has(node.id));
  }, [selected]);

  // Every node answers the same question: "which processes are behind this?"
  // A process node answers with its own instances; a policy/file/peer node is
  // evidence, so it answers with the processes it is wired to. Resolving via
  // edges (rather than copying instances onto context nodes) keeps one source
  // of truth and stops the same process appearing with stale data on five dots.
  const nodeProcesses = useMemo<ProcessInstance[]>(() => {
    if (!selected) return [];
    const source = selected.group === "process" ? [selected] : neighbours.filter((n) => n.group === "process");
    const byExec = new Map<string, ProcessInstance>();
    for (const node of source) {
      for (const proc of node.processes ?? []) {
        const existing = byExec.get(proc.execId);
        if (!existing || proc.score > existing.score) byExec.set(proc.execId, proc);
      }
    }
    return [...byExec.values()].sort((a, b) => b.score - a.score);
  }, [selected, neighbours]);

  const visibleProcesses = useMemo(() => {
    const q = procFilter.trim().toLowerCase();
    return nodeProcesses.filter((proc) => {
      if (containedOnly) {
        const state = circuits.get(proc.execId)?.state;
        if (!state || state === "pristine") return false;
      }
      if (!q) return true;
      return String(proc.pid ?? "").includes(q) || proc.execId.toLowerCase().includes(q);
    });
  }, [nodeProcesses, procFilter, containedOnly, circuits]);

  if (!active) {
    return <EmptyState title="Graph paused" detail="Open the correlation graph to load the D3 graph engine." />;
  }

  return (
    <div className={cx("soc-graph-shell", maximized && "is-maximized")}>
      <div className="soc-graph-main">
        <GraphBrief alerts={alerts} events={events} topProcesses={topProcesses} meta={meta} live={live} />
        <div className="soc-graph-controlbar">
          <div className="soc-graph-counts">
            <strong>{meta.processes}</strong> processes · <strong>{meta.edges}</strong> edges
          </div>
          <SearchField value={query} onChange={setQuery} placeholder="Search binary or exec_id…" />
          <div className="soc-graph-segment" role="group" aria-label="show">
            <span>show</span>
            {GRAPH_CLASSES.map((entry) => (
              <button
                key={entry.key}
                type="button"
                className={cx("soc-graph-show", `cls-${entry.key}`, show.has(entry.key) && "is-active")}
                onClick={() => toggleClass(entry.key)}
              >
                {entry.label}
              </button>
            ))}
          </div>
          <div className="soc-graph-segment" role="group" aria-label="layout">
            <span>layout</span>
            {(["force", "radial", "decay"] as GraphLayout[]).map((entry) => (
              <button
                key={entry}
                type="button"
                className={cx("soc-graph-layout", layout === entry && "is-active")}
                onClick={() => setLayout(entry)}
              >
                {entry}
              </button>
            ))}
          </div>
          <button
            type="button"
            className={cx("soc-graph-live", live && "is-live")}
            onClick={() => {
              setLive((value) => !value);
              setLiveAdded(0);
            }}
            title={live ? "Live — new processes stream in. Click to pause." : "Paused. Click to resume."}
          >
            <span className="soc-graph-live-dot" />
            {live ? "LIVE" : "PAUSED"}
            {live && liveAdded > 0 ? <em>+{liveAdded}</em> : null}
          </button>
          <button
            type="button"
            className="soc-graph-icon"
            onClick={() => setMaximized((value) => !value)}
            title={maximized ? "Minimize graph" : "Maximize graph"}
            aria-label={maximized ? "Minimize graph" : "Maximize graph"}
          >
            {maximized ? <Minimize2 size={14} aria-hidden="true" /> : <Maximize2 size={14} aria-hidden="true" />}
          </button>
          <button type="button" className="soc-graph-icon" onClick={() => setRefreshKey((key) => key + 1)} title="Rebuild" aria-label="Rebuild">
            <RefreshCw size={14} aria-hidden="true" />
          </button>
        </div>

        <div className="soc-graph-canvas">
          <svg ref={svgRef} className="soc-correlation-graph" role="img" aria-label="Process correlation graph" />
          <div className="soc-graph-zoomdock">
            <button type="button" onClick={() => controlsRef.current?.zoomOut()} aria-label="Zoom out">−</button>
            <button type="button" onClick={() => controlsRef.current?.zoomIn()} aria-label="Zoom in">+</button>
            <button type="button" onClick={() => controlsRef.current?.fit()} title="Fit to view">Fit</button>
            <button type="button" onClick={() => controlsRef.current?.reset()} title="Reset zoom">Reset</button>
          </div>
          {phase === "loading" ? <div className="soc-graph-overlay">Loading graph engine…</div> : null}
          {phase === "empty" ? (
            <div className="soc-graph-overlay">
              <MiniBarList
                rows={topProcesses.map((row) => ({ label: row.process, value: row.score, meta: `${row.count} alerts`, id: row.execId }))}
                empty="No correlated processes in the selected range."
              />
            </div>
          ) : null}
          {phase === "error" ? (
            <div className="soc-graph-overlay">
              <InlineNotice tone="warn" title="Graph engine unavailable">
                {errorMsg}
              </InlineNotice>
            </div>
          ) : null}
        </div>

        <div className="soc-graph-legend">
          <span className="cls-attack"><i />attack</span>
          <span className="cls-threat"><i />threat</span>
          <span className="cls-baseline"><i />baseline</span>
          <span className="node-policy"><i />policy</span>
          <span className="node-file"><i />file</span>
          <span className="node-device"><i />device</span>
          <span className="node-peer"><i />peer</span>
          {/* The ring is a different kind of fact from the fills above — those
              say how suspicious a node looks, this says what has been DONE to
              it. Named "contained" rather than by rung because one swatch
              stands for the whole ladder; the exact rung is on the node and in
              the detail panel. */}
          <span className="node-contained"><i />contained</span>
        </div>
      </div>

      <GraphSelectionRail
        selected={selected}
        neighbours={neighbours}
        nodeProcesses={nodeProcesses}
        visibleProcesses={visibleProcesses}
        procFilter={procFilter}
        onProcFilterChange={setProcFilter}
        containedOnly={containedOnly}
        onToggleContainedOnly={() => setContainedOnly((v) => !v)}
        circuits={circuits}
        drillExecId={drill?.execId}
        onPickProcess={setDrill}
        onSelectNode={(id) => handleRef.current?.setSelected(id)}
      />

      {/* Click node → list → click a process → this modal. Rendered last so it
          layers over the whole shell; the rail list stays visible underneath. */}
      {drill ? (
        <ProcessActionModal
          drill={drill}
          state={drillState}
          nodeLabel={selected?.fullLabel || selected?.label || drill.binary}
          apply={applyToProcess}
          readState={readProcessState}
          onClose={() => setDrill(null)}
        />
      ) : null}
    </div>
  );
}
