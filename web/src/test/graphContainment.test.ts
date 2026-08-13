import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

/**
 * Containment has to be visible on the correlation graph CANVAS.
 *
 * The rung was already fetched (the graph polls /api/choke/circuits every 5s)
 * and already rendered — but only inside a node's drill-in process list. So on
 * a graph of any size the first question during triage, "what is already
 * held?", could only be answered by clicking every node in turn.
 */
const soc = readFileSync("src/features/soc/SocRoute.tsx", "utf8");
const css = readFileSync("src/features/soc/soc.css", "utf8");

describe("containment is marked on the graph canvas", () => {
  it("the renderer exposes a containment channel", () => {
    expect(soc).toMatch(/setContained:\s*\(byNode: Map<string, Rung>\) => void/);
    expect(soc, "the class must be applied in the restyle pass").toMatch(/\.classed\("is-contained"/);
    expect(soc, "the rung must ride on the node so CSS can style per rung").toMatch(/attr\("data-rung"/);
  });

  it("marking goes through restyle, not a data update", () => {
    // A data update restarts the force simulation and scatters the layout. A 5s
    // containment poll must never do that, so setContained calls restyle().
    // Anchor on the implementation, not the interface declaration above it.
    const impl = soc.indexOf("setContained: (byNode: Map<string, Rung>) => {");
    expect(impl, "setContained implementation not found").toBeGreaterThan(-1);
    expect(soc.slice(impl, impl + 220)).toMatch(/restyle\(\)/);
  });

  it("uses the shared ladder helper rather than a private copy", () => {
    // A second ladder ordering in this file is exactly how the three surfaces
    // drift apart; features/common/enforcement.ts is the one definition.
    expect(soc).toMatch(/ladderIndex/);
    expect(soc, "a private rung ordering was reintroduced").not.toMatch(/const RUNG_ORDER\s*=/);
  });

  it("styles every contained rung, and marks the irreversible one differently", () => {
    expect(css).toMatch(/\.is-contained:not\(\.is-selected\):not\(\.is-match\)/);
    expect(css, "quarantined/severed must not read as a mild rung").toMatch(/data-rung="quarantined"/);
    expect(css, "severed is terminal and must be distinguishable").toMatch(
      /data-rung="severed"\][^{]*\{[^}]*stroke-dasharray/s,
    );
  });

  it("takes ring colour from theme tokens, not a second hardcoded palette", () => {
    const rules = css.slice(css.indexOf(".is-contained"));
    const block = rules.slice(0, 1200);
    expect(block).toMatch(/var\(--soc-warn\)/);
    expect(block).toMatch(/var\(--soc-danger\)/);
  });
});

describe("the graph legend actually shows its colours", () => {
  it("swatches have a background, not only an SVG fill", () => {
    // The swatch is an HTML <i>. Every key set `fill:`, which is SVG-only and
    // inert here, so all seven rendered as blank 9x9 gaps — a legend that
    // taught nothing. Each class now declares --swatch once and it drives both
    // the circle's fill and this background.
    expect(css).toMatch(/\.soc-graph-legend i \{[^}]*background:\s*var\(--swatch/s);
    const swatches = [...css.matchAll(/--swatch:\s*#[0-9a-fA-F]{3,8}/g)];
    expect(swatches.length, "expected every legend key to declare a swatch colour").toBeGreaterThanOrEqual(7);
  });

  it("contained is in the legend, keyed as a ring", () => {
    expect(soc).toMatch(/node-contained/);
    // A ring, because it reports what was DONE to a node rather than how
    // suspicious it looks — a different kind of fact from the fills.
    expect(css).toMatch(/\.node-contained i \{[^}]*box-shadow/s);
  });
});
