import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

/**
 * Light-theme regressions in the enforcement surfaces.
 *
 * These are CSS-source assertions rather than render tests: the failures they
 * pin are not "a component threw", they are "the page renders legibly in dark
 * and muddy in light", which no unit render catches and every screenshot does.
 */
const containment = readFileSync("src/features/common/containment.css", "utf8");
const choke = readFileSync("src/features/choke/ChokeRoute.css", "utf8");
const soc = readFileSync("src/features/soc/soc.css", "utf8");

/** Strip comments so prose describing a past bug never satisfies a check. */
const code = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, "");

describe("containment header themes with its host page", () => {
  it("declares no hardcoded dark surface colours", () => {
    // rgba(15,18,26,.4) and friends composite to a muddy grey-brown over a
    // white page — dark-theme furniture in a light room.
    const dark = code(containment).match(/rgba\(\s*(?:[0-9]|[1-4][0-9])\s*,\s*(?:[0-9]|[1-4][0-9])\s*,\s*(?:[0-9]|[1-5][0-9])\s*,/g);
    expect(dark, `hardcoded dark surfaces: ${dark?.join(", ")}`).toBeNull();
  });

  it("never uses --surface as a colour", () => {
    // --surface is an RGB TRIPLET ("10 12 16") for rgb(var(--surface)).
    // `background: var(--surface, #10131b)` yields `background: 10 12 16`,
    // which is invalid, so the rule is dropped and the fallback never applies.
    // That left the posture ring's inner disc unpainted — the gauge rendered
    // as a filled pie instead of a donut, in BOTH themes.
    expect(code(containment)).not.toMatch(/background:\s*var\(--surface/);
  });

  it("paints the posture ring's inner disc from an opaque token", () => {
    expect(code(containment)).toMatch(/--cc-disc:/);
    expect(code(containment)).toMatch(/background:\s*var\(--cc-disc\)/);
  });
});

describe("choke fields are recessed, not dark", () => {
  it("inputs and the policy editor use a themed field token", () => {
    // rgba(10,13,20,.3) over white gave the policy textarea a grey wash with
    // dark text — the look of a disabled control, on the one surface an
    // operator types into.
    expect(code(choke)).toMatch(/background:\s*var\(--field-bg\)/);
    expect(code(choke)).toMatch(/--field-bg:/);
  });

  it("defines --field-bg in BOTH palettes", () => {
    const decls = code(choke).match(/--field-bg:/g) || [];
    expect(decls.length).toBeGreaterThanOrEqual(2);
  });
});

describe("state pills stay legible on white", () => {
  it("overrides every state pill for light theme", () => {
    // The dark palette uses pale inks (#fed7aa, #fde68a, #bfdbfe) on a 16%
    // wash. Those same inks on white sit near 1.5:1 against their own chip.
    for (const state of ["pristine", "throttled", "tarpit", "quarantined", "severed"]) {
      expect(
        code(choke),
        `no light override for .state-${state}`
      ).toMatch(new RegExp(`\\[data-theme="light"\\][^{]*\\.state-${state}`));
    }
  });
});


describe("SOC overlay controls theme with the page", () => {
  it("the graph zoom dock uses a themed surface, not a hardcoded dark pill", () => {
    // soc.css's habit is: hardcode a dark background, then correct it with a
    // .theme-light override. The zoom dock got the first half and not the
    // second, so Fit/Reset sat on a near-black pill on a white page.
    const dock = code(soc).match(/\.soc-graph-zoomdock\s*\{[^}]*\}/)?.[0] ?? "";
    expect(dock, "zoom dock rule not found").not.toBe("");
    expect(dock).toMatch(/background:\s*var\(--soc-panel\)/);
    expect(dock).not.toMatch(/background:\s*rgba\(\s*\d{1,2}\s*,/);
  });

  it("the dock's hover is not painted in the dock's own colour", () => {
    // background: var(--soc-panel) on hover is the surface behind the button,
    // so the affordance never appeared in either theme.
    const hover = code(soc).match(/\.soc-graph-zoomdock button:hover\s*\{[^}]*\}/)?.[0] ?? "";
    expect(hover).toMatch(/background:\s*var\(--soc-panel-soft\)/);
  });
});
