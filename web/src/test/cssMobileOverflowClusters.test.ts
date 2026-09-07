import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * The mobile-overflow contract for the Choke Gateway and Devices stylesheets.
 *
 * WHY A STYLESHEET TEST AND NOT A LAYOUT TEST: horizontal overflow is measured
 * by `web/e2e/mobile.spec.ts` in a real browser, because jsdom does not lay out
 * boxes. What jsdom CAN do is read the stylesheet, and that is where the bug
 * lived both times. `ChokeRoute.css` lost the body of its toolbar-cluster rule
 * once already — the declarations and the `.choke-brand-mark {` line that
 * followed them were deleted together, fusing two selector lists — which left
 * seven CONTAINERS as plain blocks inheriting the brand mark's
 * `white-space: nowrap`. Their children became inline boxes on one unbreakable
 * line: `.choke-chip-row`'s five state chips measured ~457px inside a 366px
 * column and the route reported a 475px document on a 390px phone.
 *
 * The first repair attempt added `flex-wrap` to those selectors from inside a
 * media query. That did nothing, because `flex-wrap` on something that is not
 * a flex container is inert — which is the second thing asserted here.
 */

// Resolved from the vitest root (web/) so the test reads the shipped stylesheet,
// not a bundler-transformed copy.
const CHOKE = readFileSync(resolve("src/features/choke/ChokeRoute.css"), "utf8");
const DEVICES = readFileSync(resolve("src/features/devices/devices.css"), "utf8");

type Rule = { selectors: string[]; body: string; media: string };

/** Flat list of every declaration block, media queries flattened in with it. */
function rules(css: string): Rule[] {
  const stripped = css.replace(/\/\*[\s\S]*?\*\//g, "");
  const out: Rule[] = [];
  const walk = (block: string, media: string) => {
    let i = 0;
    while (i < block.length) {
      const open = block.indexOf("{", i);
      if (open < 0) break;
      const prelude = block.slice(i, open).trim();
      if (prelude.startsWith("@")) {
        let depth = 1;
        let k = open + 1;
        while (k < block.length && depth > 0) {
          if (block[k] === "{") depth += 1;
          else if (block[k] === "}") depth -= 1;
          k += 1;
        }
        if (prelude.startsWith("@media")) walk(block.slice(open + 1, k - 1), prelude);
        i = k;
        continue;
      }
      const close = block.indexOf("}", open);
      out.push({
        selectors: prelude.split(",").map((s) => s.trim()).filter(Boolean),
        body: block.slice(open + 1, close),
        media,
      });
      i = close + 1;
    }
  };
  walk(stripped, "");
  return out;
}

/** Rules whose selector list contains exactly this selector (not a descendant of it). */
function rulesFor(css: string, selector: string): Rule[] {
  return rules(css).filter((rule) => rule.selectors.includes(selector));
}

function declares(rule: Rule, property: string, value: RegExp): boolean {
  return new RegExp(`(^|;|\\n)\\s*${property}\\s*:\\s*${value.source}\\s*(;|$)`).test(rule.body);
}

/**
 * Every cluster in the fused block. Each one is a row of controls that must be
 * able to break onto a second line; `.choke-brand-mark`, the rule they were
 * fused with, is the only one of the eight selectors that is a text run.
 */
const CLUSTERS = [
  ".choke-brand",
  ".choke-status-cluster",
  ".choke-user-cluster",
  ".choke-panel-actions",
  ".choke-chip-row",
  ".choke-row-actions",
];

describe("choke toolbar clusters wrap on a phone", () => {
  for (const selector of CLUSTERS) {
    it(`${selector} is a flex container that wraps`, () => {
      const owned = rulesFor(CHOKE, selector);
      expect(owned.length, `${selector} has no rule of its own`).toBeGreaterThan(0);

      const flex = owned.some((rule) => declares(rule, "display", /flex/));
      expect(flex, `${selector} never declares display:flex, so any flex-wrap on it is inert`).toBe(true);

      // The wrap may be unconditional or come from a media query; either is a
      // real wrap, as long as the same selector is a flex container somewhere.
      const wraps = owned.some((rule) => declares(rule, "flex-wrap", /wrap/));
      expect(wraps, `${selector} never wraps, so its children lay out on one line`).toBe(true);
    });

    it(`${selector} is never told to keep its children on one line`, () => {
      const nowrap = rulesFor(CHOKE, selector).filter((rule) => declares(rule, "white-space", /nowrap/));
      expect(
        nowrap.map((r) => r.selectors.join(", ")),
        `${selector} inherits white-space:nowrap, which forbids the line break it needs`,
      ).toEqual([]);
    });
  }
});

describe("flex-wrap is only ever declared on flex containers", () => {
  // The three grids that were listed in a flex-wrap rule, where the
  // declaration did nothing and made the overflow look handled.
  const GRIDS: Array<[string, string]> = [
    [".choke-grid", "choke"],
    [".choke-ti-ribbon", "choke"],
    [".devices-topbar-primary", "devices"],
  ];

  for (const [selector, sheet] of GRIDS) {
    it(`${selector} carries no inert flex-wrap`, () => {
      const css = sheet === "choke" ? CHOKE : DEVICES;
      const owned = rulesFor(css, selector);
      const isGrid = owned.some((rule) => declares(rule, "display", /grid/));
      expect(isGrid, `${selector} is expected to be a grid`).toBe(true);
      expect(owned.some((rule) => declares(rule, "display", /flex/))).toBe(false);

      const inert = owned.filter((rule) => /flex-wrap\s*:/.test(rule.body));
      expect(
        inert.map((r) => `${r.media} { ${r.selectors.join(", ")} }`),
        `${selector} is a grid: flex-wrap on it is inert and the row still overflows`,
      ).toEqual([]);
    });
  }
});

describe("the process list has no width floor left on a phone", () => {
  it("drops the eight-column 1010px minimum when it drops to four columns", () => {
    const fourColumn = rules(CHOKE).filter(
      (rule) =>
        rule.media.includes("max-width") &&
        rule.selectors.includes(".choke-process-row") &&
        /grid-template-columns/.test(rule.body),
    );
    expect(fourColumn.length, "no narrow-viewport rule for .choke-process-row").toBeGreaterThan(0);

    // The desktop rule pins min-width:1010px for the eight-column layout. A
    // narrow rule that re-columns without releasing it stretches a 342px row
    // to 1010px and gives the list its own horizontal scrollbar.
    const releases = fourColumn.some((rule) => /min-width\s*:\s*0/.test(rule.body));
    expect(releases, "narrow .choke-process-row keeps the 1010px eight-column floor").toBe(true);
  });
});
