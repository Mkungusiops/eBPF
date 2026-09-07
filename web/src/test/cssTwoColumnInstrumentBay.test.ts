import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * The DESKTOP half of the instrument cluster's contract.
 *
 * ccChromeMobileWidth.test.ts pins that the cluster can drop to one column on a
 * phone. It cannot pin the other direction, and that is the direction that
 * regressed: `.cc-plane-controls` was given
 * `repeat(auto-fit, minmax(min(148px, 100%), 1fr))`, and auto-fit counts its
 * repetitions against the container's DEFINITE inline size — or its definite
 * max size, or its definite min size. Against an indefinite one the spec says
 * the track list repeats exactly once.
 *
 * Nothing in the chain was definite. `.cc-header`'s third track is `auto`
 * (content-sized), `.cc-head-controls` declared no track list at all (so its
 * implicit column was `auto` too), and `justify-items: end` on that column
 * sizes the cluster shrink-to-fit. So the two plane controls stacked on a
 * 2560px monitor exactly as they stacked on a 390px phone, while the comment
 * beside the rule described a two-column layout the rule could not produce.
 *
 * What is asserted here is the stylesheet fact that produces the measurement
 * web/e2e/mobile.spec.ts and the desktop probes take in a real browser: the bay
 * that holds the cluster has a definite width at every viewport band, the
 * cluster is stretched into it rather than shrink-to-fit, and that width has
 * room for two 148px tracks plus the 1px divider.
 */
const CSS = readFileSync(resolve("src/features/common/containment.css"), "utf8");

type Rule = { selectors: string[]; body: string; media: string; order: number };

/**
 * Flat list of every declaration block, media queries flattened in beside it,
 * each tagged with its source order so the cascade can be replayed.
 *
 * Deliberately duplicated from the two sibling stylesheet tests rather than
 * shared: a parser imported into a contract test is one more thing that can be
 * "simplified" in a way that makes every suite pass vacuously.
 */
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
        order: out.length,
      });
      i = close + 1;
    }
  };
  walk(stripped, "");
  return out;
}

const ALL = rules(CSS);

function appliesAt(rule: Rule, viewport: number): boolean {
  if (!rule.media) return true;
  const max = /max-width\s*:\s*(\d+)px/.exec(rule.media);
  if (max && viewport > Number(max[1])) return false;
  const min = /min-width\s*:\s*(\d+)px/.exec(rule.media);
  if (min && viewport < Number(min[1])) return false;
  return true;
}

function decl(rule: Rule, property: string): string[] {
  const out: string[] = [];
  for (const part of rule.body.split(";")) {
    const [name, ...rest] = part.split(":");
    if (name.trim() === property) out.push(rest.join(":").trim());
  }
  return out;
}

/**
 * The declaration that actually wins for `selector` at `viewport`. All the
 * rules involved carry a single class selector, so specificity is equal and
 * source order decides — which is why `order` is tracked above.
 */
function winning(selector: string, property: string, viewport: number): string | null {
  let won: string | null = null;
  for (const rule of ALL.filter((r) => r.selectors.includes(selector) && appliesAt(r, viewport)).sort(
    (a, b) => a.order - b.order,
  )) {
    for (const value of decl(rule, property)) won = value;
  }
  return won;
}

/** The last track in a track list — the one the instrument cluster sits in. */
function bayTrack(trackList: string): string {
  // Split on top-level whitespace only: `minmax(0, 1fr)` is ONE track.
  const tracks: string[] = [];
  let depth = 0;
  let current = "";
  for (const ch of trackList) {
    if (ch === "(") depth += 1;
    if (ch === ")") depth -= 1;
    if (/\s/.test(ch) && depth === 0) {
      if (current) tracks.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  if (current) tracks.push(current);
  return tracks[tracks.length - 1] ?? "";
}

/** 148px preference + 1px divider + 148px preference. */
const TWO_COLUMN_WIDTH = 297;
/** The widest content box the hero band has on either route at a 390px viewport. */
const PHONE_BUDGET = 344;

describe("the bay that holds the instrument cluster has a definite width", () => {
  // 2560px and 1440px are the desktop band (three header tracks); 900px is the
  // single-column band; 390px is the phone. Every one of them must resolve.
  for (const viewport of [2560, 1440, 900, 390]) {
    it(`.cc-head-controls declares a track list at ${viewport}px`, () => {
      const tracks = winning(".cc-head-controls", "grid-template-columns", viewport);
      expect(
        tracks,
        "with no track list the implicit column is `auto` — content-sized, therefore indefinite, and `repeat(auto-fit, …)` inside an indefinite container repeats exactly once at every viewport",
      ).not.toBeNull();
    });

    it(`the bay track is definite at ${viewport}px, not content-sized`, () => {
      const bay = bayTrack(winning(".cc-head-controls", "grid-template-columns", viewport) ?? "");
      expect(
        /^(auto|min-content|max-content|fit-content\(.*\))$/.test(bay),
        `the cluster's track is \`${bay}\`, which is sized from its own content: the cluster can never learn how much room it has, so auto-fit collapses to one column`,
      ).toBe(false);
      expect(
        /(\d+(?:\.\d+)?)px|fr\b/.test(bay),
        `the cluster's track is \`${bay}\`, which is neither a length nor a flexible track`,
      ).toBe(true);
    });
  }

  it("the cluster is stretched into that bay rather than shrink-to-fit", () => {
    // `.cc-head-controls` sets `justify-items: end`, which sizes its items
    // shrink-to-fit. A shrink-to-fit box has no definite inline size, so a
    // definite bay alone is not enough — the cluster has to fill it.
    const endAligned = winning(".cc-head-controls", "justify-items", 1440) === "end";
    const stretched =
      winning(".cc-plane-controls", "justify-self", 1440) === "stretch" ||
      winning(".cc-head-controls", "justify-items", 1440) === "stretch";
    expect(
      stretched,
      endAligned
        ? "the parent end-aligns its items, so without `justify-self: stretch` the cluster is shrink-to-fit and auto-fit sees an indefinite size"
        : "the cluster must fill its bay for auto-fit to have a size to count against",
    ).toBe(true);
  });
});

describe("the bay is wide enough for the two columns it claims", () => {
  /** The px preference inside `minmax(min(<pref>, 100%), 1fr)`. */
  function preference(): number {
    const tracks = winning(".cc-plane-controls", "grid-template-columns", 1440) ?? "";
    const pref = /min\s*\(\s*(\d+(?:\.\d+)?)px/.exec(tracks);
    if (!pref) throw new Error(`no px preference found in \`${tracks}\``);
    return Number(pref[1]);
  }

  function gap(): number {
    const g = winning(".cc-plane-controls", "gap", 1440) ?? "0";
    return Number(/^(\d+(?:\.\d+)?)px$/.exec(g.trim())?.[1] ?? 0);
  }

  for (const viewport of [2560, 1440, 900]) {
    it(`two preferred tracks plus the divider fit the bay at ${viewport}px`, () => {
      const bay = bayTrack(winning(".cc-head-controls", "grid-template-columns", viewport) ?? "");
      const px = /^(\d+(?:\.\d+)?)px$/.exec(bay);
      if (!px) {
        // A flexible bay takes the header's own width, which above the phone
        // band is far more than two tracks need; nothing to check.
        expect(/fr\b/.test(bay)).toBe(true);
        return;
      }
      const needed = 2 * preference() + gap();
      expect(
        Number(px[1]),
        `the bay is ${px[1]}px but two columns need ${needed}px, so auto-fit resolves to a single track and the two controls stack at ${viewport}px`,
      ).toBeGreaterThanOrEqual(needed);
      expect(needed).toBe(TWO_COLUMN_WIDTH);
    });
  }

  it("the phone bay is flexible, so it cannot become a floor wider than the viewport", () => {
    const bay = bayTrack(winning(".cc-head-controls", "grid-template-columns", 390) ?? "");
    expect(
      /^minmax\(\s*0\s*,.*fr\s*\)$/.test(bay),
      `the phone bay is \`${bay}\`; a fixed bay is a floor, and 312px of floor does not fit the 320px viewport this console still supports`,
    ).toBe(true);
  });

  it("no bay declared at phone width exceeds the hero band's content box", () => {
    const offenders: string[] = [];
    for (const rule of ALL.filter((r) => r.selectors.includes(".cc-head-controls") && appliesAt(r, 390))) {
      for (const value of decl(rule, "grid-template-columns")) {
        const floor = [...value.matchAll(/(\d+(?:\.\d+)?)px/g)].map((m) => Number(m[1])).reduce((a, b) => a + b, 0);
        if (floor > PHONE_BUDGET) offenders.push(`${rule.media} { grid-template-columns: ${value} }`);
      }
    }
    expect(offenders, "a fixed bay wider than the hero band pushes the header past the phone viewport").toEqual([]);
  });
});
