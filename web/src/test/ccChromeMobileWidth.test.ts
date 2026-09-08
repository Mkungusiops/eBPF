import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createElement } from "react";
import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ContainmentCommandHeader } from "../features/common/ContainmentCommand";

/**
 * The mobile-width contract for the SHARED containment chrome.
 *
 * WHY THIS FILE EXISTS SEPARATELY FROM cssMobileOverflowClusters.test.ts: that
 * one covers the two route stylesheets. `containment.css` is neither of them —
 * it is mounted inside BOTH the Choke Gateway and the Devices console, so a
 * floor declared here overflows two routes at once, and it was outside the
 * scope of the agent that fixed `ChokeRoute.css`. `web/e2e/mobile.spec.ts`
 * measures the result in a real browser; jsdom cannot lay out a box, so what is
 * asserted here is the stylesheet fact that produced the measurement.
 *
 * THE MEASUREMENT THAT MOTIVATES IT. On a 390px phone the hero band gets
 * 329px of content box on the Choke route and 305px on the Devices route
 * (390 − 24px of `.devices-layout` padding − 44px of header padding − 2px of
 * border). The instrument cluster inside it declared two `1fr` tracks over
 * buttons with `min-width: 148px`, and an `fr` track's automatic minimum IS its
 * item's min-content — so the cluster could not measure under 297px, and
 * because a grid item's automatic minimum propagates upward, neither could the
 * header. It fitted by 8px. That is not a fit, it is a coincidence, and it is
 * the kind of coincidence a longer label or a wider system font spends.
 *
 * WHY THE CLUSTER TEST RESOLVES TRACKS INSTEAD OF MATCHING KEYWORDS. The first
 * version of it asserted that `.cc-plane-controls` declared a track list
 * matching /auto-fit/ AND /min\(/. A rule was then shipped that matched both
 * patterns and could never produce two columns at ANY width: the cluster sat in
 * a shrink-to-fit box (`justify-items: end` on the bay, no `justify-self` on the
 * cluster), and `repeat(auto-fit, …)` counts repetitions against a DEFINITE
 * inline size — against an indefinite one the spec says the list repeats
 * exactly once. So the cluster stacked on a 2560px monitor, and the test that
 * existed to pin the reflow passed the whole time, because it was pinning the
 * spelling of the fix. Two keywords are not a layout.
 *
 * What follows instead resolves the cascade the way the browser does — header
 * track → bay track → cluster track — and asserts the OUTCOME: how many columns
 * the cluster gets at a given viewport, and whether what it demands fits in what
 * holds it. Any rule that reflows both ways passes, however it is spelled.
 * `describe("the resolver reports the layouts that actually shipped broken")`
 * replays the real regressions through the same resolver, so this is never
 * again a check nobody has watched fail.
 */
const CSS = readFileSync(resolve("src/features/common/containment.css"), "utf8");

type Rule = { selectors: string[]; body: string; media: string };

/**
 * Flat list of every declaration block, media queries flattened in beside it,
 * in source order — which is also cascade order for the single-class selectors
 * this file resolves, since they all carry the same specificity.
 *
 * Deliberately duplicated from cssMobileOverflowClusters.test.ts rather than
 * shared: a parser imported into a stylesheet contract test is one more thing
 * that can be "simplified" in a way that makes both suites pass vacuously.
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
      });
      i = close + 1;
    }
  };
  walk(stripped, "");
  return out;
}

const PHONE = 390;

/** Rules in force at `width`: unconditional, or a width query that covers it. */
function appliesAt(rule: Rule, width: number): boolean {
  if (!rule.media) return true;
  const max = /max-width\s*:\s*(\d+)px/.exec(rule.media);
  if (max && Number(max[1]) < width) return false;
  const min = /min-width\s*:\s*(\d+)px/.exec(rule.media);
  if (min && Number(min[1]) > width) return false;
  return true;
}

function appliesAtPhone(rule: Rule): boolean {
  return appliesAt(rule, PHONE);
}

function rulesFor(selector: string, css = CSS): Rule[] {
  return rules(css).filter((rule) => rule.selectors.includes(selector));
}

function decl(rule: Rule, property: string): string[] {
  const out: string[] = [];
  for (const part of rule.body.split(";")) {
    const [name, ...rest] = part.split(":");
    if (name.trim() === property) out.push(rest.join(":").trim());
  }
  return out;
}

/** The declaration that WINS for `selector`/`property` at `width` — last one standing. */
function inForce(selector: string, property: string, width: number, css: string): string | undefined {
  const values = rulesFor(selector, css)
    .filter((rule) => appliesAt(rule, width))
    .flatMap((rule) => decl(rule, property));
  return values.length ? values[values.length - 1] : undefined;
}

/* ────────────────────────────────────────────────────────────────────────────
   A grid resolver: narrow enough to read, wide enough to be honest.

   It answers one question — how many columns does `.cc-plane-controls` get at
   viewport W, and does what it demands fit inside what holds it. Every input
   comes out of the cascade above; no keyword ever decides an answer.
   ──────────────────────────────────────────────────────────────────────────── */

/** An inline size is DEFINITE or it is not; auto-fit only counts against the former. */
type Size = { definite: true; px: number } | { definite: false };

const INDEFINITE: Size = { definite: false };

function px(value: string | undefined, fallback = 0): number {
  const match = /(-?\d+(?:\.\d+)?)px/.exec(value ?? "");
  return match ? Number(match[1]) : fallback;
}

/** Horizontal padding from a `padding` shorthand ("18px 22px" → 22, "14px" → 14). */
function paddingX(shorthand: string | undefined): number {
  const parts = (shorthand ?? "").trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return 0;
  return px(parts[parts.length >= 2 ? 1 : 0]);
}

/** Split a track list on top-level whitespace, keeping `minmax(0, 1fr)` intact. */
function splitTracks(list: string | undefined): string[] {
  const out: string[] = [];
  let depth = 0;
  let current = "";
  for (const ch of (list ?? "").trim()) {
    if (ch === "(") depth += 1;
    if (ch === ")") depth -= 1;
    if (/\s/.test(ch) && depth === 0) {
      if (current) out.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  if (current) out.push(current);
  return out;
}

function splitAtTopLevelComma(value: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let current = "";
  for (const ch of value) {
    if (ch === "(") depth += 1;
    if (ch === ")") depth -= 1;
    if (ch === "," && depth === 0) {
      out.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }
  out.push(current.trim());
  return out;
}

/** The upper bound of a track — what decides whether the track has a definite size. */
function trackMax(track: string): string {
  const minmax = /^minmax\((.*)\)$/.exec(track.trim());
  return minmax ? splitAtTopLevelComma(minmax[1])[1] ?? "auto" : track.trim();
}

/**
 * A length that may name its container: `min(148px, 100%)` is the whole point
 * of the current rule — the preference yields to the box rather than
 * overflowing it — so it has to be resolved, not matched.
 *
 * `auto`, an intrinsic keyword and a bare `fr` (which is `minmax(auto, 1fr)`)
 * all bottom out at the ITEM's min-content, and the only thing a stylesheet can
 * say about that is the item's own `min-width` — which is exactly how a
 * button's 148px reached the page, so it is passed in from `.cc-ctl` rather
 * than guessed.
 */
function resolveLength(value: string, container: Size, itemFloor: number): number {
  const trimmed = value.trim();
  const fn = /^(min|max)\((.*)\)$/.exec(trimmed);
  if (fn) {
    const args = splitAtTopLevelComma(fn[2]).map((arg) => resolveLength(arg, container, itemFloor));
    return fn[1] === "min" ? Math.min(...args) : Math.max(...args);
  }
  const percent = /^(\d+(?:\.\d+)?)%$/.exec(trimmed);
  if (percent) return container.definite ? (container.px * Number(percent[1])) / 100 : Infinity;
  if (/^(auto|min-content|max-content|fit-content.*)$/.test(trimmed)) return itemFloor;
  if (/fr$/.test(trimmed)) return itemFloor;
  return px(trimmed, 0);
}

/** The lower bound of a track, resolved against the container it sits in. */
function trackMin(track: string, container: Size, itemFloor: number): number {
  const minmax = /^minmax\((.*)\)$/.exec(track.trim());
  const lower = minmax ? splitAtTopLevelComma(minmax[1])[0] : track.trim();
  return resolveLength(lower, container, itemFloor);
}

function isFixedPx(track: string): boolean {
  return /^\d+(?:\.\d+)?px$/.test(trackMax(track));
}

/** The size of track `index` in `tracks`, laid out in a container of `container`. */
function resolveTrackSize(tracks: string[], index: number, container: Size, gap: number): Size {
  // No track list at all: one implicit `auto` column, which is content-sized.
  if (tracks.length === 0 || index < 0) return INDEFINITE;
  const max = trackMax(tracks[index]);
  if (/^\d+(?:\.\d+)?px$/.test(max)) return { definite: true, px: Number(max.replace("px", "")) };
  if (/fr$/.test(max)) {
    // A fraction of a definite container is definite; a fraction of a
    // content-sized one is not, and that distinction is what the whole cluster
    // regression turned on.
    if (!container.definite) return INDEFINITE;
    const fixed = tracks.reduce((sum, track) => (isFixedPx(track) ? sum + px(trackMax(track)) : sum), 0);
    const frTracks = tracks.filter((track) => /fr$/.test(trackMax(track))).length;
    const free = container.px - fixed - gap * (tracks.length - 1);
    return { definite: true, px: Math.max(0, free / Math.max(1, frTracks)) };
  }
  // `auto`, `max-content`, `fit-content(…)`: content-sized, therefore indefinite.
  return INDEFINITE;
}

/**
 * The track a grid item lands in. Auto-placement fills the columns in order and
 * wraps, so the second of two items sits in the second track when there is one
 * and underneath the first when the list is a single column.
 */
function trackForItem(tracks: string[], itemIndex: number): number {
  return Math.min(itemIndex, tracks.length - 1);
}

/**
 * Does a grid item stretch to fill its track? `justify-self` on the item wins,
 * then `justify-items` on the grid, then the initial `normal`, which stretches.
 * A non-stretching item is shrink-to-fit — an INDEFINITE inline size — and
 * `justify-items: end` on the bay is precisely what made auto-fit repeat once
 * at every viewport while the comment above it claimed the cluster reflowed.
 */
function stretches(item: string, grid: string, width: number, css: string): boolean {
  const effective = inForce(item, "justify-self", width, css) ?? inForce(grid, "justify-items", width, css) ?? "normal";
  return effective === "stretch" || effective === "normal";
}

/**
 * Content box of `.cc-header` at a viewport, on the tighter of the two routes.
 *
 * Both hosts inset the hero by 12px a side at phone widths (`.devices-layout`
 * padding drops to 12px at ≤860, and `.choke-route > .cc-header` takes a 12px
 * margin at ≤720), so the two routes agree exactly where it matters: below 720,
 * which is the only branch where the bay is a fraction of the header rather
 * than a fixed 312px. Above 860 the wider Devices inset is used, and there the
 * header's width decides nothing.
 */
function headerContentBox(width: number, css: string): number {
  const routeInset = width <= 860 ? 24 : 40;
  const padding = paddingX(inForce(".cc-header", "padding", width, css));
  const border = px(inForce(".cc-header", "border", width, css), 0);
  return width - routeInset - padding * 2 - border * 2;
}

/** The inline size `.cc-plane-controls` is laid out in, at a given viewport. */
function clusterContainer(width: number, css: string): Size {
  const headerTracks = splitTracks(inForce(".cc-header", "grid-template-columns", width, css));
  const headerBox: Size = { definite: true, px: headerContentBox(width, css) };
  // The bay is the LAST thing in the hero band (lead, metric strip, controls).
  const bayTrack = resolveTrackSize(
    headerTracks,
    headerTracks.length - 1,
    headerBox,
    px(inForce(".cc-header", "gap", width, css))
  );
  const bay = stretches(".cc-head-controls", ".cc-header", width, css) ? bayTrack : INDEFINITE;

  const bayTracks = splitTracks(inForce(".cc-head-controls", "grid-template-columns", width, css));
  // The cluster is the second child of the bay, after the view toggle.
  const own = resolveTrackSize(
    bayTracks,
    trackForItem(bayTracks, 1),
    bay,
    px(inForce(".cc-head-controls", "gap", width, css))
  );
  return stretches(".cc-plane-controls", ".cc-head-controls", width, css) ? own : INDEFINITE;
}

interface ClusterLayout {
  /** Columns the cluster resolves to at this viewport. */
  columns: number;
  /** The narrowest the cluster can be drawn — anything above the container overflows. */
  floorPx: number;
  container: Size;
}

function clusterLayout(width: number, css: string, cells: number): ClusterLayout {
  const container = clusterContainer(width, css);
  const list = inForce(".cc-plane-controls", "grid-template-columns", width, css);
  const gap = px(inForce(".cc-plane-controls", "gap", width, css));
  // Any pixel floor the cells declare for themselves; a track cannot shrink an
  // item below its own min-width, whatever the track list says.
  const itemFloor = px(inForce(".cc-ctl", "min-width", width, css));
  const auto = /^repeat\(\s*(auto-fit|auto-fill)\s*,\s*(.+)\)$/.exec((list ?? "").trim());

  if (auto) {
    const minTrack = trackMin(auto[2].trim(), container, itemFloor);
    let columns: number;
    if (!container.definite) {
      // CSS Grid §7.2.3.2: against an indefinite available size the repetition
      // count is 1. That is not a fallback here — it is the bug that shipped.
      columns = 1;
    } else {
      columns = Math.max(1, Math.floor((container.px + gap) / (minTrack + gap)));
      // auto-fit collapses the tracks no item occupies, so the cluster is never
      // given more columns than it has controls to fill.
      if (auto[1] === "auto-fit") columns = Math.min(columns, cells);
    }
    const perColumn = Math.max(minTrack, itemFloor);
    return { columns, floorPx: columns * perColumn + gap * (columns - 1), container };
  }

  const tracks = splitTracks(list).flatMap((track) => {
    const repeated = /^repeat\(\s*(\d+)\s*,\s*(.+)\)$/.exec(track);
    return repeated ? Array.from({ length: Number(repeated[1]) }, () => repeated[2].trim()) : [track];
  });
  const columns = Math.max(1, tracks.length);
  const perColumn = Math.max(itemFloor, ...tracks.map((track) => trackMin(track, container, itemFloor)));
  return { columns, floorPx: columns * perColumn + gap * (columns - 1), container };
}

/**
 * Widths this console is expected to survive. 320 is the narrowest phone still
 * in the support set, 390 is the measurement in the header comment, and 720 and
 * 1180 are the two breakpoint edges, sampled from both sides.
 */
const NARROW = [280, 300, 320];
const ROOMY = [390, 414, 480, 719, 720, 721, 900, 1180, 1181, 1440, 2560];
const ALL_WIDTHS = [...NARROW, ...ROOMY];

/** How many controls the cluster holds — read off the component, not assumed. */
function renderedCells(): number {
  const { container } = render(
    createElement(ContainmentCommandHeader, {
      metrics: {
        subject: "processes",
        mode: "enforcing",
        activeThreats: 2,
        contained: 1,
        tracked: 9,
        auditOk: true,
        auditRows: 12,
        posture: 71,
      },
      viewMode: "command",
      onViewMode: () => {},
      onToggleMode: () => {},
      onKillSwitch: () => {},
    })
  );
  const cluster = container.querySelector(".cc-plane-controls");
  if (!cluster) throw new Error(".cc-plane-controls is not in the DOM: this stylesheet contract has no subject");
  return cluster.querySelectorAll(".cc-ctl").length;
}

afterEach(cleanup);

describe("the instrument cluster reflows instead of overflowing", () => {
  // The resolver needs the cell count before it can cap auto-fit; the first
  // test is what makes that number true rather than assumed. Without it the
  // whole file could go vacuous on a class rename — every lookup would return
  // undefined and every "no offender" assertion would pass over a stylesheet
  // nothing on screen is using.
  const CELLS = 2;

  it("holds exactly the two controls this file resolves for, under the classes the CSS names", () => {
    expect(renderedCells()).toBe(CELLS);
  });

  it("gets more than one column wherever there is room for two", () => {
    for (const width of ROOMY) {
      const { columns, container } = clusterLayout(width, CSS, CELLS);
      expect(
        container.definite,
        `at ${width}px the cluster has no definite inline size, so repeat(auto-fit, …) resolves to one track at EVERY viewport`
      ).toBe(true);
      expect(columns, `the cluster stacked at ${width}px, where both controls fit side by side`).toBeGreaterThan(1);
    }
  });

  it("drops to a single column where two will not fit", () => {
    for (const width of NARROW) {
      const { columns } = clusterLayout(width, CSS, CELLS);
      expect(columns, `the cluster kept ${columns} columns at ${width}px, which is an overflow, not a layout`).toBe(1);
    }
  });

  it("never demands more width than the box that holds it", () => {
    for (const width of ALL_WIDTHS) {
      const { floorPx, container } = clusterLayout(width, CSS, CELLS);
      expect(container.definite, `${width}px`).toBe(true);
      if (!container.definite) continue;
      expect(
        Math.round(floorPx),
        `at ${width}px the cluster cannot measure below ${Math.round(floorPx)}px inside ${Math.round(container.px)}px of bay`
      ).toBeLessThanOrEqual(Math.round(container.px));
    }
  });
});

/**
 * The resolver is only worth having if it says NO to the layouts that actually
 * shipped. Each case below is a rule this stylesheet really had, applied to the
 * real file IN MEMORY — nothing on disk is touched — so a "simplification" that
 * makes the resolver answer "two columns, fits" to everything fails here rather
 * than passing quietly upstairs.
 */
describe("the resolver reports the layouts that actually shipped broken", () => {
  const CELLS = 2;

  it("catches a shrink-to-fit cluster, which never reflows at any width", () => {
    // The rule that matched /auto-fit/ and /min\(/ and still produced one
    // column on a 2560px monitor: the cluster was sized to its content, so
    // auto-fit had no number to count repetitions against.
    const broken = CSS.replace("justify-self: stretch;", "justify-self: end;");
    expect(broken, "the cluster no longer declares justify-self; this mutation is inert").not.toBe(CSS);
    for (const width of ALL_WIDTHS) {
      expect(clusterLayout(width, broken, CELLS).container.definite, `${width}px`).toBe(false);
      expect(clusterLayout(width, broken, CELLS).columns, `${width}px`).toBe(1);
    }
  });

  it("catches a content-sized bay, which makes the cluster indefinite from above", () => {
    // `.cc-head-controls` had no track list at all, so its single implicit
    // column was `auto`: nothing in the chain had a definite inline size, and
    // the cluster stacked on a desktop for the same reason it stacked on a
    // phone. Only the desktop branch is asserted — below 1180 the bay declares
    // a second track list of its own, which this mutation leaves in place.
    const broken = CSS.replace("  grid-template-columns: 312px;\n", "");
    expect(broken, "the bay no longer declares a 312px bay; this mutation is inert").not.toBe(CSS);
    for (const width of [1181, 1440, 2560]) {
      const wide = clusterLayout(width, broken, CELLS);
      expect(wide.container.definite, `${width}px`).toBe(false);
      expect(wide.columns, `${width}px`).toBe(1);
    }
  });

  it("catches the fixed two-column list that pinned a 297px floor into a 266px box", () => {
    // `1fr 1fr` over two buttons declaring `min-width: 148px`. Two tracks exist
    // at every width, so the housing can never be narrower than the sum of what
    // the buttons demand: it cannot reflow, and on a 320px phone the hero band
    // overflows the screen.
    const broken = CSS
      .replace(
        "grid-template-columns: repeat(auto-fit, minmax(min(148px, 100%), 1fr));",
        "grid-template-columns: 1fr 1fr;"
      )
      // The floor has to REPLACE `.cc-ctl`'s `min-width: 0`, not precede it:
      // the later declaration in the same block is the one in force, so an
      // appended floor would be overridden and the mutation would be inert.
      .replace(
        ".cc-ctl {\n  display: flex;\n  gap: 9px;\n  align-items: center;\n  min-width: 0;",
        ".cc-ctl {\n  display: flex;\n  gap: 9px;\n  align-items: center;\n  min-width: 148px;"
      );
    expect(broken.includes("1fr 1fr"), "the cluster's track list was not replaced; this mutation is inert").toBe(true);
    expect(px(inForce(".cc-ctl", "min-width", 320, broken)), "the cell floor did not take").toBe(148);
    const phone = clusterLayout(320, broken, CELLS);
    expect(phone.columns).toBe(2);
    expect(phone.container.definite).toBe(true);
    if (phone.container.definite) expect(phone.floorPx).toBeGreaterThan(phone.container.px);
  });
});

describe("the instrument cluster can narrow below the phone viewport", () => {
  it(".cc-ctl declares no fixed pixel min-width", () => {
    const owned = rulesFor(".cc-ctl").filter(appliesAtPhone);
    expect(owned.length, ".cc-ctl has no rule of its own").toBeGreaterThan(0);
    const pinned = owned.flatMap((rule) => decl(rule, "min-width")).filter((v) => /\d+px/.test(v));
    expect(
      pinned,
      "a per-cell pixel floor is multiplied by the track count: 148px x 2 plus the divider pinned 297px inside 305px of header on the Devices route",
    ).toEqual([]);
  });

  it("the divider is not a left border, which is wrong once the cluster stacks", () => {
    const sideBorders = rules(CSS)
      .filter((rule) => rule.selectors.some((s) => s.includes(".cc-ctl + .cc-ctl")))
      .flatMap((rule) => decl(rule, "border-left"));
    expect(
      sideBorders,
      "a left hairline on the second control draws down the left edge of a full-width button once the cluster is one column",
    ).toEqual([]);
  });

  it("the control labels are allowed to break", () => {
    // min-width:0 does not make an unbreakable word narrower. "ENFORCEMENT" and
    // "Kill-switch" are ~80px of min-content each; without a break opportunity
    // the cell keeps a ~130px floor whatever the track list says.
    const body = rulesFor(".cc-ctl-body").filter(appliesAtPhone);
    expect(body.some((rule) => decl(rule, "overflow-wrap").some((v) => /anywhere|break-word/.test(v)))).toBe(true);
  });
});

describe("the hero band's own tracks carry no inherited floor", () => {
  it(".cc-head-controls releases its min-content minimum", () => {
    const released = rulesFor(".cc-head-controls")
      .filter(appliesAtPhone)
      .some((rule) => decl(rule, "min-width").includes("0"));
    expect(
      released,
      ".cc-head-controls is a grid item whose automatic minimum is its min-content, so its widest button becomes a floor on .cc-header itself",
    ).toBe(true);
  });

  it(".cc-header's narrow track list is floored at zero, not at auto", () => {
    const narrow = rulesFor(".cc-header")
      .filter((rule) => rule.media.includes("max-width"))
      .flatMap((rule) => decl(rule, "grid-template-columns"));
    expect(narrow.length, "no narrow-viewport track list for .cc-header").toBeGreaterThan(0);
    // `1fr` is `minmax(auto, 1fr)` and that `auto` is min-content: the exact
    // mechanism by which a button's floor reached the page.
    expect(
      narrow.filter((t) => !/minmax\(\s*0/.test(t)),
      ".cc-header's narrow column is a bare fr track, so its content's min-content is its floor",
    ).toEqual([]);
  });
});

describe("no shared-chrome rule pins a width wider than a phone", () => {
  // 344px is the widest content box the hero band has on either route at 390px
  // (Choke: 390 - 44 header padding - 2 border, before the 24px gutter).
  const BUDGET = 344;

  it("declares no min-width or width above the phone budget", () => {
    const offenders: string[] = [];
    for (const rule of rules(CSS).filter(appliesAtPhone)) {
      for (const property of ["min-width", "width", "flex-basis"]) {
        for (const value of decl(rule, property)) {
          const pixels = /^(\d+(?:\.\d+)?)px$/.exec(value.trim());
          if (pixels && Number(pixels[1]) > BUDGET) {
            offenders.push(`${rule.selectors.join(", ")} { ${property}: ${value} }`);
          }
        }
      }
      for (const value of decl(rule, "grid-template-columns")) {
        // Sum the pixel minimums a track list demands; a list that demands more
        // than the container is an overflow, not a layout.
        const floor = [...value.matchAll(/(\d+(?:\.\d+)?)px/g)]
          .map((m) => Number(m[1]))
          .reduce((a, b) => a + b, 0);
        // `min(148px, 100%)` yields to the container, so it is not a floor.
        if (!/min\s*\(/.test(value) && floor > BUDGET) {
          offenders.push(`${rule.selectors.join(", ")} { grid-template-columns: ${value} }`);
        }
      }
    }
    expect(offenders, "shared containment chrome pins a box wider than the phone viewport").toEqual([]);
  });
});
