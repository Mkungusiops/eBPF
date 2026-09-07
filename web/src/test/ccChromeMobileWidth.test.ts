import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

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
 */
const CSS = readFileSync(resolve("src/features/common/containment.css"), "utf8");

type Rule = { selectors: string[]; body: string; media: string };

/**
 * Flat list of every declaration block, media queries flattened in beside it.
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

/** Rules in force at a 390px viewport: unconditional, or a max-width that covers it. */
function appliesAtPhone(rule: Rule): boolean {
  if (!rule.media) return true;
  const max = /max-width\s*:\s*(\d+)px/.exec(rule.media);
  if (max && Number(max[1]) < PHONE) return false;
  const min = /min-width\s*:\s*(\d+)px/.exec(rule.media);
  if (min && Number(min[1]) > PHONE) return false;
  return true;
}

function rulesFor(selector: string): Rule[] {
  return rules(CSS).filter((rule) => rule.selectors.includes(selector));
}

function decl(rule: Rule, property: string): string[] {
  const out: string[] = [];
  for (const part of rule.body.split(";")) {
    const [name, ...rest] = part.split(":");
    if (name.trim() === property) out.push(rest.join(":").trim());
  }
  return out;
}

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

  it(".cc-plane-controls drops to one column instead of overflowing", () => {
    const tracks = rulesFor(".cc-plane-controls")
      .filter(appliesAtPhone)
      .flatMap((rule) => decl(rule, "grid-template-columns"));
    expect(tracks.length, ".cc-plane-controls declares no track list").toBeGreaterThan(0);

    // `1fr 1fr` cannot reflow: two tracks exist at every width, so the housing
    // is at least the sum of what the two buttons demand.
    expect(
      tracks.filter((t) => /^1fr\s+1fr$/.test(t)),
      ".cc-plane-controls keeps a fixed two-column track list, which cannot reflow",
    ).toEqual([]);

    // auto-fit collapses the second track when it no longer fits; min() keeps
    // the track's own minimum from ever exceeding the container.
    const reflows = tracks.some((t) => /auto-fit/.test(t) && /min\s*\(/.test(t));
    expect(
      reflows,
      "expected repeat(auto-fit, minmax(min(<pref>, 100%), 1fr)) so the cluster stacks rather than overflows",
    ).toBe(true);
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
          const px = /^(\d+(?:\.\d+)?)px$/.exec(value.trim());
          if (px && Number(px[1]) > BUDGET) {
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
