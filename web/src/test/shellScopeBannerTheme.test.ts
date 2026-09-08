import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

/**
 * THE SCOPE CAPTION HAS TO BE READABLE ON A LIGHT DESKTOP.
 *
 * The shell banner was styled with the SOC route's tokens — var(--soc-text),
 * var(--soc-accent), var(--soc-line) — which are declared on `.soc-route`
 * (soc.css). app/render.tsx mounts this banner as a SIBLING of the route, so
 * none of them resolved and every colour fell through to the dark fallback
 * written beside it: #e2e8f0 ink on a 10% tint over a near-white page, which is
 * 1.15:1. Not "low contrast" — absent.
 *
 * It took the amber state with it, and that is the state these tests are really
 * about: the unconfirmed banner is the only thing on screen telling an operator
 * that their containment is being withheld and which customer it was withheld
 * from. A refusal nobody can read is a console that looks broken.
 *
 * Asserted on the RESOLVED TOKENS rather than on a render: the failure is a
 * colour pair, jsdom resolves neither var() nor a media query, and a screenshot
 * test would pin a picture instead of the contrast. That is also why the
 * backgrounds are opaque hexes — contrast is then a property of these two
 * declarations and not of whatever page happens to scroll underneath.
 */
const css = readFileSync("src/app/tenantScopeBanner.css", "utf8");

/** Strip comments so prose describing the old bug never satisfies a check. */
const code = css.replace(/\/\*[\s\S]*?\*\//g, "");

/** Every declaration block whose selector list matches, in source order. */
function blocks(selector: string): string[] {
  const found: string[] = [];
  const pattern = new RegExp(`(^|[},{])\\s*(${selector})\\s*\\{([^}]*)\\}`, "g");
  for (const match of code.matchAll(pattern)) found.push(match[3]);
  return found;
}

function token(block: string, name: string): string {
  const value = new RegExp(`--${name}:\\s*([^;]+);`).exec(block)?.[1];
  expect(value, `--${name} is not declared in "${block.trim()}"`).toBeTruthy();
  return (value as string).trim();
}

function luminance(hex: string): number {
  const match = /^#([0-9a-f]{6})$/i.exec(hex);
  expect(match, `${hex} is not an opaque six-digit hex; contrast cannot be resolved from it`).toBeTruthy();
  const int = parseInt((match as RegExpExecArray)[1], 16);
  const channels = [(int >> 16) & 255, (int >> 8) & 255, int & 255].map((raw) => {
    const value = raw / 255;
    return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrast(ink: string, background: string): number {
  const a = luminance(ink);
  const b = luminance(background);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

/** The palette a banner state resolves to under one theme. */
function palette(state: "" | "--unconfirmed", theme: "dark" | "light-stamped" | "light-system"): string {
  const cls = `\\.console-scope-banner${state.replace("--", "\\-\\-")}`;
  const selector =
    theme === "dark"
      ? cls
      : theme === "light-stamped"
        ? `\\.theme-light ${cls}`
        : `:root:not\\(\\.theme-dark\\) ${cls}`;
  const matched = blocks(selector);
  expect(matched.length, `no rule for ${theme} ${state || "(base)"}`).toBe(1);
  return matched[0];
}

describe("the shell scope banner is legible in all three theme states", () => {
  // lib/theme.ts stamps .theme-light/.theme-dark, but from an effect on three
  // of the five entries — so this banner, which renders above the route, has a
  // first paint with NEITHER class on the document. Three states, not two.
  for (const theme of ["dark", "light-stamped", "light-system"] as const) {
    it(`gives the unconfirmed alert a legible ink/background pair (${theme})`, () => {
      const block = palette("--unconfirmed", theme);
      const ratio = contrast(token(block, "csb-ink"), token(block, "csb-bg"));
      expect(
        ratio,
        `the containment-refused banner reads at ${ratio.toFixed(2)}:1 in ${theme}`
      ).toBeGreaterThanOrEqual(4.5);
    });

    it(`gives the ordinary scope caption a legible ink/background pair (${theme})`, () => {
      const block = palette("", theme);
      const ratio = contrast(token(block, "csb-ink"), token(block, "csb-bg"));
      expect(ratio, `the scope caption reads at ${ratio.toFixed(2)}:1 in ${theme}`).toBeGreaterThanOrEqual(4.5);
    });
  }

  it("paints from its own tokens, never from the SOC route's", () => {
    // --soc-* is declared on .soc-route; this banner is that route's SIBLING,
    // so every one of those references resolved to its dark fallback whatever
    // the desktop was set to.
    expect(code, "the banner is reaching for tokens it is not inside").not.toMatch(/var\(--soc-/);
  });

  it("declares one light palette, not two that can drift", () => {
    // A selector list cannot straddle a media query, so the light values are
    // written twice: once for the explicit .theme-light stamp and once for the
    // unstamped first paint. They have to stay the same palette.
    for (const state of ["", "--unconfirmed"] as const) {
      expect(palette(state, "light-stamped").replace(/\s+/g, " ").trim()).toBe(
        palette(state, "light-system").replace(/\s+/g, " ").trim()
      );
    }
  });

  it("lets an explicit dark stamp win on a light desktop", () => {
    // The system-preference block is the fallback for "nothing stamped yet". A
    // page that has resolved dark must not be repainted light underneath it.
    const guarded = code.includes(":root:not(.theme-dark) .console-scope-banner");
    expect(guarded, "the prefers-color-scheme block is not guarded against an explicit dark stamp").toBe(true);
    expect(code).toMatch(/@media\s*\(prefers-color-scheme:\s*light\)/);
  });
});
