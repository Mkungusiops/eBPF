import { readFileSync, existsSync } from "node:fs";
import { describe, expect, it } from "vitest";

/**
 * The tab icon must ship, and must be legible on both tab strips.
 *
 * The theme-swap logic in lib/theme.ts was correct all along — but neither SVG
 * existed in web/public, so nginx answered /favicon.svg from the SPA catch-all
 * with index.html (content-type text/html). The browser discarded it and fell
 * back, which is why a dark tile stayed put in light mode: the swap was between
 * two URLs that both returned HTML.
 */
describe("favicon assets ship with the bundle", () => {
  it("both variants exist in public/", () => {
    expect(existsSync("public/favicon.svg"), "public/favicon.svg missing").toBe(true);
    expect(existsSync("public/favicon-light.svg"), "public/favicon-light.svg missing").toBe(true);
  });

  it("they are actually SVG, not an HTML fallback", () => {
    for (const f of ["public/favicon.svg", "public/favicon-light.svg"]) {
      const body = readFileSync(f, "utf8");
      expect(body, `${f} is not SVG`).toMatch(/^<svg[\s>]|^<\?xml/);
      expect(body).not.toMatch(/<!doctype html>/i);
    }
  });

  it("the light variant uses ink that is legible on white", () => {
    // #22d3ee on white is ~1.9:1 — invisible at 16px. The light variant must
    // use the deeper cyan.
    const light = readFileSync("public/favicon-light.svg", "utf8");
    expect(light).toMatch(/#0891b2/);
    expect(light).not.toMatch(/#0a0f1c/); // no dark tile on a light tab strip
  });

  it("the default variant adapts on its own, for pages that run no JS", () => {
    const dark = readFileSync("public/favicon.svg", "utf8");
    expect(dark).toMatch(/prefers-color-scheme:\s*light/);
  });

  it("the referenced filenames match what applyTheme swaps to", () => {
    const theme = readFileSync("src/lib/theme.ts", "utf8");
    expect(theme).toMatch(/favicon-light\.svg/);
    expect(theme).toMatch(/favicon\.svg/);
  });
});
