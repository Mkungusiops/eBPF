import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * This file exists because of a bug that shipped to production and made the
 * assistant panel INVISIBLE — the dashboard read straight through the
 * conversation.
 *
 * The console stores its palette as space-separated RGB triples:
 *
 *     --panel: 18 22 31;
 *
 * so a colour must be written `rgb(var(--panel))`. Written the ordinary-looking
 * way, `var(--panel, #121722)`, the property resolves to the literal string
 * "18 22 31", which is not a colour — and CSS discards an invalid declaration
 * SILENTLY. No error, no warning, no failing test. The element simply has no
 * background.
 *
 * Every one of the 80 colour declarations in this stylesheet was written that
 * way, so the drill-panel assistant had been shipping with its entire palette
 * dead, hidden only by sitting inside an already-dark panel.
 *
 * A type checker cannot see this and a component test cannot either: jsdom does
 * not evaluate custom properties. So the guard is a lint of the stylesheet.
 */

// Comments are stripped first. The block comments in this stylesheet DOCUMENT
// the broken form in order to warn against it, and a lint that cannot tell a
// declaration from prose would force the documentation to be vaguer than the
// rule it explains.
const css = readFileSync(join(__dirname, "assistant.css"), "utf8").replace(/\/\*[\s\S]*?\*\//g, "");

describe("assistant.css colour contract", () => {
  it("never uses a bare var() for a colour", () => {
    // The exact broken shape: var(--name, #hex). The fallback makes it LOOK
    // careful, which is what stopped anyone from noticing.
    const broken = [...css.matchAll(/var\((--[a-z]+),\s*#[0-9a-fA-F]{3,8}\)/g)];
    expect(
      broken.map((m) => m[0]),
      "these resolve to a raw RGB triple, not a colour, so the browser drops the " +
        "declaration and the element renders transparent; use rgb(var(--x)) instead"
    ).toEqual([]);
  });

  it("still actually styles things — the guard above is not vacuous", () => {
    // If the stylesheet were emptied or the token names changed wholesale, the
    // first test would pass by matching nothing at all. A completeness check in
    // this repo has already gone green while parsing zero entries; this makes
    // that failure mode impossible here.
    const correct = [...css.matchAll(/rgb\(var\(--[a-z]+\)/g)];
    expect(correct.length).toBeGreaterThan(40);
  });

  it("only references palette tokens the console actually defines", () => {
    // A typo like --pannel is silently transparent for exactly the same reason.
    const defined = new Set([
      "surface",
      "panel",
      "row",
      "text",
      "muted",
      "dim",
      "accent",
      "good",
      "warn",
      "danger",
      "info",
      // Set by the sidebar itself for its persisted width.
      "chat-w"
    ]);
    const used = new Set([...css.matchAll(/var\(--([a-z-]+)/g)].map((m) => m[1]));
    expect([...used].filter((t) => !defined.has(t))).toEqual([]);
  });
});
