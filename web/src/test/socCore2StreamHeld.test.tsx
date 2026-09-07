import { readFileSync } from "node:fs";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { EventStream } from "../features/soc/EventStream";

/**
 * The paused stream's held-frame readout has to be VISIBLE, not just present.
 *
 * It was added carrying a class no stylesheet had a rule for, so the one line
 * that distinguishes "held, and N frames are waiting" from "the estate has gone
 * quiet" rendered as unstyled inline text in a row of pill-shaped controls —
 * the disclosure existed in the DOM and not on the screen.
 *
 * The class is read off the rendered element rather than written out here, so
 * renaming it cannot quietly re-open the gap.
 */
const css = readFileSync("src/features/soc/soc.css", "utf8");
/** Strip comments so prose mentioning a class never counts as styling it. */
const rules = css.replace(/\/\*[\s\S]*?\*\//g, "");

function renderHeld() {
  render(
    <EventStream
      events={[]}
      paused
      heldCount={3}
      onPaused={() => {}}
      hideNoise={false}
      onHideNoise={() => {}}
      filter=""
      onFilter={() => {}}
      onOpenEvent={() => {}}
    />
  );
  return screen.getByText(/3 arrived while held/);
}

describe("the held-frame readout is styled", () => {
  it("carries at least one class", () => {
    expect(renderHeld().className.trim()).not.toBe("");
  });

  it("has a rule for every class it carries", () => {
    const classes = renderHeld().className.split(/\s+/).filter(Boolean);
    const unstyled = classes.filter((name) => !new RegExp(`\\.${name}\\b`).test(rules));
    expect(unstyled, `the readout renders unstyled: no rule for ${unstyled.join(", ")}`).toEqual([]);
  });

  it("is painted with a theme token, so it survives the light theme", () => {
    const classes = renderHeld().className.split(/\s+/).filter(Boolean);
    const declarations = classes
      .map((name) => new RegExp(`\\.${name}\\s*\\{[^}]*\\}`).exec(rules)?.[0] ?? "")
      .join("\n");
    expect(declarations, "the readout's colour is not a themed token").toMatch(/color:\s*var\(--soc-/);
  });
});
