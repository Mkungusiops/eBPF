import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

/**
 * The window selector must never render a raw minute count.
 *
 * Adding a 7-day range surfaced a second, inline formatter on the button
 * (`${value}m`) that had drifted from rangeLabel: the control read "10080m"
 * while every notice on the same page called that window "7d".
 */
const soc = readFileSync("src/features/soc/SocRoute.tsx", "utf8");
const choke = readFileSync("src/features/choke/ChokeRoute.tsx", "utf8");

describe("window selector labels", () => {
  it("SOC renders its range buttons through rangeLabel", () => {
    expect(soc).toMatch(/\{rangeLabel\(value\)\}/);
  });

  it("SOC has no inline minute formatter left on the buttons", () => {
    expect(soc).not.toMatch(/value === 1440 \? "24h" : `\$\{value\}m`/);
  });

  it("no caption anywhere renders the raw minute count", () => {
    // The button was only the first of five. Three KPI tiles kept their own
    // `${rangeMin}m window`, so a 7-day view showed "10080m window" under
    // Critical, High and Medium while the selector above them said "7d" — the
    // exact drift the button fix was supposed to end, still on screen.
    expect(soc).not.toMatch(/\$\{rangeMin\}m\s*window/);
    expect(soc).not.toMatch(/\$\{value\}m\s*window/);
  });

  it("every window caption goes through rangeLabel", () => {
    const captions = [...soc.matchAll(/meta=\{`([^`]*window)`\}/g)].map((m) => m[1]);
    expect(captions.length, "expected the KPI tiles to declare a window caption").toBeGreaterThan(0);
    for (const c of captions) {
      expect(c, `caption "${c}" bypasses rangeLabel`).toMatch(/rangeLabel\(/);
    }
  });

  it("both selectors offer the 7-day range", () => {
    expect(soc).toMatch(/\[5, 30, 60, 1440, 10080\]/);
    expect(choke).toMatch(/WINDOW_OPTIONS = \[5, 30, 60, 1440, 10080\]/);
  });
});

/** The label maths, mirrored from rangeLabel/formatWindow. */
const rangeLabel = (m: number) =>
  m >= 1440 ? (Math.round(m / 1440) === 1 ? "24h" : `${Math.round(m / 1440)}d`) : m >= 60 ? `${Math.round(m / 60)}h` : `${m}m`;

describe("rangeLabel", () => {
  it("names days past a day", () => {
    expect(rangeLabel(10080)).toBe("7d");
    expect(rangeLabel(43200)).toBe("30d");
    expect(rangeLabel(1440)).toBe("24h");
  });
  it("keeps short windows in their natural unit", () => {
    expect(rangeLabel(5)).toBe("5m");
    expect(rangeLabel(30)).toBe("30m");
    expect(rangeLabel(60)).toBe("1h");
  });
});
