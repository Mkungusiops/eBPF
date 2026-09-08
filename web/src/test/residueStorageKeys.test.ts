import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { SOC_PANEL_INVENTORY, SOC_STORAGE_KEYS } from "../features/soc/panelInventory";

/**
 * ADVERTISED STORAGE MUST BE STORAGE THAT EXISTS — IN BOTH DIRECTIONS.
 *
 * SOC_STORAGE_KEYS is not a note to developers. SocModals passes its length to
 * AccountBody, which prints "N local preference keys stored in this browser"
 * (panels.tsx). That number is the one storage claim the operator is actually
 * shown, so a listed key nothing writes is a lie told with a number, and a key
 * the console does write but never lists under-reports what is held on the
 * operator's machine.
 *
 * The per-panel `storage` arrays are NOT rendered anywhere — panels are handed
 * PANELS[...] for their title, description and risk only. They are developer
 * documentation of which surface owns which key, and they are held to the same
 * standard here because they are what an author reads when deciding whether a
 * new key belongs in the count above.
 *
 * It has been the first kind twice. `soc.savedViews` was advertised for a
 * saved-view control that was never built. Then the kprobe board was replaced by
 * SensorHealthBody and its `soc.kprobeThreshold` / `soc.kprobeUI.*` keys stayed
 * listed with their only writer deleted — the same defect, recreated by the
 * cleanup that removed the first one. Sweeping for the rest turned up
 * `soc.theme` (theme has followed the OS since lib/theme.ts), `soc.hpUI.*` (the
 * honeypot toolbar is component state), `soc.graphFilters`/`Layout`/`TTL`,
 * `soc.refreshInterval`, `soc.notifySoundEnabled`, `soc.prefGroupAlerts` and
 * `soc.prefHideNoise`: seventeen of thirty-five advertised keys had no writer,
 * leaving eighteen, to which five more with real writers were added.
 *
 * This test reads the console's real writes out of its source rather than
 * trusting a second list, so re-adding a withdrawn key fails here.
 */

// Every persistence call this console makes, by the helper that makes it. A key
// mentioned only in a comment or a placeholder string is deliberately NOT a
// write — that is exactly how an unwritten key survives a grep.
const WRITE_CALL =
  /(?:useLocalJsonState|useLocalState|useStoredBoolean|writeJsonStorage|saveJSON|localStorage\.setItem)\s*(?:<[^(]*>)?\s*\(\s*(["`])([^"`]+)\1/g;
const NAMED_CONST = /const\s+([A-Za-z_$][\w$]*)\s*=\s*"([^"]+)"/g;

// The console's own source: colocated `*.test.tsx` files (src/features/fleet has
// them) are skipped along with src/test, or a key a test writes to set up a
// fixture would read as a console write and have to be advertised.
function consoleSources(): string {
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const path = join(dir, entry);
      if (statSync(path).isDirectory()) {
        if (entry === "test" || entry === "__tests__") continue;
        walk(path);
      } else if (/\.tsx?$/.test(entry) && !/\.(test|spec)\.tsx?$/.test(entry) && entry !== "panelInventory.ts") {
        files.push(path);
      }
    }
  };
  walk("src");
  return files.map((file) => readFileSync(file, "utf8")).join("\n");
}

// `soc.nav.v2.${slug}` in Sidebar.tsx and "soc.nav.v2.<section>" in the
// inventory are the same claim: one key per collapsible nav section.
const normalize = (key: string) => key.replace(/\$\{[^}]*\}/g, "<var>").replace(/<[^>]*>/g, "<var>");

const source = consoleSources();

function writtenKeys(): string[] {
  const keys = new Set<string>();
  for (const match of source.matchAll(WRITE_CALL)) keys.add(match[2]);
  // Keys held in a named constant and written through it (lib/tenantScope.ts
  // does this for soc.selectedTenant). localStorage only: SOC_STORAGE_KEYS is
  // what the account page calls "stored in this browser", and lib/pwa.ts's
  // soc.pwa.login.first-control-reload is a sessionStorage latch that dies with
  // the tab — listing it would over-report what the operator's machine keeps.
  for (const match of source.matchAll(NAMED_CONST)) {
    if (source.includes(`localStorage.setItem(${match[1]}`)) keys.add(match[2]);
  }
  return [...keys].filter((key) => key.startsWith("soc.")).map(normalize).sort();
}

describe("the SOC console advertises exactly the browser storage it writes", () => {
  const written = writtenKeys();
  const advertised = SOC_STORAGE_KEYS.map(normalize).sort();

  it("finds the console's writes at all, or every assertion below is vacuous", () => {
    // A regex that matched nothing would make both directions trivially pass.
    expect(written).toContain("soc.alertStates");
    expect(written).toContain("soc.nav.v2.<var>");
    expect(written.length).toBeGreaterThan(15);
  });

  it("lists no key the console never writes", () => {
    const unwritten = advertised.filter((key) => !written.includes(key));
    expect(
      unwritten,
      `SOC_STORAGE_KEYS advertises storage nothing writes: ${unwritten.join(", ")}`
    ).toEqual([]);
  });

  it("omits no key the console does write", () => {
    const unlisted = written.filter((key) => !advertised.includes(key));
    expect(
      unlisted,
      `the console keeps these on the operator's machine without listing them: ${unlisted.join(", ")}`
    ).toEqual([]);
  });

  it("names no withdrawn kprobe key — the board that wrote them is gone", () => {
    for (const key of ["soc.kprobeThreshold", "soc.kprobeUI.search", "soc.kprobeUI.filter", "soc.kprobeUI.sortBy", "soc.kprobeUI.sortDir"]) {
      expect(advertised, `${key} outlived its only writer`).not.toContain(key);
      expect(source, `${key} would need a writer before it may be advertised again`).not.toContain(key);
    }
  });

  it("holds every panel's own storage claim to the same standard", () => {
    const perPanel = SOC_PANEL_INVENTORY.flatMap((panel) =>
      (panel.storage ?? []).map((key) => ({ id: panel.id, key: normalize(key) }))
    );
    // The account page counts SOC_STORAGE_KEYS, so a panel key missing from it
    // is held by the console but absent from the number the operator is shown.
    const unwritten = perPanel.filter((entry) => !written.includes(entry.key));
    expect(
      unwritten.map((entry) => `${entry.id}: ${entry.key}`),
      "a panel advertises storage nothing writes"
    ).toEqual([]);
    const uncounted = perPanel.filter((entry) => !advertised.includes(entry.key));
    expect(
      uncounted.map((entry) => `${entry.id}: ${entry.key}`),
      "a panel advertises a key the account page's inventory does not count"
    ).toEqual([]);
  });

  /**
   * THE OTHER DIRECTION OF THE PANEL CLAIM: a panel may not stay silent about a
   * key its own controls write.
   *
   * Until this assertion existed, the block above only checked that keys a panel
   * DOES list are real. Nothing checked the omission, and the top-bar entry
   * showed why that matters: the fleet consolidation moved the customer switcher
   * into the top bar, the switcher's onSelectTenant reaches
   * lib/tenantScope.setSelectedTenant which writes soc.selectedTenant, and the
   * entry went on listing soc.prefDefaultRange alone — under-reporting the same
   * way the withdrawn keys over-reported.
   *
   * Attribution cannot be derived from the source: the write happens one prop
   * hop away from the control that causes it, in a different file. So the rule
   * is coverage instead — every counted key belongs to some panel, or is named
   * below with the reason it belongs to no panel. A new key can then be added to
   * SOC_STORAGE_KEYS only by saying which surface keeps it.
   */
  const NOT_A_PANEL_KEY = new Map([
    // The executive band's collapse and its briefing toggle. The band is a
    // route-level strip in SocRoute, not one of the inventoried panels — it has
    // no PANELS entry to attribute these to (its data-panel is "exec-summary",
    // which is not a panel id).
    ["soc.execBand", "executive band collapse — the band has no panel entry"],
    ["soc.briefingMode", "executive band briefing toggle — same surface"]
  ]);

  it("attributes every counted key to a panel, or names why it has none", () => {
    const claimed = new Set(
      SOC_PANEL_INVENTORY.flatMap((panel) => (panel.storage ?? []).map((key) => normalize(key)))
    );
    const orphans = advertised.filter((key) => !claimed.has(key) && !NOT_A_PANEL_KEY.has(key));
    expect(
      orphans,
      `counted on the account page but attributed to no panel: ${orphans.join(", ")}`
    ).toEqual([]);
    // And the excuse list may not outlive the keys it excuses.
    const stale = [...NOT_A_PANEL_KEY.keys()].filter((key) => !advertised.includes(key));
    expect(stale, `NOT_A_PANEL_KEY names keys the console no longer counts: ${stale.join(", ")}`).toEqual([]);
  });
});
