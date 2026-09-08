import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * NO EXPORT WITHOUT A CALLER, IN THE FILES THE KPROBE CLEANUP TOUCHED.
 *
 * Deleting KprobeBody removed the last caller of api.ts's exported
 * fetchPolicyStats and left it standing with a doc comment that described a
 * cadence — "the Kprobe panel self-polls this on a fast cadence" — no panel had
 * any more. That is worse than dead code: it is a live-looking description of a
 * surface that no longer exists, and it is how the deleted board would get
 * "restored for symmetry" by the next reader. src/test/deadSymbols.test.ts pins
 * KprobeBody's own machinery; this pins the general property, so the next
 * deletion cannot leave the same shape behind.
 *
 * A reference means a use in the console's own source FROM ANOTHER FILE. Tests
 * do not count — a symbol kept alive only by the suite that asserts it exists
 * would pass — and neither do uses inside the declaring file, because those keep
 * the symbol alive without making the `export` on it mean anything. Test files
 * are excluded by path (src/test, and colocated `*.test.tsx` such as the ones
 * now sitting in src/features/fleet). Only src/test was skipped before, so a
 * colocated test counted as a caller in contradiction of this paragraph — no
 * export in the files below is kept alive that way today, which is exactly why
 * it was worth closing while it was still cheap.
 *
 * SCOPE: the three files below — the ones the kprobe cleanup touched.
 * features/common/panelData.ts is deliberately not among them. Its own exports
 * (PanelSpec, socPanels, chokePanels) have no caller anywhere in src, so adding
 * it here would assert "delete this module", which is a decision about a
 * hand-maintained panel ledger the e2e suite reads as documentation, not a
 * residue this test can adjudicate. It is checked below for content instead.
 */

const FILES = ["src/features/soc/panels.tsx", "src/features/soc/api.ts", "src/features/soc/panelInventory.ts"];

/**
 * PoliciesBody is a known, documented residue of the same commit and cannot be
 * removed from panels.tsx alone: src/test/policySurfaces.test.ts asserts that
 * THIS file contains the viewer's `loaded on ${policy.loadedAgents}` string, so
 * deleting the component turns that suite red until the assertion is retargeted
 * at DetectionsBody (which carries the same guarantee). The exception is listed
 * here rather than hidden by a looser rule, and the note above the component
 * says the same thing.
 */
const KNOWN_UNREMOVABLE = new Set(["PoliciesBody"]);

/**
 * EXPORTS WITH NO EXTERNAL CALLER THAT ARE KEPT ANYWAY, EACH WITH ITS REASON.
 *
 * Tightening the reference count to other-file uses (see referenceCount) turned
 * up fifteen exports whose only uses are inside their own file. They are not one
 * kind, so they are not excused by one rule:
 *
 *  - api.ts TYPES that name part of an exported signature. `fetchTenantRoster`
 *    returns TenantRoster, `socIdentityOf` returns SocIdentity,
 *    `probeFleetHosts` returns FleetProbeResult[], `responseAuthorityNow`
 *    returns ResponseAuthorityState, `recordResponseAuthority` takes
 *    ResponseAuthority, and SeverityCounts / AlertStatsBucket are fields of
 *    exported alert-stat interfaces.
 *
 *    SocWhoamiWithAuthority is the ONE member of this group that does NOT meet
 *    that description, and it is listed anyway with its own reason. No exported
 *    signature has it: `normalizeWhoami` returns it but is not exported, and
 *    SocSnapshot.whoami is the narrower SocWhoami, so a caller cannot obtain
 *    one through this module's public API. It is kept because it names the
 *    shape the normaliser produces — the whoami document PLUS the authority
 *    fields the console derives from it — and deleting it would leave that
 *    distinction expressed only by a function signature nobody outside the
 *    file can see. If the narrowing at SocSnapshot.whoami ever goes, this
 *    becomes an ordinary member of the group above. A caller that wants to hold one of those values in a named
 *    variable needs the type, so the export is a real surface even with no
 *    import today. These stay.
 *  - PURE FUNCTIONS exported as a unit-test seam: normalizePeerUrl (peerUrl
 *    test), normalizeVersion (labSurfaces), normalizePolicy (policySurfaces).
 *    The header says tests are not callers, and that stands — these are listed
 *    as a deliberate exception rather than quietly counted as one.
 *  - panels.tsx COMPONENTS used only by their neighbours: StatGrid, StatCard,
 *    FilterChips, techniqueForPolicy. These are the genuine residue of this
 *    class — the `export` should come off them. It is not done here because
 *    panels.tsx is not this change's file; the names are pinned so the removal
 *    is a deletion from this list, not a discovery.
 */
const KEPT_WITHOUT_EXTERNAL_CALLER = new Set([
  "SeverityCounts",
  "AlertStatsBucket",
  "FleetProbeResult",
  "ResponseAuthority",
  "ResponseAuthorityState",
  "SocWhoamiWithAuthority",
  "SocIdentity",
  "TenantRoster",
  "normalizePeerUrl",
  "normalizeVersion",
  "normalizePolicy",
  "StatGrid",
  "StatCard",
  "FilterChips",
  "techniqueForPolicy"
]);

function consoleSources(): Array<{ file: string; source: string }> {
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const path = join(dir, entry);
      if (statSync(path).isDirectory()) {
        if (entry === "test" || entry === "__tests__") continue;
        walk(path);
      } else if (/\.tsx?$/.test(entry) && !/\.(test|spec)\.tsx?$/.test(entry)) {
        files.push(path);
      }
    }
  };
  walk("src");
  return files.map((file) => ({ file, source: stripComments(readFileSync(file, "utf8")) }));
}

/**
 * COMMENTS ARE NOT CALLERS. The first draft of this test passed with
 * fetchPolicyStats restored, because a comment in features/common/panelData.ts
 * names it — the same way a grep for a withdrawn storage key finds the note
 * recording its withdrawal. References are counted over code only.
 *
 * `//` is treated as a comment start only when it does not follow a colon, so
 * the "https://" and "/api/..." literals this console is full of survive.
 */
function stripComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .split("\n")
    .map((line) => line.replace(/(^|[^:])\/\/.*$/, "$1"))
    .join("\n");
}

const sources = consoleSources();

function exportedSymbols(file: string): string[] {
  const source = sources.find((entry) => entry.file === file)?.source ?? "";
  expect(source, `${file} was not read`).not.toEqual("");
  return [...source.matchAll(/^export (?:async )?(?:function|const|class|type|interface|enum) ([A-Za-z0-9_$]+)/gm)].map(
    (match) => match[1]
  );
}

/**
 * Uses of `name` in the console OUTSIDE the file that declares it. \b keeps
 * fetchPolicyStats from being kept alive by a longer name.
 *
 * The first version of this subtracted only the declaration line, so uses inside
 * the declaring file counted — and an export whose only callers are its own
 * neighbours passed a test titled "every export is used somewhere in the
 * console". That is precisely the residue this file exists to catch: the symbol
 * is not dead code, but the `export` on it is a dead advertisement of a surface
 * nothing outside consumes. Counting other files only is what makes the title
 * true; the price is KEPT_WITHOUT_EXTERNAL_CALLER above, which must name every
 * symbol kept exported for a reason other than an external caller.
 */
function referenceCount(name: string, declaringFile: string): number {
  const word = new RegExp(`\\b${name}\\b`, "g");
  return sources.reduce((total, entry) => {
    if (entry.file === declaringFile) return total;
    return total + (entry.source.match(word)?.length ?? 0);
  }, 0);
}

describe("the kprobe cleanup left no exported symbol without a caller", () => {
  it("finds the exports at all, or every assertion below is vacuous", () => {
    const symbols = FILES.flatMap(exportedSymbols);
    expect(symbols).toContain("HoneypotsBody");
    expect(symbols).toContain("fetchSocSnapshot");
    expect(symbols.length).toBeGreaterThan(40);
  });

  for (const file of FILES) {
    it(`${file}: every export is used from another file, or is listed with a reason`, () => {
      const dead = exportedSymbols(file).filter(
        (name) =>
          !KNOWN_UNREMOVABLE.has(name) &&
          !KEPT_WITHOUT_EXTERNAL_CALLER.has(name) &&
          referenceCount(name, file) === 0
      );
      expect(dead, `exported with no caller outside its own file: ${dead.join(", ")}`).toEqual([]);
    });
  }

  it("keeps no excuse alive past the thing it excuses", () => {
    // A name on either list that has since gained an external caller, or stopped
    // being exported, is an excuse for a problem that no longer exists — and
    // leaving it there hides the next symbol that inherits the name.
    const exported = new Map(FILES.flatMap((file) => exportedSymbols(file).map((name) => [name, file] as const)));
    const stale = [...KEPT_WITHOUT_EXTERNAL_CALLER, ...KNOWN_UNREMOVABLE].filter((name) => {
      const file = exported.get(name);
      return !file || referenceCount(name, file) > 0;
    });
    expect(stale, `listed as unremovable but no longer needs the exemption: ${stale.join(", ")}`).toEqual([]);
  });

  it("carries no policy-stats fetch of its own — the snapshot serves that data", () => {
    const api = readFileSync("src/features/soc/api.ts", "utf8");
    // SensorHealthBody renders snapshot.policyStats, which fetchSocSnapshot
    // fills. A second, faster reader existed only for the deleted board.
    expect(api).not.toContain("export async function fetchPolicyStats");
    expect(api).toContain("policyStats: unwrapList(map.policyStats.data");
  });

  it("advertises no kprobe surface in the shared panel list", () => {
    // features/common/panelData.ts is the second, hand-maintained copy of the
    // panel list; it kept a "Kprobe performance modal … /api/policy-stats
    // polling" row after the board and its poller were both gone.
    const panelData = readFileSync("src/features/common/panelData.ts", "utf8");
    // Matched on the row form, not the word: the comment recording the
    // withdrawal names the old title on purpose.
    expect(panelData).not.toMatch(/\["Kprobe|"soc-kprobes"/);
    expect(panelData).toContain("soc-sensor-health");
  });
});
