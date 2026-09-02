import { readFile } from "node:fs/promises";

import type { Locator, Page } from "@playwright/test";

import { installMockApi, mockData, type MockApiOptions } from "./support/mock-api";
import { expect, socNavItem, test } from "./support/test";

/**
 * The export studio — the surface that turns the window an analyst is looking
 * at into a file somebody else reads.
 *
 * WHAT BUG THIS PINS: an export is the one part of the console whose output
 * survives the session, so its failures are silent and durable. Four shapes of
 * that failure are asserted here, all of them things this surface can do while
 * still looking perfectly healthy on screen:
 *
 *   · a file that downloads but is empty, or is a header with no rows — the
 *     buttons animate, a file lands in ~/Downloads, and the incident report
 *     handed to the customer contains none of the alerts that caused it;
 *   · a section toggle (or a preset) that changes the preview but not the
 *     BYTES, so an operator who deselected "Events" ships them anyway, or the
 *     "Threat intel" bundle they mailed out carries the full alert table;
 *   · a scope selector that counts something other than what is on screen —
 *     "On screen (12)" over a queue showing three is a report whose stated
 *     scope is a lie, and so is a file that quietly ships two rows for the four
 *     alerts a grouped queue collapsed (that one is still broken; see the
 *     test.fail below);
 *   · a decisions table that manufactures a verdict. `ok: d.ok !== false` once
 *     stamped every decision successful because no backend sends a boolean
 *     `ok`, so rows whose real outcome read "skipped: system-critical chain"
 *     exported as ok — a false claim of containment in the artefact most
 *     likely to be read by an auditor. src/test/decisionHonesty.test.ts guards
 *     that by grepping SOURCE and says in its own comment that a behavioural
 *     test would be better; this is that test, on the actual file.
 *
 * WHY IT IS HERE AND NOT IN UNIT TESTS: none of the above is observable in
 * jsdom. The subject is a real Blob handed to a real browser through an <a
 * download> whose object URL is revoked on the next line, a real jsPDF binary
 * written by a library that is DYNAMICALLY imported (so it is not even loaded
 * when the assertions about first paint are made), and a real clipboard behind
 * a real permission. jsdom has no download manager, no PDF, and stubs the
 * clipboard — a unit test can only assert that a function was called with a
 * Blob, which is exactly the assertion that passes over a zero-byte file.
 *
 * FIXTURES: the mocked backend's default alert ("Credential file read", cat,
 * critical, score 44, 2026-06-25T09:00:00Z) and its one file_open event on
 * /etc/shadow, which is the only IOC in the window. Everything time-windowed
 * needs soc.prefDefaultRange widened, because the fixture is dated.
 */

/** A year, in minutes — wide enough for the dated fixture to be in range. */
const WIDE_RANGE = 525_600;

const FIXTURE_NOW = mockData.alerts[0].timestamp;

/**
 * Three alerts that differ in severity, policy, process AND title, which is
 * the whole of groupAlertList's key — so the queue renders one row each.
 *
 * That is a DELIBERATE simplification of the scope test, not an accident: the
 * queue groups by default (soc.groupAlerts is true), and what an export does
 * to a grouped queue is a separate, currently-broken story pinned on its own
 * by "a grouped queue exports every alert it stands for" below.
 */
const THREE_ALERTS = [
  mockData.alerts[0],
  {
    id: "alert-fixture-2",
    timestamp: FIXTURE_NOW,
    severity: "high",
    title: "Reverse shell attempt",
    description: "Fixture alert two",
    policy_name: "override-reverse-shell",
    process: "bash",
    binary: "bash",
    exec_id: "exec-fixture-2",
    pid: 4243,
    score: 61
  },
  {
    id: "alert-fixture-3",
    timestamp: FIXTURE_NOW,
    severity: "medium",
    title: "Outbound beacon observed",
    description: "Fixture alert three",
    policy_name: "override-beacon",
    process: "curl",
    binary: "curl",
    exec_id: "exec-fixture-3",
    pid: 4244,
    score: 38
  }
];

async function gotoSoc(page: Page, options: MockApiOptions = {}): Promise<void> {
  await page.addInitScript((range) => {
    window.localStorage.setItem("soc.prefDefaultRange", String(range));
  }, WIDE_RANGE);
  await installMockApi(page, options);
  await page.goto("/");
  await expect(page.locator('[data-panel="left-sidebar"]')).toBeVisible();
}

async function openReports(page: Page): Promise<Locator> {
  await socNavItem(page, "Reports").click();
  const panel = page.locator('[data-panel="export-confirm-modal"]');
  await expect(panel, "the Reports nav item did not open the export studio").toBeVisible();
  return panel;
}

/** The run button, whatever format it currently offers. */
function runButton(panel: Locator): Locator {
  return panel.getByRole("button", { name: /^Export (PDF|CSV|JSON)$/ });
}

/** The section list of the live preview — one line per section that will ship. */
function previewLines(panel: Locator): Locator {
  return panel.locator(".soc-export-preview-list li");
}

const SECTION = {
  summary: /^Executive summary/,
  alerts: /^Alerts/,
  events: /^Events/,
  decisions: /^Enforcement decisions/,
  iocs: /^Indicators/,
  mitre: /^ATT&CK coverage/
} as const;

function section(panel: Locator, key: keyof typeof SECTION): Locator {
  return panel.getByRole("button", { name: SECTION[key] });
}

/**
 * Split the CSV back into its "# BLOCK" sections.
 *
 * The block NAMES are the contract under test: they are what says which
 * sections actually reached the file, independently of what the preview drew.
 */
function csvBlocks(text: string): Record<string, string[]> {
  const blocks: Record<string, string[]> = {};
  let current: string | null = null;
  for (const line of text.split("\n")) {
    const header = /^# ([A-Z_]+)$/.exec(line);
    if (header) {
      current = header[1];
      blocks[current] = [];
      continue;
    }
    if (current && line.trim()) blocks[current].push(line);
  }
  return blocks;
}

/** Click the run button and read whatever file the browser was handed. */
async function downloadReport(page: Page, panel: Locator): Promise<{ filename: string; body: Buffer }> {
  const [download] = await Promise.all([
    page.waitForEvent("download", { timeout: 60_000 }),
    runButton(panel).click()
  ]);
  const failure = await download.failure();
  expect(failure, `the browser aborted the download: ${failure}`).toBeNull();
  const path = await download.path();
  expect(path, "the download produced no file on disk").toBeTruthy();
  return { filename: download.suggestedFilename(), body: await readFile(path as string) };
}

test.describe("export studio", () => {
  test.use({ viewport: { width: 1600, height: 1000 } });

  /**
   * The preview is the only thing an operator can check BEFORE committing to a
   * file, so it has to name the real artefact. A preview that says "PDF" while
   * the button writes a CSV is a surface nobody can proof-read.
   */
  test("opens from the sidebar and names the file each format will produce", async ({ page }) => {
    await gotoSoc(page);
    const panel = await openReports(page);

    const filename = panel.locator(".soc-export-preview-file strong");
    await expect(filename, "the default format is the board-ready PDF").toHaveText("soc-incident-report.pdf");
    await expect(runButton(panel), "the run button must name the format it will write").toHaveText(/Export PDF/);

    // The default assembly is a report, not a flat alert dump: four sections.
    await expect(previewLines(panel), "the default section set is not what the preview lists").toHaveText([
      /executive summary/i,
      /alerts/i,
      /indicators/i,
      /att&ck coverage/i
    ]);

    for (const [button, expected, run] of [
      ["CSV", "soc-export.csv", /Export CSV/],
      ["JSON", "soc-export.json", /Export JSON/],
      ["PDF report", "soc-incident-report.pdf", /Export PDF/]
    ] as const) {
      await panel.getByRole("button", { name: button, exact: true }).click();
      await expect(filename, `choosing ${button} must repoint the preview at the file it writes`).toHaveText(expected);
      await expect(runButton(panel), `choosing ${button} must relabel the run button`).toHaveText(run);
    }
  });

  /**
   * WHAT BUG THIS PINS: "On screen (N)" is a claim about the queue behind the
   * modal. If N is computed from a different list than the one the alert queue
   * renders — the pre-filter list, or the whole range — then the report's own
   * stated scope is wrong, and it is wrong in the direction of claiming to
   * cover more than it does. The search box forces the two lists apart (one of
   * the three fixtures survives it), so "On screen" and "Full range" have to
   * disagree, and the preview and the scope label have to follow the choice.
   *
   * WHAT IT DOES NOT PROVE — corrected claim: the rendered row count and
   * "On screen (N)" are the SAME expression. AlertQueue.tsx maps one row per
   * model.filteredAlerts entry and exportStudio.tsx prints filteredAlerts
   * .length, so a change that moved both together would still pass here. This
   * catches the modal reading rangeAlerts or a pre-filter list — the way it has
   * actually drifted — and it is NOT the cross-check of two independently
   * derived numbers an earlier version of this docblock claimed it was.
   */
  test("scope counts match the alert queue behind the modal", async ({ page }) => {
    await gotoSoc(page, { routes: { "/api/alerts": THREE_ALERTS } });

    const rows = page.locator(".soc-alert-row");
    await expect(rows, "three ungroupable fixtures must render three rows").toHaveCount(3);

    await page.getByPlaceholder("Search alerts, processes, policies…").fill("curl");
    await expect(rows, "the search box did not narrow the queue, so scope is untested").toHaveCount(1);
    // Taken from the assertion above rather than re-measured with rows.count():
    // after toHaveCount(1), asserting 1 > 0 and 1 < THREE_ALERTS.length would be
    // two tautologies. One of three is what makes the two scope numbers differ.
    const onScreen = 1;

    const panel = await openReports(page);
    await expect(
      panel.getByRole("button", { name: `On screen (${onScreen})`, exact: true }),
      `"On screen" must count the ${onScreen} row(s) actually rendered`
    ).toBeVisible();
    await expect(
      panel.getByRole("button", { name: `Full range (${THREE_ALERTS.length})`, exact: true }),
      `"Full range" must count all ${THREE_ALERTS.length} alerts in the window`
    ).toBeVisible();

    // And the choice has to move the report, not just the highlight.
    const alertLine = previewLines(panel).filter({ hasText: /alerts/i });
    await expect(alertLine, "the filtered scope must preview the filtered count").toHaveText(
      new RegExp(`^${onScreen}\\s+alerts$`)
    );
    await expect(panel.locator(".soc-export-preview-file em"), "the preview must name the scope").toContainText(
      "filtered (on screen)"
    );

    await panel.getByRole("button", { name: `Full range (${THREE_ALERTS.length})`, exact: true }).click();
    await expect(alertLine, "switching to the full range must preview every alert in the window").toHaveText(
      new RegExp(`^${THREE_ALERTS.length}\\s+alerts$`)
    );
    await expect(panel.locator(".soc-export-preview-file em"), "the preview must follow the scope change").toContainText(
      "full range"
    );
  });

  /**
   * WHAT BUG THIS PINS — a live one, hence test.fail.
   *
   * The alert queue GROUPS by default (soc.groupAlerts defaults to true in
   * SocRoute.tsx:88), so `filteredAlerts` is a list of AlertGroups, each one
   * standing for `groupCount` real alerts (analytics.ts groups on
   * severity:policy:process:title). The export model is built straight off that
   * list: one exported row per GROUP, and summary.total / counts.<severity>
   * counted over groups — with no groupCount column anywhere and nothing in the
   * file saying anything was collapsed.
   *
   * Measured on the fixture below (three identical criticals + one high): the
   * modal offers "On screen (2)" over four alerts, the CSV's SUMMARY says
   * alerts=2 / critical=1 where the window holds 4 and 3, and the ALERTS block
   * carries two rows. Two critical alerts leave the artefact silently. It is
   * the same class as the scope lie above — a report whose stated scope is not
   * what it covers — except this one UNDER-states, which in an incident report
   * means the collapsed criticals are simply not in the document the customer
   * is handed.
   *
   * THE PRODUCT FIX (one line): expand the groups where ExportStudioBody feeds
   * the scope into buildExportModel in src/features/soc/exportStudio.tsx —
   * `scope === "filtered" ? filteredAlerts.flatMap((g) => g.members) : rangeAlerts`
   * — or, if one row per group is wanted in the file, emit `groupCount` as a
   * column and count members in the summary. Either way the file has to account
   * for every alert it claims to cover.
   */
  test("a grouped queue exports every alert it stands for", async ({ page }) => {
    test.fail(true, "known defect: grouped scope exports one row per group and counts groups as alerts");

    const duplicate = (id: string, pid: number) => ({
      id,
      timestamp: FIXTURE_NOW,
      severity: "critical",
      title: "Credential file read",
      description: "One of three identical criticals the queue collapses into one row",
      policy_name: "override-credential-read",
      process: "cat",
      binary: "cat",
      exec_id: id,
      pid,
      score: 44
    });
    const GROUPED = [
      duplicate("alert-dup-1", 5001),
      duplicate("alert-dup-2", 5002),
      duplicate("alert-dup-3", 5003),
      {
        id: "alert-solo-1",
        timestamp: FIXTURE_NOW,
        severity: "high",
        title: "Reverse shell attempt",
        description: "The one alert that does not group",
        policy_name: "override-reverse-shell",
        process: "bash",
        binary: "bash",
        exec_id: "exec-solo-1",
        pid: 6001,
        score: 61
      }
    ];
    await gotoSoc(page, { routes: { "/api/alerts": GROUPED } });

    // Precondition: grouping is ON, so four alerts render as two rows. This
    // stays true after the export-side fix — the defect is in the FILE.
    await expect(
      page.locator(".soc-alert-row"),
      "grouping is off, so this fixture is not exercising the collapsed path"
    ).toHaveCount(2);

    const panel = await openReports(page);
    await panel.getByRole("button", { name: "CSV", exact: true }).click();
    const { body } = await downloadReport(page, panel);
    const blocks = csvBlocks(body.toString("utf8"));

    const summary = blocks.SUMMARY.join("\n");
    expect(summary, `the summary counts groups, not alerts; SUMMARY was\n${summary}`).toContain(
      `"alerts","${GROUPED.length}"`
    );
    expect(summary, "the summary lost two of the three criticals to grouping").toContain('"critical","3"');

    const alertRows = blocks.ALERTS.slice(1);
    expect(
      alertRows.length,
      `every alert in scope must have a row (or a groupCount saying it was collapsed); got\n${alertRows.join("\n")}`
    ).toBe(GROUPED.length);
  });

  /**
   * WHAT BUG THIS PINS: with no sections there is nothing to write, and the
   * CSV path would happily hand the browser a zero-byte file named
   * soc-export.csv. The empty state has to be refused at the button, and the
   * preview has to say why rather than simply going blank.
   */
  test("the run button refuses an empty report", async ({ page }) => {
    await gotoSoc(page);
    const panel = await openReports(page);

    await expect(runButton(panel), "the default four-section report must be runnable").toBeEnabled();
    await expect(previewLines(panel), "precondition: four sections are selected").toHaveCount(4);

    for (const key of ["summary", "alerts", "iocs", "mitre"] as const) {
      await section(panel, key).click();
    }

    await expect(previewLines(panel), "an empty report must say what is missing").toHaveText([
      /select at least one section/i
    ]);
    await expect(runButton(panel), "a report with no sections must not be runnable").toBeDisabled();

    await section(panel, "alerts").click();
    await expect(runButton(panel), "re-selecting a section must make the report runnable again").toBeEnabled();
  });

  /**
   * WHAT BUG THIS PINS: the whole point of the surface. A CSV that downloads,
   * is named correctly, and contains no alert rows is indistinguishable from a
   * working export until someone opens it — and the section toggles are only
   * real if they change the BYTES, not the preview.
   */
  test("a CSV carries the alerts on screen, and only the chosen sections", async ({ page }) => {
    await gotoSoc(page);
    const panel = await openReports(page);
    await panel.getByRole("button", { name: "CSV", exact: true }).click();

    const first = await downloadReport(page, panel);
    expect(first.filename, "a CSV export must be offered as a .csv").toMatch(/\.csv$/);

    // No byte-length floor here, deliberately. A CSV with all four blocks
    // present and ZERO rows under each measures 381 bytes on this fixture set,
    // so there is no threshold a real export clears that a header-only file
    // does not — a size check would carry the message "a header-only export is
    // the bug" while being unable to detect one. The row assertions below are
    // what tells the two apart.
    const csv = first.body.toString("utf8");
    const blocks = csvBlocks(csv);
    expect(
      // Sorted: WHICH sections reached the file is the contract, so reordering
      // the `if (sections.has(...))` chain in exportCsv must not fail this.
      Object.keys(blocks).sort(),
      `only the four selected sections may reach the file; got ${Object.keys(blocks).join(", ")}`
    ).toEqual(["ALERTS", "IOCS", "MITRE_OBSERVED", "SUMMARY"]);

    const alertRows = blocks.ALERTS.slice(1);
    expect(alertRows.length, "the ALERTS block has a header and no rows").toBeGreaterThan(0);
    const alert = mockData.alerts[0];
    expect(alertRows.join("\n"), `the exported alerts do not include "${alert.title}"`).toContain(alert.title);
    expect(alertRows.join("\n"), "the exported alert lost its severity").toContain(`"${alert.severity}"`);
    expect(alertRows.join("\n"), "the exported alert lost its score").toContain(`"${alert.score}"`);

    // The one IOC in the window is the file the fixture event opened.
    expect(blocks.IOCS.join("\n"), "the IOC block does not carry the observed file").toContain(
      mockData.events[0].path
    );

    // Now the toggle: Events was off, so it must be absent above and present
    // below, with the same fixture telemetry in it.
    expect(csv, "Events was not selected but reached the file anyway").not.toContain("# EVENTS");

    await section(panel, "events").click();
    const second = await downloadReport(page, panel);
    const withEvents = csvBlocks(second.body.toString("utf8"));
    expect(
      Object.keys(withEvents),
      "selecting Events must add an EVENTS block to the file, not just to the preview"
    ).toContain("EVENTS");
    expect(withEvents.EVENTS.slice(1).join("\n"), "the EVENTS block is empty").toContain(
      mockData.events[0].event_type
    );
  });

  /**
   * WHAT BUG THIS PINS: a preset is a one-click promise about what leaves the
   * building. "Threat intel" is IOCs to hand to somebody else, so a preset that
   * repaints the buttons without narrowing the FILE mails an analyst's full
   * alert and event tables to a third party. The JSON bundle is where that is
   * checkable exactly — its top-level keys ARE the section list.
   */
  test("the threat-intel preset ships indicators and nothing else", async ({ page }) => {
    await gotoSoc(page);
    const panel = await openReports(page);

    // Precondition: the default report is a broad one, so narrowing is real.
    await expect(previewLines(panel), "the default report must be broader than one section").toHaveCount(4);

    await panel.getByRole("button", { name: "Threat intel", exact: true }).click();
    await expect(runButton(panel), "the intel preset must switch the format to JSON").toHaveText(/Export JSON/);
    await expect(previewLines(panel), "the intel preset must reduce the report to indicators").toHaveText([
      /indicators/i
    ]);

    const { filename, body } = await downloadReport(page, panel);
    expect(filename, "a JSON bundle must be offered as a .json").toMatch(/\.json$/);

    const bundle = JSON.parse(body.toString("utf8")) as Record<string, unknown>;
    expect(
      Object.keys(bundle).sort(),
      `the bundle must carry provenance and indicators only; got ${Object.keys(bundle).join(", ")}`
    ).toEqual(["iocs", "meta"]);

    const iocs = bundle.iocs as { ips: unknown[]; files: [string, number][]; binaries: [string, number][] };
    expect(
      iocs.files.map(([value]) => value),
      "the intel bundle carries no observed file, so it is empty of intel"
    ).toContain(mockData.events[0].path);
    expect(
      iocs.binaries.map(([value]) => value),
      "the intel bundle carries no observed binary"
    ).toContain(mockData.events[0].process);
    expect(
      (bundle.meta as { scope: string }).scope,
      "a shared bundle must state the scope it was taken from"
    ).toBeTruthy();
  });

  /**
   * WHAT BUG THIS PINS: the export used to compute `ok: d.ok !== false`. No
   * backend sends a boolean `ok` — they send free-text `outcome` — so every
   * decision exported as successful, including rows that read "skipped:
   * system-critical chain (auto-only; manual override allowed)". The report
   * asserted a containment that never happened.
   *
   * THE FIX this pins: the decisions table carries the engine's own words in
   * an `outcome` column, and has no fabricated `ok` column at all.
   *
   * BOTH RENDERERS, because they have already drifted once. exportStudio.tsx's
   * own comment on the decisions autoTable records that the CSV emitted
   * `outcome` while the PDF table dropped it, and that decisionHonesty.test.ts
   * asserted on the CSV header alone — which is how nobody noticed. The PDF is
   * also the artefact an auditor is most likely to be handed. So the same
   * fixture is exported twice here, once through each writer.
   */
  test("an exported decision carries the engine's outcome, never a manufactured ok", async ({ page }) => {
    test.setTimeout(120_000);
    const skipped = "skipped: system-critical chain (auto-only; manual override allowed)";
    await gotoSoc(page, {
      routes: {
        "/api/decisions": [
          {
            id: 9,
            timestamp: FIXTURE_NOW,
            exec_id: "exec-fixture-1",
            pid: 4242,
            binary: "cat",
            action: "sever",
            state: "quarantined",
            score: 88,
            reason: "score above sever threshold",
            dry_run: false,
            outcome: skipped
          }
        ]
      }
    });

    const panel = await openReports(page);
    await panel.getByRole("button", { name: "CSV", exact: true }).click();
    await section(panel, "decisions").click();
    await expect(
      previewLines(panel).filter({ hasText: /enforcement decisions/i }),
      "the decision fixture is not in the report, nothing under test"
    ).toHaveText(/^1\s+enforcement decisions$/);

    const { body } = await downloadReport(page, panel);
    const blocks = csvBlocks(body.toString("utf8"));
    expect(blocks.DECISIONS, "no DECISIONS block in the exported CSV").toBeTruthy();

    expect(
      blocks.DECISIONS[0],
      `the decisions header must carry outcome and no fabricated ok; got ${blocks.DECISIONS[0]}`
    ).toBe('"action","state","target","reason","outcome","timestamp"');

    const rows = blocks.DECISIONS.slice(1).join("\n");
    expect(rows.length, "the DECISIONS block has a header and no rows").toBeGreaterThan(0);
    expect(rows, "the exported decision dropped the engine's own outcome").toContain(skipped);
    expect(rows, `a skipped decision must not be exported as ok; row was ${rows}`).not.toMatch(/"ok"/);

    // And now the half that actually regressed: the same decision through the
    // PDF writer. jsPDF leaves its text streams uncompressed, so the table's
    // header cell and the engine's words are both findable in the raw bytes —
    // autoTable wraps the cell, which is why the assertion is on the first
    // wrapped line ("skipped: system-critical chain") and not the full string.
    await panel.getByRole("button", { name: "PDF report", exact: true }).click();
    await expect(runButton(panel), "the studio must now be offering a PDF").toHaveText(/Export PDF/);
    const pdf = (await downloadReport(page, panel)).body.toString("latin1");
    expect(pdf.slice(0, 5), "the second download is not a PDF").toBe("%PDF-");
    expect(pdf, "the PDF decisions table has no Outcome column").toContain("Outcome");
    expect(pdf, "the PDF asserts a containment the engine reported as skipped").toContain(
      "skipped: system-critical chain"
    );
  });

  /**
   * WHAT BUG THIS PINS: two things at once.
   *
   * (1) jspdf + jspdf-autotable are ~400KB and are needed by exactly one
   *     button, so pdf.ts loads them with a dynamic import and scripts/lint.mjs
   *     enforces that the import stays dynamic. A lint rule over source text
   *     cannot see a static import reintroduced through a re-export or a
   *     barrel file; the network can. This asserts the library is NOT fetched
   *     for a dashboard that never exports, and IS fetched when the button is
   *     pressed.
   *
   * (2) the file that arrives is an actual PDF *with the window's data in it*.
   *     jsPDF fails soft: a document built against a broken model still saves,
   *     and it saves at very nearly full size. Measured against an empty
   *     backend (alerts, events and decisions all []), this report still
   *     downloads as soc-incident-report.pdf, still starts "%PDF-", still
   *     contains "%%EOF" and still measures 20,154 bytes against the real
   *     fixture's 20,879 — exportPdf substitutes a "No alerts in scope"
   *     placeholder row and every heading, tile and tactic bar is drawn
   *     regardless. So magic bytes and a size floor CANNOT tell a real report
   *     from an empty one; only the fixture's own strings can, and jsPDF writes
   *     these text streams uncompressed (no FlateDecode), so they are findable
   *     in the raw bytes.
   */
  test("the PDF is produced by a library that is only loaded when asked for", async ({ page }) => {
    test.setTimeout(120_000);

    const moduleRequests: string[] = [];
    page.on("request", (request) => moduleRequests.push(request.url()));

    await gotoSoc(page);
    const panel = await openReports(page);

    expect(
      moduleRequests.filter((url) => /jspdf/i.test(url)),
      "jsPDF was fetched before anyone asked for a PDF — the dynamic import regressed"
    ).toEqual([]);

    await expect(runButton(panel), "the studio must be offering a PDF").toHaveText(/Export PDF/);
    const { filename, body } = await downloadReport(page, panel);

    expect(filename, "a PDF export must be offered as a .pdf").toMatch(/\.pdf$/);
    expect(body.subarray(0, 5).toString("latin1"), "the downloaded file is not a PDF").toBe("%PDF-");
    expect(body.toString("latin1"), "the PDF has no trailer, so it was never finished").toContain("%%EOF");

    // The assertions that an empty report fails: content, not shape. Both of
    // these are absent from the same document built over an empty backend.
    const pdf = body.toString("latin1");
    expect(pdf, "the PDF's alert table does not name the alert in the window").toContain(mockData.alerts[0].title);
    expect(pdf, "the PDF's IOC table does not name the file the window observed").toContain(
      mockData.events[0].path
    );

    await expect
      .poll(
        () => moduleRequests.filter((url) => /jspdf/i.test(url)).length,
        { message: "pressing Export PDF never fetched jsPDF" }
      )
      .toBeGreaterThan(0);
  });

  /**
   * WHAT BUG THIS PINS: the two copy buttons are the fastest path from console
   * to ticket, and their failure mode is silent — the write is wrapped in a
   * try/catch that swallows everything, so a copy that produced an empty string
   * (or the OTHER button's text) looks identical to one that worked. Only the
   * clipboard's actual contents can tell them apart.
   *
   * The visible "Copied" flash is deliberately NOT the assertion: it lives for
   * 1500ms on a shared timer, so racing it is a flake and not a claim. The
   * clipboard is polled instead, because the write is asynchronous.
   *
   * Needs a context with clipboard permission, hence browser.newContext rather
   * than the page fixture.
   */
  test("copy IOCs and copy summary put usable text on the clipboard", async ({ browser }) => {
    const context = await browser.newContext({
      viewport: { width: 1600, height: 1000 },
      permissions: ["clipboard-read", "clipboard-write"]
    });
    const page = await context.newPage();
    const readClipboard = () => page.evaluate(() => navigator.clipboard.readText());
    try {
      await gotoSoc(page);
      await page.bringToFront();
      const panel = await openReports(page);

      expect(await readClipboard(), "precondition: the clipboard starts empty").toBe("");

      await panel.getByRole("button", { name: /Copy IOCs/ }).click();
      await expect
        .poll(readClipboard, { message: "Copy IOCs never put the observed file on the clipboard" })
        .toContain(mockData.events[0].path);
      // The whole indicator set, not just the one line — an IOC list that
      // drops the binaries is a list nobody can pivot on.
      expect(
        (await readClipboard()).split("\n").filter(Boolean),
        "the copied IOCs are not the file and binary the window observed"
      ).toEqual([mockData.events[0].path, mockData.events[0].process]);

      await panel.getByRole("button", { name: /Copy summary/ }).click();
      await expect
        .poll(readClipboard, { message: "Copy summary never replaced the clipboard with a Markdown summary" })
        .toContain("## eBPF SOC summary");

      const summary = await readClipboard();
      expect(summary, "the summary copy must state the alert count it is summarising").toMatch(
        /- Alerts: 1 \(1 critical/
      );
      expect(summary, "the summary copy must name the scope it covers").toContain("filtered (on screen)");
    } finally {
      await context.close();
    }
  });
});
