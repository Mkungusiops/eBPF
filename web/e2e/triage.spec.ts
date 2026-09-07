import type { Locator, Page } from "@playwright/test";

import { SOC_PANEL_INVENTORY } from "../src/features/soc/panelInventory";
import { installMockApi } from "./support/mock-api";
import { expect, test } from "./support/test";

/**
 * The alert triage queue — the surface an analyst actually works in.
 *
 * WHAT BUG THIS PINS: everything that decides WHICH alerts an analyst sees, and
 * in WHAT ORDER, plus the three pieces of triage state (ack, pin, note) that
 * live only in this browser. Each of those is a claim about the estate:
 *
 *   · a query that filters wrongly hides work and nobody is told;
 *   · a sort control that does not sort makes "worst first" a lie;
 *   · a ×2 group whose Ack lands on one member reports work as done that is not;
 *   · ack/pin/note are localStorage-backed, so a shift handover that does not
 *     survive a reload silently loses the whole shift's triage;
 *   · and an empty queue means two OPPOSITE things — "your filters excluded
 *     everything" and "nothing has happened on this estate" — which the panel
 *     must not render with the same words. That confusion is this codebase's
 *     most expensive recurring defect class (see honesty.spec.ts).
 *
 * WHY IT IS HERE AND NOT IN UNIT TESTS: the derivations (matchesQuery,
 * compareAlerts, groupAlertList, classifyAlert) are pure and unit-tested. What
 * jsdom cannot observe is whether the route WIRES them to the controls an
 * operator presses — that the "score" button reaches sortField, that the chip
 * toggling `hideBaseline` is the one labelled "Hide baseline", that bulk ack
 * walks the selection rather than the visible row, and above all that state
 * written to localStorage is READ BACK on a real navigation. Every bug in that
 * list is a wiring bug in a component tree with real persistence, not a bug in
 * a function.
 *
 * FIXTURE: this file supplies its own /api/alerts (TRIAGE_ALERTS) — the default
 * mock has a single alert, and one row can neither be sorted, grouped, filtered
 * nor bulk-acked observably. Timestamps are the mock's own 2026-06-25 window,
 * so every test widens `soc.prefDefaultRange` to a year to keep them in range.
 * The SSE frames are suppressed (`streamFrames: []`) because the default frame
 * set pushes an extra untitled alert into the buffer, which would land in the
 * middle of these orderings.
 */

/** The queue's own panel id, from the inventory the route renders from. */
const QUEUE = '[data-panel="alert-triage-queue"]';

const CRED = "Credential file read";
const SHELL = "Reverse shell established";
const BEACON = "Outbound beacon to rare peer";
const EDITOR = "Config file touched by editor";
const TIMER = "systemd timer refreshed units";

/**
 * Six alerts, in the wire shape both servers emit (snake_case, `mitre_id`).
 *
 * Chosen so each control has an observable effect and no two controls produce
 * the same answer: the three sort fields give three DIFFERENT orders, two of
 * the six are identical on (severity, policy, process, title) so grouping has
 * something to collapse, and exactly one classifies as `baseline` so the
 * "Hide baseline" chip can be seen to be the thing hiding it.
 */
const TRIAGE_ALERTS = [
  {
    id: "alert-cred-1",
    timestamp: "2026-06-25T09:00:00Z",
    severity: "critical",
    title: CRED,
    description: "cat opened /etc/shadow",
    policy_name: "override-credential-read",
    process: "cat",
    binary: "cat",
    exec_id: "exec-cred-1",
    pid: 4242,
    score: 44,
    mitre_id: "T1003",
    tactic: "Credential Access"
  },
  {
    id: "alert-cred-2",
    timestamp: "2026-06-25T08:55:00Z",
    severity: "critical",
    title: CRED,
    description: "cat opened /etc/shadow",
    policy_name: "override-credential-read",
    process: "cat",
    binary: "cat",
    exec_id: "exec-cred-2",
    pid: 4243,
    score: 44,
    mitre_id: "T1003",
    tactic: "Credential Access"
  },
  {
    id: "alert-shell-1",
    timestamp: "2026-06-25T08:30:00Z",
    severity: "high",
    title: SHELL,
    description: "bash connected back to 203.0.113.9",
    policy_name: "reverse-shell-detect",
    process: "bash",
    binary: "bash",
    exec_id: "exec-shell-1",
    pid: 5150,
    score: 91,
    mitre_id: "T1059"
  },
  {
    id: "alert-beacon-1",
    timestamp: "2026-06-25T09:45:00Z",
    severity: "medium",
    title: BEACON,
    description: "curl reached 198.51.100.7 on a regular interval",
    policy_name: "egress-watch",
    process: "curl",
    binary: "curl",
    exec_id: "exec-beacon-1",
    pid: 6060,
    score: 26
  },
  {
    id: "alert-editor-1",
    timestamp: "2026-06-25T09:55:00Z",
    severity: "info",
    title: EDITOR,
    description: "nano wrote /etc/hosts.allow",
    policy_name: "file-write-watch",
    process: "nano",
    binary: "nano",
    exec_id: "exec-editor-1",
    pid: 7070,
    score: 5
  },
  {
    id: "alert-timer-1",
    timestamp: "2026-06-25T06:00:00Z",
    severity: "low",
    title: TIMER,
    description: "routine maintenance timer fired",
    policy_name: "housekeeping",
    process: "systemd",
    binary: "systemd",
    exec_id: "exec-timer-1",
    pid: 1,
    score: 8
  }
] as const;

/** What the queue shows by default: grouped, newest first, baseline hidden. */
const BY_TIME = [EDITOR, BEACON, CRED, SHELL];
const BY_SEVERITY = [CRED, SHELL, BEACON, EDITOR];
const BY_SCORE = [SHELL, CRED, BEACON, EDITOR];

async function loadQueue(page: Page): Promise<Locator> {
  await installMockApi(page, { streamFrames: [], routes: { "/api/alerts": TRIAGE_ALERTS } });
  // The fixtures are timestamped in the mock's June window; the default 30m
  // range would exclude every one of them and the queue would be empty for a
  // reason that has nothing to do with what is under test.
  await page.addInitScript(() => window.localStorage.setItem("soc.prefDefaultRange", "525600"));
  await page.goto("/");
  const queue = page.locator(QUEUE);
  await expect(queue, "the alert triage queue never rendered").toBeVisible();
  return queue;
}

function rows(queue: Locator): Locator {
  return queue.locator(".soc-alert-row");
}

function rowFor(queue: Locator, title: string): Locator {
  return rows(queue).filter({ hasText: title });
}

/** The titles currently on screen, top to bottom. */
function titles(queue: Locator): Promise<string[]> {
  return queue.locator(".soc-alert-row .soc-alert-head > strong").allInnerTexts();
}

/** Poll the visible titles — every filter/sort here settles through a render. */
function expectTitles(queue: Locator, message: string) {
  return expect.poll(() => titles(queue), { message });
}

/**
 * The "N shown" pill in the panel header. Scoped to `.soc-pill` because
 * `.soc-panel-actions` also holds the three toggle chips, and the coverage pill
 * sits beside it.
 */
function shownPill(queue: Locator): Locator {
  return queue.locator(".soc-panel-actions .soc-pill").filter({ hasText: "shown" });
}

function searchBox(page: Page): Locator {
  return page.getByPlaceholder(/Search alerts/i);
}

/** The ack pill a row is currently showing ("New" / "Ack'd" / "Resolved"). */
function ackPill(queue: Locator, title: string): Locator {
  return rowFor(queue, title).locator(".soc-ack");
}

test.describe("alert triage queue", () => {
  test.use({ viewport: { width: 1600, height: 1000 } });

  /**
   * The search box is the analyst's primary filter and it is a small DSL, not a
   * substring match: `severity:`, `process:` and `score:>` mean different things
   * from the same words typed bare. A `severity:high` that quietly degraded to
   * "contains the word high" would match a description and look like it worked.
   */
  test("the search DSL filters the queue by field, and says so when nothing matches", async ({ page }) => {
    const queue = await loadQueue(page);
    await expectTitles(queue, "the queue must start populated or nothing below is under test").toEqual(BY_TIME);
    await expect(
      shownPill(queue),
      "the 'shown' pill must count what is on screen before any filter is typed"
    ).toHaveText(`${BY_TIME.length} shown`);

    const search = searchBox(page);

    await search.fill("severity:high");
    await expectTitles(queue, "severity:high must select the one high alert, by FIELD not by text").toEqual([SHELL]);

    await search.fill("process:cat");
    await expectTitles(queue, "process:cat must select the two cat alerts (one group)").toEqual([CRED]);

    await search.fill("score:>50");
    await expectTitles(queue, "score:>50 must select only the score-91 alert (44, 26, 5 are below)").toEqual([SHELL]);

    await search.fill("curl");
    await expectTitles(queue, "a bare term must match anywhere in the alert").toEqual([BEACON]);

    // The panel header states the size of what it is showing; it has to agree
    // with the list underneath it, exactly — "1 shown" as a substring is also
    // satisfied by "11 shown" and by "21 shown".
    await expect(shownPill(queue), "the 'shown' pill must count the FILTERED rows, not the fetched alerts").toHaveText(
      "1 shown"
    );

    await search.fill("no-such-alert-anywhere");
    await expectTitles(queue, "a query matching nothing must empty the queue").toEqual([]);
    // The distinction that matters: this queue is empty BECAUSE OF THE FILTER,
    // and the analyst has alerts one backspace away.
    await expect(
      queue.locator(".soc-empty"),
      "an empty-after-filtering queue must name the filter as the reason, not report an empty estate"
    ).toContainText(/match current filters/i);
  });

  /**
   * Classification is the queue's opinion, not the server's: classifyAlert reads
   * an alert's text and score and calls it attack / threat / baseline / unknown,
   * and "Hide baseline" — ON by default — drops a whole class of alert out of
   * the analyst's view. A chip that hides alerts by default has to be visibly
   * the thing doing it, or the queue is under-reporting for reasons nobody
   * can see.
   */
  test("Hide baseline is what suppresses baseline-classified alerts, and unhiding labels them", async ({ page }) => {
    const queue = await loadQueue(page);
    const chip = queue.getByRole("switch", { name: "Hide baseline" });

    await expect(chip, "Hide baseline must default ON — the rest of this test assumes it").toHaveAttribute(
      "aria-checked",
      "true"
    );
    await expectTitles(queue, `"${TIMER}" classifies as baseline and must be hidden while the chip is on`).toEqual(
      BY_TIME
    );

    await chip.click();

    await expect(chip, "clicking the chip must flip its state").toHaveAttribute("aria-checked", "false");
    await expectTitles(queue, "unhiding baseline must reveal the baseline alert and nothing else").toEqual([
      ...BY_TIME,
      TIMER
    ]);
    // And the row says which class it is in, so an analyst can see why it was
    // being withheld rather than guessing.
    await expect(
      rowFor(queue, TIMER).locator(".soc-entity-chip.cls-baseline"),
      "a revealed baseline alert must be labelled baseline"
    ).toHaveText("baseline");
  });

  /**
   * Three sort fields, three orders. The fixtures are built so the orders are
   * all different — a sort control wired to the wrong field, or to nothing,
   * would otherwise still produce a plausible-looking list.
   */
  test("each sort field reorders the queue", async ({ page }) => {
    const queue = await loadQueue(page);
    const sort = queue.locator(".soc-sort-row");
    await expect(rows(queue), "no rows, so ordering is not under test").toHaveCount(BY_TIME.length);

    await expectTitles(queue, "the queue must open on newest-first").toEqual(BY_TIME);

    await sort.getByRole("button", { name: "severity", exact: true }).click();
    await expectTitles(queue, "sort by severity must be critical → high → medium → info").toEqual(BY_SEVERITY);

    await sort.getByRole("button", { name: "score", exact: true }).click();
    await expectTitles(queue, "sort by score must be 91 → 44 → 26 → 5, which is NOT the severity order").toEqual(
      BY_SCORE
    );

    await sort.getByRole("button", { name: "time", exact: true }).click();
    await expectTitles(queue, "sort by time must return to newest-first").toEqual(BY_TIME);
  });

  /**
   * Grouping collapses repeats of the same (severity, policy, process, title)
   * into one row with a count. The count is a claim about how many alerts that
   * row stands for, so it must appear when there are repeats and the rows must
   * come back apart when grouping is off — an analyst who cannot ungroup cannot
   * see the individual timestamps.
   */
  test("grouping collapses repeats behind a count, and ungrouping restores every row", async ({ page }) => {
    const queue = await loadQueue(page);
    const group = queue.getByRole("switch", { name: "Group" });

    await expect(group, "Group must default ON — the rest of this test assumes it").toHaveAttribute(
      "aria-checked",
      "true"
    );
    await expect(
      rowFor(queue, CRED).locator(".soc-group-count"),
      "two identical credential alerts must collapse into one row marked ×2"
    ).toHaveText("×2");
    // The header count is a claim about the same list. Grouped, four rows stand
    // for five in-window non-baseline alerts, so this pins which of the two the
    // number means: it counts ROWS.
    await expect(shownPill(queue), "the 'shown' pill must count the grouped rows on screen").toHaveText(
      `${BY_TIME.length} shown`
    );

    await group.click();

    await expectTitles(queue, "ungrouping must show both credential alerts as separate rows").toEqual([
      EDITOR,
      BEACON,
      CRED,
      CRED,
      SHELL
    ]);
    await expect(
      queue.locator(".soc-group-count"),
      "no row stands for more than one alert once grouping is off, so no count may be shown"
    ).toHaveCount(0);
    await expect(
      shownPill(queue),
      "ungrouping splits the ×2 row in two, so the 'shown' pill must follow the rows up to five"
    ).toHaveText("5 shown");

    await group.click();
    await expectTitles(queue, "re-grouping must collapse them again").toEqual(BY_TIME);
  });

  /**
   * Bulk ack/resolve is how a shift clears a burst. It walks the SELECTION, so
   * the bug it has to be protected from is applying to the wrong rows — the
   * visible one, the first one, or (having cleared the selection first) none.
   *
   * Uses only single-member rows: what a bulk action does to a GROUPED row is a
   * separate claim, pinned below.
   */
  test("bulk acknowledge and resolve apply to the selected rows, and the ack chip agrees", async ({ page }) => {
    const queue = await loadQueue(page);
    await expect(ackPill(queue, BEACON), "rows must start unacked").toHaveText("New");

    await queue.getByRole("checkbox", { name: `Select ${BEACON}` }).check();
    await queue.getByRole("checkbox", { name: `Select ${EDITOR}` }).check();

    const bulkBar = queue.locator(".soc-bulk-bar");
    await expect(bulkBar, "selecting two rows must open the bulk bar and count them").toContainText("2 selected");

    await bulkBar.getByRole("button", { name: "Acknowledge" }).click();

    await expect(ackPill(queue, BEACON), "a selected row must be acknowledged").toHaveText("Ack'd");
    await expect(ackPill(queue, EDITOR), "a selected row must be acknowledged").toHaveText("Ack'd");
    await expect(ackPill(queue, SHELL), "an UNSELECTED row must be left alone by a bulk action").toHaveText("New");
    await expect(ackPill(queue, CRED), "an UNSELECTED row must be left alone by a bulk action").toHaveText("New");
    await expect(bulkBar, "the selection must be released once the bulk action landed").toBeHidden();

    await queue.getByRole("checkbox", { name: `Select ${SHELL}` }).check();
    await bulkBar.getByRole("button", { name: "Resolve" }).click();

    await expect(ackPill(queue, SHELL), "bulk resolve must reach the resolved state, not merely acked").toHaveText(
      "Resolved"
    );
    await expect(
      rowFor(queue, SHELL).getByRole("button", { name: "Reopen" }),
      "a resolved row must offer the way back — triage state an analyst cannot undo is a trap"
    ).toBeVisible();

    // The states are not decoration: "Unacked only" is driven by them, and it
    // is what an analyst uses to see the work that is left.
    await queue.getByRole("switch", { name: "Unacked only" }).click();
    await expectTitles(queue, "only the untouched alert may remain once acked and resolved rows are filtered out").toEqual(
      [CRED]
    );
  });

  /**
   * Clear must release the selection WITHOUT triaging anything. It sits between
   * Acknowledge and Resolve in the same bar, so a mis-wire there marks a whole
   * selection as handled and the alerts are gone from the unacked view with
   * nobody having looked at them.
   */
  test("clearing the selection releases the rows without acknowledging them", async ({ page }) => {
    const queue = await loadQueue(page);

    const beaconBox = queue.getByRole("checkbox", { name: `Select ${BEACON}` });
    const editorBox = queue.getByRole("checkbox", { name: `Select ${EDITOR}` });
    await beaconBox.check();
    await editorBox.check();

    const bulkBar = queue.locator(".soc-bulk-bar");
    await expect(bulkBar, "nothing selected, so Clear is not under test").toContainText("2 selected");

    await bulkBar.getByRole("button", { name: "Clear" }).click();

    await expect(bulkBar, "Clear must close the bulk bar").toBeHidden();
    await expect(beaconBox, "Clear must untick the row").not.toBeChecked();
    await expect(editorBox, "Clear must untick the row").not.toBeChecked();
    await expect(ackPill(queue, BEACON), "Clear must NOT acknowledge anything").toHaveText("New");
    await expect(ackPill(queue, EDITOR), "Clear must NOT acknowledge anything").toHaveText("New");
  });

  /**
   * A pin is an analyst saying "keep this in front of me". It has to beat the
   * sort — a pin that only wins under the current sort field is worthless the
   * moment the analyst re-sorts, which is exactly when they need it.
   */
  test("a pinned alert is held at the top whatever the queue is sorted by", async ({ page }) => {
    const queue = await loadQueue(page);
    await expectTitles(queue, `"${SHELL}" must start at the BOTTOM or the pin proves nothing`).toEqual(BY_TIME);

    await rowFor(queue, SHELL).getByRole("button", { name: "Pin" }).click();

    await expect(
      rowFor(queue, SHELL).getByRole("button", { name: "Pinned" }),
      "the pin control must report the state it just entered"
    ).toBeVisible();
    await expectTitles(queue, "a pinned alert must be lifted to the top under the time sort").toEqual([
      SHELL,
      EDITOR,
      BEACON,
      CRED
    ]);

    // Severity order would put the critical first; the pin has to outrank it.
    await queue.locator(".soc-sort-row").getByRole("button", { name: "severity", exact: true }).click();
    await expectTitles(queue, "a pin must outrank the sort field, not merely tie-break within it").toEqual([
      SHELL,
      CRED,
      BEACON,
      EDITOR
    ]);

    await rowFor(queue, SHELL).getByRole("button", { name: "Pinned" }).click();
    await expectTitles(queue, "unpinning must return the alert to its sorted position").toEqual(BY_SEVERITY);
  });

  /**
   * WHAT BUG THIS PINS: ack, pin and note are held in localStorage and nowhere
   * else — no server knows about them. A write that never lands, or a read that
   * runs before hydration, loses an entire shift's triage on the next refresh
   * and the console gives no sign it happened: the queue simply comes back
   * looking untouched. The assertion is therefore made AFTER a real reload,
   * through the rendered rows, not against the store.
   */
  test("ack, pin and note survive a reload", async ({ page }) => {
    const queue = await loadQueue(page);
    const note = "paged the host owner, awaiting confirmation";

    await rowFor(queue, BEACON).getByRole("button", { name: "Ack", exact: true }).click();
    await rowFor(queue, SHELL).getByRole("button", { name: "Pin" }).click();

    await rowFor(queue, EDITOR).locator(".soc-alert-main").click();
    const drill = page.locator('[data-panel="drill-down-slide-over"]');
    // NOT toBeVisible(): SlideOver renders its <aside> unconditionally and
    // soc.css hides the closed panel with transform: translateX(102%), which
    // Playwright still counts as visible. `is-open` is the only class that
    // tracks the open flag, so it is the only precondition that can fail.
    await expect(drill, "the drill-down never opened, so the note cannot be written").toHaveClass(/is-open/);
    await drill.getByLabel("Investigator notes").fill(note);
    await expect(
      drill.getByLabel("Investigator notes"),
      "the note did not land even before reloading"
    ).toHaveValue(note);
    await drill.locator(".soc-close-button").click();

    // Precondition: all three landed before the reload.
    await expect(ackPill(queue, BEACON), "the ack did not land even before reloading").toHaveText("Ack'd");
    await expectTitles(queue, "the pin did not land even before reloading").toEqual([SHELL, EDITOR, BEACON, CRED]);

    await page.reload();
    const reloaded = page.locator(QUEUE);
    await expect(reloaded, "the queue did not come back after the reload").toBeVisible();

    await expect(
      ackPill(reloaded, BEACON),
      "the acknowledgement was lost on reload — the shift's triage is gone with no notice"
    ).toHaveText("Ack'd");
    await expectTitles(reloaded, "the pin was lost on reload").toEqual([SHELL, EDITOR, BEACON, CRED]);

    await rowFor(reloaded, EDITOR).locator(".soc-alert-main").click();
    const reloadedDrill = page.locator('[data-panel="drill-down-slide-over"]');
    await expect(
      reloadedDrill,
      "the drill-down did not reopen after the reload, so the note cannot be read back"
    ).toHaveClass(/is-open/);
    await expect(
      reloadedDrill.getByLabel("Investigator notes"),
      "the investigator note was lost on reload"
    ).toHaveValue(note);
  });

  /**
   * KNOWN DEFECT — acknowledging a grouped row acks only its representative.
   *
   * CAUSE: filteredAlerts filters PER ALERT and groups afterwards
   * (useSocWindowModel), but the row it renders carries the id of members[0]
   * only. onAck/applyBulkAck therefore write one entry into soc.alertStates for
   * a row that says it stands for ×2 alerts. The row then shows "Ack'd" while
   * its unacked sibling is still outstanding — and it reappears the moment the
   * analyst filters to "Unacked only", which is the view they use to decide
   * they are done. The console both claims the work is handled and lists it as
   * outstanding, two inches apart.
   *
   * FIX: hand AlertRow the group's member ids and have onAck/onPin apply to all
   * of them (AlertGroup already carries `members`), or stop drawing a count on
   * a row whose actions only reach one member.
   */
  test("acknowledging a grouped row acknowledges everything it stands for", async ({ page }) => {
    const queue = await loadQueue(page);
    const credRow = rowFor(queue, CRED);
    await expect(
      credRow.locator(".soc-group-count"),
      "the credential row must be a ×2 group or this test is about nothing"
    ).toHaveText("×2");

    await credRow.getByRole("button", { name: "Ack", exact: true }).click();
    await expect(ackPill(queue, CRED), "the row must report itself acknowledged").toHaveText("Ack'd");

    await queue.getByRole("switch", { name: "Unacked only" }).click();

    // The other three alerts are genuinely untouched and must stay. The
    // credential row is the claim: it was acknowledged, so no part of it may
    // still be listed as outstanding work.
    await expectTitles(
      queue,
      "an acknowledged ×2 row must not reappear in the unacked view — it says the work is both done and outstanding"
    ).toEqual([EDITOR, BEACON, SHELL]);
  });

  /**
   * KNOWN DEFECT — the queue advertises saved views it does not have.
   *
   * CAUSE: the panel inventory (rendered by this console: PanelFrame prints the
   * inventory's description, the sidebar counts its entries, and the account
   * surface prints "N local preference keys stored in this browser" from
   * SOC_STORAGE_KEYS) claims `soc.savedViews` for the triage queue, and
   * features/common/panelData lists "saved views" among the queue's
   * capabilities. Nothing in src ever reads or writes that key: there is no
   * control to save the current query/sort/chip set and no way to restore one.
   * An operator told the panel keeps views goes looking for the control, and
   * the browser-storage inventory over-counts what this console actually keeps.
   *
   * FIX: implement saved views over `soc.savedViews` (query + sortField +
   * grouped + hideBaseline + filterUnack is the whole state), or drop the key
   * from panelInventory and the claim from panelData.
   */
  test("every storage key the queue advertises is one the queue actually writes", async ({ page }) => {
    const advertised = SOC_PANEL_INVENTORY.find((panel) => panel.id === "alert-triage-queue")?.storage ?? [];
    expect(advertised, "the queue advertises no storage at all, so nothing is under test").not.toEqual([]);

    const queue = await loadQueue(page);

    // Use the panel the way its inventory says it can be used: triage a row,
    // pin one, and set up a view worth keeping.
    await rowFor(queue, BEACON).getByRole("button", { name: "Ack", exact: true }).click();
    await rowFor(queue, SHELL).getByRole("button", { name: "Pin" }).click();
    await searchBox(page).fill("severity:critical");
    await queue.locator(".soc-sort-row").getByRole("button", { name: "score", exact: true }).click();
    await expectTitles(queue, "the filter/sort set that a saved view would capture never took effect").toEqual([CRED]);

    const written = await page.evaluate(() => Object.keys(window.localStorage));
    const missing = advertised.filter((key) => !written.includes(key));

    expect(
      missing,
      `the queue advertises storage it never writes; keys present were ${JSON.stringify(written.filter((key) => key.startsWith("soc.")).sort())}`
    ).toEqual([]);
  });

  /**
   * KNOWN DEFECT — an empty estate and an over-filtered queue read identically.
   *
   * CAUSE: AlertQueue renders one EmptyState, hard-coded to "No alerts match
   * current filters", whenever `alerts.length` is 0. With no query, no chip
   * engaged and a server that returned zero alerts, the panel tells the analyst
   * their filters excluded everything — so they go loosening filters that are
   * not set, and never learn the feed is dry. The inverse reading is worse: an
   * analyst who has learned the queue says "no alerts match current filters"
   * when the estate is quiet will read the same words as "quiet" on the day a
   * stray query is hiding real alerts.
   *
   * The rest of this console already makes exactly this distinction — see
   * rows.tsx `emptyBecause`, which the IOC and network panels use to separate
   * "nothing in this window" from "nothing recorded on this estate". The queue
   * is the one panel that does not.
   *
   * FIX: choose the empty copy from the state — filters engaged (query, chips,
   * or rangeAlerts non-empty) → "no alerts match current filters"; otherwise
   * "no alerts recorded on this estate", with the beyond-window count the model
   * already computes when alerts exist outside the range.
   */
  test("an empty estate and an over-filtered queue are different claims", async ({ page }) => {
    let feedIsEmpty = false;
    await installMockApi(page, {
      streamFrames: [],
      routes: { "/api/alerts": () => (feedIsEmpty ? [] : TRIAGE_ALERTS) }
    });
    await page.addInitScript(() => window.localStorage.setItem("soc.prefDefaultRange", "525600"));
    await page.goto("/");

    const queue = page.locator(QUEUE);
    await expectTitles(queue, "alerts must arrive first, or the filtered case cannot be produced").toEqual(BY_TIME);

    // Case A: alerts exist, the analyst's query excludes them all.
    await searchBox(page).fill("no-such-alert-anywhere");
    await expectTitles(queue, "the query must exclude everything").toEqual([]);
    const filteredOut = (await queue.locator(".soc-empty").innerText()).replace(/\s+/g, " ").trim();

    // Case B: no filters at all (the query is component state, so the reload
    // clears it), and the server has nothing to give.
    feedIsEmpty = true;
    await page.reload();
    await expect(page.locator(QUEUE), "the queue did not come back after the reload for case B").toBeVisible();
    await expect(searchBox(page), "the reload must have cleared the query for case B").toHaveValue("");
    await expectTitles(page.locator(QUEUE), "the feed must be empty for case B").toEqual([]);
    const nothingArrived = (await page.locator(QUEUE).locator(".soc-empty").innerText())
      .replace(/\s+/g, " ")
      .trim();

    expect(
      nothingArrived,
      `an estate with no alerts must not blame the analyst's filters; it said "${nothingArrived}"`
    ).not.toMatch(/match current filters/i);
    expect(
      nothingArrived,
      `"nothing arrived" and "your filters excluded everything" are opposite claims and both read "${filteredOut}"`
    ).not.toEqual(filteredOut);
  });
});
