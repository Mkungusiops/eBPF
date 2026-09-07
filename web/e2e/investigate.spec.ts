import type { Locator, Page } from "@playwright/test";

import { installMockApi, type MockRouteResponse } from "./support/mock-api";
import { expect, socNavItem, test } from "./support/test";

/**
 * The three investigation surfaces the suite otherwise only opens: the Time
 * Machine, the Watchlist, and the KPI drill.
 *
 * WHAT BUG THIS PINS. Each of these can be wrong in a way that opening the
 * panel does not reveal, because each one renders a plausible screen either
 * way:
 *
 *   · TIME MACHINE replays the buffer at an instant. If the playhead moves but
 *     the state under it does not — or the clock keeps reading "now" while the
 *     numbers are historical — an analyst reads a SNAPSHOT AS LIVE and calls
 *     an incident over that ended an hour before the window closed. The panel
 *     is only useful if the two are distinguishable on screen.
 *   · WATCHLIST used to be a notepad: terms went into localStorage and were
 *     never matched against anything. A stored-but-never-matched watchlist is
 *     indistinguishable from a working one until the thing you are watching
 *     for happens and nothing lights up. So the claim is not "the term is
 *     listed", it is "the term is listed WITH the hits it drew from the loaded
 *     alerts and events" — and the term that matches nothing must say so.
 *   · KPI DRILL is opened by clicking a headline tile, and the tile's number
 *     comes from the SERVER aggregate (/api/alert-stats) while the drill lists
 *     the BROWSER buffer. Two sources, one screen. The default fixture here
 *     makes the two AGREE deliberately (see ALERT_STATS), so what those cases
 *     prove is narrower than "the console cannot contradict itself": they prove
 *     the drill is scoped to the tile that opened it — right severity, right
 *     count, no rows from another bucket. The case where the two sources
 *     genuinely disagree (server counts more than the buffer holds) is its own
 *     test below, and what it pins is the DISCLOSURE, not agreement.
 *
 * WHY IT IS HERE AND NOT IN UNIT TESTS. All three are interaction over state
 * that jsdom cannot produce: a native <input type="range"> whose value comes
 * from where the pointer landed on the track (the Time Machine has no other
 * way to move the playhead), a localStorage round-trip that must survive a
 * real page RELOAD rather than a re-render, and a tile in one component tree
 * opening a modal in another with the number carried between them. The
 * derivations themselves are unit-testable; that the operator's click reaches
 * them, and that the two independently-sourced numbers meet on the screen, is
 * not.
 *
 * FIXTURE. These specs do not use the default single-alert fixture — one alert
 * gives the Time Machine a zero-width window and the drill nothing to be
 * inconsistent about. They install five alerts spread over 2026-06-25 08:00 →
 * 09:00 (critical, high, medium, high, critical) with five matching events,
 * and an /api/alert-stats override that agrees with them, so that "the tile
 * and the drill disagree" can only ever be the console's fault and not the
 * mock's. The stream is SILENT deliberately: the default frames inject a
 * further critical alert with no timestamp, which would both move the Time
 * Machine's live edge mid-scrub and put the severity counts one ahead of the
 * server aggregate.
 *
 * The default range is widened to a year because the fixtures are timestamped
 * in the past; without it nothing is in the window and every assertion here
 * passes or fails on an empty buffer.
 *
 * Three cases replace part of that fixture through `openConsole`'s overrides,
 * because the shared one cannot express what they are about: SCORED_CRITICALS
 * (a bucket big enough for "top 10 by score" to mean something), OVERCOUNTED
 * _STATS (a server that counts more than the browser holds), and the events/sec
 * drill, which pins the browser's clock 30s after the newest fixture event so
 * "the last 60 seconds" is a real window rather than an empty one.
 */

const T = (hhmm: string) => `2026-06-25T${hhmm}:00Z`;

/** The five alerts everything below is measured against. */
const ALERTS = [
  {
    id: "alert-shadow",
    timestamp: T("08:00"),
    severity: "critical",
    title: "Credential file read",
    description: "cat read /etc/shadow",
    policy_name: "override-credential-read",
    process: "/usr/bin/cat",
    exec_id: "exec-cat-1",
    pid: 4242,
    score: 44,
    mitre_id: "T1003",
    tactic: "Credential Access"
  },
  {
    id: "alert-c2",
    timestamp: T("08:10"),
    severity: "high",
    title: "Outbound connection to known C2",
    description: "curl connected to 203.0.113.10",
    policy_name: "network-observe",
    process: "/usr/bin/curl",
    exec_id: "exec-curl-1",
    pid: 4310,
    score: 30
  },
  {
    id: "alert-listener",
    timestamp: T("08:20"),
    severity: "medium",
    title: "Listener opened on a high port",
    description: "nc bound port 4444",
    policy_name: "network-observe",
    process: "/usr/bin/nc",
    exec_id: "exec-nc-1",
    pid: 4380,
    score: 14
  },
  {
    id: "alert-sshkey",
    timestamp: T("08:50"),
    severity: "high",
    title: "SSH private key read",
    description: "scp read /root/.ssh/id_rsa",
    policy_name: "override-credential-read",
    process: "/usr/bin/scp",
    exec_id: "exec-scp-1",
    pid: 4400,
    score: 26
  },
  {
    id: "alert-exfil",
    timestamp: T("09:00"),
    severity: "critical",
    title: "Shadow copy staged for exfiltration",
    description: "python3 packaged /tmp/stage.tar",
    policy_name: "override-credential-read",
    process: "/usr/bin/python3",
    exec_id: "exec-py-1",
    pid: 4500,
    score: 51
  }
] as const;

/** One event per alert, sharing its exec_id, so the two views agree on the estate. */
const EVENTS = [
  {
    id: "event-shadow",
    timestamp: T("08:00"),
    event_type: "file_open",
    process: "/usr/bin/cat",
    exec_id: "exec-cat-1",
    pid: 4242,
    parent_pid: 4100,
    severity: "critical",
    policy_name: "override-credential-read",
    path: "/etc/shadow"
  },
  {
    id: "event-c2",
    timestamp: T("08:10"),
    event_type: "connect",
    process: "/usr/bin/curl",
    exec_id: "exec-curl-1",
    pid: 4310,
    dest_ip: "203.0.113.10",
    dest_port: 443,
    proto: "tcp"
  },
  {
    id: "event-listener",
    timestamp: T("08:20"),
    event_type: "listen",
    process: "/usr/bin/nc",
    exec_id: "exec-nc-1",
    pid: 4380,
    args: "nc -lvnp 4444"
  },
  {
    id: "event-sshkey",
    timestamp: T("08:50"),
    event_type: "file_open",
    process: "/usr/bin/scp",
    exec_id: "exec-scp-1",
    pid: 4400,
    path: "/root/.ssh/id_rsa"
  },
  {
    id: "event-exfil",
    timestamp: T("09:00"),
    event_type: "exec",
    process: "/usr/bin/python3",
    exec_id: "exec-py-1",
    pid: 4500,
    args: "python3 -c package(/tmp/stage.tar)"
  }
] as const;

/**
 * The server-side histogram, made to agree with ALERTS.
 *
 * The KPI tiles read this endpoint, NOT the alert buffer, so leaving the
 * default fixture in place would make "tile says 1, drill lists 2" a property
 * of the mock rather than of the console.
 */
const ALERT_STATS = {
  from: T("08:00"),
  to: T("09:00"),
  counts: { critical: 2, high: 2, medium: 1, low: 0, info: 0 },
  previous: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  total: 5,
  buckets: [
    { at: T("08:00"), counts: { critical: 1, high: 1, medium: 1, low: 0, info: 0 }, total: 3 },
    { at: T("09:00"), counts: { critical: 1, high: 1, medium: 0, low: 0, info: 0 }, total: 2 }
  ],
  truncated: false
};

/**
 * Load the console on the fixture above.
 *
 * `routes` replaces individual endpoints for the cases that need a different
 * estate; `fixedTime` pins the browser's clock (Date.now and new Date(), timers
 * left running — the console derives every rate from `useNow`, so a fixture
 * timestamped in the past is otherwise permanently "an hour ago" and every rate
 * on the screen is a rounded zero).
 */
async function openConsole(
  page: Page,
  overrides: { routes?: Record<string, MockRouteResponse>; fixedTime?: string } = {}
): Promise<void> {
  if (overrides.fixedTime) await page.clock.setFixedTime(new Date(overrides.fixedTime));
  await installMockApi(page, {
    stream: "silent",
    routes: {
      "/api/alerts": ALERTS,
      "/api/events": EVENTS,
      "/api/alert-stats": ALERT_STATS,
      ...overrides.routes
    }
  });
  await page.addInitScript(() => window.localStorage.setItem("soc.prefDefaultRange", "525600"));
  await page.goto("/");
  await expect(page.locator('[data-panel="kpi-row"]'), "the dashboard never rendered").toBeVisible();
}

/**
 * The panel's own clock format, evaluated in the page so the timezone is the
 * browser's.
 *
 * This mirrors TimeMachineBody's `fmtClock` (the same three toLocaleTimeString
 * options), which is a known coupling: a purely cosmetic change to the panel's
 * clock format fails three assertions here for the wrong reason. It is kept
 * because the alternative — asserting a literal "08:00:00" — would be wrong on
 * any machine that is not on UTC, and because the claim under test is that TWO
 * INSTANTS READ DIFFERENTLY, which needs the panel's own formatting to state at
 * all. The format itself is asserted nowhere; only the difference is.
 */
function clockFor(page: Page, iso: string): Promise<string> {
  return page.evaluate(
    (value) =>
      new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
    iso
  );
}

// ── Time Machine ───────────────────────────────────────────────────────────

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
type SeverityCounts = Record<(typeof SEVERITIES)[number], number>;

/**
 * The five severity cells, read as a record keyed by the label each cell
 * PRINTS — so a panel that renders the right five numbers against the wrong
 * five severities cannot pass. (The labels are uppercased by CSS, which
 * innerText honours, hence the fold.)
 */
async function severityCells(panel: Locator): Promise<SeverityCounts> {
  const cells = panel.locator(".soc-tm-sevs .soc-tm-sev");
  const counts = { critical: -1, high: -1, medium: -1, low: -1, info: -1 } as SeverityCounts;
  for (let index = 0; index < (await cells.count()); index += 1) {
    const cell = cells.nth(index);
    const label = (await cell.locator("span").innerText()).trim().toLowerCase();
    if ((SEVERITIES as readonly string[]).includes(label)) {
      counts[label as keyof SeverityCounts] = Number((await cell.locator("strong").innerText()).trim());
    }
  }
  return counts;
}

/**
 * Drag the playhead to a fraction of the track.
 *
 * A real click on the native range input, not `fill()`: the value React sees
 * has to come through the browser's own input handling, and clicking is also
 * the only gesture the panel offers for reaching a moment in the middle of the
 * window — the step is one millisecond, so keyboard arrows cannot get there.
 */
async function scrubTo(panel: Locator, fraction: number): Promise<void> {
  const slider = panel.locator("input.soc-tm-range");
  const box = await slider.boundingBox();
  expect(box, "the Time Machine scrubber has no box to click on").not.toBeNull();
  await slider.click({ position: { x: (box as { width: number }).width * fraction, y: 4 } });
}

test.describe("time machine", () => {
  test.use({ viewport: { width: 1600, height: 1000 } });

  /**
   * WHAT BUG THIS PINS: a snapshot rendered as the live state. The panel prints
   * one clock and one posture line; if the playhead moves and those do not
   * follow it, the operator is reading 08:00 numbers under a 09:00 heading (or
   * the reverse), and nothing on screen tells them which instant they have.
   */
  test("the live edge and a scrubbed snapshot are labelled as different moments", async ({ page }) => {
    await openConsole(page);
    await socNavItem(page, "Time Machine").click();

    const panel = page.locator('[data-panel="time-machine-modal"]');
    await expect(panel, "the Time Machine never opened").toBeVisible();

    const liveClock = await clockFor(page, T("09:00"));
    const earliestClock = await clockFor(page, T("08:00"));
    expect(liveClock, "the two ends of the window format identically, nothing to distinguish").not.toBe(
      earliestClock
    );

    // Opening lands on the live edge: the newest alert in the buffer.
    await expect(panel.locator(".soc-tm-clock"), "the panel did not open at the live edge").toHaveText(
      liveClock
    );
    await expect(
      panel.locator(".soc-tm-risk em"),
      "the live view must account for all five buffered alerts"
    ).toContainText("5 alerts");
    await expect(
      panel.locator(".soc-tm-cols .soc-tm-alert").first(),
      "the newest alert must be the one firing at the live edge"
    ).toContainText("Shadow copy staged for exfiltration");

    // THE OTHER DIRECTION, DECIDED. "Firing at this moment" is
    // `upTo.slice(-6).reverse()` — the six most recent alerts UP TO the
    // playhead, not the alerts firing AT it — so at the live edge the column
    // also lists the 08:00 alert, an hour stale under a heading that says "this
    // moment". That is tolerable only because every row prints its OWN clock;
    // strip those and the column asserts five simultaneous detections. So the
    // per-row stamp is the load-bearing part of the heading's honesty, and it
    // is pinned here rather than left to the heading's wording.
    await expect(
      panel.locator(".soc-tm-cols .soc-tm-alert").filter({ hasText: "Credential file read" }).locator("em"),
      "an hour-old alert is listed under \"Firing at this moment\" without its own timestamp to place it"
    ).toHaveText(earliestClock);

    // Scrub to the oldest instant in the window.
    await panel.locator("input.soc-tm-range").focus();
    await page.keyboard.press("Home");

    await expect(
      panel.locator(".soc-tm-clock"),
      "the clock still reads the live edge after scrubbing to the start — a snapshot presented as live"
    ).toHaveText(earliestClock);
    await expect(
      panel.locator(".soc-tm-risk em"),
      "the snapshot still counts alerts that had not happened yet at that instant"
    ).toContainText("1 alerts");
    await expect(
      panel.locator(".soc-tm-cols"),
      "an alert from 09:00 is shown as firing at 08:00"
    ).not.toContainText("Shadow copy staged for exfiltration");
    await expect(
      panel.locator(".soc-tm-cols"),
      "the alert that WAS firing at that instant is missing from the snapshot"
    ).toContainText("Credential file read");

    // And back: the live edge is reachable again, and reads as itself.
    await page.keyboard.press("End");
    await expect(
      panel.locator(".soc-tm-clock"),
      "the playhead could not be returned to the live edge"
    ).toHaveText(liveClock);
    await expect(panel.locator(".soc-tm-risk em"), "the live view lost alerts on the way back").toContainText(
      "5 alerts"
    );
  });

  /**
   * WHAT BUG THIS PINS: severity cells that are decoration. They are the only
   * per-severity readout in the panel, and the whole point of a replay is that
   * the mix AT AN INSTANT differs from the mix at the end — a set of cells
   * wired to the whole buffer (or to the wrong severity) looks identical on
   * screen and is worthless.
   *
   * The fixture is chosen so the three positions give three DIFFERENT mixes:
   * 08:00 critical only, mid-window one of each, live edge 2/2/1.
   */
  test("the severity cells count the alerts up to the playhead, not the whole buffer", async ({ page }) => {
    await openConsole(page);
    await socNavItem(page, "Time Machine").click();

    const panel = page.locator('[data-panel="time-machine-modal"]');
    await expect(panel, "the Time Machine never opened, so there are no cells to read").toBeVisible();
    await expect(
      panel.locator(".soc-tm-sevs .soc-tm-sev"),
      "no severity cells rendered, nothing under test"
    ).toHaveCount(5);

    await expect
      .poll(() => severityCells(panel), {
        message: "at the live edge the cells must be the fixture's own severity mix (2 critical, 2 high, 1 medium)"
      })
      .toEqual({ critical: 2, high: 2, medium: 1, low: 0, info: 0 });

    // Mid-window: 08:30. Three alerts have happened, one of each severity.
    await scrubTo(panel, 0.5);
    await expect(
      panel.locator(".soc-tm-clock"),
      "the mid-window click did not move the playhead off the live edge"
    ).not.toHaveText(await clockFor(page, T("09:00")));
    await expect
      .poll(() => severityCells(panel), {
        message: "mid-window only the 08:00/08:10/08:20 alerts had happened — one of each severity"
      })
      .toEqual({ critical: 1, high: 1, medium: 1, low: 0, info: 0 });

    await panel.locator("input.soc-tm-range").focus();
    await page.keyboard.press("Home");
    await expect
      .poll(() => severityCells(panel), {
        message: "at the earliest instant only the 08:00 critical had fired"
      })
      .toEqual({ critical: 1, high: 0, medium: 0, low: 0, info: 0 });
  });
});

// ── Watchlist ──────────────────────────────────────────────────────────────

/**
 * The Watchlist nav button once it carries a count badge.
 *
 * socNavItem() matches the accessible name EXACTLY, which is what every other
 * tool needs — but this one's name grows a badge ("Watchlist 2") the moment
 * something is watched, so an exact match stops resolving precisely when the
 * panel has done its job. Same disambiguation as socNavItem (a real sidebar
 * button, never the section header), prefix-matched instead.
 */
function watchlistNav(page: Page): Locator {
  return page.getByRole("button", { name: /^Watchlist/ }).and(page.locator("button.soc-sidebar-item"));
}

function watchRow(page: Page, term: string): Locator {
  return page.locator('[data-panel="watchlist-modal"] .soc-watch-item').filter({ hasText: term });
}

async function addWatch(page: Page, kind: "paths" | "ips" | "binaries", term: string): Promise<void> {
  const panel = page.locator('[data-panel="watchlist-modal"]');
  await panel.locator(".soc-watch-add select").selectOption(kind);
  await panel.locator(".soc-watch-add input").fill(term);
  await panel.getByRole("button", { name: "Watch", exact: true }).click();
  await expect(watchRow(page, term), `"${term}" was accepted but never listed`).toBeVisible();
}

/** What the browser actually persisted, which is this panel's only storage. */
function storedWatchlist(page: Page): Promise<{ paths: string[]; ips: string[]; binaries: string[] }> {
  return page.evaluate(() => {
    const raw = window.localStorage.getItem("soc.watchlist");
    return raw ? (JSON.parse(raw) as { paths: string[]; ips: string[]; binaries: string[] }) : { paths: [], ips: [], binaries: [] };
  });
}

test.describe("watchlist", () => {
  test.use({ viewport: { width: 1600, height: 1000 } });

  /**
   * WHAT BUG THIS PINS: the notepad watchlist. A term is only worth adding if
   * it is MATCHED — so this asserts the exact hit count each term drew, which
   * is what separates real matching from a list that renders "1 hit" for
   * anything, and it adds a term that matches nothing so a panel that reports
   * hits for everything fails too.
   *
   * The counts are load-bearing: /etc/shadow appears in one EVENT (its path)
   * and one ALERT (its description), so 2 hits proves both sides of the match
   * are wired. The C2 address is only reachable through the event's dest_ip
   * peer and the alert description; the binary only through the event's
   * process field.
   */
  test("a watched path, address and binary each report the hits they drew", async ({ page }) => {
    await openConsole(page);
    await socNavItem(page, "Watchlist").click();

    const panel = page.locator('[data-panel="watchlist-modal"]');
    await expect(panel, "the Watchlist never opened").toBeVisible();
    await expect(
      panel.locator(".soc-watch-item"),
      "the watchlist started with entries, so persistence from another spec is leaking in"
    ).toHaveCount(0);

    await addWatch(page, "paths", "/etc/shadow");
    await addWatch(page, "ips", "203.0.113.10");
    await addWatch(page, "binaries", "/usr/bin/nc");
    await addWatch(page, "paths", "/var/log/never-touched");

    await expect(
      panel.locator(".soc-watch-item"),
      "four terms were added and the panel does not list four"
    ).toHaveCount(4);

    await expect(
      watchRow(page, "/etc/shadow").locator(".soc-watch-count"),
      "/etc/shadow is in an event path AND an alert description — both must count"
    ).toHaveText("2 hits");
    await expect(
      watchRow(page, "203.0.113.10").locator(".soc-watch-count"),
      "the watched address did not match the connect event's peer and the alert that named it"
    ).toHaveText("2 hits");
    await expect(
      watchRow(page, "/usr/bin/nc").locator(".soc-watch-count"),
      "the watched binary did not match the listen event that ran it"
    ).toHaveText("1 hit");

    // The negative control. Note the wording: not "clean" — this panel only
    // ever saw the loaded window.
    await expect(
      watchRow(page, "/var/log/never-touched").locator(".soc-watch-count"),
      "a term nothing matched is reporting a hit count"
    ).toHaveCount(0);
    await expect(
      watchRow(page, "/var/log/never-touched").locator(".soc-watch-quiet"),
      "a term with no hits must say what it actually searched, not claim the estate is clean"
    ).toHaveText("no hits in loaded window");

    // The three that fired are surfaced as triggered; the fourth is not.
    // The separator is left out of the pattern on purpose: "·" is styling, the
    // 3 is the claim.
    const triggered = panel.locator(".soc-watch-triggered");
    await expect(triggered, "three watches matched and none were surfaced as triggered").toContainText(
      /Triggered now\D+3/
    );
    await expect(
      triggered,
      "a watch that matched nothing was surfaced as triggered"
    ).not.toContainText("/var/log/never-touched");

    expect(
      await storedWatchlist(page),
      "the terms were listed but not persisted under the kind they were added as"
    ).toEqual({
      paths: ["/etc/shadow", "/var/log/never-touched"],
      ips: ["203.0.113.10"],
      binaries: ["/usr/bin/nc"]
    });
  });

  /**
   * WHAT BUG THIS PINS: a remove that only takes the row off the screen. The
   * store is this panel's whole state, so a removal that leaves the term in
   * localStorage comes back on the next reload — and the operator has already
   * moved on believing it is gone.
   */
  test("removing a watch drops it from the panel and from the store", async ({ page }) => {
    await openConsole(page);
    await socNavItem(page, "Watchlist").click();
    await expect(
      page.locator('[data-panel="watchlist-modal"]'),
      "the Watchlist never opened, so there is nothing to remove from"
    ).toBeVisible();

    await addWatch(page, "paths", "/etc/shadow");
    await addWatch(page, "binaries", "/usr/bin/nc");
    expect(
      (await storedWatchlist(page)).paths,
      "nothing was stored, so removal has nothing to prove"
    ).toContain("/etc/shadow");

    await page
      .locator('[data-panel="watchlist-modal"]')
      .getByRole("button", { name: "Remove /etc/shadow" })
      .click();

    await expect(watchRow(page, "/etc/shadow"), "the removed watch is still listed").toHaveCount(0);
    await expect(
      watchRow(page, "/usr/bin/nc"),
      "removing one watch took the other with it"
    ).toBeVisible();
    await expect
      .poll(() => storedWatchlist(page), { message: "the removed term is still in localStorage and will return on reload" })
      .toEqual({ paths: [], ips: [], binaries: ["/usr/bin/nc"] });
  });

  /**
   * WHAT BUG THIS PINS: watches that do not survive the browser. They are
   * stored per-browser and nowhere else, so a reload is the only test of the
   * claim the panel's own copy makes ("stored in this browser"). A re-render
   * cannot see this; only a real navigation can.
   *
   * AND the reopening itself. Every content assertion below passed with the
   * reopening click DELETED, because ModalShell mounts every modal body
   * permanently and CSS-hides the backdrop (`.soc-modal-back` without
   * `is-open`) — so the rows are counted, and their hit counts read, whether or
   * not the operator can get back to them. The `is-open` assertion after the
   * click is what makes the click load-bearing, and it is the only thing
   * exercising `watchlistNav`: the badge the panel earns by working ("Watchlist
   * 2") is what breaks socNavItem's exact-name match, which is asserted here
   * directly rather than left as a comment on the helper.
   */
  test("watches survive a reload and are re-matched against the new buffer", async ({ page }) => {
    await openConsole(page);
    await socNavItem(page, "Watchlist").click();
    await expect(
      page.locator('[data-panel="watchlist-modal"]'),
      "the Watchlist never opened, so nothing can be stored from it"
    ).toBeVisible();
    await addWatch(page, "paths", "/etc/shadow");
    await addWatch(page, "ips", "203.0.113.10");

    await page.reload();
    await expect(page.locator('[data-panel="kpi-row"]'), "the console did not come back").toBeVisible();
    await expect(
      socNavItem(page, "Watchlist"),
      "the restored watches never reached the sidebar badge — the nav still reads exactly \"Watchlist\""
    ).toHaveCount(0);
    await watchlistNav(page).click();
    await expect(
      page.locator('[data-panel="watchlist-modal"]'),
      "the Watchlist did not reopen after the reload — the badge changed its accessible name"
    ).toHaveClass(/is-open/);

    await expect(
      page.locator('[data-panel="watchlist-modal"] .soc-watch-item'),
      "the two watches did not survive the reload"
    ).toHaveCount(2);
    await expect(
      watchRow(page, "/etc/shadow").locator(".soc-watch-count"),
      "the restored watch was listed but never re-matched against the reloaded telemetry"
    ).toHaveText("2 hits");
  });
});

// ── KPI drill ──────────────────────────────────────────────────────────────

/**
 * Twelve criticals whose scores are deliberately OUT of wire order, with the
 * two highest last.
 *
 * The shared fixture gives each severity at most two alerts, which makes "Top
 * 10 by score" a table of everything in the bucket — the ordering claim in its
 * own heading is unfalsifiable there. Twelve rows with the top scorers arriving
 * last is the smallest fixture where "top 10" and "by score" both have to mean
 * something: a table that takes the first ten in wire order drops 98 and 71,
 * the two an analyst opened the drill to find.
 */
const SCORE_ORDER = [12, 40, 8, 55, 21, 33, 5, 47, 16, 29, 98, 71];

const SCORED_CRITICALS = SCORE_ORDER.map((score, index) => ({
  id: `alert-scored-${index}`,
  timestamp: `2026-06-25T08:${String(index * 4).padStart(2, "0")}:00Z`,
  severity: "critical",
  title: `Scored detection ${index}`,
  description: `synthetic alert scoring ${score}`,
  policy_name: "override-credential-read",
  process: "/usr/bin/cat",
  exec_id: `exec-scored-${index}`,
  pid: 5000 + index,
  score
}));

const SCORED_STATS = {
  ...ALERT_STATS,
  counts: { critical: SCORED_CRITICALS.length, high: 0, medium: 0, low: 0, info: 0 },
  total: SCORED_CRITICALS.length,
  buckets: [
    { at: T("08:00"), counts: { critical: 6, high: 0, medium: 0, low: 0, info: 0 }, total: 6 },
    { at: T("08:24"), counts: { critical: 6, high: 0, medium: 0, low: 0, info: 0 }, total: 6 }
  ]
};

/**
 * A server that counts SEVEN criticals in the window while the browser holds
 * the two it was sent.
 *
 * This is the shape that actually ships and that the agreeing fixture above can
 * never produce: /api/alert-stats aggregates the whole window server-side,
 * /api/alerts returns a bounded page of rows. `truncated` stays false because
 * the server DID scan the whole window — it is the row feed that is smaller,
 * which is precisely the case the console has no flag for.
 */
const OVERCOUNTED_STATS = {
  ...ALERT_STATS,
  counts: { critical: 7, high: 2, medium: 1, low: 0, info: 0 },
  total: 10,
  buckets: [
    { at: T("08:00"), counts: { critical: 4, high: 1, medium: 1, low: 0, info: 0 }, total: 6 },
    { at: T("09:00"), counts: { critical: 3, high: 1, medium: 0, low: 0, info: 0 }, total: 4 }
  ]
};

function kpiTile(page: Page, label: string): Locator {
  return page.locator(
    `[data-panel="kpi-row"] .soc-exec-metric:has(.soc-exec-metric-head span:text-is("${label}"))`
  );
}

function drill(page: Page): Locator {
  return page.locator('[data-panel="kpi-drill-modal"]');
}

function drillStat(page: Page, label: string): Locator {
  return drill(page).locator(`.soc-kpi-stat:has(span:text-is("${label}"))`).locator("strong");
}

/** The small print under a drill stat — the only place it names its scope. */
function drillStatMeta(page: Page, label: string): Locator {
  return drill(page).locator(`.soc-kpi-stat:has(span:text-is("${label}"))`).locator("em");
}

/** Body rows of a drill table, without its header row. */
function drillTableRows(page: Page, heading: string): Locator {
  return drill(page)
    .locator(`.soc-kpi-panel:has(h3:text-is("${heading}")) .soc-kpi-table > div`)
    .filter({ hasNot: page.locator('span:text-is("Time"), span:text-is("Binary")') });
}

async function closeDrill(page: Page): Promise<void> {
  await drill(page).getByRole("button", { name: "Close" }).click();
  await expect(drill(page), "the drill did not close").toBeHidden();
}

test.describe("kpi drill", () => {
  test.use({ viewport: { width: 1600, height: 1000 } });

  /**
   * WHAT BUG THIS PINS: a drill that contradicts the tile that opened it. The
   * tile counts through the server aggregate and the drill filters the browser
   * buffer, so "Critical 2" opening onto four rows — or onto rows of another
   * severity — is the console showing two different answers to one question,
   * and the operator has no way to tell which is the real one.
   */
  test("each severity tile opens its own drill, listing only that severity", async ({ page }) => {
    await openConsole(page);

    const expected = [
      { label: "Critical", title: "Critical alerts", count: 2, titles: ["Credential file read", "Shadow copy staged for exfiltration"] },
      { label: "High", title: "High alerts", count: 2, titles: ["Outbound connection to known C2", "SSH private key read"] },
      { label: "Medium", title: "Medium alerts", count: 1, titles: ["Listener opened on a high port"] }
    ];

    for (const bucket of expected) {
      const tile = kpiTile(page, bucket.label);
      await expect(tile, `no ${bucket.label} KPI tile, nothing to drill`).toBeVisible();
      // The precondition: the tile's own number, which the drill must match.
      await expect(
        tile.locator(".soc-exec-metric-value strong"),
        `the ${bucket.label} tile does not show the fixture's count`
      ).toHaveText(String(bucket.count));

      await tile.click();
      await expect(drill(page), `clicking the ${bucket.label} tile opened nothing`).toBeVisible();
      await expect(
        drill(page).getByRole("heading", { level: 2 }),
        "the drill does not name which KPI it is drilling"
      ).toHaveText(bucket.title);
      await expect(
        drillStat(page, "Total"),
        `the ${bucket.label} tile said ${bucket.count} and its drill totals something else`
      ).toHaveText(String(bucket.count));

      const rows = drillTableRows(page, "Top 10 by score");
      await expect(
        rows,
        `the ${bucket.label} drill lists a different number of alerts than the ${bucket.count} it claims`
      ).toHaveCount(bucket.count);
      for (const title of bucket.titles) {
        await expect(
          rows.filter({ hasText: title }),
          `the ${bucket.label} drill omits "${title}"`
        ).toHaveCount(1);
      }
      for (const other of expected.filter((row) => row.label !== bucket.label).flatMap((row) => row.titles)) {
        await expect(
          rows.filter({ hasText: other }),
          `the ${bucket.label} drill lists "${other}", which is not ${bucket.label.toLowerCase()}`
        ).toHaveCount(0);
      }

      await closeDrill(page);
    }
  });

  /**
   * KNOWN DEFECT — the table headed "Top 10 by score" is not ordered by score,
   * and drops the highest-scoring alerts once a bucket exceeds ten.
   *
   * CAUSE: KpiDrillBody.tsx renders `scopedAlerts.slice(0, 10)` with no sort.
   * `scopedAlerts` is `alerts.filter(...)` over `rangeAlerts`, which is never
   * score-ordered upstream either — it arrives in wire order (newest-first from
   * the server, and re-sorted by the queue's own control, which this panel does
   * not read). Contrast `topProcessRows` in analytics.ts, one import away in
   * the same file, which does sort by score.
   *
   * WHY IT MATTERS: this is the console-metric-honesty class — a panel whose
   * heading states a stronger claim than its arithmetic. An analyst opens the
   * Critical drill precisely to find the worst thing in the bucket; on any
   * bucket over ten alerts the table headed "Top 10 by score" is showing the
   * first ten it happened to receive, and the 98 and the 71 in this fixture are
   * the two it silently discards. Nothing on screen says a row was dropped.
   *
   * FIX (one line): `[...scopedAlerts].sort((a, b) => b.score - a.score).slice(0, 10)`.
   */
  test("the drill's 'Top 10 by score' table really is the top ten by score", async ({ page }) => {
    await openConsole(page, {
      routes: { "/api/alerts": SCORED_CRITICALS, "/api/alert-stats": SCORED_STATS }
    });

    const tile = kpiTile(page, "Critical");
    await expect(
      tile.locator(".soc-exec-metric-value strong"),
      "the bucket must hold more than ten alerts or 'top 10' is a table of everything"
    ).toHaveText(String(SCORED_CRITICALS.length));
    await tile.click();
    await expect(drill(page), "clicking the Critical tile opened nothing").toBeVisible();

    const rows = drillTableRows(page, "Top 10 by score");
    await expect(rows, "a table headed 'Top 10' listed a different number of rows").toHaveCount(10);

    const scores = await rows.evaluateAll((nodes) =>
      nodes.map((node) => Number(node.querySelector("strong")?.textContent ?? "NaN"))
    );
    const descending = [...scores].sort((a, b) => b - a);
    expect(
      scores,
      `the table headed "Top 10 by score" rendered ${JSON.stringify(scores)} — wire order, not score order`
    ).toEqual(descending);
    expect(
      scores[0],
      `the highest-scoring alert in the bucket (${Math.max(...SCORE_ORDER)}) is not in the table it heads`
    ).toBe(Math.max(...SCORE_ORDER));
  });

  /**
   * WHAT BUG THIS PINS: a drill that presents the browser's buffer as the
   * window, when the tile that opened it counted the window on the server.
   *
   * This is the disagreement the shared fixture cannot produce, and the one
   * that ships: /api/alert-stats aggregates every alert in the range where the
   * rows live, /api/alerts returns a bounded page of them. So the tile can
   * honestly read 7 while the console holds 2 — and the operator, one click
   * apart, sees 7 and then a list of 2 with no other number on the screen to
   * reconcile them. The console's whole disclosure here is the KpiStat's small
   * print, "in current view", which is what this pins.
   *
   * NOTE — WHAT THIS DOES NOT PROVE, AND CANNOT FROM A BROWSER TEST. That four
   * -word meta is a scope label, not a reconciliation: the drill never states
   * the server's larger number, never says rows are missing, and the two other
   * disclosure paths the console has both stay silent here by design —
   * SocNotices' "counts are a floor" band is keyed on the SERVER's `truncated`
   * flag (the server scanned fine; it is the row feed that is short), and the
   * partial-window band is keyed on the browser buffer being FULL
   * (`alerts.length >= MAX_BUFFERED_ALERTS`, 1000), which a short page never
   * trips. A server that returns fewer rows than it counted is therefore
   * undisclosed beyond the label, and no assertion through a mock can fail on
   * that — it is a product gap, recorded here rather than certified away.
   */
  test("a drill listing fewer alerts than its tile counted says which set it is listing", async ({ page }) => {
    await openConsole(page, { routes: { "/api/alert-stats": OVERCOUNTED_STATS } });

    const tile = kpiTile(page, "Critical");
    await expect(
      tile.locator(".soc-exec-metric-value strong"),
      "the tile is not reading the server aggregate, so the two sources cannot differ"
    ).toHaveText("7");

    await tile.click();
    await expect(drill(page), "clicking the Critical tile opened nothing").toBeVisible();
    await expect(
      drillStat(page, "Total"),
      "the drill restated the server's 7 over a buffer holding 2 — a total it cannot see"
    ).toHaveText("2");
    await expect(
      drillTableRows(page, "Top 10 by score"),
      "the drill listed a different number of alerts than the 2 criticals in the buffer"
    ).toHaveCount(2);
    await expect(
      drillStatMeta(page, "Total"),
      "the drill's total disagrees with the tile that opened it and does not say it is scoped to the loaded view"
    ).toHaveText("in current view");
  });

  /**
   * WHAT BUG THIS PINS: a rate drill that restates the buffer as the rate. The
   * tile is badged LIVE, and the drill's four stats answer four different
   * questions about the same events — how many are LOADED, how many arrived in
   * the last minute, the busiest 5s bucket, and the rate. A drill that answered
   * "5" to "events in the last 60 seconds" would be reporting history as
   * ingestion, the same shape as the counts that were shown as measurements.
   *
   * THE CLOCK IS PINNED, and that is the whole point. Run against the wall
   * clock, this fixture is two months old: every rate is 0, "Last 60s" is 0,
   * and "the drill agrees with the tile" degenerates to "both print zero" —
   * an assertion a hardcoded zero satisfies. Pinned to 30 seconds after the
   * newest event, exactly ONE of the five events is inside the last minute, so
   * the three stats take three different values (1 ingested, 1 peak bucket, 5
   * buffered) and a drill wired to the buffer fails on two of them.
   *
   * 0.0/s IS THE HONEST RATE at that instant: one event per minute is 0.016/s
   * and the tile prints one decimal. The claim being pinned is that the drill
   * prints the SAME rate as the tile that opened it, and separately that it
   * does not confuse the buffer for it.
   */
  test("the events-per-second drill separates the loaded buffer from the current rate", async ({ page }) => {
    await openConsole(page, { fixedTime: "2026-06-25T09:00:30Z" });

    const tile = kpiTile(page, "Events / sec");
    await expect(tile, "no events/sec tile, nothing to drill").toBeVisible();
    const tileRate = await tile.locator(".soc-exec-metric-value strong").innerText();
    expect(
      tileRate,
      `one event in the last minute over five buffered reads as ${tileRate}/s on the tile`
    ).toBe("0.0");

    await tile.click();
    await expect(drill(page), "clicking the events/sec tile opened nothing").toBeVisible();
    await expect(
      drill(page).getByRole("heading", { level: 2 }),
      "the events/sec drill does not name what it is drilling"
    ).toHaveText("Events per second");

    await expect(
      drillStat(page, "Current"),
      `the tile says ${tileRate}/s and the drill it opened disagrees`
    ).toHaveText(tileRate);
    await expect(
      drillStat(page, "Last 60s"),
      "the drill counted more than the one event that arrived in the last minute — history read as ingestion"
    ).toHaveText("1");
    await expect(
      drillStat(page, "Peak"),
      "the busiest 5s bucket held one event; the drill reports another number"
    ).toHaveText("1");
    await expect(
      drillStat(page, "Live buffer"),
      "the drill lost the events it is drilling — all five are in the window"
    ).toHaveText(String(EVENTS.length));
  });

  /**
   * WHAT BUG THIS PINS: a process drill whose rows do not add up to the tile.
   * The tile's foot says how many processes were SCORED; the drill's table is
   * that same set, per binary, with its alert count. If they disagree, one of
   * the two is counting something it is not naming.
   */
  test("the process drill lists the processes the tile counted", async ({ page }) => {
    await openConsole(page);

    const tile = kpiTile(page, "Processes seen");
    await expect(tile, "no processes tile, nothing to drill").toBeVisible();
    await expect(
      tile.locator(".soc-exec-metric-value strong"),
      "the tile does not count the five exec_ids the fixture emitted"
    ).toHaveText("5");
    await expect(
      tile.locator(".soc-exec-metric-foot"),
      "the tile does not say how many processes it scored"
    ).toContainText("5 scored");

    await tile.click();
    await expect(drill(page), "clicking the processes tile opened nothing").toBeVisible();
    await expect(
      drill(page).getByRole("heading", { level: 2 }),
      "the process drill does not name what it is drilling"
    ).toHaveText("Processes seen");
    await expect(
      drillStat(page, "Unique exec_ids"),
      "the tile counted five processes and the drill it opened counts a different number"
    ).toHaveText("5");

    const rows = drillTableRows(page, "Top processes");
    await expect(rows, "the drill lists a different number of processes than the tile scored").toHaveCount(5);
    for (const binary of ["/usr/bin/cat", "/usr/bin/curl", "/usr/bin/nc", "/usr/bin/scp", "/usr/bin/python3"]) {
      await expect(
        rows.filter({ has: page.locator(`strong:text-is("${binary}")`) }),
        `the drill omits ${binary}, which raised an alert in this window`
      ).toHaveCount(1);
    }

    // The per-row alert counts must add up to the alerts in the window;
    // otherwise the table is dropping or double-counting signal.
    const alertCounts = await rows.evaluateAll((nodes) =>
      nodes.map((node) => Number(node.querySelectorAll("span")[1]?.textContent ?? "NaN"))
    );
    expect(
      alertCounts.reduce((sum, value) => sum + value, 0),
      `per-process alert counts ${JSON.stringify(alertCounts)} do not add up to the ${ALERTS.length} alerts in the window`
    ).toBe(ALERTS.length);
  });
});
