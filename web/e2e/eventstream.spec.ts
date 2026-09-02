import type { Page } from "@playwright/test";

import { installMockApi } from "./support/mock-api";
import { expect, test } from "./support/test";

/**
 * The live event stream, driven frame by frame over the SSE transport.
 *
 * WHAT BUGS THIS PINS:
 *
 *  · An UNCAPPED tail. `useSocWindowModel` slices the filtered event list to
 *    200 rows and `VirtualList` renders only the visible slice of those. Both
 *    halves are load-bearing and both are invisible to the model: an operator
 *    opens this console during an incident, which is exactly when the frame
 *    rate is highest, so an uncapped or unvirtualised list is a tab that dies
 *    at the moment it is needed. A regression here (a stray `.map` over the
 *    whole buffer, a lost `.slice`) still renders a correct-looking list on a
 *    quiet fixture.
 *  · The filter being a SUBSTRING match. The input is labelled "filter
 *    /regex/" and `filterEvents` compiles it with `new RegExp`. A substring
 *    implementation passes every single-word test and fails the alternation an
 *    analyst actually types.
 *  · A half-typed regex BLANKING the list. `safeRegex` returns null on a
 *    syntax error so the list stays whole; a console that empties itself while
 *    someone types "/etc/(" is telling them the estate went quiet.
 *  · The self-noise filter, which is ON by default and therefore hides rows
 *    nobody asked it to hide unless the toggle really reveals them again.
 *  · PAUSE. See the docblock on that test — it is a real defect.
 *  · A frame delivered while the FIRST snapshot poll is still in flight being
 *    dropped. See the docblock on the last test — it is a real defect too.
 *  · The stream being wired to ONE panel. Frames feed the shared zustand store
 *    that the KPI row and the severity timeline also read; a batch that moves
 *    the event list and nothing else is a dashboard that is live in one corner
 *    and stale everywhere the eye actually goes.
 *
 * FRAMES ARE DELIVERED AFTER THE PAGE SETTLES in every test but the last. That
 * is not a way of dodging the pre-poll race — the last test pins it — it is
 * what keeps the others about the control under test rather than about the
 * order two async things happened in. See openDashboard's docblock.
 *
 * WHY IT IS HERE AND NOT IN UNIT TESTS: `streamCore` (the rAF batcher, the
 * 500-frame store cap) is unit tested in sse.spec.ts, and `filterEvents` is
 * pure. None of that can see what this file asserts. The render cap only
 * matters after the frames have travelled EventSource → rAF batch → zustand →
 * `applySocStreamBatch` → the window model → `VirtualList`, and virtualisation
 * is a pure layout property — jsdom reports every element as 0x0, so
 * `@tanstack/react-virtual` renders a degenerate window there and a test in
 * jsdom would "pass" against a list that renders all 200 rows in a browser.
 * Pause and the toggles are three-component state paths (SocRoute owns the
 * flag, EventStream renders the control, useSocWindowModel applies it).
 *
 * FIXTURES: the mock's single polled event (`event-fixture-1`, file_open cat
 * /etc/shadow) and its single alert (`alert-fixture-1`, critical, timestamped
 * 2026-06-25T09:00:00Z) — hence the widened default range where a windowed
 * panel is under test. Every stream frame below is minted in this file so the
 * assertions can name rows the poll could not possibly have supplied.
 */

/** Panel-render cap, from useSocWindowModel: `filterEvents(...).slice(0, 200)`. */
const RENDER_CAP = 200;

/** Frames the mocked EventSource is asked to deliver after the page settles. */
type Frame = { type: string; payload: Record<string, unknown> };

function eventFrame(
  id: string,
  overrides: Partial<{ process: string; args: string; eventType: string; timestamp: string }> = {}
): Frame {
  return {
    type: "event",
    payload: {
      id,
      timestamp: overrides.timestamp ?? new Date().toISOString(),
      event_type: overrides.eventType ?? "file_open",
      process: overrides.process ?? "curl",
      args: overrides.args ?? `/var/tmp/${id}`,
      exec_id: `exec-${id}`
    }
  };
}

/** The accessible name EventRow builds: `${eventType} ${process} ${detail}`. */
function rowName(frame: Frame): string {
  const payload = frame.payload;
  return `${String(payload.event_type)} ${String(payload.process)} ${String(payload.args)}`;
}

/**
 * Lets this spec deliver frames AFTER the page has settled.
 *
 * The shared mock replays `streamFrames` once, 10ms after the connection
 * opens, and keeps no handle on the instance it created — so there is no way
 * to say "now send another frame", which is the only way to test a control
 * whose whole job is to change what happens to the NEXT frame. Rather than
 * edit the shared support file, this wraps whatever `window.EventSource` is at
 * init time (the mock, since installMockApi's init script is registered first)
 * and records every instance. Nothing about the mock's behaviour changes.
 */
async function installStreamProbe(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const Base = window.EventSource;
    const sources: EventSource[] = [];
    (window as unknown as { __streamProbe: EventSource[] }).__streamProbe = sources;

    class ProbedEventSource extends Base {
      constructor(url: string | URL, init?: EventSourceInit) {
        super(url, init);
        sources.push(this);
      }
    }

    Object.defineProperty(window, "EventSource", { configurable: true, value: ProbedEventSource });
  });
}

/** Delivers frames down the open mocked EventSource, as the server would. */
async function pushFrames(page: Page, frames: Frame[]): Promise<void> {
  const delivered = await page.evaluate((list) => {
    type Sink = { readyState: number; onmessage: ((event: MessageEvent) => void) | null };
    const sources = ((window as unknown as { __streamProbe?: Sink[] }).__streamProbe ?? []).filter(
      (source) => source.readyState === 1 && typeof source.onmessage === "function"
    );
    // React may mount the provider twice (StrictMode); earlier sources are
    // closed and must not be written to. The live one is the last.
    const sink = sources[sources.length - 1];
    if (!sink) return 0;
    for (const frame of list) {
      sink.onmessage?.(new MessageEvent("message", { data: JSON.stringify(frame) }));
    }
    return list.length;
  }, frames);

  expect(delivered, "no open mocked EventSource accepted the frames, nothing under test").toBe(
    frames.length
  );
}

function streamPanel(page: Page) {
  return page.locator('[data-panel="live-event-stream"]');
}

/** The panel's own header count — `${visibleEvents.length} events`. */
function visibleCount(page: Page) {
  return streamPanel(page)
    .locator(".soc-panel-actions .soc-pill")
    .innerText()
    .then((text) => Number(text.replace(/[^\d]/g, "")));
}

/**
 * Types a pattern into the panel's filter and waits for it to take effect.
 *
 * The input is CONTROLLED (`value={filter}` in EventStream), so the DOM carries
 * the new text only once React has committed the render that stored it — and
 * that is the same render that recomputes `visibleEvents`. Waiting on the value
 * is therefore a real settle signal rather than a sleep: the count read next is
 * the filtered one, not the list as it was a tick ago.
 */
async function applyFilter(page: Page, pattern: string): Promise<void> {
  const input = streamPanel(page).getByPlaceholder("filter /regex/");
  await input.fill(pattern);
  await expect(input, `the filter input never committed "${pattern}"`).toHaveValue(pattern);
}

/** How many of the rows currently in the list survive `pattern`. */
async function countUnder(page: Page, pattern: string): Promise<number> {
  await applyFilter(page, pattern);
  return visibleCount(page);
}

/**
 * A settled dashboard whose event list contains exactly the polled fixture.
 *
 * `streamFrames` is emptied deliberately. The mock replays those 10ms after the
 * connection opens, which is BEFORE the initial /api/events poll resolves — and
 * `useSocData` resolves that poll with `setSnapshot(read.snapshot)`, replacing
 * the whole buffer, so anything the stream delivered in that window is gone
 * from every panel. (The store still counts it: the stream pill reads
 * "FRAMES 1" beside a list that never showed the frame.) That race is pinned by
 * the last test in this file, which opts back in by passing its own
 * `streamFrames`; here it would only make every assertion a timing coin-flip,
 * so these tests deliver their frames after the page has settled instead.
 */
async function openDashboard(page: Page, options: Parameters<typeof installMockApi>[1] = {}) {
  await installMockApi(page, { streamFrames: [], ...options });
  await installStreamProbe(page);
  await page.goto("/");
  await expect(streamPanel(page), "the event stream panel never rendered").toBeVisible();
  // The poll has landed and its row is on screen: from here the list only
  // changes because a frame arrived.
  await expect(
    page.getByRole("button", { name: "file_open cat /etc/shadow" }),
    "the polled fixture event never rendered, so the page had not settled"
  ).toBeVisible();
}

test.describe("live event stream", () => {
  test.use({ viewport: { width: 1600, height: 1000 } });

  test("frames the poll never returned arrive, newest first", async ({ page }) => {
    const first = eventFrame("stream-a", { process: "curl", args: "/var/tmp/stage.sh" });
    const second = eventFrame("stream-b", { process: "cat", args: "/etc/gshadow", eventType: "file_open" });

    await openDashboard(page);

    const rows = streamPanel(page).locator("button.soc-event-row");
    // Precondition: the list is fed by the /api/events poll at all. Without
    // this, every assertion below could pass on a list that renders only
    // stream frames — or fail for a reason that has nothing to do with SSE.
    await expect(
      page.getByRole("button", { name: "file_open cat /etc/shadow" }),
      "the polled fixture event is missing, so the list is not wired to /api/events"
    ).toBeVisible();
    // What the poll supplied, measured rather than assumed: the claim is that
    // two frames ADD two rows, and it should not break because the shared mock
    // grew a second fixture event.
    const polled = await visibleCount(page);

    await pushFrames(page, [first, second]);

    await expect(
      page.getByRole("button", { name: rowName(first) }),
      `the first streamed frame (${rowName(first)}) never reached the list`
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: rowName(second) }),
      `the second streamed frame (${rowName(second)}) never reached the list`
    ).toBeVisible();

    // A tail is read from the top. The last frame of a batch is the most
    // recent event, so it must end up at row 0 — a batch prepended in arrival
    // order instead of reverse would put the OLDEST of the burst on top and
    // an analyst would read the burst backwards.
    await expect(
      rows.first(),
      "the newest frame of the batch is not the top row of the tail"
    ).toHaveAttribute("aria-label", rowName(second));

    await expect
      .poll(() => visibleCount(page), {
        message: `two streamed frames did not grow the list from its ${polled} polled row(s)`
      })
      .toBe(polled + 2);
  });

  /**
   * WHAT BUG THIS PINS — and it is a live one.
   *
   * "Pause" is wired to `streamPaused` in SocRoute, which reaches EventStream
   * and does exactly two things: it flips the header pill to a warn tone and
   * adds `.is-paused` to the list, whose only rule is `opacity: 0.62`. The
   * rows themselves come from `model.visibleEvents`, which is
   * `filterEvents(snapshot.events, ...)` — a derivation that has never heard
   * of the pause flag — and `applySocStreamBatch` keeps writing every arriving
   * frame into `snapshot.events` regardless.
   *
   * So the control an analyst uses to hold a row still while they read it
   * dims the list and then keeps moving it. Rows shift under the cursor at
   * the arrival rate, and the click lands on whatever scrolled into that
   * position: on a busy host the analyst opens the drill panel for an event
   * they never saw.
   *
   * THE FIX: freeze the LIST, not the ingest — keep filling `snapshot.events`
   * (the buffer, the KPIs and the timeline must stay live) and have SocRoute
   * hold the events handed to EventStream while paused, e.g. a ref that
   * snapshots `model.visibleEvents` on the pause edge and is released on
   * resume. The header already has the affordance for the rest: the pill can
   * report how many frames arrived while held.
   */
  test("pause freezes the list while frames keep arriving", async ({ page }) => {
    test.fail(true, "known defect: Pause only dims the list (opacity .62); rows keep moving underneath");

    await openDashboard(page);

    const beforeAnything = eventFrame("live-1", { args: "/var/tmp/live-1" });
    await pushFrames(page, [beforeAnything]);
    // Precondition: the post-settle delivery path works at all, so a "no new
    // row appeared" below means PAUSE held it rather than the harness failing
    // to send anything.
    await expect(
      page.getByRole("button", { name: rowName(beforeAnything) }),
      "a frame pushed after settle never appeared, so the pause assertion would be vacuous"
    ).toBeVisible();
    const held = await visibleCount(page);

    const pause = streamPanel(page).getByRole("switch", { name: /^Pause/ });
    await pause.click();
    await expect(pause, "the pause control did not latch on").toHaveAttribute("aria-checked", "true");

    // Every frame carries a distinct exec_id, so "Processes seen" counts one
    // more for each one that reaches the buffer.
    const processesValue = page
      .locator('[data-panel="kpi-row"] .soc-exec-metric')
      .filter({ hasText: "Processes seen" })
      .locator(".soc-exec-metric-value strong");
    const processesBefore = Number((await processesValue.innerText()).replace(/[^\d]/g, ""));

    const whilePaused = eventFrame("paused-1", { process: "sshd", args: "/var/tmp/paused-1" });
    await pushFrames(page, [whilePaused]);

    // Pause must freeze the VIEW, not the ingest: the KPI tile moving is proof
    // the frame was received, batched and written to the buffer. Asserting the
    // list's absence only AFTER that is what stops this test passing merely by
    // outrunning the rAF batch — which it did, intermittently, when it polled
    // the row count straight after the push.
    await expect
      .poll(async () => Number((await processesValue.innerText()).replace(/[^\d]/g, "")), {
        message: `the frame pushed while paused never reached the buffer ("Processes seen" stayed at ${processesBefore}) — the pause assertions below would be vacuous`
      })
      .toBe(processesBefore + 1);

    expect(await visibleCount(page), `the list grew from ${held} while paused`).toBe(held);
    await expect(
      page.getByRole("button", { name: rowName(whilePaused) }),
      "a frame that arrived while paused was rendered anyway"
    ).toHaveCount(0);

    await pause.click();
    await expect(pause, "the pause control did not latch off").toHaveAttribute("aria-checked", "false");

    // Resuming must not lose what arrived while held — a pause that drops
    // frames is worse than no pause, because the gap is invisible.
    await expect(
      page.getByRole("button", { name: rowName(whilePaused) }),
      "the frame that arrived while paused was dropped rather than deferred"
    ).toBeVisible();
    await expect
      .poll(() => visibleCount(page), { message: "resuming did not release the held frame" })
      .toBe(held + 1);
  });

  test("the filter is a regex over the row, not a substring match", async ({ page }) => {
    const curl = eventFrame("f-curl", { process: "curl", args: "/var/tmp/payload" });
    const sshd = eventFrame("f-sshd", { process: "sshd", args: "/var/tmp/authorized_keys" });
    const rsync = eventFrame("f-rsync", { process: "rsync", args: "/var/tmp/exfil.tar" });

    await openDashboard(page);

    // What the POLL contributes, to each of the patterns used below as well as
    // to the unfiltered list. Measuring it is what keeps every number in this
    // test a claim about the three streamed frames: hardcoding 4 / 2 / 1 would
    // really be asserting that the shared mock returns exactly one event, and a
    // second fixture there — a harmless change — would break the file.
    const polled = await visibleCount(page);
    const polledAlternation = await countUnder(page, "sshd|rsync");
    const polledUpper = await countUnder(page, "EXFIL");
    await applyFilter(page, "");

    await pushFrames(page, [curl, sshd, rsync]);

    // Precondition: all three arrived, so a narrowed list below is the filter
    // working rather than frames that never landed.
    await expect
      .poll(() => visibleCount(page), {
        message: `the three streamed frames did not all land on top of the ${polled} polled row(s)`
      })
      .toBe(polled + 3);

    await applyFilter(page, "sshd|rsync");
    // The alternation is the point. A substring match finds no row containing
    // the literal "sshd|rsync" and would leave the list empty.
    await expect
      .poll(() => visibleCount(page), {
        message: `an alternation kept neither of its two branches on top of the ${polledAlternation} polled row(s) it matches — this is a substring match`
      })
      .toBe(polledAlternation + 2);
    await expect(
      page.getByRole("button", { name: rowName(sshd) }),
      "the sshd row did not survive /sshd|rsync/"
    ).toBeVisible();
    // Both branches, not just the first: an implementation that stopped at the
    // leading alternative would still show sshd.
    await expect(
      page.getByRole("button", { name: rowName(rsync) }),
      "the rsync row did not survive /sshd|rsync/, so only the first branch matched"
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: rowName(curl) }),
      "the curl row survived a filter that does not match it"
    ).toHaveCount(0);

    // Case-insensitive, because the operator types lower case and the wire
    // does not: filterEvents compiles with the "i" flag.
    await applyFilter(page, "EXFIL");
    await expect
      .poll(() => visibleCount(page), {
        message: `an upper-case pattern did not match the lower-case row it should have added to the ${polledUpper} polled row(s) it matches`
      })
      .toBe(polledUpper + 1);
    await expect(
      page.getByRole("button", { name: rowName(rsync) }),
      "/EXFIL/ did not keep the row whose path is /var/tmp/exfil.tar"
    ).toBeVisible();

    // A regex under construction. Every keystroke of "/etc/(" is an invalid
    // pattern; the list must not read as an empty estate mid-type.
    await applyFilter(page, "(etc");
    await expect
      .poll(() => visibleCount(page), { message: "a half-typed regex blanked the list" })
      .toBe(polled + 3);

    await applyFilter(page, "");
    await expect
      .poll(() => visibleCount(page), { message: "clearing the filter did not restore the tail" })
      .toBe(polled + 3);
  });

  test("self-noise is hidden by default and the toggle brings it back", async ({ page }) => {
    // The console's own traffic. `filterEvents` drops rows matching
    // /vite|node|chrome|browser|npm/ while the chip is on.
    const noise = eventFrame("n-node", { process: "node", args: "/usr/lib/vite/client" });
    const real = eventFrame("n-real", { process: "cat", args: "/etc/gshadow" });

    await openDashboard(page);
    await pushFrames(page, [noise, real]);

    const panel = streamPanel(page);
    const chip = panel.getByRole("switch", { name: "Hide self-noise" });
    await expect(chip, "self-noise hiding must default ON, or the tail is mostly the console").toHaveAttribute(
      "aria-checked",
      "true"
    );

    // Precondition: a real row from the same batch IS shown, so "the noise row
    // is absent" means it was filtered rather than never delivered.
    await expect(
      page.getByRole("button", { name: rowName(real) }),
      "the non-noise frame from the batch never rendered"
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: rowName(noise) }),
      "a node/vite row was shown while self-noise hiding was on"
    ).toHaveCount(0);
    const hidden = await visibleCount(page);

    await chip.click();
    await expect(chip, "the self-noise chip did not latch off").toHaveAttribute("aria-checked", "false");

    // Hidden, not discarded: the operator debugging the console itself has to
    // be able to see its own syscalls again.
    await expect(
      page.getByRole("button", { name: rowName(noise) }),
      "turning self-noise hiding off did not reveal the suppressed row"
    ).toBeVisible();
    await expect
      .poll(() => visibleCount(page), { message: `the count did not grow from ${hidden} when noise was revealed` })
      .toBe(hidden + 1);
  });

  test("a flood is capped at the render limit and the DOM holds only a screenful", async ({ page }) => {
    await openDashboard(page);

    const rows = streamPanel(page).locator("button.soc-event-row");
    const before = await visibleCount(page);
    // Precondition: a small list renders every row it has, so the bounded DOM
    // count asserted below is virtualisation and not a broken list.
    expect(before, "the list started empty, so growth cannot be measured").toBeGreaterThan(0);
    await expect(rows, "a short list should render all of its rows").toHaveCount(before);

    // Twice the cap plus change, in one burst — a host under an active attack.
    const flood = Array.from({ length: 2 * RENDER_CAP + 47 }, (_, index) =>
      eventFrame(`flood-${index}`, { process: "curl", args: `/var/tmp/flood-${index}` })
    );
    await pushFrames(page, flood);

    await expect
      .poll(() => visibleCount(page), {
        message: `${flood.length} frames must leave the list at the ${RENDER_CAP}-row cap, not growing without bound`,
        timeout: 15_000
      })
      .toBe(RENDER_CAP);

    // The cap alone is not enough. 200 rows is still 200 subtrees re-rendered
    // on every batch; the virtualiser is what keeps a flood cheap, and it is
    // the half no unit test can see.
    // The viewport is min(52vh, 520px) over 68px rows, so a screenful plus the
    // virtualiser's overscan is ~24 rows and cannot honestly approach 50.
    const rendered = await rows.count();
    expect(
      rendered,
      `${rendered} of ${RENDER_CAP} capped rows are in the DOM — the list is not virtualised`
    ).toBeLessThan(RENDER_CAP / 4);
    expect(rendered, "the virtual window rendered nothing at all").toBeGreaterThan(0);

    // Still a live tail, not a frozen one: the newest frame of the flood is on
    // top, and it is the flood that was kept rather than the oldest 200.
    await expect(
      rows.first(),
      "the newest frame of the flood is not the top row"
    ).toHaveAttribute("aria-label", rowName(flood[flood.length - 1]));
  });

  /**
   * WHAT BUG THIS PINS: the stream feeding exactly one panel. Every frame goes
   * through the same shared store, and three different derivations read it —
   * the event list, the KPI tiles, the timeline buckets. A wiring change that
   * keeps the tail live while the numbers above it stop moving is invisible on
   * a dashboard whose fixtures never change, and it is the worst kind of
   * dishonesty here: the screen looks live.
   *
   * The stats endpoints are switched OFF for this test on purpose. When a
   * server serves /api/alert-stats the counts and the timeline are
   * SERVER-computed over the whole window (by design — the buffer is not the
   * window), and no stream frame can or should move them. This is the older
   * deployment, where the browser buffer is the only source there is.
   */
  test("one batch moves the tail, the KPI row and the timeline together", async ({ page }) => {
    await page.addInitScript(() => window.localStorage.setItem("soc.prefDefaultRange", "525600"));
    await openDashboard(page, {
      routes: {
        "/api/alert-stats": { status: 404, body: { error: "not found" } },
        "/api/decision-stats": { status: 404, body: { error: "not found" } }
      }
    });

    const criticalValue = page
      .locator('[data-panel="kpi-row"] .soc-exec-metric')
      .filter({ hasText: "Containment priority" })
      .locator(".soc-exec-metric-value strong");
    const processesValue = page
      .locator('[data-panel="kpi-row"] .soc-exec-metric')
      .filter({ hasText: "Processes seen" })
      .locator(".soc-exec-metric-value strong");
    const timelineTotal = page.locator('[data-panel="severity-timeline"] .soc-panel-actions .soc-pill');

    const readNumber = (text: string) => Number(text.replace(/[^\d]/g, ""));
    // Precondition: the fallback derivations rendered numbers at all. On a
    // blank fallback every "+1" below would be comparing NaN with NaN.
    await expect(criticalValue, "the critical KPI tile is empty on the buffer fallback").not.toBeEmpty();
    await expect(timelineTotal, "the timeline count is empty on the buffer fallback").toContainText(/\d+ alerts/);

    const beforeCritical = readNumber(await criticalValue.innerText());
    const beforeTimeline = readNumber(await timelineTotal.innerText());
    const beforeProcesses = readNumber(await processesValue.innerText());
    const beforeEvents = await visibleCount(page);

    const at = new Date().toISOString();
    const event = eventFrame("wired-1", { process: "mimidump", args: "/var/tmp/lsass.dmp", timestamp: at });
    const alert: Frame = {
      type: "alert",
      payload: {
        id: "alert-streamed-1",
        timestamp: at,
        severity: "critical",
        title: "Streamed credential dump",
        policy_name: "override-credential-read",
        process: "mimidump",
        exec_id: "exec-wired-1",
        score: 91
      }
    };
    await pushFrames(page, [event, alert]);

    await expect
      .poll(() => visibleCount(page), { message: `the event tail did not grow from ${beforeEvents}` })
      .toBe(beforeEvents + 1);
    await expect
      .poll(async () => readNumber(await criticalValue.innerText()), {
        message: `the critical KPI tile stayed at ${beforeCritical} after a critical alert frame`
      })
      .toBe(beforeCritical + 1);
    await expect
      .poll(async () => readNumber(await timelineTotal.innerText()), {
        message: `the timeline still totals ${beforeTimeline} after a critical alert frame`
      })
      .toBe(beforeTimeline + 1);
    // A process nobody had seen before must raise the distinct-process count —
    // the tile that answers "how much of this estate is involved".
    await expect
      .poll(async () => readNumber(await processesValue.innerText()), {
        message: `"Processes seen" stayed at ${beforeProcesses} after a frame from a new process`
      })
      .toBe(beforeProcesses + 1);
  });

  /**
   * WHAT BUG THIS PINS — and it is a live one.
   *
   * The console opens two things at once: the SSE stream and the first
   * /api/events + /api/alerts poll. `useSocData` resolves that poll with
   * `setSnapshot(read.snapshot)` — it REPLACES the buffer rather than merging
   * into it — so every frame the stream delivered while the request was in
   * flight is erased, including frames the store already counted and already
   * wrote through `applySocStreamBatch`.
   *
   * The window is the whole round-trip to the server, which on a loaded estate
   * is exactly when frames are arriving fastest: the first alerts of an
   * incident land in the browser, are counted in the stream pill, and are then
   * dropped by the poll that was supposed to fill the page. What the operator
   * sees is a console reporting frames beside a list that never shows them,
   * with no reconnect and no error to explain the gap.
   *
   * THE FIX: merge, do not replace — resolve the poll with a reducer that
   * unions the polled rows into the current buffer by id
   * (`setSnapshot((current) => mergeSocSnapshot(current, read.snapshot))`,
   * de-duplicating the way `applySocStreamBatch` already does) instead of
   * handing `setSnapshot` a bare value.
   *
   * DETERMINISTIC HERE, not a coin-flip: the mocked EventSource replays its
   * frames 10ms after it opens, which is always inside the mocked poll's
   * round-trip, so the frame is always delivered into the doomed window.
   */
  test("a frame that arrives during the first poll is not erased by it", async ({ page }) => {
    test.fail(true, "known defect: a frame delivered while the first snapshot poll is in flight is discarded by setSnapshot");

    const preflight = eventFrame("preflight-1", { process: "sshd", args: "/var/tmp/preflight-1" });

    // The one test that opts back INTO the race openDashboard otherwise avoids:
    // these frames are replayed 10ms after the stream opens, i.e. while the
    // first poll is still out. openDashboard returns once the polled fixture
    // row is on screen, so the poll has landed by the assertions below.
    await openDashboard(page, { streamFrames: [preflight] });

    // Precondition: the frame really was delivered and the store really
    // counted it. Without this, "the row is missing" could mean the mock never
    // sent anything, and the assertion below would be vacuous. The count lives
    // in the live pill's popover, which is mounted whether it is open or not —
    // hence the class assertion rather than toBeVisible.
    const livePill = page.locator("button.soc-live-pill");
    await livePill.click();
    const livePopover = page
      .locator('.soc-popover[data-panel="pill-popovers"]')
      .filter({ hasText: "Live data stream" });
    await expect(livePopover, "the live-stream popover never opened").toHaveClass(/is-open/);
    const framesTile = livePopover
      .locator(".soc-metric")
      .filter({ hasText: "Frames" })
      .locator(".soc-metric-value");
    await expect
      .poll(async () => Number((await framesTile.innerText()).replace(/[^\d]/g, "")), {
        message: "the stream store counted no frames at all, so the missing-row assertion below would be vacuous"
      })
      .toBeGreaterThan(0);
    await page.locator(".soc-popover-scrim").click();
    await expect(livePopover, "the live-stream popover never closed").not.toHaveClass(/is-open/);

    // The claim: a frame the store counted is IN THE LIST. It is not — the
    // poll replaced the buffer it had already been written into.
    await expect(
      page.getByRole("button", { name: rowName(preflight) }),
      "a frame the stream store had already counted is missing from the list: the first snapshot poll replaced the buffer it was written into"
    ).toBeVisible();
  });
});
