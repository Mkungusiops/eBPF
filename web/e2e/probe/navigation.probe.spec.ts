import type { ConsoleMessage, Locator, Page } from "@playwright/test";

import { SOC_SURFACES } from "../support/contracts";
import { socNavLink } from "../support/test";
import {
  expect,
  hasClass,
  hasCredentials,
  hasSecondTenant,
  readProbeEnv,
  readWhoami,
  readText,
  releaseBlocking,
  settles,
  signIn,
  signedInContext,
  test
} from "./support/live";

/**
 * Every menu and sub-menu of the console, opened on a LIVE deployment.
 *
 * WHAT "EVERY MENU" MEANS HERE: the NON-LAB rail, plus the chrome of the four
 * routes. Both deployments this file is run against report `lab_mode=false`, so
 * Rule Simulator, Attack Sim and Honeypots are asserted ABSENT rather than
 * driven — the lab branch below is live-dead on the estate by design, and the
 * only claim this file makes about those three is that they are not on offer.
 * The other direction is covered too: the palette DOES offer them, which is a
 * defect and is pinned as one.
 *
 * WHAT BUG THIS PINS: a surface that renders perfectly on fixtures and fails on
 * a real estate. The bodies behind this navigation are all mounted at once (see
 * SocModals.tsx) and hidden with CSS, so nothing about them is exercised until
 * an operator clicks the item — and what they render then is whatever THIS
 * deployment answered with: an empty tenant, thousands of live processes, an
 * agent that stopped heart-beating mid-render, or an endpoint this half of the
 * platform never registered. Each of those produces a panel that is quiet
 * rather than broken, which is the failure mode this console has shipped
 * repeatedly (a drill panel dereferencing an optional field; a tool
 * advertising eleven filter parameters no server read).
 *
 * "QUIET RATHER THAN BROKEN" IS THE BAR, SO IT IS MEASURED AS ONE. A body with
 * eight characters of prose in it satisfies every EmptyState in the app, so
 * that is not what is asserted: each surface declares the WORKING PART its body
 * must produce (BODY_PROOF below — a detection card, an agent summary, the
 * replay controls, the graph canvas), and a surface that opens without one is
 * either reported as quiet-with-a-stated-reason or failed outright.
 *
 * WHY IT IS A PROBE AND NOT THE MOCKED FAN-OUT: e2e/surfaces.spec.ts already
 * opens every advertised tool against `installMockApi`, where every route
 * resolves, every payload is well-formed and every list has two rows. It
 * therefore cannot see a body that only breaks on real data, a rail that
 * renders differently because the SERVER reported lab_mode or an assistant, or
 * a panel whose endpoint 404s here. Those are properties of a deployment, and
 * the only way to observe them is to drive one.
 *
 * WHAT IT NEEDS: PROBE_URL, PROBE_USER, PROBE_PASSWORD, and a deployment that
 * is up. It runs unchanged against both halves of the platform — the
 * single-tenant engine and the multi-tenant control plane — and the
 * differences between their rails are asserted rather than tolerated.
 *
 * THE DESIGN RULE: the navigation is DISCOVERED, never hardcoded. The rail is
 * enumerated from the DOM of the deployment under test and every discovered
 * item is driven, so a menu item added tomorrow is covered tomorrow. What an
 * undeclared item is NOT is clicked: these are production boxes and nothing
 * guarantees that tomorrow's rail button merely opens a panel, so an item that
 * is in neither SOC_SURFACES nor this file's exception lists is REPORTED, by
 * name, as an uncovered item — discovery through a failed assertion, not
 * through a blind press.
 *
 * READ-ONLY. Every control that would change the estate (arm, contain, thaw,
 * kill-switch, preset, threshold write, policy push, attack run, approve/deny)
 * is asserted PRESENT and left alone. Menus, popovers, client-side context
 * menus, localStorage view state and GET-backed filters are driven. "Sign out"
 * is never clicked in the shared session, and on the control plane it is not
 * clicked at all without an explicit opt-in — see the sign-out test.
 *
 * SHAPE: Pattern A, from surfaces.spec.ts — failures are collected and
 * asserted once at the end, so a run reports every broken item rather than the
 * first one.
 */

const env = readProbeEnv();

/** A rail entry as the DEPLOYMENT renders it — not as the contract imagines it. */
type RailEntry = {
  group: string;
  label: string;
  kind: "button" | "link";
  href?: string;
};

type Failure = { item: string; reason: string };

/** What opening one rail item is supposed to produce. */
type Expectation =
  | { kind: "surface"; panel: string; contains?: RegExp }
  | { kind: "assistant" }
  | { kind: "route"; href: RegExp }
  /** Nobody declared it. Report it; do NOT press it on a production estate. */
  | { kind: "undeclared"; why: string };

/**
 * Rail items that are NOT in SOC_SURFACES and legitimately never will be.
 *
 * The route links and the account entry are navigation, not overlay surfaces.
 * "Assistant" is the interesting one: it opens a persistent sidebar rather
 * than one of the mutually-exclusive overlays, which is why Sidebar.tsx routes
 * it through its own prop pair — but it IS an advertised tool, and the
 * contract does not list it. That divergence is reported, not patched here.
 */
/**
 * Rail links that really are EXITS — a click must leave for this route.
 *
 * The Fleet Console is deliberately NOT here any more. It is still an anchor
 * carrying href="/fleet" (bookmarks, this suite's own sign-in target and the
 * command palette all address it that way, and /fleet still answers), but a
 * plain click no longer navigates: it opens the fleet SURFACE in place over the
 * console. Listing it here would make this file follow the click as a
 * navigation and never inspect the body it actually opens — a rail entry that
 * looks tested and is not. SOC_SURFACES declares it instead, flagged navIsLink.
 */
const ROUTE_LINKS: Record<string, RegExp> = {
  Dashboard: /\/$/,
  "Choke Gateway": /\/choke$/,
  "Device Choke": /\/devices$/,
  "Sign out": /\/api\/logout$/
};

/**
 * The working part each surface's body must produce.
 *
 * This is the anti-vacuity floor for the fan-out, and it is deliberately NOT
 * prose. Every EmptyState in this app renders a heading and a sentence, so a
 * check for "some nodes and some text" is satisfied by "No devices known to
 * this deployment", "No attack catalog returned" and an empty tenant's
 * watchlist alike — which is precisely the "quiet rather than broken" state
 * the file exists to catch. A body that cannot produce its own machinery is
 * either quiet FOR A STATED REASON (an EmptyState, reported as an annotation
 * and allowed only where it is listed below) or a failure.
 *
 * Several of these are load-bearing live reads rather than layout: the sensor
 * summary only renders once /api/sensor-health answered, the replay controls
 * only once there is telemetry in the buffer, the guardrail/retention blocks
 * only once their settings endpoints did.
 */
const BODY_PROOF: Record<string, { selector: string; what: string }> = {
  "mitre-navigator-modal": { selector: ".soc-mitre-cell", what: "technique cells" },
  "process-correlation-graph-modal": { selector: "svg.soc-correlation-graph", what: "graph canvas" },
  "time-machine-modal": { selector: ".soc-tm-controls", what: "replay controls" },
  "behaviour-modal": { selector: ".soc-intel-section", what: "enrichment sections" },
  "watchlist-modal": { selector: ".soc-watch-item", what: "watched-term rows" },
  "detections-modal": { selector: ".soc-detections-card", what: "detection cards" },
  "fleet-modal": { selector: ".soc-fleet-table", what: "peer table" },
  // The fleet CONSOLE, which is a different surface from "fleet-modal" above:
  // that one is the SOC rail's Peer Consoles list, this one is the host-level
  // view that moved in from /fleet. `.fleet-table` is rendered only when the
  // fan-out produced peers — a loading or empty fleet renders
  // `.fleet-table-empty` instead — so it is a real floor rather than a wrapper
  // that exists whatever the estate answered.
  "fleet-console-modal": { selector: ".fleet-table tbody tr", what: "peer rows" },
  "sensor-health-modal": { selector: ".soc-sensor-summary", what: "agent summary" },
  "settings-modal": { selector: ".soc-settings-row", what: "settings rows" },
  "export-confirm-modal": { selector: ".soc-export-presets", what: "report presets" },
  "notifications-center-modal": { selector: ".soc-notify-row", what: "channel rows" },
  "help-modal": { selector: ".soc-help-grid strong", what: "keyboard map" },
  "account-profile-modal": { selector: ".soc-account-grid", what: "identity grid" },
  "kpi-drill-modal": { selector: ".soc-kpi-drill", what: "drill body" },
  // Lab-only. Never reached on either deployment this file runs against, but
  // declared so a lab box gets the same floor rather than the old prose bar.
  "rule-simulator-modal": { selector: ".soc-sim-bars", what: "severity bars" },
  "quick-fire-attacks-modal": { selector: ".soc-modal-list article", what: "attack entries" },
  "honeypots-modal": { selector: ".soc-honeypots", what: "decoy list" }
};

/** The two shapes an "I have nothing to show" body takes in this console. */
const EMPTY_STATE = ".soc-empty, .soc-graph-selection-empty";

/**
 * Surfaces whose body may legitimately be an EmptyState on a live estate.
 *
 * A shrinking allowlist, in the shape a11y.spec.ts uses for unnamed controls:
 * an entry here is a claim about the DEPLOYMENT ("this box really can have
 * nothing to show, and the panel says so"), not a licence to render nothing.
 * Anything not listed that opens without its BODY_PROOF fails. Empty by
 * default is the whole failure mode, so this list starts empty and every
 * addition has to carry the reason a quiet panel is correct there.
 */
const QUIET_IS_LEGITIMATE: Record<string, string> = {
  // Nothing the DEPLOYMENT answers can put a row in either of these. The
  // watchlist is a per-browser list of terms an operator types (DEFAULT_WATCHLIST
  // is empty, and this probe's context has never added one), and the Time
  // Machine replays the alert buffer this browser is currently holding for the
  // selected window — on an idle host, in a 30-minute window, there is nothing
  // to replay and the panel says exactly that.
  "watchlist-modal": "the watchlist is operator-typed and stored in this browser only",
  "time-machine-modal": "it replays this browser's buffer for the selected window, and an idle host fills none"
};

/**
 * Optional capabilities a deployment may legitimately answer 503, saying so.
 *
 * Not every red line in a browser console is a defect here. The single-tenant
 * engine answers the chat-history routes 503 ON PURPOSE — chat isolation is
 * enforced by Postgres RLS and this deployment stores to SQLite, so rather than
 * keep conversations under weaker isolation than every other partitioned table
 * it has no history and says which (see handleAssistantChatsUnavailable in
 * engine/internal/api/assistant.go). The fleet and device planes do the same
 * where they are switched off. Chrome logs a "Failed to load resource" error
 * for each anyway, and a probe that counts those reports a correctly-configured
 * box as broken.
 */
const CAPABILITY_DISABLED_503 = /^\/api\/(assistant(\/|$)|fleet\/|choke\/device)/;

/**
 * Console noise is filtered by releaseBlocking(); this collects what is left.
 *
 * The 503 allowance is COUNTED and CORRELATED, never pattern-matched away: one
 * resource error is forgiven per deliberate 503 actually observed on the wire,
 * so a 503 from anywhere else — or a second one the server did not send — still
 * fails. A permissive filter here is how a real console error gets ignored for
 * a year.
 */
class ConsoleWatch {
  private readonly messages: string[] = [];
  /** messages.length at the moment each deliberate 503 landed. */
  private readonly declined: number[] = [];
  readonly disabledCapabilities = new Set<string>();

  constructor(page: Page) {
    page.on("console", (message: ConsoleMessage) => {
      if (message.type() === "error") this.messages.push(`console: ${message.text()}`);
    });
    page.on("pageerror", (error: Error) => this.messages.push(`pageerror: ${error.message}`));
    page.on("response", (response) => {
      if (response.status() !== 503) return;
      const path = new URL(response.url()).pathname;
      if (!CAPABILITY_DISABLED_503.test(path)) return;
      this.declined.push(this.messages.length);
      this.disabledCapabilities.add(path);
    });
  }

  mark(): number {
    return this.messages.length;
  }

  since(mark: number): string[] {
    let forgiven = this.declined.filter((at) => at >= mark).length;
    const remaining: string[] = [];
    for (const message of this.messages.slice(mark)) {
      if (
        forgiven > 0 &&
        /Failed to load resource: the server responded with a status of 503/.test(message)
      ) {
        forgiven -= 1;
        continue;
      }
      remaining.push(message);
    }
    return releaseBlocking(remaining);
  }
}

/**
 * One rail control, addressed by the label an operator reads.
 *
 * NOT by accessible name: Watchlist and Notifications render a badge inside
 * the button, so their accessible name is "Watchlist 3" on any deployment that
 * has something to count, and an exact-name locator silently stops matching
 * the day the estate gets busy. Scoping to `.soc-sidebar-item` is what keeps
 * the "Settings" tool distinct from the "Settings" group header.
 */
function railItem(page: Page, label: string): Locator {
  return page
    .locator('[data-panel="left-sidebar"] .soc-sidebar-item')
    .filter({ has: page.getByText(label, { exact: true }) });
}

async function discoverRail(page: Page): Promise<RailEntry[]> {
  const rail = page.locator('[data-panel="left-sidebar"]');
  await expect(rail, "the SOC rail never rendered — there would be nothing to fan out over").toBeVisible();

  const sections = rail.locator(".soc-sidebar-section");
  const sectionCount = await sections.count();
  const entries: RailEntry[] = [];

  for (let s = 0; s < sectionCount; s += 1) {
    const section = sections.nth(s);
    const group = (await section.locator(".soc-sidebar-label").first().innerText()).trim();
    const items = section.locator(".soc-sidebar-item");
    const itemCount = await items.count();
    for (let i = 0; i < itemCount; i += 1) {
      const item = items.nth(i);
      const label = (await item.locator("span").first().innerText()).trim();
      const tag = (await item.evaluate((node: Element) => node.tagName)).toLowerCase();
      entries.push({
        group,
        label,
        kind: tag === "a" ? "link" : "button",
        href: tag === "a" ? ((await item.getAttribute("href")) ?? undefined) : undefined
      });
    }
  }
  return entries;
}

/** A JSON GET made as the signed-in operator, or null when it did not answer 200. */
async function readJson<T>(page: Page, path: string): Promise<T | null> {
  const response = await page.request.get(path, { failOnStatusCode: false });
  if (response.status() !== 200) return null;
  try {
    return (await response.json()) as T;
  } catch {
    return null;
  }
}

/** Does this deployment have an assistant to reach Behaviour & Intel FROM? */
async function assistantIsConfigured(page: Page): Promise<boolean> {
  const body = await readJson<{ enabled?: boolean }>(page, "/api/assistant");
  return body?.enabled === true;
}

/** Does the SERVER report this deployment as a lab? The rail follows this flag. */
async function labModeReported(page: Page): Promise<boolean> {
  const body = await readJson<{ lab_mode?: boolean }>(page, "/api/version");
  return body?.lab_mode === true;
}

/**
 * Open one item, prove its BODY rendered, and close it again.
 *
 * `toBeVisible()` is deliberately not the claim anywhere here. ModalShell
 * renders its body unconditionally and hides it by withholding `is-open`, and
 * SlideOver hides itself with a transform Playwright still counts as visible —
 * so a visibility assertion on either cannot fail. `is-open` can.
 *
 * Nor is "the shell has text" the claim: the shell prints the panel's own
 * title and description whether or not the body rendered a thing, and an
 * EmptyState prints a sentence of its own. Only the surface's declared
 * BODY_PROOF settles it.
 */
async function openAndInspect(
  page: Page,
  watch: ConsoleWatch,
  entry: RailEntry,
  expected: Expectation
): Promise<Failure | null> {
  const mark = watch.mark();
  const boundary = page.getByRole("heading", { name: /stopped rendering/i });

  try {
    const item = railItem(page, entry.label);
    const matches = await item.count();
    if (matches !== 1) {
      return { item: entry.label, reason: `expected exactly one rail control, found ${matches}` };
    }

    // NOT PRESSED. See the header: an undeclared control on a production estate
    // is reported by name, never discovered by clicking it.
    if (expected.kind === "undeclared") {
      return { item: entry.label, reason: expected.why };
    }

    if (expected.kind === "route") {
      const href = entry.href ?? "";
      if (!expected.href.test(href)) {
        return { item: entry.label, reason: `links to "${href}", which does not match ${expected.href}` };
      }
      return null;
    }

    await item.click();

    if (expected.kind === "assistant") {
      const sidebar = page.getByRole("complementary", { name: "Platform assistant" });
      await Promise.race([
        sidebar.waitFor({ state: "visible", timeout: 20_000 }),
        boundary.waitFor({ state: "visible", timeout: 20_000 })
      ]).catch(() => undefined);
      if (await boundary.count()) {
        return {
          item: entry.label,
          reason: `route fell to the error boundary: ${watch.since(mark)[0] ?? "no error captured"}`
        };
      }
      if (!(await sidebar.count())) {
        return { item: entry.label, reason: "the assistant sidebar never mounted" };
      }
      // WHAT IT SAYS ABOUT ITSELF IS ASSERTED IN ITS OWN TEST, against
      // /api/assistant and the enrichment endpoints. Not here, and not against
      // the header's static "Read-only" chip, which renders on every open
      // whether or not there is a model behind it.
      await sidebar.getByRole("button", { name: "Close assistant" }).click();
      await sidebar.waitFor({ state: "detached", timeout: 10_000 }).catch(() => undefined);
      if (await sidebar.count()) {
        return { item: entry.label, reason: "the assistant would not close" };
      }
      const noise = watch.since(mark);
      return noise.length ? { item: entry.label, reason: `opened, but logged: ${noise[0].slice(0, 200)}` } : null;
    }

    const openShell = page.locator(`[data-panel="${expected.panel}"].is-open`);

    await Promise.race([
      openShell.first().waitFor({ state: "visible", timeout: 20_000 }),
      boundary.waitFor({ state: "visible", timeout: 20_000 })
    ]).catch(() => undefined);

    if (await boundary.count()) {
      return {
        item: entry.label,
        reason: `route fell to the error boundary: ${watch.since(mark)[0] ?? "no error captured"}`
      };
    }
    if (!(await openShell.count())) {
      return { item: entry.label, reason: `[data-panel="${expected.panel}"] never took the is-open class` };
    }

    const reasons: string[] = [];
    const bodyFailure = await inspectBody(openShell.first(), entry.label, expected.panel, expected.contains);
    if (bodyFailure) reasons.push(bodyFailure.reason);

    // CLOSED WHATEVER HAPPENED. A surface left open puts its backdrop over the
    // rail, and every remaining item then fails with a click timeout — one bad
    // panel reported as eleven, which is the opposite of what a fan-out that
    // exists to name every broken item should produce.
    await page.keyboard.press("Escape");
    await openShell.first().waitFor({ state: "hidden", timeout: 10_000 }).catch(() => undefined);
    if (await openShell.count()) {
      reasons.push("Escape did not close it (an operator has no way out)");
      await openShell
        .first()
        .locator(".soc-close-button")
        .click({ timeout: 5_000 })
        .catch(() => undefined);
      await openShell.first().waitFor({ state: "hidden", timeout: 10_000 }).catch(() => undefined);
    }

    const noise = watch.since(mark);
    if (noise.length) reasons.push(`opened, but logged: ${noise[0].slice(0, 200)}`);
    return reasons.length ? { item: entry.label, reason: reasons.join(" | ") } : null;
  } catch (error) {
    // Best effort, for the same reason as above: whatever went wrong, the next
    // item must not fail merely because this one left an overlay on the rail.
    await page.keyboard.press("Escape").catch(() => undefined);
    return { item: entry.label, reason: String((error as Error).message).split("\n")[0] };
  }
}

/**
 * The body bar, applied to an already-proven-open shell.
 *
 * Three outcomes, and only one of them is silent: the surface produced its
 * working part; or it produced an EmptyState and is allowed to; or it did
 * neither, which is the quiet panel this file exists to report.
 */
async function inspectBody(
  shell: Locator,
  label: string,
  panel: string,
  contains?: RegExp
): Promise<Failure | null> {
  const card = shell.locator(".soc-modal-card");
  const proof = BODY_PROOF[panel];
  if (!proof) {
    return {
      item: label,
      reason: `no BODY_PROOF is declared for [data-panel="${panel}"] — a new surface must say what its body has to produce`
    };
  }

  // WAITED FOR, not sampled. Half of these bodies start their fetch when the
  // shell opens, so a one-shot read catches "Loading sensor health…" and calls
  // a working panel quiet. Fifteen seconds is also what makes "quiet" a claim
  // worth reporting rather than a race.
  await card
    .locator(proof.selector)
    .first()
    .waitFor({ state: "attached", timeout: 15_000 })
    .catch(() => undefined);

  const body = card.locator("> *:not(.soc-modal-head):not(.soc-panel-copy)");
  const bodyNodes = await body.count();
  if (bodyNodes === 0) {
    return { item: label, reason: "the shell opened with nothing beneath its header" };
  }
  const text = (await body.allInnerTexts()).join(" ").replace(/\s+/g, " ").trim();
  if (text.length < 8) {
    return { item: label, reason: `${bodyNodes} body node(s) rendered, but no text in them` };
  }
  if (contains && !contains.test(text)) {
    return {
      item: label,
      reason: `opened but its body matched nothing of ${contains}; text was "${text.slice(0, 160)}"`
    };
  }

  if (await card.locator(proof.selector).count()) return null;

  const empties = card.locator(EMPTY_STATE);
  const emptyCount = await empties.count();
  if (emptyCount === 0) {
    return {
      item: label,
      reason: `opened without any ${proof.what} (${proof.selector}) and without an empty state saying why`
    };
  }
  const said = (await empties.allInnerTexts()).join(" · ").replace(/\s+/g, " ").trim();
  if (said.length < 12) {
    return {
      item: label,
      reason: `opened onto an empty state that states nothing: "${said}" — an operator cannot tell quiet from broken`
    };
  }
  if (!(panel in QUIET_IS_LEGITIMATE)) {
    return {
      item: label,
      reason: `rendered no ${proof.what} on this deployment — only an empty state: "${said.slice(0, 160)}"`
    };
  }
  test.info().annotations.push({
    type: "note",
    description: `${label} is quiet here (${QUIET_IS_LEGITIMATE[panel]}) and said so: "${said.slice(0, 160)}"`
  });
  return null;
}

function report(failures: Failure[]): string[] {
  return failures.map((failure) => `${failure.item}: ${failure.reason}`);
}


/** What each panel of the rail beside the queue must produce, or say why it cannot. */
const RAIL_PROOF = [
  { id: "mitre-coverage", body: ".soc-mini-bars", what: "technique bars" },
  { id: "top-processes", body: ".soc-mini-bars", what: "scored-process bars" },
  { id: "iocs-observed", body: ".soc-ioc-list", what: "indicator rows" },
  { id: "network-connections", body: ".soc-network-list", what: "peer rows" }
];

type Fail = (item: string, reason: string) => void;
type Acted = (action: Promise<unknown>, item: string, what: string) => Promise<boolean>;

/** Five seconds, not the config's fifteen: a broken estate must still finish and report. */
const CLICK = { timeout: 5_000 } as const;

/** An annotation, in the one shape this file's notes take. */
function note(description: string): void {
  test.info().annotations.push({ type: "note", description });
}


/** `is-open`, never toBeVisible(): these overlays sit in the layout at all times. */
async function isOpen(target: Locator): Promise<boolean> {
  return ((await target.getAttribute("class")) ?? "").includes("is-open");
}

/** Closed means closed: the class is gone AND the overlay is really unpainted. */
async function closed(target: Locator): Promise<boolean> {
  if (await isOpen(target)) return false;
  return target.evaluate((node: Element) => getComputedStyle(node).display === "none").catch(() => false);
}

/** What a panel says when it has nothing to show. */
async function quietSays(scope: Locator): Promise<string> {
  return (await scope.locator(EMPTY_STATE).allInnerTexts()).join(" ").replace(/\s+/g, " ").trim();
}

/**
 * Pattern A, bound to one list: a claim REPORTS itself instead of raising.
 *
 * `acted` is the load-bearing half. A click that cannot land throws, and an
 * exception mid-test abandons whatever state the run has left this browser in
 * and discards every finding already collected — so the Playwright error, which
 * names the element and the reason, becomes one more collected failure.
 */
function collector(): { failures: Failure[]; fail: Fail; acted: Acted } {
  const failures: Failure[] = [];
  const fail: Fail = (item, reason) => {
    failures.push({ item, reason });
  };
  const acted: Acted = async (action, item, what) => {
    try {
      await action;
      return true;
    } catch (error) {
      fail(item, `${what} — ${String(error).replace(/\s+/g, " ").slice(0, 200)}`);
      return false;
    }
  };
  return { failures, fail, acted };
}

/** Undo view state up to three times, quietly, and report what is still standing. */
async function undoUntil(dirty: Locator, undo: () => Promise<void>): Promise<number> {
  for (let attempt = 0; attempt < 3 && (await dirty.count()) > 0; attempt += 1) {
    await undo().catch(() => undefined);
  }
  return dirty.count();
}

/**
 * Escape the drill, and RECOVER when it will not go.
 *
 * The slide-over is fixed over the right 680px of the viewport, exactly where
 * the rail sits, so one panel left open would be reported as three dead clicks.
 */
async function dismissDrill(slide: Locator, item: string, fail: Fail, acted: Acted): Promise<void> {
  await slide.page().keyboard.press("Escape");
  if (await settles(async () => !(await isOpen(slide)))) return;
  fail(item, "Escape did not close the drill, and its backdrop now covers the queue");
  await acted(slide.locator("button.soc-close-button").click(CLICK), item, "its close button would not take a click either");
}

/**
 * inspectBody()'s bar, applied to a panel of the dashboard rail.
 *
 * inspectBody() itself cannot be reused — it looks inside `.soc-modal-card` —
 * but the claim is the same one: a panel produces its declared machinery, or an
 * empty state that says WHICH window it is empty for, or it is a finding.
 */
async function inspectPanel(rail: Locator, entry: (typeof RAIL_PROOF)[number], fail: Fail): Promise<void> {
  // Scoped to the rail: `.soc-mini-bars` is NOT unique in this DOM
  // (CorrelationGraph.tsx:779 and KpiDrillBody.tsx:46,110 render it inside
  // always-mounted modal bodies), so an unscoped body reads another panel's.
  const panel = rail.locator(`[data-panel="${entry.id}"]`);
  const mounts = await rail.page().locator(`[data-panel="${entry.id}"]`).count();
  const here = await panel.count();
  if (mounts !== 1) return fail(entry.id, `${mounts} elements carry this data-panel — it is not one panel`);
  if (here !== 1) return fail(entry.id, "it is mounted somewhere other than the rail beside the queue");
  const heading = panel.locator(".soc-panel-header h2");
  const headings = await heading.count();
  if (headings !== 1) fail(entry.id, `the panel header is not one title (${headings})`);
  else if (((await heading.textContent()) ?? "").trim().length === 0) fail(entry.id, "the panel rendered without a title");
  if ((await panel.locator(entry.body).count()) !== 0) return;
  const said = await quietSays(panel);
  if (said.length < 12) fail(entry.id, `rendered no ${entry.what} (${entry.body}) and no empty state saying why — its body reads "${said}"`);
  else note(`${entry.id} is quiet on ${env.kind} and said so: "${said.slice(0, 160)}"`);
}

/**
 * One round trip over a control cluster: every button it offers, plus the count
 * and the textContent of whatever readouts the caller names.
 *
 * ONE evaluate because the parts have to describe the SAME alert, and two round
 * trips on an SSE-fed queue cannot promise that. textContent throughout because
 * several of these readouts are CSS-uppercased.
 */
async function readCluster(
  scope: Locator,
  parts: Record<string, string>
): Promise<{ offered: string[]; counts: Record<string, number>; texts: Record<string, string> } | null> {
  return scope
    .evaluate(
      (node: Element, spec: Record<string, string>) => ({
        offered: Array.from(node.querySelectorAll("button")).map((button) => (button.textContent ?? "").trim()),
        counts: Object.fromEntries(Object.entries(spec).map(([key, sel]): [string, number] => [key, node.querySelectorAll(sel).length])),
        texts: Object.fromEntries(
          Object.entries(spec).map(([key, sel]): [string, string] => [key, (node.querySelector(sel)?.textContent ?? "").replace(/\s+/g, " ").trim()])
        )
      }),
      parts
    )
    .catch(() => null);
}

/**
 * The hover preview, judged in ONE evaluate.
 *
 * AlertPreview renders its children only while it holds an alert
 * (rows.tsx:281-288) and the row underneath can lose the pointer to a re-render
 * at any moment, so a second round trip reads a preview that has already
 * emptied and throws on a missing <strong>. The title is accepted against the
 * row as it read BOTH before and after the hover: a queue that re-sorted under
 * the pointer is annotated, not reported as a mismatched preview.
 */
async function inspectPreview(preview: Locator, titleBefore: string, readHeadline: () => Promise<string>, fail: Fail): Promise<void> {
  const item = "alert hover preview";
  const shot = await preview
    .evaluate((node: Element) => ({
      hidden: node.getAttribute("aria-hidden"),
      onScreen: getComputedStyle(node).display !== "none" && node.getBoundingClientRect().width > 0 && node.getBoundingClientRect().height > 0,
      strongs: node.querySelectorAll("strong").length,
      codes: node.querySelectorAll("code").length,
      title: (node.querySelector("strong")?.textContent ?? "").replace(/\s+/g, " ").trim(),
      identifier: (node.querySelector("code")?.textContent ?? "").trim()
    }))
    .catch(() => null);
  if (!shot) return fail(item, "it took is-open and then could not be read at all");
  if (shot.hidden !== "false") fail(item, "it opened but stayed aria-hidden from assistive tech");
  if (!shot.onScreen) fail(item, "it took is-open and still has no box on screen");
  if (shot.strongs !== 1 || shot.codes !== 1) fail(item, `it is not one title and one identifier (${shot.strongs} strong / ${shot.codes} code)`);
  // The identifier line is the point of the overlay: an analyst hovers to learn
  // WHICH process this is without opening anything.
  if (shot.identifier.length === 0) fail(item, "it named no exec_id, process or alert id, so it identifies nothing");
  const titleNow = await readHeadline();
  const seen = shot.title.slice(0, 60);
  if (shot.title.length === 0) fail(item, "it previewed an alert with no title in it");
  else if (titleBefore && titleNow && shot.title !== titleBefore && shot.title !== titleNow) {
    fail(item, `it previewed "${seen}" while the row it was raised from read "${titleBefore.slice(0, 60)}" before the hover and "${titleNow.slice(0, 60)}" after it`);
  } else if (titleBefore && shot.title !== titleBefore) {
    note(`the queue re-sorted under the hover on ${env.kind}: the preview reads "${seen}" and the top row now reads "${titleNow.slice(0, 60)}"`);
  }
}

const setCookiesOf = (response: { headersArray(): Array<{ name: string; value: string }> }) =>
  response
    .headersArray()
    .filter((header) => header.name.toLowerCase() === "set-cookie")
    .map((header) => header.value);

const cookieName = (cookie: string) => cookie.split(";")[0].split("=")[0].trim();

/** An expiry, not a fresh session: empty value AND a past lifetime. */
const isExpiry = (cookie: string) => {
  const [pair, ...attributes] = cookie.split(";");
  const value = pair.slice(pair.indexOf("=") + 1).trim();
  const attrs = attributes.map((attribute) => attribute.trim().toLowerCase());
  const maxAge = attrs.find((attribute) => attribute.startsWith("max-age="));
  const expires = attrs.find((attribute) => attribute.startsWith("expires="));
  const zeroed = maxAge !== undefined && Number(maxAge.slice("max-age=".length)) <= 0;
  const past = expires !== undefined && new Date(expires.slice("expires=".length)).getTime() <= Date.now();
  return value === "" && (zeroed || past);
};

/**
 * What a logout response did to the cookies the browser actually holds.
 *
 * INTERSECTION, not "every held cookie is expired": a jar can legitimately carry
 * something a logout handler has no opinion about, and failing on that reports a
 * working sign-out as broken. What must never be true is that a logout expires
 * NOTHING the browser is authenticated with — a cookie cleared under the wrong
 * name or path looks exactly like a working sign-out from the outside, and
 * leaves the session live.
 */
function inspectCookies(item: string, held: string[], cookies: string[]): Failure[] {
  const cleared = cookies.filter(isExpiry).map(cookieName);
  const reissued = cookies.filter((cookie) => !isExpiry(cookie)).map(cookieName);
  const found: Failure[] = [];
  if (!held.length) {
    found.push({ item, reason: 'this browser holds no HttpOnly cookie at path "/" though /api/whoami authenticates it, so there is nothing for a cookie assertion to be about — the session travels some other way now and this check has gone vacuous' });
  } else if (!held.some((name) => cleared.includes(name))) {
    found.push({ item, reason: `expires ${cleared.join(", ") || "nothing"} while this browser is authenticated with ${held.join(", ")} — sign-out is clearing a cookie the operator is not holding, which from the outside looks exactly like a working one` });
  }
  if (reissued.length) {
    found.push({ item, reason: `sets a live value for ${reissued.join(", ")} — a logout that issues a cookie is starting a session, not ending one` });
  }
  return found;
}

test.describe("console navigation, live", () => {
  test.skip(!hasCredentials(env), "Set PROBE_URL, PROBE_USER and PROBE_PASSWORD");
  // NOT serial. Each test signs in for itself and shares no state with its
  // neighbours, and serial mode would skip the rest of the fan-out after the
  // first failure — the opposite of what a file that exists to report every
  // broken menu item at once should do.

  test("the rail this deployment renders agrees with the surface contract", async ({ page }) => {
    await signIn(page, env);
    const watch = new ConsoleWatch(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const settled = watch.mark();

    const lab = await labModeReported(page);
    const assistant = await assistantIsConfigured(page);

    // Settle the ONE conditional entry before enumerating. Behaviour & Intel is
    // rendered on the answer to a capability probe that resolves after first
    // paint, so a rail read too early is a rail missing an item — and an
    // auto-retrying count assertion is both the wait and the claim.
    await expect(
      railItem(page, "Behaviour & Intel"),
      assistant
        ? "an assistant is configured here, so Behaviour & Intel is reached from inside it and must not also sit in the nav"
        : "no assistant is configured here, so Behaviour & Intel would be unreachable without its fallback nav entry"
    ).toHaveCount(assistant ? 0 : 1);

    // SETTLE THE IDENTITY BEFORE ENUMERATING. The rail's account entry is
    // labelled from the SOC snapshot, and normalizeWhoami falls back to the
    // literal "operator" until /api/whoami lands — a window long enough on the
    // control plane for a rail read to capture the placeholder and report the
    // console's own account item as an undeclared nav entry. Waiting for the
    // real subject to appear is also the claim that it ever does.
    const whoami = await readWhoami(page);
    await expect(
      railItem(page, whoami.user),
      `the rail never resolved who is signed in — it is still labelled with a placeholder rather than "${whoami.user}"`
    ).toHaveCount(1);

    const rail = await discoverRail(page);

    // Preconditions. Without these the whole fan-out below can pass over zero
    // items and report a healthy console.
    expect(rail.length, "no rail items were discovered").toBeGreaterThan(12);
    expect(
      [...new Set(rail.map((entry) => entry.group))].length,
      "the rail rendered as one flat list — the groups are gone"
    ).toBeGreaterThan(4);

    test.info().annotations.push({
      type: "note",
      description: `rail on ${env.kind}: ${rail.map((entry) => `${entry.group}/${entry.label}`).join(", ")}`
    });

    const expectedSurfaces = SOC_SURFACES.filter((surface) => {
      if (surface.labOnly) return lab;
      if (surface.assistantFallbackOnly) return !assistant;
      return true;
    }).map((surface) => surface.nav);

    const labels = rail.map((entry) => entry.label);
    const missing = expectedSurfaces.filter((nav) => !labels.includes(nav));
    expect(missing, "the contract advertises these tools and this deployment's rail does not offer them").toEqual([]);

    // The other direction, which is the one that rots quietly: an item the app
    // renders that nobody declared. Everything not a surface is enumerated
    // explicitly, so a NEW nav item fails here instead of going untested.
    //
    // There is no `SOC_SURFACES.some(...)` escape clause on the end of this
    // filter. It used to have one, and it forgave exactly what the assertion is
    // for: a lab-only or assistant-fallback surface appearing in a rail that
    // this deployment's own flags say must not carry it.
    const uncontracted = labels.filter(
      (label) =>
        !expectedSurfaces.includes(label) &&
        !(label in ROUTE_LINKS) &&
        label !== whoami.user &&
        label !== "Assistant"
    );
    expect(
      uncontracted,
      "these rail items are rendered by the console and declared nowhere (or are gated off on this deployment) — add them to SOC_SURFACES or to this file's exceptions"
    ).toEqual([]);

    // The two known divergences, stated rather than silently allowed above.
    // Neither is a bug in the console; both are gaps in e2e/support/contracts.ts.
    test.info().annotations.push({
      type: "note",
      description:
        "contract gap: the rail offers 'Assistant' (a persistent sidebar, not an overlay) and an account entry " +
        `labelled '${whoami.user}' opening [data-panel="account-profile-modal"]. SOC_SURFACES lists neither.`
    });
    expect(watch.since(settled), "the rail logged errors while it was being enumerated").toEqual([]);
  });

  test("every menu item the rail offers opens, renders a body, and closes", async ({ page }) => {
    test.setTimeout(6 * 60_000);
    // SIGN IN FIRST, THEN LISTEN. signIn is allowed to recover a stale session,
    // and on the control plane that recovery is loud by design — nginx serves
    // the SPA shell for every path, so the console boots unauthenticated, takes
    // its 401s, and only then follows the OIDC chain back. Those are facts
    // about the cached state file, not about the deployment.
    await signIn(page, env);
    const watch = new ConsoleWatch(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });

    const assistant = await assistantIsConfigured(page);
    await expect(
      railItem(page, "Behaviour & Intel"),
      "the conditional rail entry disagrees with what /api/assistant reported"
    ).toHaveCount(assistant ? 0 : 1);

    // See the note in the contract test: the account entry carries a fallback
    // label until the snapshot lands, and enumerating through that window
    // produces a rail item nobody declared.
    const whoami = await readWhoami(page);
    await expect(
      railItem(page, whoami.user),
      `the rail never resolved who is signed in — it is still labelled with a placeholder rather than "${whoami.user}"`
    ).toHaveCount(1);

    const rail = await discoverRail(page);
    expect(rail.length, "no rail items were discovered, so this fan-out would pass over nothing").toBeGreaterThan(12);

    const byNav = new Map(SOC_SURFACES.map((surface) => [surface.nav, surface]));
    const expectationFor = (entry: RailEntry): Expectation => {
      if (entry.kind === "link") {
        // A surface can be addressed by a link without being an exit. Check the
        // surface contract BEFORE the route table: get this order wrong and the
        // fleet console is followed as a navigation, its body is never opened,
        // and the fan-out reports a pass over a surface it did not inspect.
        const linkedSurface = byNav.get(entry.label);
        if (linkedSurface?.navIsLink) {
          return { kind: "surface", panel: linkedSurface.panel, contains: linkedSurface.contains };
        }
        const href = ROUTE_LINKS[entry.label];
        return href
          ? { kind: "route", href }
          : {
              kind: "undeclared",
              why: `a rail LINK nobody declared (href "${entry.href ?? ""}") — add it to ROUTE_LINKS with the route it must reach. Not followed.`
            };
      }
      if (entry.label === "Assistant") return { kind: "assistant" };
      if (entry.label === whoami.user) {
        return {
          kind: "surface",
          panel: "account-profile-modal",
          contains: /operator|host|build|session|theme|stream/i
        };
      }
      const surface = byNav.get(entry.label);
      return surface
        ? { kind: "surface", panel: surface.panel, contains: surface.contains }
        : {
            kind: "undeclared",
            why: "a rail BUTTON in neither SOC_SURFACES nor this file's exceptions. Not pressed: on a production estate an undeclared control is reported, not tried."
          };
    };

    const failures: Failure[] = [];
    for (const entry of rail) {
      const failure = await openAndInspect(page, watch, entry, expectationFor(entry));
      if (failure) failures.push(failure);
    }

    if (watch.disabledCapabilities.size) {
      test.info().annotations.push({
        type: "note",
        description: `switched off on ${env.kind} and answering 503 by design: ${[...watch.disabledCapabilities].join(", ")}`
      });
    }
    expect(report(failures), `${failures.length} of ${rail.length} rail items failed on ${env.kind}`).toEqual([]);
  });

  test("collapsing a nav group does not put its items out of reach", async ({ page }) => {
    await signIn(page, env);
    const watch = new ConsoleWatch(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const settled = watch.mark();

    const toggles = page.locator('[data-panel="left-sidebar"] button.soc-sidebar-group-toggle');
    const count = await toggles.count();
    expect(count, "no collapsible nav groups were found").toBeGreaterThan(3);

    const failures: Failure[] = [];
    for (let index = 0; index < count; index += 1) {
      const toggle = toggles.nth(index);
      const title = (await toggle.locator("span").first().innerText()).trim();
      // The section is the toggle's OWN parent, not the nth section. Sidebar.tsx
      // supports collapsible={false}, and the day a group uses it the toggles
      // and the sections stop being index-aligned — at which point an nth-based
      // pairing asserts against a neighbouring group and still passes.
      const section = toggle.locator("xpath=..");
      const items = section.locator(".soc-sidebar-item");
      const before = await items.count();
      expect(before, `${title} rendered no items, so collapsing it proves nothing`).toBeGreaterThan(0);

      await toggle.click();
      if ((await toggle.getAttribute("aria-expanded")) !== "false") {
        failures.push({ item: title, reason: "clicking the group header did not collapse it" });
        continue;
      }
      // Collapse is a CSS state, not an unmount. If a collapsed group ever
      // starts removing its children, the icon-only rail loses those icons and
      // the surfaces behind them become unreachable rather than merely hidden.
      const during = await items.count();
      if (during !== before) {
        failures.push({ item: title, reason: `collapsing removed ${before - during} item(s) from the DOM` });
      }

      await toggle.click();
      if ((await toggle.getAttribute("aria-expanded")) !== "true") {
        failures.push({ item: title, reason: "the group would not expand again" });
        continue;
      }
      await expect(items.first(), `${title} did not come back`).toBeVisible();
      if ((await items.count()) !== before) {
        failures.push({ item: title, reason: "re-expanding restored a different set of items" });
      }
    }

    expect(report(failures), "collapsing a nav group misbehaved").toEqual([]);
    expect(watch.since(settled), "the rail logged errors while its groups were collapsed").toEqual([]);
  });

  /**
   * The icon-only rail is a NAVIGATION MODE, not a decoration.
   *
   * Collapsing the sidebar is what the source comment about "hides items via
   * CSS only, so the icon-only rail keeps every icon reachable" is protecting,
   * and nothing exercised it. The phone scrim is asserted here too because it
   * is the only dismiss control on a viewport this suite cannot otherwise
   * reach — its tabIndex is the observable half of the same state.
   */
  test("the rail collapses to icons and every item stays reachable", async ({ page }) => {
    await signIn(page, env);
    const watch = new ConsoleWatch(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const settled = watch.mark();

    const route = page.locator(".soc-route");
    // BY CLASS, not by role: the scrim is display:none outside the phone
    // breakpoint, which takes it out of the accessibility tree entirely, so a
    // role locator finds nothing on a desktop viewport. Its tabIndex is the
    // half of its state that is still observable here.
    const scrim = page.locator("button.soc-sidebar-scrim");
    await expect(scrim, "the phone drawer has no dismiss scrim").toHaveCount(1);
    await expect(scrim, "the scrim lost its accessible name").toHaveAttribute("aria-label", "Close menu");
    const toggle = page.getByRole("button", { name: "Toggle sidebar" });
    await expect(toggle, "the rail has no toggle").toHaveCount(1);
    await expect(route, "the desktop rail did not start open").toHaveClass(/sidebar-open/);
    await expect(scrim, "the phone dismiss scrim is focusable while the drawer is open").toHaveAttribute(
      "tabindex",
      "0"
    );

    const items = page.locator('[data-panel="left-sidebar"] .soc-sidebar-item');
    // SNAPSHOT ONLY ONCE THE RAIL HAS STOPPED GROWING. Two entries arrive after
    // first paint on a live deployment — "Behaviour & Intel" lands with the
    // assistant capability read, and the account entry is a placeholder until
    // whoami resolves — so a count taken at domcontentloaded is one or two short
    // of the settled rail. Measured on engine.adanianlabs.io: 17 immediately,
    // 18 six seconds later. Comparing the early number against a post-toggle one
    // reported "collapsing the rail removed items from the DOM" for a rail that
    // had simply finished loading, which is a false accusation against the very
    // behaviour this test defends.
    let previous = -1;
    await settles(async () => {
      const seen = await items.count();
      const steady = seen === previous && seen > 12;
      previous = seen;
      return steady;
    }, 20_000);
    const before = await items.count();
    expect(before, "no rail items to lose").toBeGreaterThan(12);

    await toggle.click();
    await expect(route, "Toggle sidebar did not collapse the rail").not.toHaveClass(/sidebar-open/);
    expect(await items.count(), "collapsing the rail removed items from the DOM").toBe(before);
    await expect(scrim, "the scrim stayed in the tab order behind a closed drawer").toHaveAttribute(
      "tabindex",
      "-1"
    );
    // Reachable, not merely present: an icon-only rail whose buttons cannot be
    // hit is the same outage as one that unmounted them. Addressed by `title`
    // rather than by label — the collapsed rail sets `display: none` on every
    // item's span, which is exactly what makes the icons the only handle.
    await page.locator('[data-panel="left-sidebar"] .soc-sidebar-item[title="Help"]').click();
    const help = page.locator('[data-panel="help-modal"].is-open');
    await expect(help, "an icon-only rail item did not open its surface").toHaveCount(1);
    await page.keyboard.press("Escape");
    await expect(help, "Escape did not close the help modal").toHaveCount(0);

    await toggle.click();
    await expect(route, "the rail would not expand again").toHaveClass(/sidebar-open/);
    expect(watch.since(settled), "the rail logged errors while it was collapsed").toEqual([]);
  });

  /**
   * Settings, measured against the DEPLOYMENT rather than against the constant
   * it renders from.
   *
   * The section list and its row counts come from settingsModel.ts, which is
   * static product data — so "six sections" and "this section has rows" are
   * facts about a TypeScript file, not about the box under test, and asserting
   * them against that same import cannot fail. The literals below are the
   * contract; what is actually probed is the LIVE half: every one of these
   * panes is a control over an endpoint (suppressions, the choke ladder, the
   * protect-lists, the retention floor, change control, the access trail), each
   * renders a "Reading the …" placeholder until its read resolves, and each is
   * cross-checked here against what that endpoint answers this operator.
   */
  test("the Settings sub-menu swaps its pane for all six sections, and each one resolves its live read", async ({
    page
  }) => {
    test.setTimeout(4 * 60_000);
    await signIn(page, env);
    const watch = new ConsoleWatch(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });

    // What the deployment itself says, before the console is asked about it.
    // Three of these routes are control-plane only, and a single-tenant engine
    // answering 404 is CORRECT — so what is asserted is agreement, not success.
    const chokeState = await readJson<{ thresholds?: Record<string, number> }>(page, "/api/choke/state");
    const served: Record<string, boolean> = {
      "/api/settings/suppressions": Boolean(await readJson(page, "/api/settings/suppressions")),
      "/api/settings/protected": Boolean(await readJson(page, "/api/settings/protected")),
      // Answered is not the same as editable here: a deployment with no
      // per-tenant store returns 200 and says the horizon is platform-wide,
      // which the pane states in a notice instead of rendering a control.
      "/api/settings/retention": (await readJson<{ editable?: boolean }>(page, "/api/settings/retention"))?.editable === true,
      "/api/settings/change-control": Boolean(await readJson(page, "/api/settings/change-control"))
    };
    // A 200 is not enough for the access trail: the panel renders a notice
    // rather than a control when the deployment says it keeps no durable trail.
    const trail = await readJson<{ supported?: boolean }>(page, "/api/operator-audit?limit=100");
    served["/api/operator-audit"] = trail !== null && trail.supported !== false;

    /** Which live read each section stands or falls on. */
    const sectionReads: Record<string, string[]> = {
      Noise: ["/api/settings/suppressions"],
      Guardrails: ["/api/settings/protected"],
      Evidence: ["/api/settings/retention"],
      Access: ["/api/settings/change-control", "/api/operator-audit"]
    };

    await railItem(page, "Settings").click();
    const modal = page.locator('[data-panel="settings-modal"].is-open');
    await expect(modal, "Settings did not open").toHaveCount(1);

    const nav = modal.locator("nav.soc-settings-nav button.soc-settings-navitem");
    const titles = (await nav.locator("strong").allInnerTexts()).map((title) => title.trim());
    // The literal six. Not SETTINGS_SECTIONS.length — that moves with the file
    // it renders from, so deleting a section leaves the count green at five.
    expect(titles, "the settings sub-menu is not the six sections this console ships").toEqual([
      "Noise",
      "Response",
      "Guardrails",
      "Evidence",
      "Access",
      "Platform"
    ]);

    const pane = modal.locator(".soc-settings-pane");
    const failures: Failure[] = [];
    for (let index = 0; index < titles.length; index += 1) {
      const title = titles[index];
      const mark = watch.mark();
      await nav.nth(index).click();

      const head = pane.locator(".soc-settings-head h3");
      await expect(head, `${title} did not become the active section`).toHaveText(title);
      // The pane, not the nav. A sub-menu that highlights the item it was given
      // and leaves the previous section on screen is the failure here.
      if ((await pane.locator(".soc-settings-row").count()) === 0) {
        failures.push({ item: title, reason: "the section opened with no rows in it" });
      }

      if (title === "Response") {
        // The ladder shows what an operator WOULD be changing. Its four inputs
        // are filled from /api/choke/state and left blank when that read fails,
        // so the only honest assertion is that they agree with it. Auto-retrying
        // because the section's two reads are sequential and the pane is opened
        // the moment the modal does.
        const inputs = pane.locator(".soc-settings-ladder input[type='number']");
        await expect(inputs, "the containment ladder lost an input").toHaveCount(4);
        const keys = ["throttle_at", "tarpit_at", "quarantine_at", "sever_at"];

        // A PANE THAT NEVER LOADED IS NOT A PANE THAT DISAGREES. SettingsResponse
        // renders `editing = draft ?? thresholds` (SettingsResponse.tsx:63) and
        // `value={editing ? editing[k] : ""}`, so a thresholds prop that never
        // arrives leaves ALL FOUR inputs blank — and the per-key loop below then
        // reports one "shows '' where the server reports N" per key the server
        // happens to publish. That reads as the console contradicting the server
        // when the truth is that its read failed, which is precisely the kind of
        // fabricated finding this file exists to avoid. Seen for real: 2026-08-28,
        // where two keys were reported as mismatched and the test passed on an
        // immediate re-run. So: if the server publishes a ladder and the pane is
        // ENTIRELY blank after settling, say that once, and skip the per-key diff.
        const serverHasLadder = keys.some((key) => chokeState?.thresholds?.[key] !== undefined);
        const populated = await settles(
          async () => (await inputs.evaluateAll((els) => els.some((el) => (el as HTMLInputElement).value !== ""))),
          30_000
        );
        const neverLoaded = serverHasLadder && !populated;
        if (neverLoaded) {
          failures.push({
            item: title,
            reason:
              "the containment ladder is entirely blank while /api/choke/state publishes thresholds — the pane never resolved its read, so its values cannot be compared"
          });
        }

        // Guarded, not `continue`d: the section's own live-read check below still
        // has to run for Response, and skipping the loop must not skip that too.
        for (let k = 0; !neverLoaded && k < keys.length; k += 1) {
          const want =
            chokeState?.thresholds && chokeState.thresholds[keys[k]] !== undefined
              ? String(chokeState.thresholds[keys[k]])
              : "";
          try {
            await expect(inputs.nth(k)).toHaveValue(want);
          } catch {
            failures.push({
              item: title,
              reason: `the ladder's ${keys[k]} shows "${await inputs.nth(k).inputValue()}" where /api/choke/state reports "${want}"`
            });
          }
        }
      }

      const reads = sectionReads[title];
      if (reads) {
        const resolved = reads.filter((path) => served[path]).length;
        const unserved = reads.length - resolved;

        // A placeholder that never resolves is this pane's quiet failure: every
        // live control renders "Reading the …" until its endpoint answers, and
        // a route this deployment does not serve must end that wait with a
        // statement rather than leaving the operator on it.
        await expect(
          pane.getByText(/^Reading the /),
          `${title} is still waiting on a read that never resolved`
        ).toHaveCount(0);

        if (title !== "Noise") {
          // One resolved control block per read that answered.
          const blocks = await pane.locator(".soc-guardrails").count();
          if (blocks !== resolved) {
            failures.push({
              item: title,
              reason: `${blocks} resolved control block(s) rendered where this deployment's endpoints support ${resolved}`
            });
          }
        }

        // And the console's account of the reads must match what they did.
        // A read that ANSWERED and is reported as broken is the failure; a read
        // this deployment does not serve has to be accounted for, not ignored.
        const excuses = pane.locator(".soc-notice").filter({
          hasText: /could not be|not applicable|no durable|deployment-wide here/i
        });
        const stated = await excuses.count();
        if (unserved === 0 && stated > 0) {
          failures.push({
            item: title,
            reason: `every endpoint behind this section answered, yet it says: "${(await excuses.first().innerText()).replace(/\s+/g, " ").slice(0, 160)}"`
          });
        }
        if (unserved > 0 && stated === 0) {
          failures.push({
            item: title,
            reason: `${unserved} of its reads did not answer here and the section says nothing about it`
          });
        }
      }

      const noise = watch.since(mark);
      if (noise.length) failures.push({ item: title, reason: `logged: ${noise[0].slice(0, 200)}` });
    }

    expect(report(failures), "settings sections misreported what this deployment answered").toEqual([]);

    await page.keyboard.press("Escape");
    await expect(modal, "Escape did not close Settings").toHaveCount(0);
  });

  /**
   * WHAT BUG THIS PINS: the Platform section promises a value it never shows.
   *
   * settingsModel.ts's `runtime` row is captioned "The deployed shape of this
   * installation" and its caveat says in as many words "Shown as the effective
   * value. Secrets are deliberately absent." SettingsBody.tsx renders a control
   * for suppressions, thresholds, protected, dual-control, retention and the
   * access trail, and NOTHING for `runtime` — so the one section a platform
   * engineer opens to answer "where does this run, and against what?" renders
   * the question, the caveat about the value, and no value.
   *
   * FIXED 2026-09-02: the section renders the effective runtime configuration it
   * advertises, and a field whose source did not answer says so rather than
   * showing a default that reads as a measurement.
   */
  test("the Platform settings section shows the effective values it says it shows", async ({ page }) => {
    await signIn(page, env);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await railItem(page, "Settings").click();
    const modal = page.locator('[data-panel="settings-modal"].is-open');
    await expect(modal, "Settings did not open").toHaveCount(1);

    // Matched on the section TITLE, not the button's text. Each nav item
    // renders <strong>{title}</strong><span>{owner}</span> (SettingsBody.tsx),
    // and "Platform team" is the OWNER of Guardrails, Access AND Platform — so
    // hasText:"Platform" resolves to three buttons and throws a strict-mode
    // violation — which, while this test was pinned, counted as the expected
    // failure, so it reported green while never reaching the product claim in
    // its docstring at all.
    await modal
      .locator("nav.soc-settings-nav button.soc-settings-navitem")
      .filter({ has: page.locator("strong", { hasText: /^Platform$/ }) })
      .click();
    const pane = modal.locator(".soc-settings-pane");
    await expect(pane.locator(".soc-settings-head h3")).toHaveText("Platform");

    // Anything at all that carries a READ VALUE rather than the static prose of
    // settingsModel: a field, a table, a code span, a resolved control block.
    await expect(
      pane.locator("input, select, code, table, .soc-guardrails, .soc-settings-form"),
      "the Platform section states the effective value is shown here and shows none"
    ).not.toHaveCount(0);
  });

  /**
   * WHAT BUG THIS PINS: a settings route this deployment deliberately does not
   * serve is reported to the operator as a FAILED READ.
   *
   * Retention, change control and the access trail are control-plane concepts;
   * a single-tenant engine registers none of them and answers 404. Two of the
   * three panels know that and say so — ChangeControlControls and
   * AccessTrailPanel both branch on 404 and render "not applicable to this
   * deployment", with a comment saying that showing a warning for it "would be
   * crying wolf on every engine console". RetentionControls has no such branch:
   * its catch sets loadError for any failure, so a correctly configured engine
   * shows an amber "Retention could not be read" every time an operator opens
   * Evidence. That is the exact habit this codebase's own notes say a console
   * must not teach — a warning that means nothing on a healthy box.
   *
   * FIXED 2026-09-02: RetentionControls has the 404 branch its two siblings have. The
   * control plane serves all three, so there is nothing to state as unavailable
   * and this test skips there — it is the engine that had the false warning.
   */
  test("a settings route this deployment does not serve is stated as not applicable, not as a failed read", async ({
    page
  }) => {
    await signIn(page, env);
    await page.goto("/", { waitUntil: "domcontentloaded" });

    const candidates = [
      { section: "Guardrails", path: "/api/settings/protected" },
      { section: "Evidence", path: "/api/settings/retention" },
      { section: "Access", path: "/api/settings/change-control" }
    ];
    const unserved: typeof candidates = [];
    for (const candidate of candidates) {
      const response = await page.request.get(candidate.path, { failOnStatusCode: false });
      if (response.status() === 404) unserved.push(candidate);
    }
    test.skip(
      unserved.length === 0,
      "this deployment serves every settings route, so it has nothing to describe as unavailable"
    );

    await railItem(page, "Settings").click();
    const modal = page.locator('[data-panel="settings-modal"].is-open');
    await expect(modal, "Settings did not open").toHaveCount(1);
    const pane = modal.locator(".soc-settings-pane");

    const failures: Failure[] = [];
    for (const entry of unserved) {
      await modal
        .locator("nav.soc-settings-nav button.soc-settings-navitem")
        .filter({ hasText: entry.section })
        .click();
      await expect(pane.locator(".soc-settings-head h3")).toHaveText(entry.section);
      // SETTLED FIRST. Each of these panes mounts its control only when its
      // section becomes active, and renders "Reading the …" until the fetch
      // it starts on mount resolves — so a one-shot count taken straight after
      // the click samples the placeholder, finds no warning, and reports a
      // pane that is about to cry wolf as well-behaved. That is not a
      // hypothetical: it is what made this test pass on the engine while the
      // engine answers /api/settings/retention 404 and the pane does raise
      // "Retention could not be read" a moment later.
      await expect(
        pane.getByText(/^Reading the /),
        `${entry.section} never finished the read this test is about`
      ).toHaveCount(0);
      const alarm = pane.locator(".soc-notice.tone-warn").filter({ hasText: /could not be (read|loaded)/i });
      if (await alarm.count()) {
        failures.push({
          item: entry.section,
          reason: `${entry.path} is not served here (404) and the pane raises a warning about it: "${(
            await alarm.first().innerText()
          )
            .replace(/\s+/g, " ")
            .slice(0, 120)}"`
        });
      }
    }

    expect(
      report(failures),
      "a route this deployment does not serve is being reported as a fault"
    ).toEqual([]);
  });

  /**
   * THE MENU LAYER THAT IS NOT THE RAIL. Every other test in this file walks
   * the navigation chrome — rail, palette, top bar, modals. The dashboard body
   * carries its own controls, and they were not being driven at all: the alert
   * queue's three filter chips and three sort buttons, and the event stream's
   * two. Those decide WHICH alerts an analyst is looking at, which makes a chip
   * that toggles its own pixels and filters nothing a wrong-conclusion bug, not
   * a cosmetic one — and that is exactly the class of defect already found in
   * this pair (event-stream Pause dims the strip and keeps appending).
   *
   * Read-only: each control is returned to the state it was found in, and the
   * assertions are on the console's own reported state, never on the estate.
   */
  test("the dashboard body's own filter, sort and stream controls all respond", async ({ page }) => {
    await signIn(page, env);
    const watch = new ConsoleWatch(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });

    const queue = page.locator('[data-panel="alert-triage-queue"]');
    const stream = page.locator('[data-panel="live-event-stream"]');
    await expect(queue, "the dashboard rendered without its alert queue").toHaveCount(1);
    await expect(stream, "the dashboard rendered without its event stream").toHaveCount(1);

    const settled = watch.mark();
    const failures: Failure[] = [];

    // ── the switches ────────────────────────────────────────────────────────
    // role=switch + aria-checked, so the assertion is on what the control
    // REPORTS about itself, not on a class name that happens to be styled.
    // `list` is the container each panel must still be rendering afterwards.
    // The CONTAINER, not rows: "Unacked only" on a fully-acked queue is
    // legitimately empty, and demanding rows would fail a working filter. What
    // must never happen is the panel losing its list altogether.
    const switches: Array<{ panel: Locator; label: string; where: string; list: string }> = [
      { panel: queue, label: "Hide baseline", where: "alert queue", list: ".soc-alert-list" },
      { panel: queue, label: "Unacked only", where: "alert queue", list: ".soc-alert-list" },
      { panel: queue, label: "Group", where: "alert queue", list: ".soc-alert-list" },
      { panel: stream, label: "Hide self-noise", where: "event stream", list: ".soc-event-list" },
      // Pause reads "Pause" when off and "Paused" when on, so it is matched on
      // the stem. This one is the known defect: the strip dims and keeps
      // appending. The toggle itself must still report its own state.
      { panel: stream, label: "Pause", where: "event stream", list: ".soc-event-list" }
    ];

    for (const control of switches) {
      const chip = control.panel.getByRole("switch", { name: new RegExp(`^${control.label}d?$`) });
      const item = `${control.where}: ${control.label}`;
      if ((await chip.count()) !== 1) {
        failures.push({ item, reason: `${await chip.count()} switches carry this label` });
        continue;
      }
      const before = await chip.isChecked();
      const mark = watch.mark();
      await chip.click();
      // Polled: the queue re-derives and re-renders, and an immediate read can
      // catch the pre-commit frame.
      const flipped = await settles(async () => (await chip.count()) === 1 && (await chip.isChecked()) !== before);
      if (!flipped) {
        failures.push({ item, reason: `clicking it left aria-checked at ${before} — the control does not report its own state` });
        continue;
      }
      // The panel must still have a body. A filter that empties its own panel
      // into a blank box is indistinguishable from a crash. inspectBody is not
      // reusable here — it looks inside `.soc-modal-card`, and these are
      // dashboard panels, not modals.
      if ((await control.panel.locator(control.list).count()) !== 1) {
        failures.push({ item, reason: `toggling it left no ${control.list} in the panel` });
      }
      const noise = watch.since(mark);
      if (noise.length) failures.push({ item, reason: `logged: ${noise[0].slice(0, 200)}` });

      // Put it back.
      await chip.click();
      await expect
        .poll(async () => chip.isChecked(), { timeout: 10_000, message: `${item} would not toggle back` })
        .toBe(before);
    }

    // ── the sort row ────────────────────────────────────────────────────────
    // Three fields. Each must take is-active, and exactly one at a time: two
    // active buttons means the analyst cannot tell what order they are reading.
    const sorts = queue.locator(".soc-sort-row button");
    await expect(sorts, "the alert queue does not offer time/severity/score").toHaveCount(3);
    const originalSort = await queue.locator(".soc-sort-row button.is-active").innerText().catch(() => "");
    for (let index = 0; index < 3; index += 1) {
      const field = (await sorts.nth(index).innerText()).trim();
      const mark = watch.mark();
      await sorts.nth(index).click();
      const active = queue.locator(".soc-sort-row button.is-active");
      // readText, not innerText: `.soc-sort-row > span` is uppercased in CSS and
      // the buttons are not, but that is a stylesheet away from changing and the
      // failure would read as a broken sort rather than a casing mismatch.
      const ok = await settles(async () => (await active.count()) === 1 && (await readText(active)) === field);
      if (!ok) {
        failures.push({
          item: `alert queue: sort by ${field}`,
          reason: `after clicking it, ${await active.count()} sort buttons are active and the active one is "${(await readText(active.first())) || "none"}"`
        });
      }
      const noise = watch.since(mark);
      if (noise.length) failures.push({ item: `alert queue: sort by ${field}`, reason: `logged: ${noise[0].slice(0, 200)}` });
    }
    if (originalSort) await sorts.filter({ hasText: originalSort }).first().click();

    expect(report(failures), "a dashboard body control did not respond").toEqual([]);
    expect(watch.since(settled), "the dashboard logged errors while its controls were driven").toEqual([]);
  });

  test("every KPI tile drills into its own distinct panel", async ({ page }) => {
    await signIn(page, env);
    const watch = new ConsoleWatch(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });

    const tiles = page.locator('[data-panel="kpi-row"] button.soc-exec-metric');
    // Exactly five. KpiDrill declares five kinds and the row ships five tiles,
    // so "more than three" is satisfied by a row that lost one.
    await expect(tiles, "the KPI row is not the five headline metrics").toHaveCount(5);
    const count = 5;

    const failures: Failure[] = [];
    const titles: string[] = [];
    for (let index = 0; index < count; index += 1) {
      const mark = watch.mark();
      const label = (await tiles.nth(index).locator(".soc-exec-metric-head span").innerText()).trim();
      await tiles.nth(index).click();

      const drill = page.locator('[data-panel="kpi-drill-modal"].is-open');
      await drill.waitFor({ state: "visible", timeout: 20_000 }).catch(() => undefined);
      if ((await drill.count()) === 0) {
        failures.push({ item: label, reason: "the tile opened no drill" });
        continue;
      }
      titles.push((await drill.locator(".soc-modal-head h2").innerText()).trim());

      const failure = await inspectBody(drill.first(), label, "kpi-drill-modal", /alert|event|process|score|window/i);
      if (failure) failures.push(failure);

      const noise = watch.since(mark);
      if (noise.length) failures.push({ item: label, reason: `logged: ${noise[0].slice(0, 200)}` });

      await page.keyboard.press("Escape");
      await expect(drill, `${label}'s drill would not close`).toHaveCount(0);
    }

    // COVERAGE, not merely separation. Distinct titles prove the five tiles do
    // not share a drill; they do not prove the five DRILLS were reached, which
    // is what a mis-wired tile costs.
    expect(titles.slice().sort(), "the five tiles did not reach the five declared drills").toEqual(
      ["Critical alerts", "Events per second", "High alerts", "Medium alerts", "Processes seen"].sort()
    );
    expect(report(failures), "a KPI drill failed on live data").toEqual([]);
  });

  /**
   * The top bar is a menu too: it re-scopes every panel below it.
   *
   * The five-button time-range group is the single most consequential control
   * on the dashboard that changes nothing on the estate — every count, every
   * sparkline, every notice's stated window follows it — and the search field
   * and its "/" hotkey are the only way an analyst narrows the queue. All of it
   * is client state plus GETs.
   */
  test("the top bar re-scopes the dashboard, refreshes it, and takes the search hotkey", async ({ page }) => {
    await signIn(page, env);
    const watch = new ConsoleWatch(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const settled = watch.mark();

    const range = page.getByRole("group", { name: "Time range" });
    const buttons = range.getByRole("button");
    await expect(buttons, "the time-range group is not the five windows the dashboard offers").toHaveCount(5);
    expect(
      (await buttons.allInnerTexts()).map((text) => text.trim()),
      "the time-range labels drifted from the window formatter every notice uses"
    ).toEqual(["5m", "30m", "1h", "24h", "7d"]);

    const active = range.locator("button.is-active");
    const restore = (await active.count()) === 1 ? (await active.innerText()).trim() : "30m";
    const failures: Failure[] = [];
    for (const label of ["5m", "30m", "1h", "24h", "7d"]) {
      const button = buttons.filter({ hasText: new RegExp(`^${label}$`) });
      await button.click();
      await expect(button, `${label} did not become the selected window`).toHaveClass(/is-active/);
      // The claim is not that a button highlighted — it is that the PANELS
      // below now say they cover that window. The KPI tiles print it.
      const meta = page.locator('[data-panel="kpi-row"] .soc-exec-metric-foot > span').first();
      if ((await meta.count()) === 0) {
        failures.push({ item: label, reason: "the KPI tiles stopped stating the window they cover" });
        continue;
      }
      const text = (await meta.innerText()).replace(/\s+/g, " ").trim();
      if (!text.includes(label)) {
        failures.push({ item: label, reason: `the tiles still say "${text}" after selecting ${label}` });
      }
    }
    await buttons.filter({ hasText: new RegExp(`^${restore}$`) }).click();

    // Refresh: a read, and the only control that re-polls on demand.
    const refresh = page.getByRole("button", { name: "Refresh snapshots" });
    await expect(refresh, "the dashboard cannot be refreshed by hand").toHaveCount(1);
    await refresh.click();
    await expect(page.getByRole("heading", { name: /stopped rendering/i })).toHaveCount(0);

    // The search field and the hotkey that focuses it. The listener is on
    // window and ignores keys typed inside an input, so the body has to hold
    // focus first — which is also the state an analyst is in when they press it.
    const search = page.locator(".soc-search input");
    await expect(search, "the top bar has no search field").toHaveCount(1);
    await page.locator('[data-panel="top-bar"]').click({ position: { x: 2, y: 2 } });
    await page.keyboard.press("/");
    await expect(search, "the / hotkey did not focus the search field").toBeFocused();
    await search.fill("zzz-no-such-process-zzz");
    await expect(search).toHaveValue("zzz-no-such-process-zzz");
    // A "/" typed INTO the field must reach the field, not re-trigger the hotkey.
    await page.keyboard.press("/");
    await expect(search, "the hotkey fired while the operator was typing in it").toHaveValue(
      "zzz-no-such-process-zzz/"
    );
    await search.fill("");

    expect(report(failures), "the time range did not re-scope the dashboard").toEqual([]);
    expect(watch.since(settled), "the top bar logged errors while it was driven").toEqual([]);
  });

  test("the correlation graph maximises and minimises on live telemetry", async ({ page }) => {
    await signIn(page, env);
    const watch = new ConsoleWatch(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const settled = watch.mark();

    await railItem(page, "Correlation Graph").click();
    const modal = page.locator('[data-panel="process-correlation-graph-modal"].is-open');
    await expect(modal, "the correlation graph did not open").toHaveCount(1);

    const shell = modal.locator(".soc-graph-shell");
    await expect(shell, "the graph shell did not render").toBeVisible();
    await expect(shell, "the graph opened already maximised").not.toHaveClass(/is-maximized/);

    await modal.getByRole("button", { name: "Maximize graph" }).click();
    await expect(shell, "Maximize did not change the graph shell").toHaveClass(/is-maximized/);
    // The canvas has to survive the relayout — this is where a D3 bridge that
    // measures once and never again leaves an empty box behind.
    await expect(modal.locator("svg.soc-correlation-graph"), "the graph canvas is gone after maximising").toBeVisible();

    await modal.getByRole("button", { name: "Minimize graph" }).click();
    await expect(shell, "Minimize left the graph maximised").not.toHaveClass(/is-maximized/);

    await page.keyboard.press("Escape");
    await expect(modal, "Escape did not close the graph").toHaveCount(0);
    expect(watch.since(settled), "the correlation graph logged errors while it was driven").toEqual([]);
  });

  /**
   * The palette is a menu, so its ITEMS are selected, not merely listed.
   *
   * Enumerating the labels proves the list rendered; it does not prove that
   * choosing one reaches the surface it names — which is the whole of what a
   * command palette does, and is wiring that has been wrong here before (an
   * item pointing at a surface the shell no longer hosts opens nothing at all).
   * Only the three commands whose surfaces change nothing are selected; the
   * rest fire presets, exports and lab injectors and are read, never run.
   */
  test("the command palette opens on Ctrl+K and its safe commands reach their surfaces", async ({ page }) => {
    await signIn(page, env);
    const watch = new ConsoleWatch(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const settled = watch.mark();
    // Focus the document body first: the hotkey is a window listener, and a
    // page that has never been clicked delivers the key nowhere.
    await page.locator('[data-panel="top-bar"]').click({ position: { x: 2, y: 2 } });

    await page.keyboard.press("Control+k");
    const palette = page.locator('[data-panel="command-palette"].is-open');
    await expect(palette, "Ctrl+K did not open the command palette").toHaveCount(1);

    const items = palette.locator(".soc-command-list [cmdk-item]");
    const labels = (await items.allInnerTexts()).map((text) => text.replace(/\s+/g, " ").trim());
    expect(labels.length, "the palette opened with no commands in it").toBeGreaterThan(3);
    test.info().annotations.push({ type: "note", description: `command palette: ${labels.join(" | ")}` });

    await page.keyboard.press("Escape");
    await expect(palette, "Escape did not close the palette").toHaveCount(0);

    // EVERY command the palette offers that is not lab-gated. Six of the eight;
    // "Open attacks" and "Show honeypots" are the two the lab gate is supposed
    // to withhold, and they get their own test below. Covering three of eight
    // and calling the palette exercised is how the gap in the other five would
    // have stayed invisible — each of these mounts a different body, and a
    // command that opens the wrong surface, or none, looks identical from the
    // palette itself.
    const safe: Array<{ label: string; panel: string }> = [
      { label: "Show help", panel: "help-modal" },
      { label: "Open watchlist", panel: "watchlist-modal" },
      { label: "Show sensor health", panel: "sensor-health-modal" },
      { label: "Show policies", panel: "detections-modal" },
      { label: "Open correlation graph", panel: "process-correlation-graph-modal" },
      // The export CONFIRM modal, not an export. It asks first; opening it
      // writes nothing and starts no download.
      { label: "Open export", panel: "export-confirm-modal" }
    ];
    const failures: Failure[] = [];
    for (const command of safe) {
      const mark = watch.mark();
      await page.keyboard.press("Control+k");
      await expect(palette, `Ctrl+K did not reopen the palette for "${command.label}"`).toHaveCount(1);
      const item = items.filter({ hasText: command.label });
      if ((await item.count()) !== 1) {
        failures.push({ item: command.label, reason: `${await item.count()} palette entries carry this label` });
        await page.keyboard.press("Escape");
        continue;
      }
      await item.click();

      const surface = page.locator(`[data-panel="${command.panel}"].is-open`);
      await surface.waitFor({ state: "visible", timeout: 20_000 }).catch(() => undefined);
      if ((await surface.count()) === 0) {
        failures.push({ item: command.label, reason: `selecting it opened no [data-panel="${command.panel}"]` });
        await page.keyboard.press("Escape");
        continue;
      }
      // Selecting a command must also DISMISS the palette — the surfaces are
      // mutually exclusive, so a palette still carrying is-open means the shell
      // swapped the body and left the chooser on top of it.
      if ((await palette.count()) !== 0) {
        failures.push({ item: command.label, reason: "the palette stayed open behind the surface it opened" });
      }
      const failure = await inspectBody(surface.first(), command.label, command.panel);
      if (failure) failures.push(failure);
      const noise = watch.since(mark);
      if (noise.length) failures.push({ item: command.label, reason: `logged: ${noise[0].slice(0, 200)}` });

      await page.keyboard.press("Escape");
      await expect(surface, `${command.label} would not close`).toHaveCount(0);
    }

    expect(report(failures), "a palette command did not reach its surface").toEqual([]);
    expect(watch.since(settled), "the palette logged errors while it was driven").toEqual([]);
  });

  /**
   * WHAT BUG THIS PINS: the command palette walks around the lab gate.
   *
   * Sidebar.tsx hides Attack Sim and Honeypots unless the SERVER reports
   * lab_mode, and says why in as many words — Attack Sim runs a script as root
   * on the host being defended and, on the control plane, writes fabricated
   * alerts into the tenant's real evidence store. The palette's own item list
   * (commandItems in SocModals.tsx) is gated on nothing, so "Open attacks" and
   * "Show honeypots" open those surfaces on a production deployment that
   * deliberately hides them. Selecting a palette entry opens its shell, so this
   * never depended on when the body mounted: lazy mounting does not narrow the
   * door, and the gate is the only thing that closes it.
   *
   * FIXED 2026-09-02: commandItems reads the same server-reported lab_mode the rail
   * does, from one predicate, so the two cannot drift apart again.
   */
  test("the command palette does not offer surfaces the deployment gates off", async ({ page }) => {
    await signIn(page, env);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const lab = await labModeReported(page);
    test.skip(lab, "this deployment IS a lab, so the lab commands are correctly on offer");

    await page.locator('[data-panel="top-bar"]').click({ position: { x: 2, y: 2 } });
    await page.keyboard.press("Control+k");
    const palette = page.locator('[data-panel="command-palette"].is-open');
    await expect(palette, "Ctrl+K did not open the command palette").toHaveCount(1);

    const labels = (await palette.locator(".soc-command-list [cmdk-item]").allInnerTexts()).map((text) =>
      text.replace(/\s+/g, " ").trim()
    );
    expect(labels.length, "no commands to check").toBeGreaterThan(3);
    // Read-only: the offending commands are named, never selected.
    expect(
      labels.filter((label) => /attack|honeypot|simulat/i.test(label)),
      "the palette offers lab-gated surfaces on a deployment that reported lab_mode=false"
    ).toEqual([]);

    await page.keyboard.press("Escape");
  });

  test("the dashboard status pills each open their own popover", async ({ page }) => {
    await signIn(page, env);
    const watch = new ConsoleWatch(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const settled = watch.mark();

    const pills: Array<{ name: string; locator: Locator }> = [
      { name: "host", locator: page.locator("button.soc-host-pill") },
      { name: "live", locator: page.locator("button.soc-live-pill") },
      { name: "risk", locator: page.locator('button[title="View risk breakdown"]').first() }
    ];

    const popover = page.locator('[data-panel="pill-popovers"].is-open');
    const failures: Failure[] = [];
    const titles: string[] = [];

    for (const pill of pills) {
      if ((await pill.locator.count()) === 0) {
        failures.push({ item: pill.name, reason: "the pill is not rendered on this deployment" });
        continue;
      }
      await pill.locator.click();
      await popover.first().waitFor({ state: "visible", timeout: 15_000 }).catch(() => undefined);
      if ((await popover.count()) !== 1) {
        failures.push({ item: pill.name, reason: `${await popover.count()} popovers carried is-open` });
        continue;
      }
      titles.push((await popover.locator(".soc-popover-head").first().innerText()).replace(/\s+/g, " ").trim());
      const body = popover.locator("> *:not(.soc-popover-head)");
      if (((await body.allInnerTexts()).join(" ").trim()).length < 8) {
        failures.push({ item: pill.name, reason: "the popover opened empty" });
      }
      await page.keyboard.press("Escape");
      await expect(popover, `${pill.name} popover would not close`).toHaveCount(0);
    }

    expect(new Set(titles).size, "two pills opened the same popover").toBe(titles.length);
    expect(report(failures), "a status pill misbehaved").toEqual([]);
    expect(watch.since(settled), "the status pills logged errors while they were driven").toEqual([]);
  });

  /**
   * The alert row's right-click menu, and the drill it hands off to.
   *
   * This is the console's ONLY SlideOver — the exact container that hides
   * itself with `transform: translateX(102%)` and that Playwright still counts
   * as visible, so `is-open` is the only claim that means anything about it.
   * It is also the panel this file's docstring names as the historical crash (a
   * drill dereferencing an optional field), and it renders on whatever this
   * deployment's alerts actually contain.
   *
   * Safe on a production box: the menu's four entries are Open (opens the
   * drill), Acknowledge, Resolve and Pin — all three of the latter write only
   * this browser's localStorage. Only "Open drill" is selected; the drill's own
   * containment control is asserted present and left alone.
   */
  test("right-clicking an alert offers its menu, and Open reaches the drill slide-over", async ({ page }) => {
    await signIn(page, env);
    const watch = new ConsoleWatch(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const settled = watch.mark();

    // Widen the window first: the menu needs a row, and the default 30 minutes
    // is not where a quiet estate keeps its alerts.
    await page.getByRole("group", { name: "Time range" }).getByRole("button", { name: "7d", exact: true }).click();

    const rows = page.locator(".soc-alert-row");
    await rows.first().waitFor({ state: "visible", timeout: 30_000 }).catch(() => undefined);
    if ((await rows.count()) === 0) {
      test.info().annotations.push({
        type: "note",
        description: `no alerts in 7d on ${env.kind}: the alert context menu and the drill slide-over were not exercised`
      });
      test.skip(true, "this deployment has no alert rows to open a drill from");
      return;
    }

    await rows.first().click({ button: "right" });
    // SCOPED BY CLASS as well as by panel: the hover preview and the context
    // menu are ONE entry in the panel inventory ("Alert hover preview + context
    // menu") and carry the SAME data-panel, and moving the pointer onto a row
    // opens the preview — so the panel id alone matches two overlays here.
    const menu = page.locator('[data-panel="alert-hover-preview-context-menu"].soc-context-menu');
    await expect(menu, "right-clicking an alert opened no context menu").toHaveClass(/is-open/);
    expect(
      (await menu.getByRole("button").allInnerTexts()).map((text) => text.trim()),
      "the alert context menu is not the four actions it ships"
    ).toEqual(["Open drill", "Acknowledge", "Resolve", "Toggle pin"]);

    await menu.getByRole("button", { name: "Open drill" }).click();
    const slide = page.locator('[data-panel="drill-down-slide-over"]');
    // is-open, NOT toBeVisible: this aside is in the layout at all times and is
    // pushed off-screen with a transform Playwright does not treat as hidden.
    await expect(slide, "the drill slide-over never took is-open").toHaveClass(/is-open/);
    await expect(slide, "the drill opened but stayed hidden from assistive tech").toHaveAttribute(
      "aria-hidden",
      "false"
    );

    const drill = slide.locator(".soc-drill");
    await expect(drill, "the drill panel opened with no body on live alert data").toHaveCount(1);
    await expect(drill.locator(".soc-drill-hero strong"), "the drill did not name the alert").not.toBeEmpty();
    await expect(
      drill.locator(".soc-drill-section h3"),
      "the drill lost its sections (narrative, response, lineage, indicators)"
    ).not.toHaveCount(0);
    // The containment control this panel hosts. Present, and not pressed.
    await expect(
      drill.locator("button.soc-danger-button"),
      "the drill's choke action is gone"
    ).toHaveCount(1);

    await page.keyboard.press("Escape");
    await expect(slide, "Escape did not close the drill").not.toHaveClass(/is-open/);
    expect(watch.since(settled), "the alert drill logged errors on this deployment's data").toEqual([]);
  });

  /**
   * The lab surfaces write FABRICATED findings into whatever evidence store the
   * deployment points at — on the control plane, a tenant's real one. Their
   * ABSENCE on a customer box is the correct behaviour, so it is asserted as
   * carefully as their presence would be. Both deployments report
   * lab_mode=false, so on this estate this test only ever asserts absence.
   */
  test("lab-only surfaces appear only where the server reports lab mode", async ({ page }) => {
    await signIn(page, env);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const lab = await labModeReported(page);

    const watch = new ConsoleWatch(page);
    const failures: Failure[] = [];
    for (const surface of SOC_SURFACES.filter((entry) => entry.labOnly)) {
      const item = railItem(page, surface.nav);
      if (!lab) {
        await expect(
          item,
          `${surface.nav} is offered on a deployment that did not report lab_mode`
        ).toHaveCount(0);
        continue;
      }
      // lab_mode is on: drive them, but never RUN anything.
      const failure = await openAndInspect(
        page,
        watch,
        { group: "Manage", label: surface.nav, kind: "button" },
        { kind: "surface", panel: surface.panel, contains: surface.contains }
      );
      if (failure) failures.push(failure);
    }

    test.info().annotations.push({
      type: "note",
      description: `${env.kind} reports lab_mode=${lab}; lab surfaces were ${lab ? "driven read-only" : "asserted absent"}`
    });
    expect(report(failures), "a lab surface failed on a lab deployment").toEqual([]);
  });

  /**
   * The assistant sidebar, and the ONE surface that is only reachable from it.
   *
   * What the sidebar says about itself is checked against what the deployment
   * answers, not against its own chrome: the header renders a static
   * "Read-only" chip on every open, configured or not, so a regex over the
   * panel's text passes for an assistant whose model, history and enrichment
   * all failed. The claims here are correlations — /api/assistant decides
   * whether a composer is offered, /api/assistant/chats decides whether the
   * history banner appears, /api/baseline and /api/intel decide what the
   * enrichment strip is allowed to say.
   *
   * NOTHING IS ASKED. A question spends a model call against a customer's
   * budget and writes a conversation into their store; the composer is proven
   * present and enabled, and left empty.
   */
  test("the assistant sidebar reports this deployment honestly and opens Behaviour & Intel", async ({ page }) => {
    test.setTimeout(4 * 60_000);
    await signIn(page, env);
    const watch = new ConsoleWatch(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });

    const enabled = await assistantIsConfigured(page);
    const chats = await page.request.get("/api/assistant/chats", { failOnStatusCode: false });
    const historyServed = chats.status() === 200;
    const baseline = await readJson<{ enabled?: boolean; status?: { ready?: boolean } }>(page, "/api/baseline?top=1");
    const intel = await readJson<{ status?: { indicators?: number } }>(page, "/api/intel");
    const settled = watch.mark();

    await railItem(page, "Assistant").click();
    const sidebar = page.getByRole("complementary", { name: "Platform assistant" });
    await expect(sidebar, "the Assistant rail item opened no sidebar").toBeVisible();

    // ── what it says about the model ──────────────────────────────────────
    const composer = sidebar.getByRole("textbox", { name: "Ask the assistant" });
    if (enabled) {
      await expect(composer, "/api/assistant reports enabled and there is nowhere to type").toHaveCount(1);
      await expect(composer, "the composer is present but disabled on a deployment with an assistant").toBeEnabled();
    } else {
      await expect(
        sidebar.getByText(/not configured|unavailable|no assistant|disabled/i),
        "no assistant is configured here and the sidebar does not say so"
      ).not.toHaveCount(0);
    }

    // ── what it says about history ────────────────────────────────────────
    // Settled first: the status starts "loading", and HistoryBanner renders
    // nothing while it is — so an immediate "no warning is shown" assertion is
    // satisfied by a panel that has not finished asking yet.
    await sidebar
      .locator(".chat__note, .chat__empty, .chat__item")
      .first()
      .waitFor({ state: "attached", timeout: 20_000 })
      .catch(() => undefined);
    const banner = sidebar.locator(".chat__note");
    if (historyServed) {
      await expect(
        banner,
        "the chat store answered 200 and the sidebar still warns that history is off or broken"
      ).toHaveCount(0);
    } else {
      await expect(
        banner,
        `the chat store answered ${chats.status()} and the sidebar claims nothing about it`
      ).toHaveCount(1);
    }

    // ── what it says about enrichment ─────────────────────────────────────
    // The strip is the reason Behaviour & Intel could leave the nav, so it has
    // to AGREE with the endpoints rather than merely render.
    const strip = sidebar.locator(".chat__enrich");
    await expect(strip, "the enrichment strip did not render").toHaveCount(1);
    const stripText = strip.locator(".chat__enrich-text");
    const failures: Failure[] = [];

    // Each check is one claim the ENDPOINTS make, polled against what the strip
    // says. Polled rather than sampled: the summary is fetched when the sidebar
    // opens, and until it lands the strip shows its "Behaviour & reputation"
    // placeholder — reading once catches the placeholder and proves nothing.
    const claims: Array<{ what: string; pattern: RegExp }> = [];
    if (!baseline && !intel) {
      claims.push({
        what: "neither /api/baseline nor /api/intel answered",
        pattern: /not enabled on this deployment/i
      });
    } else {
      if (baseline) {
        const ready = baseline.enabled === true && baseline.status?.ready === true;
        claims.push({
          what: `/api/baseline reports ready=${ready}`,
          pattern: ready ? /Baseline ready/i : /Baseline still learning/i
        });
      }
      if (intel) {
        const indicators = intel.status?.indicators ?? 0;
        claims.push({
          what: `/api/intel reports ${indicators} indicator(s)`,
          pattern:
            indicators === 0
              ? /no threat-intel indicators loaded/i
              : new RegExp(`\\b${indicators}\\s+indicators`)
        });
      }
    }
    // Thousands separators are stripped before matching: the strip formats with
    // the BROWSER's locale and this file runs in node's, and a probe that fails
    // on a comma is reporting nothing about the deployment.
    const readStrip = async () => (await stripText.innerText()).replace(/[,\u202f\u00a0](?=\d)/g, "").replace(/\s+/g, " ").trim();
    for (const claim of claims) {
      try {
        await expect.poll(async () => claim.pattern.test(await readStrip()), { timeout: 25_000 }).toBe(true);
      } catch {
        failures.push({ item: "enrichment strip", reason: `${claim.what}, and the strip says "${await readStrip()}"` });
      }
    }

    // ── the sidebar's own sub-menus ───────────────────────────────────────
    // BY CLASS, not by accessible name: getByRole's `name` is a case-insensitive
    // SUBSTRING match, and this list is full of buttons named after whatever the
    // operator called their conversations — one titled "New firewall rule" makes
    // a name-based locator for "New" ambiguous on exactly the deployments that
    // have history.
    const conversations = sidebar.locator("button.chat__list-toggle");
    await expect(conversations, "the Conversations list has no toggle").toHaveCount(1);
    await expect(conversations, "the conversation list did not start expanded").toHaveAttribute(
      "aria-expanded",
      "true"
    );
    const search = sidebar.getByRole("searchbox", { name: "Search conversations" });
    await expect(search, "the conversation search field is missing while the list is open").toHaveCount(1);
    const newChat = sidebar.locator("button.chat__new");
    await expect(newChat, "there is no way to start a conversation").toHaveCount(1);

    // Typing a search is a GET against the chat store; on a deployment with no
    // store it is one of the deliberate 503s ConsoleWatch correlates.
    await search.fill("zzz-no-such-conversation");
    await expect(search).toHaveValue("zzz-no-such-conversation");
    await search.fill("");

    await conversations.click();
    await expect(conversations, "the Conversations toggle did not collapse the list").toHaveAttribute(
      "aria-expanded",
      "false"
    );
    await expect(search, "collapsing the list left its search field behind").toHaveCount(0);
    await conversations.click();
    await expect(conversations, "the Conversations list would not come back").toHaveAttribute(
      "aria-expanded",
      "true"
    );
    // Starting a new conversation is local until a question is sent: it clears
    // the selection and focuses the composer. Nothing is created server-side.
    await newChat.click();
    if (enabled) {
      await expect(composer, "the new-chat button did not put the operator in the composer").toBeFocused();
    }

    // ── Behaviour & Intel, reachable ONLY from here when an assistant exists ─
    const findings = sidebar.getByRole("button", { name: "View the findings" });
    await expect(
      findings,
      "the enrichment strip offers no way into the findings — with an assistant configured, Behaviour & Intel has no other entry point"
    ).toHaveCount(1);
    await findings.click();
    const behaviour = page.locator('[data-panel="behaviour-modal"].is-open');
    await expect(behaviour, "'View the findings' opened no Behaviour & Intel panel").toHaveCount(1);
    const failure = await inspectBody(behaviour.first(), "Behaviour & Intel", "behaviour-modal", /baseline|anomal|intel|normal/i);
    if (failure) failures.push(failure);

    await page.keyboard.press("Escape");
    await expect(behaviour, "Escape did not close Behaviour & Intel").toHaveCount(0);

    expect(report(failures), "the assistant sidebar misreported this deployment").toEqual([]);
    expect(watch.since(settled), "the assistant logged errors while its menus were driven").toEqual([]);
  });

  test("the Choke Gateway's chrome opens every surface it advertises", async ({ page }) => {
    test.setTimeout(5 * 60_000);
    await signIn(page, env);
    const watch = new ConsoleWatch(page);
    const approvals = await readJson<{ approvals?: Array<{ status?: string }> }>(page, "/api/approvals");
    await page.goto("/choke", { waitUntil: "domcontentloaded" });
    await expect(page.locator(".choke-route"), "the Choke route did not render").toBeVisible();
    await expect(page.getByRole("heading", { name: /stopped rendering/i })).toHaveCount(0);

    // Measured from HERE, not from the first byte: what this test is about is
    // what the MENUS log, and a route's own boot-time reads (fleet and device
    // endpoints answer 503 where those planes are switched off) belong to
    // deployment.probe.spec.ts, which checks them deliberately.
    const settled = watch.mark();
    const failures: Failure[] = [];

    // ── the Command ⇄ Assurance lens ──────────────────────────────────────
    const tabs = page.locator(".cc-viewtoggle button[role='tab']");
    const tabNames = (await tabs.allInnerTexts()).map((text) => text.trim());
    expect(tabNames, "the containment lens lost a tab").toEqual(["Command", "Assurance"]);

    await tabs.nth(1).click();
    await expect(page.locator('[data-panel="assurance-view"]'), "Assurance did not render").toBeVisible();
    await tabs.nth(0).click();
    await expect(
      page.locator('[data-panel="threat-intelligence-ribbon"]'),
      "Command did not come back"
    ).toBeVisible();
    // Left as it was found: the lens is persisted in localStorage.

    // ── the four status-pill popovers, discovered from the cluster ─────────
    const statusPills = page.locator(".choke-status-cluster button.choke-pill");
    const pillCount = await statusPills.count();
    expect(pillCount, "the choke status cluster rendered no pills").toBeGreaterThan(3);

    const opened: string[] = [];
    for (let index = 0; index < pillCount; index += 1) {
      const mark = watch.mark();
      const label = (await statusPills.nth(index).innerText()).replace(/\s+/g, " ").trim();
      await statusPills.nth(index).click();
      const popover = page.locator('[data-panel^="pill-popover-"]');
      await popover.first().waitFor({ state: "visible", timeout: 15_000 }).catch(() => undefined);
      if ((await popover.count()) !== 1) {
        failures.push({ item: `pill ${label}`, reason: `${await popover.count()} popovers were mounted` });
        continue;
      }
      opened.push(((await popover.getAttribute("data-panel")) ?? "").replace("pill-popover-", ""));
      if (((await popover.innerText()).replace(/\s+/g, " ").trim()).length < 8) {
        failures.push({ item: `pill ${label}`, reason: "the popover opened empty" });
      }
      const noise = watch.since(mark);
      if (noise.length) failures.push({ item: `pill ${label}`, reason: `logged: ${noise[0].slice(0, 200)}` });
      await page.keyboard.press("Escape");
      await expect(popover, `the ${label} popover would not close`).toHaveCount(0);
    }
    expect(
      opened.slice().sort(),
      "the four status pills must open four distinct popovers"
    ).toEqual(["audit", "host", "live", "mode"]);

    // ── notifications ─────────────────────────────────────────────────────
    await page.getByRole("button", { name: "Notifications" }).click();
    const alerts = page.locator('[data-panel="notifications-panel"]');
    await expect(alerts, "the alerts drawer did not open").toBeVisible();
    await alerts.getByRole("button", { name: "Close alerts" }).click();
    await expect(alerts, "the alerts drawer would not close").toHaveCount(0);

    // ── the profile dropdown, and everything inside it ────────────────────
    await page.getByRole("button", { name: "Profile and tools" }).click();
    const profile = page.locator('[data-panel="admin-profile-dropdown-avatar"]');
    await expect(profile, "the profile dropdown did not open").toBeVisible();
    // Sign out is asserted, NEVER clicked here: this session is shared with the
    // rest of the run. It is exercised in an owned context further down.
    await expect(profile.getByRole("link", { name: "Sign out" })).toHaveAttribute("href", "/api/logout");
    for (const control of ["Snapshot", "Thaw all", "Command palette", "Help & shortcuts"]) {
      await expect(
        profile.getByRole("button", { name: control }),
        `the profile menu lost "${control}"`
      ).toHaveCount(1);
    }
    // The dropdown's own sub-controls, which nothing else enumerates.
    const kvRows = profile.locator(".choke-kv-list > div");
    expect(
      // Lower-cased: innerText returns the RENDERED text and these labels are
      // uppercased by CSS, so the case here is a styling fact, not a claim.
      (await kvRows.locator("span").allInnerTexts()).map((text) => text.trim().toLowerCase()),
      "the profile menu's session readout lost a row"
    ).toEqual(["session", "decisions seen", "acked", "theme", "density"]);
    // The density control is a button whose LABEL is the current density; it is
    // read and left alone, because it is persisted view state for this operator.
    await expect(
      profile.locator(".choke-kv-list button"),
      "the density toggle is gone from the profile menu"
    ).toHaveCount(1);
    const defaultWindow = profile.locator(".choke-profile-window select");
    await expect(defaultWindow, "the profile menu lost its default-window select").toHaveCount(1);
    // The same five windows the ops bar offers. Two lists of window options
    // that drift apart is how an operator sets a default the toolbar cannot show.
    expect(
      (await defaultWindow.locator("option").allInnerTexts()).map((text) => text.trim()),
      "the profile's default-window options disagree with the ops bar's window selector"
    ).toEqual(
      (await page.locator('[data-panel="topbar-row-2"] .choke-segmented button').allInnerTexts()).map((text) =>
        text.trim()
      )
    );

    await profile.getByRole("button", { name: "Help & shortcuts" }).click();
    const help = page.locator('[data-panel="help-modal"]');
    await expect(help, "the help modal did not open from the profile menu").toBeVisible();
    await expect(help.locator("kbd").first(), "the keyboard map rendered no keys").toBeVisible();
    await page.keyboard.press("Escape");
    await expect(help, "the help modal would not close").toHaveCount(0);

    await page.getByRole("button", { name: "Profile and tools" }).click();
    await profile.getByRole("button", { name: "Command palette" }).click();
    const palette = page.locator('[data-panel="command-palette"]');
    await expect(palette, "the command palette did not open from the profile menu").toBeVisible();
    const commands = palette.locator("[cmdk-item]");
    // LAB-AWARE, like the SOC palette test below. The palette is gated on the
    // server's lab_mode: Attack Sim, Honeypots and the Rule Simulator are
    // withheld on a deployment that is not a lab, which takes this list from
    // five items to three. A bare "more than three" encoded the UNGATED count
    // and so failed the moment the gate started working — asserting the defect
    // rather than the fix.
    const chokeLab = await labModeReported(page);
    const listed = await commands.count();
    expect(listed, "the choke palette listed no commands").toBeGreaterThan(0);
    if (chokeLab) {
      expect(listed, "a lab deployment must still offer its lab commands here").toBeGreaterThan(3);
    }
    const labCommands = palette.getByText(/attack sim|honeypot|rule simulator/i);
    expect(
      (await labCommands.count()) > 0,
      chokeLab
        ? "this deployment reports lab_mode and the palette withholds the lab commands anyway"
        : "the palette offers a lab surface on a deployment that hides it from the rail — the second door the gate exists to close"
    ).toBe(chokeLab);
    // Enumerated, never selected: these items fire presets and the kill-switch.
    await page.keyboard.press("Escape");
    await expect(palette, "the choke palette would not close").toHaveCount(0);
    // The dropdown hands off to the palette and closes behind it. If it ever
    // stops doing that, everything below would be clicking through an overlay
    // and reporting the wrong control as broken.
    await expect(profile, "the profile dropdown stayed open behind the palette it opened").toHaveCount(0);

    // ── the containment ladder: a FILTER, not an action ───────────────────
    // Read before driven: ContainmentLadder's onRungClick is toggleRungFilter,
    // client-side view state in useChokeFilters. No rung applies containment —
    // the acting controls are the plane cluster and the jail picker, both left
    // alone below.
    const ladder = page.locator('[data-panel="containment-ladder"]');
    await expect(ladder, "the containment ladder is gone").toHaveCount(1);
    const rungs = ladder.locator("button.cc-rung");
    expect(
      // Lower-cased: the rung labels are uppercased by CSS and innerText returns
      // what is rendered.
      (await rungs.locator(".cc-rung-label").allInnerTexts()).map((text) => text.trim().toLowerCase()),
      "the containment ladder is not the five rungs the platform escalates through"
    ).toEqual(["pristine", "throttle", "tarpit", "quarantine", "sever"]);
    await expect(ladder, "the ladder does not say it filters").toContainText("click a rung to filter");
    const rung = rungs.nth(1);
    await rung.click();
    await expect(rung, "clicking a rung did not select it as a filter").toHaveAttribute("aria-pressed", "true");
    await rung.click();
    await expect(rung, "clicking the selected rung did not clear the filter").toHaveAttribute(
      "aria-pressed",
      "false"
    );

    // ── the active-filter strip, which only exists while something filters ─
    const strip = page.locator('[data-panel="active-filter-strip"]');
    await expect(strip, "the filter strip is on screen with nothing filtered").toHaveCount(0);
    const search = page.locator("input[data-choke-global-search]");
    await expect(search, "the choke route has no global search").toHaveCount(1);
    await search.fill("zzz-no-such-process-zzz");
    await expect(strip, "searching did not raise the active-filter strip").toHaveCount(1);
    await expect(strip, "the strip does not name the filter it is standing for").toContainText(
      "search: zzz-no-such-process-zzz"
    );
    await strip.getByRole("button", { name: "Clear all" }).click();
    await expect(strip, "Clear all left the filter strip up").toHaveCount(0);
    await expect(search, "Clear all did not clear the search field").toHaveValue("");

    // ── the approvals queue: PRESENT when there is something to approve ────
    // It renders nothing at all when the queue is empty, so the honest claim is
    // agreement with /api/approvals. Never decided either way.
    const queue = page.locator('[data-panel="approvals-queue"]');
    const pending = (approvals?.approvals ?? []).filter((request) => request.status === "pending").length;
    if (pending > 0) {
      await expect(queue, `${pending} approvals are pending and the queue is not on screen`).toHaveCount(1);
      await expect(queue.locator(".choke-approvals-count"), "the queue miscounts what is waiting").toHaveText(
        String(pending)
      );
    } else {
      await expect(queue, "the approvals queue is on screen with nothing pending").toHaveCount(0);
      test.info().annotations.push({
        type: "note",
        description: `nothing pending in change control on ${env.kind}; the approvals queue was asserted absent`
      });
    }

    // ── the ops row's read controls ───────────────────────────────────────
    const opsRow = page.locator('[data-panel="topbar-row-2"]');
    await expect(opsRow.locator(".choke-scope-pill"), "the tracked-process count is gone").toContainText(/tracked/i);
    const refresh = opsRow.getByRole("button", { name: /Refresh/ });
    await expect(refresh, "the choke route cannot be refreshed by hand").toHaveCount(1);
    await refresh.click();
    await expect(refresh, "Refresh never came back from its in-flight state").toHaveText("Refresh", {
      timeout: 60_000
    });

    // ── the jail picker: a read-only listing with actions we do not press ──
    const jail = page.getByRole("button", { name: "Jail Process" });
    await expect(jail, "the Jail Process control is gone").toHaveCount(1);
    if (!(await jail.isDisabled())) {
      await jail.click();
      const picker = page.locator('[data-panel="jail-process-picker-modal"]');
      await expect(picker, "the jail picker did not open").toBeVisible();
      await page.keyboard.press("Escape");
      await expect(picker, "the jail picker would not close").toHaveCount(0);
    }

    // ── the estate-changing controls: present, and left alone ─────────────
    await expect(
      page.locator(".cc-plane-controls button"),
      "the enforcement mode and kill-switch controls are missing from the command header"
    ).toHaveCount(2);
    await expect(
      page.locator('[data-panel="topbar-row-2"] .choke-preset-group button'),
      "the incident-response presets are gone"
    ).not.toHaveCount(0);

    const trailing = watch.since(settled);
    if (trailing.length) failures.push({ item: "choke route", reason: `logged: ${trailing[0].slice(0, 200)}` });
    expect(report(failures), "the Choke Gateway's chrome misbehaved").toEqual([]);
  });

  test("the Device Choke chrome opens its lens, filters, and expands a device", async ({ page }) => {
    await signIn(page, env);
    const watch = new ConsoleWatch(page);
    await page.goto("/devices", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: /stopped rendering/i })).toHaveCount(0);

    const topbar = page.locator('[data-panel="topbar-row-1"]');
    await expect(topbar, "the devices topbar did not render").toBeVisible();
    // See the note on the choke route: boot-time reads are not this test's claim.
    const settled = watch.mark();
    await expect(topbar.getByRole("link", { name: "SOC" })).toHaveAttribute("href", "/");
    const search = topbar.getByLabel("Search devices");
    await expect(search, "the devices route has no search field").toBeVisible();
    // The plane strip is the honest bit: it says whether this deployment can
    // actually drop a frame, or is only auditing.
    await expect(
      topbar.locator(".devices-status-cluster"),
      "the device plane state is not reported"
    ).toBeVisible();

    const tabs = page.locator(".cc-viewtoggle button[role='tab']");
    await expect(tabs, "the device containment lens is missing").toHaveCount(2);
    await tabs.nth(1).click();
    await expect(page.locator(".cc-assur-grid"), "the device Assurance lens did not render").toBeVisible();
    await tabs.nth(0).click();
    await expect(page.locator(".devices-footnote"), "the device Command lens did not come back").toBeVisible();

    // The SAME ContainmentCommandHeader the Choke Gateway mounts, over the
    // device plane's own arm and kill-switch. Asserted present, never pressed.
    await expect(
      page.locator(".cc-plane-controls button"),
      "the device plane's enforcement and kill-switch controls are missing"
    ).toHaveCount(2);
    // The device ladder is the same client-side filter as the process one.
    const ladder = page.locator('[data-panel="containment-ladder"]');
    await expect(ladder, "the device containment ladder is gone").toHaveCount(1);
    await expect(ladder, "the device ladder does not say it filters").toContainText("devices");

    const expanders = page.locator("button.devices-icon-button[aria-expanded]");
    const rows = await expanders.count();
    if (rows === 0) {
      test.info().annotations.push({
        type: "note",
        description: "no devices are known to this deployment; the row expander and the search filter were not exercised"
      });
    } else {
      // Search is a client-side filter over the inventory this deployment
      // returned — a GET-backed view, nothing written.
      await search.fill("zz-no-such-device-zz");
      await expect(expanders, "the device search did not filter the table").toHaveCount(0);
      await search.fill("");
      await expect(expanders, "clearing the device search did not restore the table").toHaveCount(rows);

      await expanders.first().click();
      await expect(expanders.first()).toHaveAttribute("aria-expanded", "true");
      const flows = page.locator("tr.devices-flow-row").first();
      await expect(flows, "expanding a device rendered no flow row").toBeVisible();
      // The ladder is the containment control. Present, and not pressed.
      await expect(flows.locator("button"), "an expanded device offers no containment at all").not.toHaveCount(0);
      await expanders.first().click();
      await expect(expanders.first()).toHaveAttribute("aria-expanded", "false");
    }

    expect(watch.since(settled), "the devices route logged errors while its menus were driven").toEqual([]);
  });

  test("the Fleet control rail renders every section it commands", async ({ page }) => {
    await signIn(page, env);
    const watch = new ConsoleWatch(page);
    await page.goto("/fleet", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: /stopped rendering/i })).toHaveCount(0);

    const rail = page.locator("aside.fleet-rail");
    await expect(rail, "the fleet control rail did not render").toBeVisible();
    // See the note on the choke route: boot-time reads are not this test's claim.
    const settled = watch.mark();

    const sections = rail.locator("section.fleet-panel");
    expect(await sections.count(), "the fleet rail lost a section").toBe(4);
    // Located by what they SAY, not by index. An nth-based pairing asserts
    // against a neighbouring panel the moment the rail is reordered, and the
    // "present, named and untouched" checks below would still pass while
    // pointing at the wrong controls.
    expect(
      // Lower-cased: these titles are uppercased by CSS, and innerText returns
      // what is RENDERED — the case is styling, not a claim about the rail.
      (await sections.locator("h2.fleet-panel__title").allInnerTexts()).map((text) => text.trim().toLowerCase()),
      "the fleet rail is not the four things it commands"
    ).toEqual(["apply changes to", "posture preset", "thresholds", "emergency controls"]);

    const scope = sections.filter({ hasText: "Apply Changes To" });
    const posture = sections.filter({ hasText: "Posture Preset" });
    const thresholds = sections.filter({ hasText: "Thresholds" });
    const emergency = sections.filter({ hasText: "Emergency Controls" });
    await expect(scope, "the target-scope panel is not on the rail").toHaveCount(1);

    // Section 1 is the only one whose controls change nothing but which host a
    // LATER write would target, so it is the only one this probe drives.
    await scope.getByRole("button", { name: "Selected only" }).click();
    await expect(scope, "choosing a target scope did not change what the rail says it will write to").toContainText(
      /Writes target \d+ selected host/
    );
    await scope.getByRole("button", { name: "All hosts" }).click();
    await expect(scope, "restoring the scope did not restore what the rail says").toContainText(
      "Writes target every configured peer"
    );

    // Everything else: present, named, and untouched.
    await expect(posture.locator("button.fleet-posture"), "the posture presets are gone").not.toHaveCount(0);
    await expect(thresholds.locator("input"), "the threshold inputs are gone").toHaveCount(4);
    for (const control of ["Kill-switch on", "Kill-switch off", "Thaw quarantine"]) {
      await expect(
        emergency.getByRole("button", { name: control }),
        `the fleet emergency control "${control}" is missing`
      ).toHaveCount(1);
    }

    expect(watch.since(settled), "the fleet route logged errors while its rail was read").toEqual([]);
  });

  /**
   * GETTING OUT OF THE FLEET VIEW — the claim survives, its mechanism changed.
   *
   * /fleet used to be a separate HTML entry with its own bundle and its own
   * "Console navigation": a fourth nav, the only one that was not the SOC rail,
   * and the only way back to the other three consoles. That is what this test
   * used to drive, entry by entry.
   *
   * The fleet console is now a SURFACE inside the SOC console, and /fleet is a
   * redirect that opens it. So there is no fourth nav to check, and the way out
   * is the SOC rail the operator already has — which is a stronger position
   * than the one this test was written for, because the rail is exercised by
   * every other test in this file rather than existing only here.
   *
   * The test therefore asserts three things instead of the old vocabulary
   * check: arriving at /fleet lands in the console with the fleet surface open;
   * there is NO second console nav (the consolidation's whole point, and the
   * assertion that fails if a second chrome ever comes back); and the operator
   * can still reach another console from where they landed. The followed link
   * is still Devices, still for the same reason.
   */
  test("arriving at /fleet lands in the console, with one nav and a way out", async ({ page }) => {
    await signIn(page, env);
    const watch = new ConsoleWatch(page);
    await page.goto("/fleet", { waitUntil: "domcontentloaded" });
    const settled = watch.mark();

    // The redirect is part of the claim: /fleet must land on the console with
    // the surface OPEN, not merely on the console.
    await expect(
      page.locator('[data-panel="left-sidebar"]'),
      "/fleet did not land on the SOC console"
    ).toBeVisible();
    const surface = page.locator('[data-panel="fleet-console-modal"]');
    await expect(surface, "/fleet landed on the console without opening the fleet surface").toHaveClass(
      /is-open/,
      { timeout: 30_000 }
    );

    // THE CONSOLIDATION'S POINT, asserted rather than assumed: one nav. A
    // second "Console navigation" reappearing means a second chrome came back,
    // which is the thing this change removed and the thing an operator meets as
    // two consoles for one job.
    await expect(
      page.getByRole("navigation", { name: "Console navigation" }),
      "a second console navigation is back — the fleet view is carrying its own chrome again"
    ).toHaveCount(0);
    await expect(
      page.locator(".fleet-user"),
      "the fleet surface is carrying its own sign-out again"
    ).toHaveCount(0);

    // The way out is the rail the operator already has. Asserted, never
    // clicked, for sign out: this is the shared session.
    const railSignOut = socNavLink(page, "Sign out");
    await expect(railSignOut, "the console offers no way out from the fleet surface").toHaveCount(1);
    await expect(railSignOut).toHaveAttribute("href", "/api/logout");

    // Closing the surface must leave the operator on the dashboard, not on a
    // blank page: the fleet view is a door, not a destination.
    await page.keyboard.press("Escape");
    await expect(surface, "the fleet surface did not close on Escape").not.toHaveClass(/is-open/);
    await expect(
      page.locator('[data-panel="kpi-row"]'),
      "closing the fleet surface did not leave the operator on the dashboard"
    ).toBeVisible();

    // One link is FOLLOWED, and the lightest of the three: hrefs prove the
    // markup, not that the target serves a console. Devices is a seven-panel
    // route, so this costs one boot rather than the SOC route's thirty-one.
    await socNavLink(page, "Device Choke").click();
    await page.waitForURL(/\/devices$/, { timeout: 60_000 });
    await expect(
      page.locator('[data-panel="topbar-row-1"]'),
      "the fleet nav's Devices link did not land on a device console"
    ).toBeVisible();
    await expect(page.getByRole("heading", { name: /stopped rendering/i })).toHaveCount(0);

    await page.goBack({ waitUntil: "domcontentloaded" });
    // Back returns to the CONSOLE, not to /fleet: entries/fleet.tsx uses
    // location.replace, so the redirect leaves no history entry to return to.
    await expect(
      page.locator('[data-panel="left-sidebar"]'),
      "going back did not return to the console"
    ).toBeVisible();
    expect(watch.since(settled), "the fleet surface logged errors while it was driven").toEqual([]);
  });

  /**
   * Sign out, in a context this file owns — and, on the control plane, only
   * with an explicit opt-in.
   *
   * Browser-context isolation is not the whole blast radius. /api/logout is an
   * RP-INITIATED OIDC logout on the control plane (bff.go: it ends the local
   * session AND the IdP's SSO session), so signing out as the operator this run
   * signed in as ends THAT OPERATOR'S KEYCLOAK SESSION ESTATE-WIDE — for every
   * other probe sharing the estate, and for the human who is watching. Existing
   * BFF cookies survive, so it is not immediately destructive, but it is a
   * change to state outside this browser, which is exactly what
   * PROBE_ALLOW_WRITES gates in this suite's env contract.
   *
   * So: the engine runs it unconditionally (its logout clears one server-side
   * session, and this context is the only holder). The control plane runs it as
   * the SECOND tenant's operator when one is configured — a principal this run
   * is not otherwise using — and otherwise only under PROBE_ALLOW_WRITES=1.
   * With neither, it skips and says what it skipped, rather than quietly
   * cutting an operator's SSO to satisfy a test.
   */
  test("the account group's sign out ends a session it owns", async ({ browser }) => {
    const secondIdentity = hasSecondTenant(env)
      ? { user: env.otherUser, password: env.otherPassword }
      : null;
    const who =
      env.kind === "engine" || !secondIdentity
        ? { user: env.user as string, password: env.password as string }
        : secondIdentity;
    const endsIdpSession = env.kind !== "engine";
    const isSharedOperator = who.user === env.user;

    test.skip(
      endsIdpSession && isSharedOperator && !env.allowWrites,
      "control-plane sign-out is an RP-initiated OIDC logout and would end this operator's Keycloak SSO session estate-wide. " +
        "Set PROBE_OTHER_USER/PROBE_OTHER_PASSWORD to exercise it as a different principal, or PROBE_ALLOW_WRITES=1 to accept the blast radius."
    );

    const { context, page } = await signedInContext(browser, env, who, "/");
    try {
      test.info().annotations.push({
        type: "note",
        description: `signing out as '${who.user}' on ${env.kind}${endsIdpSession ? " — this ends that operator's IdP SSO session" : ""}`
      });

      const signOut = socNavLink(page, "Sign out");
      await expect(signOut, "the rail offers no way out").toHaveCount(1);
      await expect(signOut).toHaveAttribute("href", "/api/logout");

      // Its OWN budget, not the config's 15s actionTimeout. On the control plane
      // this one click is a three-hop chain — /api/logout 302s to /auth/logout,
      // which 302s to Keycloak's RP-initiated logout endpoint, which redirects
      // back — and Playwright holds the click open until those navigations
      // settle. Measured 2026-08-28: 14.2s on a quiet console, i.e. inside the
      // default by less than a second, and over it under load. It failed that
      // way in a full-suite run and passed alone minutes later, which is the
      // signature of a budget that is too tight rather than a broken sign-out.
      await signOut.click({ timeout: 60_000 });

      // THE SESSION, not the URL. The URL regex used to admit /api/logout — the
      // very href being navigated to — so a logout hop that stopped working
      // (there is no /api/logout route on the control plane itself; it exists
      // because the deploy installs an nginx redirect) would commit at that
      // path, match, and be reported as a successful sign-out with the session
      // still live. What actually ends is only visible from the server.
      await expect
        .poll(
          async () => {
            const response = await page.request.get("/api/whoami", { failOnStatusCode: false });
            return response.status();
          },
          {
            timeout: 60_000,
            message: "signing out left the operator with a live session — /api/whoami still authenticates"
          }
        )
        .toBe(401);

      // And the browser is no longer standing on the console.
      await expect
        .poll(() => new URL(page.url()).pathname, {
          timeout: 30_000,
          message: "the session ended but the operator was left sitting on a console that can no longer read anything"
        })
        .toMatch(/\/login|\/auth\/|\/realms\//);
    } finally {
      await context.close();
    }
  });

  /**
   * The enforcement drill — rail → Correlation Graph → a node → a process row →
   * ProcessActionModal — pins a drill that opens on a process the operator did not pick, or that
   * misreports where that process already sits on the ladder. Neither looks wrong (each is a
   * well-formed panel about a real process) and the action at the top of that ladder cannot be
   * undone. It pins the layering too: ProcessActionModal eats Escape in the capture phase so one
   * press does not also close the graph behind it.
   *
   * READ-ONLY, enforced rather than promised: a route handler aborts every non-GET to the choke
   * and assistant endpoints, the reason field is never typed into (typing is what un-gates
   * Quarantine and Sever), and no ladder button is ever pressed.
   */
  test("the graph's process drill opens on the process that was picked, and its ladder agrees with the rail", async ({
    page
  }) => {
    test.setTimeout(6 * 60_000);
    await signIn(page, env);
    // Scoped to the two families this surface can write through, not /api/**, so the console's own
    // polling does not spend the run in a route handler.
    const writesAttempted: string[] = [];
    for (const pattern of ["**/api/choke/**", "**/api/assistant/**"]) {
      await page.route(pattern, async (route) => {
        const method = route.request().method();
        if (method !== "GET") writesAttempted.push(`${method} ${new URL(route.request().url()).pathname}`);
        await (method === "GET" ? route.continue() : route.abort("blockedbyclient")).catch(() => undefined);
      });
    }

    const watch = new ConsoleWatch(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    // The window decides whether there is anything to click. The PERSISTED value is read, not the
    // highlighted button: a soc.prefDefaultRange outside the five
    // highlights none of them, and a "fall back to 30m" restore would rewrite the operator's
    // preference rather than put it back.
    const range = page.getByRole("group", { name: "Time range" });
    await expect(range, "the top bar offers no time-range group to widen").toHaveCount(1);
    const storedRange = await page.evaluate(() => { try { return window.localStorage.getItem("soc.prefDefaultRange"); } catch { return null; } });
    const restoreLabel = ({ "5": "5m", "30": "30m", "60": "1h", "1440": "24h", "10080": "7d" } as Record<string, string>)[(storedRange ?? "").trim()] ?? "";
    const widest = range.getByRole("button", { name: "7d", exact: true });
    await expect(widest, "the time-range group does not offer a 7d window").toHaveCount(1);
    await widest.click();
    await expect(widest, "widening the window to 7d did not take").toHaveClass(/is-active/);

    const graph = page.locator('[data-panel="process-correlation-graph-modal"].is-open');
    // 0 or 1 globally, and existence IS the open state: one render site, and `is-open` is hard-
    // coded into its class, unlike ModalShell's.
    const drill = page.locator('[data-panel="process-action-modal"]');
    const rail = graph.locator("aside.soc-graph-selection");
    const procRows = rail.locator(".soc-graph-procs button.soc-graph-proc");
    const liveToggle = graph.locator("button.soc-graph-live");
    const failures: Failure[] = [];
    // Idempotent. Called on the primary path BEFORE the verdict is read, so a restore that failed
    // is a finding rather than something a passing test swallowed; and again from the finally.
    let restoreDone = false;
    const restore = async (): Promise<string[]> => {
      if (restoreDone) return [];
      restoreDone = true;
      const problems: string[] = [];
      // The drill first: its backdrop is fixed inset:0 over the LIVE button and the whole top bar.
      if ((await drill.count()) === 1) {
        await page.keyboard.press("Escape").catch(() => undefined);
        await settles(async () => (await drill.count()) === 0, 5_000);
      }
      // LIVE next, while the graph is still open to receive the click.
      if ((await graph.count()) === 1 && (await liveToggle.count()) === 1 && !/LIVE/.test(await readText(liveToggle))) {
        await liveToggle.click({ timeout: 5_000 }).catch(() => undefined);
        if (!(await settles(async () => /LIVE/.test(await readText(liveToggle)), 5_000))) problems.push("the graph's live feed could not be switched back on");
      }
      // Two presses: the first is consumed by a drill if one is somehow still open.
      await page.keyboard.press("Escape").catch(() => undefined);
      await page.keyboard.press("Escape").catch(() => undefined);
      if (!(await settles(async () => (await graph.count()) === 0, 10_000))) problems.push("the correlation graph would not close");
      if (storedRange !== null && restoreLabel) {
        const button = range.getByRole("button", { name: restoreLabel, exact: true });
        await button.click({ timeout: 10_000 }).catch(() => undefined);
        if (!(await settles(() => hasClass(button, "is-active"), 10_000))) problems.push(`the operator's ${restoreLabel} window preference was not put back`);
      } else if (storedRange !== null) {
        // Outside the five buttons, so no click restores it: written back rather than left at 7d.
        await page.evaluate((value: string) => { try { window.localStorage.setItem("soc.prefDefaultRange", value); } catch { /* private mode */ } }, storedRange).catch(() => undefined);
      }
      return problems;
    };
    // Put back, THEN read the verdict — never the other way round.
    const settleUp = async (message: string): Promise<void> => {
      for (const problem of await restore()) failures.push({ item: "restore", reason: problem });
      expect(writesAttempted, "this test attempted a write against the estate").toEqual([]);
      expect(report(failures), message).toEqual([]);
    };

    const settled = watch.mark();
    try {
      const entry = railItem(page, "Correlation Graph");
      await expect(entry, "the rail does not offer the correlation graph").toHaveCount(1);
      await entry.click();
      await expect(graph, "the correlation graph did not open").toHaveCount(1);
      const railEmpty = rail.locator("p.soc-graph-selection-empty");
      await expect(railEmpty, "the graph opened without telling the operator that a node has to be picked first").toHaveCount(1);
      await expect(railEmpty, "the graph's opening instruction no longer tells the operator to click a node").toHaveText(/Click a node/i);

      // Stop the canvas before anything is aimed at it. Pure client state, no request: on a live
      // estate the 700ms updater also calls select(null), which closes the drill by itself.
      await expect(liveToggle, "the graph offers no LIVE/PAUSED control").toHaveCount(1);
      if (/LIVE/.test(await readText(liveToggle))) await liveToggle.click();
      await expect(liveToggle, "the graph would not stop folding in live data, so nothing below could click a node that is standing still").toContainText("PAUSED");
      // POLLED: buildFiltered() latches "empty" if the alert buffer has not landed yet and only a
      // 700ms watcher brings it back. Rebuild is the operator's own remedy, and it writes nothing.
      const nodes = graph.locator("svg.soc-correlation-graph g.soc-graph-node");
      const discs = nodes.locator("circle.soc-graph-disc");
      let built = await settles(async () => (await nodes.count()) > 0, 30_000);
      if (!built) {
        await graph.getByRole("button", { name: "Rebuild", exact: true }).click();
        built = await settles(async () => (await nodes.count()) > 0, 20_000);
      }
      if (!built) {
        // FOUR outcomes, not two: a d3 chunk that never lands is a console defect this repo has
        // already shipped once, through a stale service worker — it is not an idle estate.
        const said = (await graph.locator(".soc-graph-overlay").allTextContents().catch(() => [])).join(" ").replace(/\s+/g, " ").trim();
        const broken = /Loading graph engine/i.test(said)
          ? 'it was still saying "Loading graph engine…" after 50s — the d3 chunk never arrived on this deployment (a stale service worker, or a chunk it does not serve). That is not an idle estate'
          : /Graph engine unavailable/i.test(said) ? `the d3 graph engine failed to load here, so the canvas — the only route to the enforcement drill — does not exist: "${said}"`
          : /No correlated processes in the selected range/i.test(said) ? ""
          : `it drew no nodes and its canvas says "${said}" — an operator cannot tell an idle estate from a broken graph engine`;
        if (broken) failures.push({ item: "correlation graph", reason: broken });
        test.info().annotations.push({ type: "note", description: `no correlated processes in 7d on ${env.kind}; the canvas said "${said}" and the process drill was not exercised` });
        await settleUp("the correlation graph drew nothing and could not say why");
        test.skip(true, "this deployment has no correlated processes to open the enforcement drill from");
        return;
      }
      // CENTRES, not bounding boxes: a node entering the join animates its radius, which moves the
      // box's origin while the node itself is stationary.
      const centres = async () => discs.evaluateAll((els) => els.map((el) => { const b = el.getBoundingClientRect(); return `${Math.round(b.x + b.width / 2)},${Math.round(b.y + b.height / 2)}`; }).join("|")).catch(() => "");
      let previous = " ";
      if (!(await settles(async () => { const now = await centres(); const same = now.length > 0 && now === previous; previous = now; return same; }, 15_000, [400]))) {
        failures.push({
          item: "correlation graph",
          reason: "with LIVE paused the canvas never stopped moving — something is still re-heating the force simulation, and every click an operator aims at a node is aimed at a stale coordinate"
        });
      }

      // Process nodes first: they answer with their own instances. By INDEX — nth() resolves to
      // exactly one element by construction, where [aria-label] does not: two node kinds can share
      // a path.
      const processNodes = graph.locator("svg.soc-correlation-graph g.soc-graph-node.node-process");
      const pool = (await processNodes.count()) > 0 ? processNodes : nodes;
      const poolSize = await pool.count();
      const scan = Math.min(poolSize, 6);
      const refused: string[] = [];
      let pickedNode = "";
      for (let index = 0; index < scan && !pickedNode; index += 1) {
        const candidate = pool.nth(index);
        const name = ((await candidate.getAttribute("aria-label")) ?? `node ${index}`).trim();
        // THE DISC, AND NOT FORCED, both measured: the <g> has no fill and its box spans disc +
        // label, so its centre lands in the gap; and force skips the hit-target check but still
        // dispatches
        // there, handing the press to .soc-graph-zoomdock, whose Fit/Reset re-run the transition
        // just waited out. A candidate that cannot be reached is skipped; six are tried.
        await candidate.locator("circle.soc-graph-disc").click({ timeout: 5_000 }).catch(() => undefined);
        // THIS node, not "a" node: `selected` is sticky, so a detail-block count is vacuously true
        // from the second candidate on and would let a missed click name a node it never selected.
        if (!(await settles(() => hasClass(candidate, "is-selected"), 5_000))) {
          refused.push(`${name}: clicking it selected nothing`);
          continue;
        }
        const railNames = await readText(rail.locator(".soc-graph-detail > strong"));
        if (railNames !== name.replace(/\s+/g, " ")) {
          failures.push({
            item: `node "${name}"`,
            reason: `the canvas marks it selected while the selection rail is describing "${railNames}" — the rail resolved a different node than the operator clicked`
          });
        }
        if (await settles(async () => (await procRows.count()) > 0, 5_000)) {
          pickedNode = name;
          break;
        }
        // Selected with nothing to act on is legitimate — WHICH of the three reasons applies is the
        // point. Scoped inside .soc-graph-procs so it can only be that one empty-rail branch.
        const why = await readText(rail.locator(".soc-graph-procs p.soc-graph-selection-empty"));
        if (!/No process matches this filter|no exec_id|Nothing actionable here/i.test(why)) {
          failures.push({
            item: `node "${name}"`,
            reason: `it resolved to no process and said "${why}" — none of the three reasons the rail is supposed to distinguish`
          });
        }
        refused.push(`${name}: ${why}`);
      }
      if (!pickedNode) {
        test.info().annotations.push({ type: "note", description: `${poolSize} node(s) on ${env.kind}, ${scan} scanned, none resolving to a live process: ${refused.join(" | ")}` });
        await settleUp("a node offered nothing to act on and did not say why");
        test.skip(true, "no node in this graph resolves to a live process, so the enforcement drill is unreachable here");
        return;
      }

      // The row's title carries the FULL identity; the visible binary is truncated to 22 characters
      // by shortGraphLabel, so it cannot be compared against anything the drill renders.
      const row = procRows.first();
      const rowTitle = ((await row.getAttribute("title")) ?? "").trim();
      const parsed = /^(.*) · exec_id (\S+)$/.exec(rowTitle);
      expect(parsed, `the process row carries no identity in its title ("${rowTitle}")`).not.toBeNull();
      const [, binary, execId] = parsed ?? ["", "", ""];
      // The header states a count derived separately from the rows it sits above, which is how a
      // header comes to miscount them. .soc-stat-label is CSS-uppercased, so readText, not
      // innerText.
      const header = rail.locator(".soc-graph-procs > .soc-stat-label");
      if (!(await settles(async () => Number(/processes \((\d+)/i.exec(await readText(header))?.[1] ?? "NaN") === (await procRows.count()), 8_000))) {
        failures.push({
          item: "selection rail",
          reason: `its header reads "${await readText(header)}" and it renders ${await procRows.count()} process row(s)`
        });
      }
      const shown = await procRows.count();
      await row.click();
      await expect(drill, "picking a process in the selection rail opened no enforcement drill").toHaveCount(1);
      // toBeVisible still says something: the backdrop is display:none until is-open lands.
      await expect(drill, "the drill mounted but never took its open state").toBeVisible();
      // THE CLAIM THIS TEST EXISTS FOR. Scoped to the drill: role=dialog matches two while it is
      // open, the graph's own ModalShell card being the other.
      await expect(drill.getByRole("dialog"), `the drill's accessible name is not the process the row named ("${binary}")`).toHaveAttribute("aria-label", `Enforce on ${binary}`);
      await expect(drill.locator(".soc-proc-modal-title h2"), "the drill's heading names a different binary than the row that opened it").toHaveText(binary);
      // .soc-proc-modal-identity dt is CSS-uppercased, so filter({has}) and allTextContents — both
      // read textContent. `host` is multi-tenant only: on a single-tenant engine the box IS the
      // host.
      const identity = drill.locator(".soc-proc-modal-identity dl > div");
      const execField = identity.filter({ has: page.locator("dt", { hasText: /^exec_id$/ }) }).locator("dd");
      await expect(execField, "the drill does not state an exec_id at all").toHaveCount(1);
      await expect(execField, `the drill opened on a different exec_id than the row that was clicked ("${execId}")`).toHaveText(execId);
      const fields = (await identity.locator("dt").allTextContents()).map((text) => text.trim());
      for (const field of ["pid", "score", "exec_id", "last seen"]) if (!fields.includes(field)) failures.push({ item: "drill identity", reason: `it does not state "${field}" before offering an irreversible action (it states: ${fields.join(", ")})` });
      const active = rail.locator(".soc-graph-procs button.soc-graph-proc.is-active");
      await expect(active, "the rail marks no row as the one the drill is about").toHaveCount(1);
      await expect(active, "the rail marks a different row than the drill opened on").toHaveAttribute("title", rowTitle);
      // Scoped: a bare .soc-narrative matches three inside this modal, the third the assistant's.
      const narratives = drill.locator(".soc-proc-modal-narrative .soc-narrative");
      await expect(narratives, "the drill lost one of its two narratives").toHaveCount(2);
      const told = (await narratives.locator("p").allTextContents()).map((text) => text.replace(/\s+/g, " ").trim());
      for (const [at, label] of [[0, "in plain English"], [1, "technical"]] as Array<[number, string]>) if ((told[at] ?? "").length < 12) failures.push({ item: "drill narrative", reason: `the "${label}" narrative rendered empty ("${told[at] ?? ""}")` });
      // Scoped: [data-panel="enforcement-ladder"] has four mounts app-wide and only being on "/"
      // keeps the other three off the page. toHaveText reads textContent (the rungs are CSS-
      // uppercased) and its array form asserts the count too.
      const ladder = drill.locator('[data-panel="enforcement-ladder"]');
      await expect(ladder, "the drill offers no enforcement ladder").toHaveCount(1);
      const rungs = ladder.locator("ol.enf-ladder-rungs li.enf-ladder-rung");
      await expect(rungs, "the process ladder is not the five rungs the platform escalates through").toHaveText(["pristine", "throttled", "tarpit", "quarantined", "severed"]);
      const current = ladder.locator("li.enf-ladder-rung.is-current");
      await expect(current, "the ladder does not say where this process currently sits").toHaveCount(1);
      // CROSS-SURFACE AGREEMENT, the honest version of "is the rung right?": both readings come
      // from one circuits map in one render, which takes /api/choke/circuits' 5s refresh out of the
      // claim. Both lowercased — the rail's absent-badge case is the literal "pristine" — and ""
      // means unreadable, which agrees with nothing.
      const railRung = async (): Promise<string> => { if ((await active.count()) !== 1) return ""; const badge = active.locator(".soc-graph-proc-meta b"); return (await badge.count()) === 1 ? (await readText(badge)).toLowerCase() : "pristine"; };
      const drillRung = async (): Promise<string> => (await readText(current)).toLowerCase();
      if (!(await settles(async () => { const seen = await railRung(); return seen !== "" && seen === (await drillRung()); }, 8_000))) {
        failures.push({
          item: "enforcement ladder",
          reason: `the rail lists this process as "${await railRung()}" and the drill it opened says "${await drillRung()}" — two readings of one circuit`
        });
      }
      const actions = ladder.locator(".enf-ladder-actions button");
      await expect(actions, "the ladder's verbs are not the shared five — an operator who learned them on Devices would be pressing something else here").toHaveText(["Pristine", "Throttle", "Tarpit", "Quarantine", "Sever"]);
      // THE GATE, verified without arming it: needsReason folds into `disabled` unconditionally
      // whatever rung the process is on, so it holds on every deployment and needs no typing — and
      // typing is exactly what would un-gate them, which is why the field is read and left alone.
      const reason = ladder.locator("input.enf-ladder-reason");
      await expect(reason, "the ladder collects no reason").toHaveCount(1);
      await expect(reason, "the drill opened with a reason already filled in").toHaveValue("");
      for (const gated of [{ index: 3, verb: "Quarantine" }, { index: 4, verb: "Sever" }]) if (await actions.nth(gated.index).isEnabled()) failures.push({ item: `ladder: ${gated.verb}`, reason: "it is live with no reason typed — the only thing standing between a stray click and an irreversible action is gone" });
      const verbs = (await actions.allTextContents()).map((text) => text.trim());
      for (let index = 0; index < 5; index += 1) if (!(await actions.nth(index).isEnabled()) && ((await actions.nth(index).getAttribute("title")) ?? "").trim().length < 4) failures.push({ item: `ladder: ${verbs[index] ?? `button ${index}`}`, reason: "it is disabled and its title explains nothing" });
      // SCOPED, and it has to be: opening the drill sets drillExecId, which mounts a SECOND
      // AssistantPanel in the rail underneath, so a bare `.asst` matches two while the drill is
      // open.
      const asst = drill.locator("section.asst");
      await asst.first().waitFor({ state: "attached", timeout: 15_000 }).catch(() => undefined);
      const assistant = await assistantIsConfigured(page);
      const off = (await drill.locator("section.asst--off").count()) === 1;
      if ((await asst.count()) !== 1) {
        failures.push({
          item: "drill assistant",
          reason: `the capability probe never resolved: the drill offers neither an assistant nor a statement that this deployment has none (/api/assistant reports enabled=${assistant})`
        });
      }
      else if (assistant && off) {
        failures.push({
          item: "drill assistant",
          reason: "/api/assistant reports an assistant is configured and the drill says it is not configured here"
        });
      }
      else if (!assistant && !off) {
        failures.push({
          item: "drill assistant",
          reason: "no assistant is configured on this deployment and the drill offers a composer anyway"
        });
      }
      else if (assistant) {
        // Present, empty, and NEVER SENT: a question spends a model call on the customer's key and
        // writes a conversation into their store. Send disabled on an empty composer is both a real
        // safety property and what makes a stray keystroke in this test harmless.
        const composer = drill.locator("input.asst__input");
        await expect(composer, "the assistant offers nowhere to type").toHaveCount(1);
        await expect(composer, "the composer opened with a question already in it").toHaveValue("");
        const send = drill.locator("button.asst__send");
        await expect(send, "the assistant has a composer and no way to send from it").toHaveCount(1);
        if (await send.isEnabled()) {
          failures.push({
            item: "drill assistant",
            reason: "Send is live with an empty composer — a stray press would spend a model call on the customer's key"
          });
        }
        const tasks = drill.locator("button.asst__action");
        const taskCount = await tasks.count();
        if (taskCount === 0) {
          failures.push({
            item: "drill assistant",
            reason: 'it reports an assistant is configured and then offers no task agents at all — AgentsFor("process-action") answers with at least two on both halves of the platform'
          });
        }
        test.info().annotations.push({ type: "note", description: `drill assistant on ${env.kind}: ${taskCount} task button(s), read and not pressed: ${(await tasks.allTextContents()).map((text) => text.trim()).join(" | ")}` });
      }

      // The three ways out. The close button is SCOPED: .soc-close-button matches two while the
      // drill is open, and pressing the graph's would close the wrong surface. The backdrop is hit
      // 2px in
      // from the corner — the handler fires only when the mousedown target IS the backdrop, and the
      // card is inset by its 24px padding. The other half of that contract, that a click on the
      // CARD must not dismiss, is deliberately not probed: the middle of that card is the ladder.
      for (const dismissal of [
        { name: "Escape", act: async () => { await page.keyboard.press("Escape"); } },
        { name: "the close button", act: async () => { await drill.locator(".soc-close-button").click(); } },
        { name: "the backdrop", act: async () => { await drill.click({ position: { x: 2, y: 2 } }); } }
      ]) {
        if ((await drill.count()) === 0) await row.click();
        await expect(drill, `${dismissal.name}: the drill would not reopen from the same row`).toHaveCount(1);
        await expect(drill.getByRole("dialog"), `${dismissal.name}: reopening that row opened the drill on a different process`).toHaveAttribute("aria-label", `Enforce on ${binary}`);
        const mark = watch.mark();
        await dismissal.act();
        if (!(await settles(async () => (await drill.count()) === 0, 8_000))) {
          failures.push({ item: `drill: ${dismissal.name}`, reason: "it did not close the drill" });
          await page.keyboard.press("Escape").catch(() => undefined); continue;
        }
        if ((await graph.count()) !== 1) {
          failures.push({ item: `drill: ${dismissal.name}`, reason: "closing the drill also closed the correlation graph underneath it — the operator is thrown out of the surface they were investigating in" });
          break;
        }
        if ((await procRows.count()) === 0) {
          failures.push({
            item: `drill: ${dismissal.name}`,
            reason: "closing the drill left the rail with no process list to come back to"
          });
        }
        const noise = watch.since(mark);
        if (noise.length) {
          failures.push({
            item: `drill: ${dismissal.name}`,
            reason: `logged: ${noise[0].slice(0, 200)}`
          });
        }
      }
      test.info().annotations.push({ type: "note", description: `drilled "${binary}" (exec_id ${execId}) via node "${pickedNode}" on ${env.kind}: ${shown} process row(s) behind that node, ${poolSize} node(s) on the canvas` });
      await settleUp("the graph's process drill misreported the process it opened on");
      expect(watch.since(settled), "the process drill logged errors while it was driven").toEqual([]);
    } finally {
      // The net, for an assertion that threw before the restore above ran. Idempotent.
      await restore().catch(() => []);
    }
  });

  /**
   * The rail beside the queue, and the layers one alert row raises.
   *
   * Nothing in this repo has ever touched the right-hand column or the hover preview,
   * and every way they break is QUIET: a rail panel with neither its machinery nor an
   * empty state naming its window, a MITRE row rendered as a button no handler is
   * behind, a containment form that arrives armed.
   *
   * READ-ONLY, and stricter than this file's baseline: non-GET dies at the wire,
   * the audit reason is never typed into (three characters in it enables Send),
   * Ack/Resolve are left alone, and the pin, selection and window are put back.
   */
  test("the rail beside the queue holds its four panels, and one alert row raises its preview, menu and drill", async ({ page }) => {
    // Six minutes is the sum of the worst cases — two drill opens and a dozen polls that burn their
    // timeout only when a claim FAILS — not of a healthy run.
    test.setTimeout(6 * 60_000);
    await signIn(page, env);
    // The read-only promise, ENFORCED. GET falls through; the stream is not routed.
    await page.route((url) => url.pathname.startsWith("/api/") && url.pathname !== "/api/stream", (route) => (route.request().method() === "GET" ? route.fallback() : route.abort()));
    const watch = new ConsoleWatch(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    // ONE element each, asserted not assumed: the two overlays share ONE data-panel id
    // (panelInventory.ts:284-290), so the CLASS is what separates them.
    const queue = page.locator('[data-panel="alert-triage-queue"]');
    const rail = page.locator(".soc-right-rail");
    const preview = page.locator('[data-panel="alert-hover-preview-context-menu"].soc-alert-preview');
    const menu = page.locator('[data-panel="alert-hover-preview-context-menu"].soc-context-menu');
    const slide = page.locator('[data-panel="drill-down-slide-over"]');
    const drill = slide.locator(".soc-drill");
    await expect(queue, "the dashboard rendered without its alert queue").toHaveCount(1);
    await expect(rail, "the dashboard rendered without the rail beside the queue").toHaveCount(1);
    await expect(preview, "the hover preview is not one element").toHaveCount(1);
    await expect(menu, "the alert context menu is not one element").toHaveCount(1);
    // Five is also the proof this group resolved ONCE: two would count ten.
    const rangeGroup = page.getByRole("group", { name: "Time range" });
    const activeRange = rangeGroup.locator("button.is-active");
    await expect(rangeGroup.getByRole("button"), "the time-range group is not the five windows the top bar offers").toHaveCount(5);
    const settled = watch.mark();
    const { failures, fail, acted } = collector();
    const closeDrill = (item: string) => dismissDrill(slide, item, fail, acted);

    // ── the four panels of the rail, which need no alerts ───────────────────
    // WAITED FOR, not sampled: the route renders on an EMPTY snapshot at first paint
    // (hooks.ts:27-53), so a one-shot read calls a busy estate quiet.
    await rail.locator(".soc-mini-bars, .soc-ioc-list, .soc-network-list").first().waitFor({ state: "attached", timeout: 15_000 }).catch(() => undefined);
    for (const entry of RAIL_PROOF) await inspectPanel(rail, entry, fail);
    // MiniBarList renders a <button> only when handed a handler AND a row id (rows.tsx:177-183);
    // MITRE rows get neither, so a button here goes nowhere.
    const mitreButtons = await rail.locator('[data-panel="mitre-coverage"] .soc-mini-bars button').count();
    if (mitreButtons !== 0) fail("mitre-coverage", `${mitreButtons} technique rows render as buttons, and RightRail wires no handler to them — they go nowhere`);

    // ── widen the window, and put it back at the end ────────────────────────
    // GUARDED: `is-active` is `value === rangeMin` (SocRoute.tsx:641), so a browser holding a range
    // outside the five leaves NO button active to read back.
    const activeCount = await activeRange.count();
    const originalRange = activeCount === 1 ? (await activeRange.innerText()).trim() : "";
    if (activeCount !== 1) fail("top bar: time range", `${activeCount} of the five windows read as active, so the bar does not say which window the dashboard is showing`);
    await acted(rangeGroup.getByRole("button", { name: "7d", exact: true }).click(CLICK), "top bar: time range", "the 7d window would not take a click");
    const rows = queue.locator(".soc-alert-row");
    await rows.first().waitFor({ state: "visible", timeout: 30_000 }).catch(() => undefined);
    if ((await rows.count()) === 0) {
      note(`no alert rows in 7d on ${env.kind}: the hover preview, the bulk bar, the pin and the row's way into the drill were not exercised; the rail beside the queue was`);
      const said = await quietSays(queue.locator(".soc-alert-list")); // it must still SAY so
      if (said.length < 12) fail("alert-triage-queue", `no rows in a 7-day window and no empty state saying why — its list reads "${said}"`);
    } else {
      // WHATEVER SITS AT THE TOP AT EACH MOMENT: this queue re-sorts on every SSE alert, so each
      // claim below is row-invariant or read in ONE evaluate.
      const row = rows.first();
      const headline = row.locator(".soc-alert-head strong");
      const headCount = await headline.count();
      if (headCount !== 1) fail("alert row", `the top row's headline is not one element (${headCount})`);
      /** textContent, not innerText; and never throws — the row may go. */
      const readHeadline = async () => ((await headline.textContent().catch(() => "")) ?? "").replace(/\s+/g, " ").trim();
      const titleBefore = headCount === 1 ? await readHeadline() : "";

      // ── the hover preview, which really is display:none until is-open ─────
      // It follows the POINTER (onMouseMove, rows.tsx:63) and opens at clientY + 18 with no clamp
      // (SocRoute.tsx:325-331), so it sits BELOW it: add no hovers.
      if (await acted(row.hover(CLICK), "alert hover preview", "the top alert row would not take a pointer")) {
        if (!(await settles(() => isOpen(preview), 5_000))) fail("alert hover preview", "hovering an alert row raised no preview — onAlertHover never opened it");
        else {
          await inspectPreview(preview, titleBefore, readHeadline, fail);
          await page.keyboard.press("Escape");
          if (!(await settles(() => closed(preview)))) fail("alert hover preview", "Escape left the preview floating over the queue");
        }
      }

      // ── the row's action cluster, which is STATE-DEPENDENT ────────────────
      // What is offered must agree with the readout beside it (rows.tsx:95-112), read
      // as textContent: `.soc-ack` is uppercased (soc.css:1572), so innerText says NEW.
      const actions = row.locator(".soc-alert-actions");
      const cluster = await readCluster(actions, { ack: "span.soc-ack", pin: "button.soc-pin" });
      if (!cluster) fail("alert row actions", "the top row rendered no action cluster at all");
      else if (cluster.counts.ack !== 1 || cluster.counts.pin !== 1) fail("alert row actions", `the cluster is not one ack readout and one pin control (${cluster.counts.ack} / ${cluster.counts.pin})`);
      else {
        const pin = cluster.texts.pin;
        const byState: Record<string, string[] | undefined> = { New: [pin, "Ack", "Resolve"], "Ack'd": [pin, "Resolve"], Resolved: [pin, "Reopen"] };
        const wanted = byState[cluster.texts.ack];
        if (!wanted) fail("alert row actions", `the ack readout says "${cluster.texts.ack}", which is none of New/Ack'd/Resolved`);
        else if (cluster.offered.join(",") !== wanted.join(",")) fail("alert row actions", `a row reading "${cluster.texts.ack}" offers ${cluster.offered.join(", ") || "nothing"} rather than ${wanted.join(", ")}`);
        if (pin !== "Pin" && pin !== "Pinned") fail("alert row: Pin", `the pin control reads "${pin}", which is neither Pin nor Pinned`);
        // Pin is the ONE reversible action here, and driven only from a browser holding no pins:
        // the restore cannot land on someone else's.
        const pinnedRows = queue.locator(".soc-alert-row.is-pinned");
        const pinnedBefore = await pinnedRows.count();
        if (pinnedBefore === 0 && pin !== "Pin") {
          fail("alert row: Pin", `no row carries is-pinned, yet the control on this one reads "${pin}" — the row and its button disagree about the same state`);
        } else if (pinnedBefore !== 0) {
          note(`this browser already holds ${pinnedBefore} pinned alert(s), so the pin toggle was asserted present and left alone rather than driven and restored blind`);
        } else {
          if (await acted(actions.locator("button.soc-pin").click(CLICK), "alert row: Pin", "the pin control would not take a click")) {
            if (!(await settles(async () => (await pinnedRows.count()) === 1))) fail("alert row: Pin", "clicking Pin left no row pinned — the control reports nothing about itself");
          }
          // Undone whatever happened: the click may have landed where the assertion did not settle,
          // so the finding is the count after, not the attempts.
          const stillPinned = await undoUntil(pinnedRows, () => pinnedRows.first().locator("button.soc-pin").click(CLICK));
          if (stillPinned !== 0) fail("alert row: Pin", "the pin could not be undone — this browser is left holding soc.pinnedAlerts");
        }
      }

      // ── selection and the bulk bar ───────────────────────────────────────
      // It does not exist until a row is ticked (AlertQueue.tsx:88), so its absence first is part
      // of the claim. Only Clear is pressed — the rest is one-way.
      const bulk = queue.locator(".soc-bulk-bar");
      const selected = queue.locator(".soc-alert-row.is-selected");
      const clear = bulk.getByRole("button", { name: "Clear", exact: true });
      if ((await bulk.count()) !== 0) fail("alert queue: bulk bar", "it was already mounted with nothing selected");
      if (await acted(row.locator("input.soc-alert-check").check(CLICK), "alert queue: bulk bar", "the row's select control would not tick")) {
        if (!(await settles(async () => (await bulk.count()) === 1))) fail("alert queue: bulk bar", "ticking a row raised no bulk bar, so bulk triage is unreachable");
        else {
          const bar = await readCluster(bulk, { counted: "strong" });
          if (!bar) fail("alert queue: bulk bar", "the bulk bar appeared and could not be read");
          else {
            if (bar.texts.counted !== "1 selected") fail("alert queue: bulk bar", `it reports "${bar.texts.counted}" for exactly one ticked row`);
            if (bar.offered.join(",") !== "Acknowledge,Resolve,Clear") fail("alert queue: bulk bar", `it offers ${bar.offered.join(", ") || "nothing"} rather than Acknowledge, Resolve, Clear`);
          }
          await acted(clear.click(CLICK), "alert queue: bulk bar", "Clear would not take a click");
          if (!(await settles(async () => (await bulk.count()) === 0 && (await selected.count()) === 0))) fail("alert queue: bulk bar", "Clear left the selection standing");
        }
      }
      // Undone: a selection left ticked hands the next claim a bar it did not raise.
      const ticked = await undoUntil(selected, async () => {
        if ((await clear.count()) === 1) await clear.click(CLICK);
        else await selected.first().locator("input.soc-alert-check").uncheck(CLICK);
      });
      if (ticked !== 0) fail("alert queue: selection", `${ticked} row(s) are left ticked — the selection could not be cleared`);

      // ── the context menu's only exit that does not act ────────────────────
      // The test above owns opening it. Nothing asserts it can be dismissed WITHOUT acting:
      // no scrim, only "Open drill" clears it (SocRoute.tsx:577-584), and Escape must take the
      // preview with it.
      if (await acted(row.click({ button: "right", ...CLICK }), "alert context menu", "the row would not take a right-click")) {
        if (!(await settles(() => isOpen(menu)))) fail("alert context menu", "right-clicking a row opened no menu");
        else {
          await page.keyboard.press("Escape");
          if (!(await settles(() => closed(menu)))) fail("alert context menu", "Escape left the menu open over the queue, and it has no scrim to click away");
          if (await isOpen(preview)) fail("alert context menu", "the same Escape cleared the menu and left the hover preview behind it");
          if (await isOpen(slide)) fail("alert context menu", "dismissing the menu opened the drill — Escape acted on the estate's behalf");
        }
      }

      // ── the drill, reached by the ROW BODY: the way an analyst opens it ───
      if (await acted(row.locator("button.soc-alert-main").click(CLICK), "alert row → drill", "the row body would not take a click")) {
        if (!(await settles(() => isOpen(slide), 20_000))) fail("alert row → drill", "clicking the row body opened no drill (onOpen → openDrill)");
        else if ((await drill.count()) !== 1) fail("alert row → drill", "the slide-over opened with no body on this deployment's alert");
        else {
          const send = drill.locator("button.soc-danger-button");
          const reasonBox = drill.locator(".soc-choke-reason input");
          const [sends, reasonBoxes] = [await send.count(), await reasonBox.count()];
          if (sends !== 1 || reasonBoxes !== 1) fail("drill: choke ladder", `the response form is not one Send control and one audit-reason field (${sends} / ${reasonBoxes})`);
          else {
            if ((await reasonBox.inputValue()).trim().length > 0) fail("drill: choke ladder", "the audit reason came pre-filled, so the form arrives one click from arming");
            // NOT CLICKED, NOT TYPED INTO: three characters in the reason box is
            // precisely what enables this button (DrillPanel.tsx:90).
            if (await send.isEnabled()) fail("drill: choke ladder", "the Send control is ENABLED on a pristine form — POST /api/choke/jail is reachable with no audit reason recorded");
          }
          // THE CONTAINMENT LADDER, read on production without sending anything, and
          // located STRUCTURALLY: DrillPanel.tsx:152-160 wraps the <select> in its
          // <label>, so getByLabel("Action", {exact:true}) matches 0. The count is
          // asserted because a zero-match read would call a healthy ladder rungless.
          const ladder = drill.locator('.soc-choke-action-grid label:has(> span:text-is("Action")) select');
          const ladders = await ladder.count();
          if (ladders !== 1) fail("drill: choke ladder", `the action ladder is not one select in the choke grid (${ladders})`);
          else {
            // textContent: the grid's labels are uppercased (soc.css:2968), inherited.
            const rungs = await ladder.locator("option").evaluateAll((nodes: Element[]) => nodes.map((node) => (node.textContent ?? "").trim()));
            if (rungs.join(",") !== "throttle,tarpit,quarantine,sever") fail("drill: choke ladder", `it offers ${rungs.join(", ") || "no rungs at all"} rather than throttle, tarpit, quarantine, sever`);
          }
          const triage = await readCluster(drill.locator(".soc-drill-actions"), {}); // one-way door: present, left alone
          if (triage?.offered.join(",") !== "Acknowledge,Resolve") fail("drill: triage actions", `the drill offers ${triage?.offered.join(", ") || "no triage actions"} rather than Acknowledge, Resolve`);
          // Left empty, and scoped to `.soc-notes`: the AssistantPanel in this drill
          // (DrillPanel.tsx:220) owns the other text box.
          const notes = await drill.locator(".soc-notes textarea").count();
          if (notes !== 1) fail("drill: investigator notes", `${notes} note fields in the drill`);
        }
        // Closed on EVERY path, the never-opened one included: a drill arriving at 20.1s would sit
        // over the rail for the rest of the run.
        await closeDrill("alert row → drill");
      }
    }

    // ── the rail's own way into the drill ───────────────────────────────────
    // The third entry path, and the only one nothing here has driven. Guarded on the BARS,
    // not the queue: top-processes derives from rangeAlerts (useSocWindowModel.ts:252), so it can
    // carry rows while the queue shows none.
    // innerText is safe on the label: `.soc-mini-bars` carries no transform.
    const bars = rail.locator('[data-panel="top-processes"] .soc-mini-bars button');
    if ((await bars.count()) === 0) note(`no scored-process bars in 7d on ${env.kind}: the rail's exec_id route into the drill was not exercised`);
    else {
      const item = `top-processes → drill (${(await bars.first().innerText().catch(() => "")).replace(/\s+/g, " ").trim().slice(0, 60)})`;
      if (await acted(bars.first().click(CLICK), item, "the bar would not take a click")) {
        if (!(await settles(() => isOpen(slide), 20_000))) fail(item, "the bar swallowed the click — openDrillByExecId found no alert in the window carrying that exec_id, so the control is inert");
        else {
          const named = ((await drill.locator(".soc-drill-hero strong").textContent().catch(() => "")) ?? "").trim();
          if (named.length === 0) fail(item, "the drill opened without naming the alert it opened onto");
        }
        await closeDrill(item);
      }
    }

    // ── put the window back ─────────────────────────────────────────────────
    // COLLECTED, NOT ASSERTED: a hard expect would discard every finding above it.
    if (!originalRange) note("no window button was active when this test began, so there was no window to put back: this browser is left on 7d");
    else {
      await acted(rangeGroup.getByRole("button", { name: originalRange, exact: true }).click(CLICK), "top bar: time range", `the ${originalRange} window would not take a click on the way back`);
      const restored = await settles(async () => (await activeRange.count()) === 1 && (await activeRange.innerText().catch(() => "")).trim() === originalRange);
      if (!restored) fail("top bar: time range", `the window was left at 7d instead of the ${originalRange} this browser had`);
    }

    expect(report(failures), "the rail beside the queue, or a layer an alert row raises, misbehaved").toEqual([]);
    expect(watch.since(settled), "the alert drawer logged errors while its layers were driven").toEqual([]);
  });

  /**
   * WHAT BUG THIS PINS: there is no /api/logout route on the control plane. The rail's
   * href resolves only because the deploy installs `location = /api/logout { return 302
   * …/auth/logout; }` into an nginx snippet (scripts/deploy/lib.sh:1150); lose that one
   * line and Sign out lands on a bare 404 — or, one block out, on the SPA catch-all's
   * 200 — with the session still live and nothing saying so. The one test that follows
   * the href ("the account group's sign out ends a session it owns") skips on a control
   * plane with no second identity, so this is what runs there.
   *
   * Read-only, and load-bearing: the run shares ONE signed-in storageState and the
   * control plane keys its session map by the soc_cp_session VALUE (bff.go:271-277), so
   * a single /auth/logout carrying it unauthenticates every test after this one.
   */
  test("sign out is one link in the Account group, and the hop behind its href resolves", async ({ page, playwright }) => {
    await signIn(page, env);
    const watch = new ConsoleWatch(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const settled = watch.mark();
    const failures: Failure[] = [];
    const rail = page.locator('[data-panel="left-sidebar"]');
    await expect(rail, "the SOC rail never rendered — there would be no exit to assert").toBeVisible();

    // ── one exit, and it is a link ─────────────────────────────────────────
    // Scoped to the rail, not the page: the account panel grows a sign-out of its own the
    // moment it is first opened (ModalShell mounts a body on first open and keeps it,
    // components.tsx:225-249, :271), and the Choke and Fleet chromes carry exits too — page-wide,
    // this would count a second exit the moment anything opened that panel.
    await expect(rail.locator('a[href="/api/logout"]'), "the rail offers no way out, or offers more than one").toHaveCount(1);
    const signOut = socNavLink(page, "Sign out");
    await expect(signOut, '"Sign out" does not resolve to exactly one rail link').toHaveCount(1);
    await expect(signOut, "the rail's exit points somewhere else").toHaveAttribute("href", "/api/logout");
    // A rail BUTTON would be a JS-driven exit, invisible to ROUTE_LINKS, to discoverRail's href
    // read, and to every assertion here.
    const buttonExit = rail.locator("button.soc-sidebar-item").filter({ has: page.getByText("Sign out", { exact: true }) });
    if (await buttonExit.count()) {
      failures.push({
        item: "rail: Sign out",
        reason: "is rendered as a BUTTON — a scripted exit whose destination no test and no operator can read off the markup"
      });
    }
    for (const attribute of ["target", "download"]) {
      const value = await signOut.getAttribute(attribute);
      if (value !== null) {
        failures.push({
          item: "rail: Sign out",
          reason: `carries ${attribute}="${value}" — sign-out has to be an ordinary same-tab navigation or it does not commit`
        });
      }
    }
    const current = await signOut.getAttribute("aria-current");
    if (current !== null) {
      failures.push({
        item: "rail: Sign out",
        reason: `is marked aria-current="${current}" — the exit claims to be the page the operator is on`
      });
    }

    // ── the group it lives in, found structurally ──────────────────────────
    // filter({ has }), never hasText: hasText is a substring match, and is what made
    // this file's "Platform" locator resolve to three buttons.
    const accountGroup = rail.locator(".soc-sidebar-section").filter({ has: page.locator('a[href="/api/logout"]') });
    await expect(accountGroup, "the exit sits in no nav group at all").toHaveCount(1);
    const groupLabel = accountGroup.locator(".soc-sidebar-label");
    await expect(groupLabel, "the group holding the exit has no heading").toHaveCount(1);
    // textContent, not innerText: .soc-sidebar-label is CSS-uppercased (soc.css:242-249).
    const groupTitle = ((await groupLabel.textContent()) ?? "").trim();
    if (groupTitle.toLowerCase() !== "account") {
      failures.push({
        item: "rail: Sign out",
        reason: `lives under "${groupTitle}", not the Account group — the exit has been filed with the tools`
      });
    }
    await expect(accountGroup.locator(".soc-sidebar-item"), "the Account group is not the operator entry plus the way out").toHaveCount(2);
    // DISCOVERED, not keyed on the operator's name: normalizeWhoami falls back to the literal
    // "operator" until /api/whoami lands (api.ts:24 + :482).
    const accountButton = accountGroup.locator("button.soc-sidebar-item");
    await expect(accountButton, "the Account group's other item is not a button").toHaveCount(1);
    const whoami = await readWhoami(page);
    // Non-vacuity: toContainText("") passes against anything.
    expect(whoami.user.length, "/api/whoami named no subject, so 'the rail says who is signed in' cannot be asserted against it").toBeGreaterThan(0);
    await expect(accountButton, `the account entry never resolved who is signed in — it should name "${whoami.user}"`).toContainText(whoami.user);
    // Stated, not failed: collapse is CSS-only and the item stays in the DOM, so what is untrue is
    // only Sidebar.tsx's "always one click away".
    const groupToggle = accountGroup.locator("button.soc-sidebar-group-toggle");
    const isCollapsible = (await groupToggle.count()) === 1;
    if (isCollapsible) test.info().annotations.push({ type: "note", description: "Sidebar.tsx documents the Account group as pinned so Sign out is always one click away; it renders a collapse toggle and persists the collapsed state under soc.nav.v2.account, so it is not." });
    // And so it can arrive collapsed: a persisted `false` hides the items with CSS
    // (soc.css:308-310) and would turn the click below into a silent 15s timeout.
    let reCollapse = false;
    if (isCollapsible && (await groupToggle.getAttribute("aria-expanded")) === "false") {
      await groupToggle.click();
      await expect(groupToggle, "the Account group arrived collapsed and would not open, so its account entry cannot be reached").toHaveAttribute("aria-expanded", "true");
      reCollapse = true;
    }

    // ── the second exit, in the panel that entry opens ─────────────────────
    // TWO CLAIMS, one per state, because neither implies the other: while the panel is shut
    // its exit must be genuinely unreachable, and once it is open the exit must be there and
    // must agree with the rail's about where signing out goes.
    //
    // ModalShell mounts a body on FIRST OPEN and keeps it from then on (components.tsx:225-249, :271,
    // pinned by src/test/lazyModalMount.test.tsx), and this anchor is rendered by AccountBody —
    // the body. So on a dashboard where nobody has opened the panel the exit does not exist at
    // all: unreachable because it is absent, which is stronger than the display:none
    // (soc.css:2095, and :2106 for .is-open) the shell used to hide it behind.
    //
    // STRONGER ON A FRESH LOAD, and only there. The body is kept once opened, so from the
    // moment an operator opens this panel even once, the exit is back in the DOM behind that
    // same display:none for the rest of the session — the original tab-into hazard, unchanged.
    // This test runs on a fresh dashboard, which is why absence is the right check HERE; it is
    // not a claim about the panel's whole life. Visibility is checked as well rather than
    // assumed, so a return to eager mounting is REPORTED instead of quietly trading the strong
    // guarantee for the weak one.
    const modalExit = page.locator('[data-panel="account-profile-modal"] a.soc-account-signout');
    const openModal = page.locator('[data-panel="account-profile-modal"].is-open');
    await expect(openModal, "the account panel is already open on a fresh dashboard, so its exit cannot be checked for reachability-while-closed").toHaveCount(0);
    // COLLECTED, not asserted: an exit sitting behind a shut panel is a finding to report, not
    // a reason to abandon the checks below it.
    if (await modalExit.count()) {
      failures.push({
        item: "account panel: Sign out",
        reason: (await modalExit.isVisible())
          ? "is reachable while its panel is closed — an exit an operator can trip over by tabbing the dashboard"
          : "exists in the DOM behind a panel nobody has opened — hidden, so not tabbable, but the shell is mounting bodies eagerly again and this exit's unreachability now rests on one CSS class"
      });
    }
    try {
      await accountButton.click();
      await expect(openModal, "the account entry did not open the profile panel").toHaveCount(1);
      // Counted HERE, after the open, not before it: the anchor only exists once this panel's
      // body has been mounted, so "the panel carries an exit of its own" is a question only an
      // opened panel can answer.
      await expect(modalExit, "the account panel carries no sign-out of its own").toHaveCount(1);
      // ASSERTED, NEVER CLICKED: this is the session the rest of the run shares.
      await expect(modalExit, "the panel's exit is not offered once it is open").toBeVisible();
      await expect(modalExit, "the console's two exits disagree about where signing out goes").toHaveAttribute("href", "/api/logout");
      await page.keyboard.press("Escape");
      await expect(openModal, "the account panel would not close").toHaveCount(0);
    } finally {
      // Closed whatever happened. Swallows nothing: a thrown assertion still propagates,
      // and Escape only nulls client-side surface state (SocRoute.tsx:191-197).
      await page.keyboard.press("Escape").catch(() => undefined);
    }

    // ── the hop behind the href, from a jar that holds no session ──────────
    // NOT tidiness: without an explicit storageState the runner fills it in from the config's
    // `use.storageState` — the run's
    // shared signed-in session — and the request reaches logout carrying soc_cp_session, the VALUE
    // the CP keys its sessions by.
    const api = await playwright.request.newContext({ baseURL: env.baseURL, ignoreHTTPSErrors: true, storageState: { cookies: [], origins: [] } });
    // Discovered, not hardcoded. Path "/" excludes the IdP's own cookies, served from the same
    // origin under /realms/… paths.
    const held = (await page.context().cookies(env.baseURL)).filter((c) => c.path === "/" && c.httpOnly).map((c) => c.name);
    const origin = new URL(env.baseURL).origin;
    try {
      // THE GUARD, GUARDED: a hard precondition, not a collected failure — if this is ever non-
      // empty nothing below may go out.
      expect((await api.storageState()).cookies, "the logout probe's request context inherited the run's cookies — it must carry no session anywhere near /api/logout").toEqual([]);
      // maxRedirects: 0 returns the response as-is and does not throw. Following it on the control
      // plane would reach /auth/logout, the destructive one.
      const hop = await api.get("/api/logout", { maxRedirects: 0, failOnStatusCode: false });
      const hopTo = hop.headers()["location"] ?? "";
      const hopURL = hopTo ? new URL(hopTo, env.baseURL) : null;
      const shape = hop.status() === 302 && hopURL?.pathname === "/auth/logout" ? "controlplane" : hop.status() === 303 && hopURL?.pathname === "/login" ? "engine" : "unknown";
      test.info().annotations.push({ type: "note", description: `GET /api/logout (no cookies) → ${hop.status()} ${hopTo || "(no Location)"} — the ${shape} sign-out contract` });
      // Which deployment this is, decided by what it ANSWERED. env.kind is a declaration nothing
      // verifies (support/live.ts:69)
      // and the sign-out click test branches its safety on it, so a mismatch is reported alongside
      // that test — not as a guard
      // on it: this describe block is not serial and retries are 0, so it still runs.
      if (shape === "unknown") {
        failures.push({
          item: "GET /api/logout",
          reason: `answered ${hop.status()} → "${hopTo}" — neither the control plane's nginx hop (302 → /auth/logout) nor the engine's handler (303 → /login). A 404 is the \`location = /api/logout\` line gone from the nginx snippet, leaving \`location /api/\` to proxy it to a control plane with no such route; a 200 is the same fault one block further out, the SPA catch-all serving index.html. Either way Sign out leaves the operator signed in.`
        });
      }
      else if (shape !== env.kind) {
        failures.push({
          item: "PROBE_KIND",
          reason: `this run declares kind "${env.kind}" and the deployment answers the ${shape} sign-out contract. The click test branches on env.kind !== "engine", so a control plane declared as an engine has an operator's SSO ended with no opt-in.`
        });
      }

      if (shape === "controlplane") {
        // nginx answering from its own config: no upstream, no Set-Cookie. A hop that sets cookies
        // has reached a handler.
        const hopCookies = setCookiesOf(hop);
        if (hopCookies.length) {
          failures.push({
            item: "GET /api/logout",
            reason: `carried ${hopCookies.length} Set-Cookie header(s) (${hopCookies.map(cookieName).join(", ")}) — the hop is supposed to be a static nginx redirect that touches no session`
          });
        }
        if (hopURL && hopURL.origin !== origin) {
          failures.push({
            item: "GET /api/logout",
            reason: `redirects off this console's origin, to ${hopURL.origin} — sign-out must stay on the deployment the operator is signed into`
          });
        }
        // Cookie-free, so the BFF's `delete(h.sessions, c.Value)` branch is never entered
        // (bff.go:271-278): what is read is the SHAPE of the redirect.
        const rp = await api.get("/auth/logout", { maxRedirects: 0, failOnStatusCode: false });
        if (rp.status() === 204) {
          failures.push({
            item: "GET /auth/logout",
            reason: "answered 204: no end_session_endpoint was discovered, so sign-out is LOCAL-ONLY — the console forgets the session, the IdP does not, and the next sign-in is silent"
          });
        }
        else if (rp.status() !== 302) {
          failures.push({
            item: "GET /auth/logout",
            reason: `answered ${rp.status()} — the console's exit reaches no RP-initiated logout at all`
          });
        }
        else {
          const endSession = new URL(rp.headers()["location"] ?? "", env.baseURL);
          test.info().annotations.push({ type: "note", description: `RP-initiated logout goes to ${endSession.origin}${endSession.pathname}` });
          if (!endSession.searchParams.has("client_id")) {
            failures.push({
              item: "GET /auth/logout",
              reason: "builds an end-session redirect with no client_id — without a hint or a client the IdP has nothing to scope the logout to and ends nothing"
            });
          }
          if (endSession.searchParams.has("id_token_hint")) {
            failures.push({
              item: "GET /auth/logout",
              reason: "carried an id_token_hint for a request that sent no session cookie — this probe must be incapable of ending a session, and a hint means it just did"
            });
          }
          const back = endSession.searchParams.get("post_logout_redirect_uri") ?? "";
          const backURL = back ? new URL(back) : null;
          if (!backURL || backURL.origin !== origin || backURL.pathname !== "/") {
            failures.push({
              item: "GET /auth/logout",
              reason: `sends the operator back to "${back}" — it must be this console's own origin at "/", registered at the IdP; anything else parks the browser on an IdP error page after a successful sign-out`
            });
          }
        }
        failures.push(...inspectCookies("GET /auth/logout", held, setCookiesOf(rp)));
      }

      if (shape === "engine") {
        failures.push(...inspectCookies("GET /api/logout", held, setCookiesOf(hop)));
        // Engine sessions are stateless signed cookies: a logout landing on a 404 leaves a browser
        // signed out with nowhere to sign back in.
        const landing = await api.get("/login", { maxRedirects: 0, failOnStatusCode: false });
        if (landing.status() !== 200) {
          failures.push({
            item: "GET /login",
            reason: `sign-out redirects here and it answers ${landing.status()} — the operator is signed out onto nothing`
          });
        }
      }
    } finally {
      await api.dispose();
    }

    // RESTORED BEFORE THE REPORT, and a restore that fails is itself a finding.
    if (reCollapse) {
      await groupToggle.click().catch(() => undefined);
      if ((await groupToggle.getAttribute("aria-expanded")) !== "false") {
        failures.push({
          item: "rail: Account",
          reason: "this test opened the collapsed Account group to reach its account entry and could not collapse it back"
        });
      }
    }

    // THE POINT OF EVERY MECHANIC ABOVE, ASSERTED: the session this test shares with the rest of
    // the run is still live.
    const shared = async () => (await page.request.get("/api/whoami", { failOnStatusCode: false })).status();
    await expect.poll(shared, { timeout: 30_000, message: "this test ended the session it shares with the rest of the run — the cookie-free context leaked" }).toBe(200);
    expect(report(failures), `the way out of this console is not sound (run declared kind "${env.kind}")`).toEqual([]);
    expect(watch.since(settled), "the console logged errors while its exits were inspected").toEqual([]);
  });
});
