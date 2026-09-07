import type { Page } from "@playwright/test";

import { fleetPartialFailure } from "./support/fixtures";
import { installMockApi, RequestLog } from "./support/mock-api";
import { expect, test } from "./support/test";

/**
 * The fleet console's WRITE path — who a write hits, what it carries, and what
 * the operator is told afterwards.
 *
 * WHAT THESE PIN. fleet.spec.ts proves the panels render; nothing proved that
 * the controls on them send the right thing to the right hosts. Every claim
 * below is a blast-radius or an honesty property:
 *
 *  1. THE TARGET SET ON SCREEN IS THE TARGET SET ON THE WIRE. "All hosts" is
 *     `targets: null` and "Selected only" is an explicit host list, and those
 *     two are one segment click apart. The assertions below pin the BODY THE
 *     BROWSER EMITS and nothing further — a mock answers whatever the console
 *     sends, so no browser test can prove a write was scoped. Both servers
 *     have honoured `targets` since 2026-09-02 and each half is pinned by its
 *     own Go test (engine/internal/api/fleet_targets_test.go and
 *     engine/internal/controlplane/fleettargeting_test.go).
 *  2. "SELECTED ONLY" WITH NOTHING SELECTED SENDS NOTHING. An empty list that
 *     leaked onto the wire as `[]` — or worse, degraded to `null` — would turn
 *     "I have not picked a host yet" into an estate-wide write. This one holds
 *     end-to-end: the guard is that no request is issued at all.
 *  3. A NON-ASCENDING THRESHOLD LADDER NEVER LEAVES THE BROWSER. throttle <
 *     tarpit < quarantine < sever is what makes the ladder a ladder; a fleet
 *     configured with sever below throttle severs on the first suspicious
 *     exec on every host at once. validateThresholds() runs BEFORE the request
 *     is built, so the assertion is on the absence of a PUT, not on a 400.
 *  4. THE ESTATE-WIDE DESTRUCTIVE ACTIONS ARE GATED, AND THE WAY OUT IS NOT.
 *     Containment, maintenance, kill-switch-ON and thaw go through a confirm
 *     (all four are clicked below); kill-switch-OFF (restoring enforcement)
 *     does not. The gated ones that carry an audit reason must refuse to send
 *     without one — including the kill-switch, which the engine audits and
 *     which carried none at all until 2026-09-02.
 *  5. A HALF-APPLIED FAN-OUT READS AS HALF-APPLIED. This is the worst outcome
 *     this view can produce: an operator who is told "applied" while one host
 *     never took the change believes the estate is uniform when it is not.
 *
 * WHY IT IS HERE AND NOT IN UNIT TESTS: the claim is about the HTTP body the
 * browser emits after a specific sequence of clicks across three components —
 * the rail's segment, the table's checkboxes, and the confirm modal — wired
 * through useFleetControls' late target resolution. jsdom can call the hook,
 * but it cannot observe that the button an operator actually reaches is the
 * one bound to the target set the rail is showing, nor that the request was
 * never issued at all. Every assertion here is on `RequestLog` — what the page
 * SENT — because on a write path the body is the contract and the toast is
 * only a claim about it.
 *
 * ── SERVER-SIDE GAPS THIS SUITE STRUCTURALLY CANNOT FAIL ON ────────────────
 * A browser suite talks to a mock, so a field the console sends correctly and
 * the server then ignores produces a green run. Two such gaps were found
 * reading the handlers behind these routes. Both were closed on 2026-09-02;
 * they are kept here because the reason e2e cannot catch them has not changed,
 * so a regression in either would show up as a green run:
 *
 *  A. `targets` WAS READ BY NO SERVER, so "Selected only" scoped nothing.
 *     CLOSED 2026-09-02. Single-tenant: `(*Fleet).fanout` called `f.Peers()` —
 *     the whole hosts file — and forwarded the body verbatim to every peer.
 *     Multi-tenant: controlplane/choke.go's `handleChokePreset` decoded only
 *     `{name, reason}` and called `dispatchAll(r, tenant, ...)`, every agent in
 *     the tenant. Ticking alpha-edge, reading "Writes target 1 selected host."
 *     and pressing Containment contained bravo-edge too.
 *     Now: both servers resolve `targets` before dispatching anything — an
 *     unknown name or an empty list is a 400 that applies NOWHERE, rather than
 *     a partial write against a target set the server misunderstood — and both
 *     return one `hosts` entry per host actually written to.
 *  B. THE KILL-SWITCH CARRIED NO AUDIT REASON. CLOSED 2026-09-02, and pinned
 *     by an executable test below rather than prose, because that half IS
 *     observable in the browser — the console now collects one.
 *
 * FIXTURES: the default mock fleet — peers `alpha-edge` and `bravo-edge`, both
 * reachable, both on thresholds 5/10/20/40 (so the majority ladder the draft
 * syncs to is 5/10/20/40, not the 10/30/60/100 built-in default). The partial
 * fan-out uses `fleetPartialFailure` from support/fixtures.ts, whose host names
 * (`alpha`/`bravo`) are deliberately the server's, not the mock peer list's —
 * the console must echo what the fan-out reported rather than what it assumed.
 *
 * NOTE ON THE MOCK: /fleet polls on a 5s interval and has no SSE, so every
 * assertion below is scoped to non-GET requests on the write paths; the poll's
 * GET traffic shares those prefixes only for the read routes. Tests 1-7 all run
 * against support/mock-api.ts's `writeResponse`, which returns the SINGLE-TENANT
 * engine's `{hosts:[...]}` fan-out envelope. The control plane answers these
 * same routes with a different shape; that shape is exercised only by the last
 * test in this file.
 */

type WriteBody = Record<string, unknown>;

/** Non-GET requests to a write path, decoded — the actual contract under test. */
function writes(recorder: RequestLog, path: RegExp): WriteBody[] {
  return recorder
    .matching(path)
    .filter((request) => request.method !== "GET")
    .map((request) => JSON.parse(request.body ?? "{}") as WriteBody);
}

const PRESET = /^\/api\/fleet\/preset$/;
const THRESHOLDS = /^\/api\/fleet\/thresholds$/;
const KILL_SWITCH = /^\/api\/fleet\/kill-switch$/;
const THAW = /^\/api\/fleet\/thaw$/;

/**
 * Waits until the rail is live: peers loaded (so `writesDisabled` is false)
 * and the threshold draft has synced to the fleet majority. Editing before the
 * sync lands means the sync overwrites the edit and the test asserts on the
 * wrong numbers.
 */
async function fleetReady(page: Page) {
  await expect(
    page.getByRole("row", { name: /alpha-edge/ }),
    "the fleet table never loaded, so no control on this page is under test"
  ).toBeVisible();
  await expect(
    page.getByLabel("Throttle", { exact: true }),
    "threshold draft never synced to the fleet majority (5/10/20/40)"
  ).toHaveValue("5");
}

function preset(page: Page, name: RegExp) {
  return page.getByRole("button", { name }).and(page.locator("button.fleet-posture"));
}

test.describe("fleet write path", () => {
  test.use({ viewport: { width: 1600, height: 1000 } });

  /**
   * CLIENT HALF ONLY — see SERVER-SIDE GAPS (A) at the top of this file. The
   * body asserted here is what the browser sends; no server currently reads
   * `targets`, so a green run does not certify that the write was scoped.
   */
  test("the target set on screen is the target set on the wire", async ({ page }) => {
    const recorder = new RequestLog();
    await installMockApi(page, { recorder });
    await page.goto("/fleet");
    await fleetReady(page);

    // Default posture: every configured peer.
    await expect(
      page.getByText("Writes target every configured peer."),
      "the rail did not open on All hosts, so the first write below is not the one this test means"
    ).toBeVisible();
    await expect(
      page.getByText(/Current target set: 2 hosts\./),
      "Emergency Controls did not restate the estate-wide count, so the rail and the panel disagree about blast radius"
    ).toBeVisible();

    await preset(page, /Everyday Default/).click();

    await expect.poll(
      () => writes(recorder, PRESET).length,
      "the Default preset click never reached /api/fleet/preset"
    ).toBe(1);
    const estateWide = writes(recorder, PRESET)[0];
    expect(
      estateWide.targets,
      `an "All hosts" write must carry targets:null (the wire's "every peer"), got ${JSON.stringify(estateWide.targets)}`
    ).toBeNull();
    expect(estateWide.name, `preset name on the wire was ${JSON.stringify(estateWide.name)}`).toBe("default");

    // Now narrow to one host. Ticking a row is itself the mode switch — an
    // operator who ticks alpha-edge and never touches the segment must not get
    // an estate-wide write.
    await page.getByLabel("Select alpha-edge", { exact: true }).check();
    await expect(
      page.getByText("Writes target 1 selected host."),
      "ticking a host row did not flip the rail out of All hosts"
    ).toBeVisible();
    await expect(
      page.getByText(/Current target set: 1 host\./),
      "Emergency Controls kept restating the estate-wide count after a host was selected"
    ).toBeVisible();

    await preset(page, /Observe Forensic/).click();

    await expect.poll(
      () => writes(recorder, PRESET).length,
      "the second preset click never reached the server"
    ).toBe(2);
    const scoped = writes(recorder, PRESET)[1];
    expect(
      scoped.targets,
      `a "Selected only" write must name the ticked hosts, got ${JSON.stringify(scoped.targets)}`
    ).toEqual(["alpha-edge"]);
    expect(
      scoped.name,
      `the scoped write applied the wrong preset; body was ${JSON.stringify(scoped)}`
    ).toBe("forensic");

    // "Select all" is an EXPLICIT list, not a shortcut back to null. The
    // distinction matters the moment a peer is added to the engine's host
    // file: null follows the estate, a list does not.
    await page.getByRole("button", { name: "Select all", exact: true }).click();
    await preset(page, /Observe Forensic/).click();

    await expect.poll(
      () => writes(recorder, PRESET).length,
      "the write after Select all never reached the server"
    ).toBe(3);
    // Membership, not order: the list comes off a Set, whose iteration order is
    // incidental to the claim.
    const enumerated = writes(recorder, PRESET)[2].targets as string[] | null;
    expect(
      enumerated,
      `Select all must enumerate the peers rather than collapse to the estate-wide null; got ${JSON.stringify(enumerated)}`
    ).toHaveLength(2);
    expect(
      enumerated,
      `Select all named hosts that are not the configured peers; got ${JSON.stringify(enumerated)}`
    ).toEqual(expect.arrayContaining(["alpha-edge", "bravo-edge"]));
  });

  test('"Selected only" with nothing selected sends nothing at all', async ({ page }) => {
    const recorder = new RequestLog();
    await installMockApi(page, { recorder });
    await page.goto("/fleet");
    await fleetReady(page);

    await page.getByRole("button", { name: "Selected only", exact: true }).click();
    await expect(
      page.getByText("Writes target 0 selected hosts."),
      "the rail is not in the empty-selection state this test exists to cover"
    ).toBeVisible();

    await preset(page, /Observe Forensic/).click();

    // The click WAS handled — the toast proves the handler ran and refused,
    // rather than the button being inert for some unrelated reason.
    await expect(
      page.locator(".fleet-toast").filter({ hasText: "No hosts selected" }),
      "no feedback at all: an operator cannot tell a refused write from a lost one"
    ).toBeVisible();
    expect(
      writes(recorder, PRESET),
      "an empty selection reached the server, where it is either a no-op or an estate-wide write"
    ).toEqual([]);
  });

  test("a non-ascending threshold ladder is refused before it can be sent", async ({ page }) => {
    const recorder = new RequestLog();
    await installMockApi(page, { recorder });
    await page.goto("/fleet");
    await fleetReady(page);

    const apply = page.getByRole("button", { name: "Apply", exact: true });
    await expect(
      apply,
      "Apply must stay disabled while the draft still matches the fleet, or a no-op write can be fired at the estate"
    ).toBeDisabled();

    // sever BELOW quarantine: the ladder inverts, and a fleet that accepted it
    // would sever at a score it is meant to merely quarantine at.
    await page.getByLabel("Sever", { exact: true }).fill("8");
    await expect(page.getByText("Unsaved changes"), "the editor did not register the edit").toBeVisible();
    await expect(
      apply,
      "Apply stayed disabled after an edit, so the refusal below would be an artefact of an inert button"
    ).toBeEnabled();
    await apply.click();

    await expect(
      page.locator(".fleet-toast").filter({ hasText: "Invalid thresholds" }),
      "a malformed ladder was accepted silently"
    ).toBeVisible();
    await expect(
      page.locator(".fleet-toast"),
      "the refusal must say WHICH rule was broken, not just that something was wrong"
    ).toContainText(/strictly ascending/i);
    expect(
      writes(recorder, THRESHOLDS),
      "an inverted ladder reached the fleet; the client-side guard is the only thing between this and every host"
    ).toEqual([]);

    // Zero is refused on the same path, and for the same reason: a threshold of
    // 0 fires the rung on every process.
    await page.getByLabel("Sever", { exact: true }).fill("0");
    await apply.click();
    await expect(
      // Toasts stack rather than replace, so this names the second rule by its
      // own message instead of matching the "Invalid thresholds" title twice.
      page.locator(".fleet-toast").filter({ hasText: "greater than zero" }),
      "a zero threshold was accepted; it fires its rung on every process on every host"
    ).toBeVisible();
    expect(
      writes(recorder, THRESHOLDS),
      "a zero threshold reached the fleet"
    ).toEqual([]);

    // Repaired: strictly ascending, and now it goes — with the target set.
    await page.getByLabel("Throttle", { exact: true }).fill("6");
    await page.getByLabel("Tarpit", { exact: true }).fill("12");
    await page.getByLabel("Quarantine", { exact: true }).fill("24");
    await page.getByLabel("Sever", { exact: true }).fill("48");
    await apply.click();

    await expect.poll(
      () => writes(recorder, THRESHOLDS).length,
      "a valid ladder never reached the server, so the guard above may simply be blocking everything"
    ).toBe(1);
    const body = writes(recorder, THRESHOLDS)[0];
    expect(
      body,
      `the four rungs must travel as sent; body was ${JSON.stringify(body)}`
    ).toMatchObject({ throttle_at: 6, tarpit_at: 12, quarantine_at: 24, sever_at: 48 });
    expect(body.targets, "the threshold write lost its target set").toBeNull();

    const method = recorder.matching(THRESHOLDS).filter((request) => request.method !== "GET")[0].method;
    expect(method, "thresholds are a replacement of the whole ladder, so PUT").toBe("PUT");
  });

  test("estate-wide destructive presets are gated on a confirm and an audit reason", async ({ page }) => {
    const recorder = new RequestLog();
    await installMockApi(page, { recorder });
    await page.goto("/fleet");
    await fleetReady(page);

    await preset(page, /Severe Containment/).click();

    const dialog = page.getByRole("dialog");
    await expect(dialog, "containment applied on a single click").toBeVisible();
    await expect(
      dialog,
      "the confirm must say what containment does, not just ask 'are you sure'"
    ).toContainText(/choke suspicious chains/i);
    expect(writes(recorder, PRESET), "the preset was sent while the confirm was still open").toEqual([]);

    // Escaping out is a refusal, not a deferral.
    await page.keyboard.press("Escape");
    await expect(dialog, "Escape did not dismiss the confirm, so the refusal below proves nothing").toHaveCount(0);
    expect(writes(recorder, PRESET), "dismissing the confirm still applied the preset").toEqual([]);

    await preset(page, /Severe Containment/).click();
    const reason = page.getByRole("dialog").getByLabel("Audit reason");
    await expect(
      reason,
      "an estate-wide containment with no reason field lands in the audit log with no explanation"
    ).toBeVisible();

    await reason.fill("   ");
    await page.getByRole("dialog").getByRole("button", { name: "Apply preset" }).click();
    await expect(
      page.getByRole("dialog"),
      "a whitespace-only reason satisfied the audit requirement"
    ).toContainText(/reason is required/i);
    expect(writes(recorder, PRESET), "containment was applied with a blank audit reason").toEqual([]);

    await reason.fill("beaconing confirmed on alpha-edge");
    await page.getByRole("dialog").getByRole("button", { name: "Apply preset" }).click();

    await expect.poll(
      () => writes(recorder, PRESET).length,
      "the confirmed containment never reached the server"
    ).toBe(1);
    const body = writes(recorder, PRESET)[0];
    expect(
      body.name,
      `the confirmed write applied the wrong preset; body was ${JSON.stringify(body)}`
    ).toBe("containment");
    expect(
      body.reason,
      `the operator's reason must travel with the write; body was ${JSON.stringify(body)}`
    ).toBe("beaconing confirmed on alpha-edge");
    await expect(page.getByRole("dialog"), "the confirm stayed open after a successful write").toHaveCount(0);

    // Maintenance is the OTHER `danger` branch in requestPreset, and it is not
    // a lesser case: it engages the kill-switch across the target set, i.e. it
    // stops enforcement estate-wide. It must be gated exactly as hard.
    await preset(page, /Pause Maintenance/).click();
    const maintenance = page.getByRole("dialog");
    await expect(maintenance, "the maintenance preset applied on a single click").toBeVisible();
    await expect(
      maintenance,
      "the confirm must state that maintenance engages the kill-switch, which is what makes it destructive"
    ).toContainText(/kill-switch/i);
    expect(
      writes(recorder, PRESET),
      "maintenance was sent while its confirm was still open"
    ).toHaveLength(1);

    const maintenanceReason = maintenance.getByLabel("Audit reason");
    await maintenanceReason.fill("  ");
    await maintenance.getByRole("button", { name: "Apply preset" }).click();
    await expect(
      page.getByRole("dialog"),
      "maintenance accepted a whitespace-only audit reason where containment refused one"
    ).toContainText(/reason is required/i);
    expect(
      writes(recorder, PRESET),
      "maintenance disabled enforcement estate-wide with a blank audit reason"
    ).toHaveLength(1);

    await maintenanceReason.fill("patch window: kernel upgrade on the edge tier");
    await maintenance.getByRole("button", { name: "Apply preset" }).click();

    await expect.poll(
      () => writes(recorder, PRESET).length,
      "the confirmed maintenance preset never reached the server"
    ).toBe(2);
    const maintenanceBody = writes(recorder, PRESET)[1];
    expect(
      maintenanceBody.name,
      `the maintenance confirm sent the wrong preset; body was ${JSON.stringify(maintenanceBody)}`
    ).toBe("maintenance");
    expect(
      maintenanceBody.reason,
      `the operator's reason must travel with the maintenance write; body was ${JSON.stringify(maintenanceBody)}`
    ).toBe("patch window: kernel upgrade on the edge tier");
  });

  test("engaging the kill-switch is gated; disengaging it is not", async ({ page }) => {
    const recorder = new RequestLog();
    await installMockApi(page, { recorder });
    await page.goto("/fleet");
    await fleetReady(page);

    await page.getByRole("button", { name: "Kill-switch on", exact: true }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog, "bypassing enforcement fleet-wide was a single click").toBeVisible();
    await expect(
      dialog,
      "the confirm must state that enforcement stops but decisions still log"
    ).toContainText(/decisions still log/i);
    expect(
      writes(recorder, KILL_SWITCH),
      "the kill-switch engaged while its confirm was still open"
    ).toEqual([]);

    await dialog.getByRole("button", { name: "Engage" }).click();
    await expect.poll(
      () => writes(recorder, KILL_SWITCH).length,
      "the confirmed kill-switch never reached the server"
    ).toBe(1);
    expect(
      writes(recorder, KILL_SWITCH)[0],
      "the kill-switch write must be explicit about direction and blast radius"
    ).toMatchObject({ on: true, targets: null });

    // The way OUT of a bad state never waits for a dialog — the same rule the
    // approvals queue follows for withdrawal.
    await page.getByRole("button", { name: "Kill-switch off", exact: true }).click();
    await expect.poll(
      () => writes(recorder, KILL_SWITCH).length,
      "restoring enforcement did not reach the server on one click"
    ).toBe(2);
    expect(
      writes(recorder, KILL_SWITCH)[1],
      `disengaging must send on:false to the same target set, not a second engage; body was ${JSON.stringify(writes(recorder, KILL_SWITCH)[1])}`
    ).toMatchObject({ on: false, targets: null });
    await expect(
      page.getByRole("dialog"),
      "restoring enforcement must not be gated behind a dialog an operator has to read mid-incident"
    ).toHaveCount(0);
  });

  /**
   * KNOWN DEFECT — the widest-blast-radius toggle on the platform lands in the
   * audit log with an empty reason.
   *
   * The engine already audits one: `handleChokeKillSwitch`
   * (engine/internal/api/choke.go) decodes `{on, reason}` and, on a real
   * transition, calls
   *
   *     g.AuditConfigChange("kill-switch", stateWord(prev), stateWord(body.On),
   *         s.auth.Username(), strings.TrimSpace(body.Reason))
   *
   * with the source comment "It is the single widest-blast-radius toggle on
   * the platform and it wrote no audit row." The console never fills that
   * field: `requestKillSwitchOn` (useFleetControls.ts) builds a ConfirmState
   * with no `reasonLabel`, so ConfirmModal renders no input at all, and
   * `writeKillSwitch(on, targets)` (api.ts) posts only `{on, targets}`.
   * Containment, maintenance and thaw all carry an operator reason; bypassing
   * enforcement across the whole estate does not, so the audit row says who
   * and when but never why.
   *
   * FIXED 2026-09-02: `requestKillSwitchOn` collects an audit reason and
   * threads it through `setKillSwitch` to `writeKillSwitch`, which posts it as
   * a third field — the shape thaw already used.
   *
   * NOTE ON THIS TEST'S SHAPE: it is separate from the gating test above
   * rather than folded into it, so a regression in the reason cannot take that
   * test's live gating and disengage-is-ungated assertions down with it.
   */
  test("engaging the kill-switch records the operator's audit reason", async ({ page }) => {
    const recorder = new RequestLog();
    await installMockApi(page, { recorder });
    await page.goto("/fleet");
    await fleetReady(page);

    await page.getByRole("button", { name: "Kill-switch on", exact: true }).click();
    const dialog = page.getByRole("dialog");
    const reason = dialog.getByLabel("Audit reason");
    await expect(
      reason,
      "the kill-switch confirm collects no reason, so the engine's audit row for the widest-blast-radius toggle on the platform is written with an empty explanation"
    ).toBeVisible();

    await reason.fill("ransomware canary tripped; enforcement is killing the recovery job");
    await dialog.getByRole("button", { name: "Engage" }).click();

    await expect.poll(
      () => writes(recorder, KILL_SWITCH).length,
      "the confirmed kill-switch never reached the server"
    ).toBe(1);
    const body = writes(recorder, KILL_SWITCH)[0];
    expect(
      body.reason,
      `the operator's reason must travel with the kill-switch write; body was ${JSON.stringify(body)}`
    ).toBe("ransomware canary tripped; enforcement is killing the recovery job");
  });

  test("thaw carries an audit reason and the selected hosts", async ({ page }) => {
    const recorder = new RequestLog();
    await installMockApi(page, { recorder });
    await page.goto("/fleet");
    await fleetReady(page);

    // Scope it first, so this also pins that the confirm path resolves targets
    // at write time rather than capturing them when the dialog opened.
    await page.getByLabel("Select bravo-edge", { exact: true }).check();

    await page.getByRole("button", { name: "Thaw quarantine", exact: true }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog, "thaw released quarantined processes without a confirm").toBeVisible();
    await expect(
      dialog.getByLabel("Audit reason"),
      "releasing quarantined processes with no recorded reason is an unexplained gap in the timeline"
    ).toHaveValue(/\S/);
    expect(
      writes(recorder, THAW),
      "the thaw was sent while its confirm was still open"
    ).toEqual([]);

    await dialog.getByLabel("Audit reason").fill("false positive on the backup job");
    await dialog.getByRole("button", { name: "Thaw", exact: true }).click();

    await expect.poll(
      () => writes(recorder, THAW).length,
      "the confirmed thaw never reached the server"
    ).toBe(1);
    const body = writes(recorder, THAW)[0];
    expect(
      body.reason,
      `the operator's reason must travel with the thaw; body was ${JSON.stringify(body)}`
    ).toBe("false positive on the backup job");
    expect(
      body.targets,
      `thaw must release only the hosts that were targeted; body was ${JSON.stringify(body)}`
    ).toEqual(["bravo-edge"]);
  });

  /**
   * The worst outcome this view can produce.
   *
   * A fan-out is partial by construction — each peer is a separate HTTP call to
   * a separate box — so "the write returned 200" says nothing about whether the
   * estate is now uniform. If the console reports a blanket "applied" over a
   * fan-out where one host refused, the operator stops looking, and the host
   * that never took containment is the one the intruder is on.
   */
  test("a half-applied fan-out is reported per host, never as a blanket success", async ({ page }) => {
    const recorder = new RequestLog();
    await installMockApi(page, {
      recorder,
      routes: { "/api/fleet/preset": fleetPartialFailure }
    });
    await page.goto("/fleet");
    await fleetReady(page);

    await preset(page, /Everyday Default/).click();

    await expect.poll(
      () => writes(recorder, PRESET).length,
      "the preset never reached the server, so no fan-out result was rendered"
    ).toBe(1);

    const toast = page.locator(".fleet-toast");
    await expect(toast, "the fan-out result was not reported at all").toBeVisible();
    await expect(
      toast,
      "a fan-out where a host refused must not read as a clean success"
    ).toContainText(/partial/i);
    await expect(
      toast,
      "the operator is not told WHICH host is now out of step with the rest of the fleet"
    ).toContainText("bravo");
    await expect(
      toast,
      "the failing host's error is what tells an operator whether to retry or investigate"
    ).toContainText("fleet peer unavailable");
    await expect(toast, "the succeeded/total count is missing").toContainText("1/2");

    await expect(
      page.locator(".fleet-toast--ok"),
      "a success-toned toast was raised over a fan-out that half-failed"
    ).toHaveCount(0);
    await expect(
      page.locator(".fleet-toast--err"),
      "the partial fan-out was not toned as a failure, so it reads like routine confirmation"
    ).toHaveCount(1);
  });

  /**
   * KNOWN DEFECT (half 1 of 2) — the control plane's real coverage is discarded.
   *
   * The body below is not invented: it is the control plane's DOCUMENTED
   * response for this route. `handleChokePreset`
   * (engine/internal/controlplane/choke.go:990-1008) answers
   *
   *     {"ok": applied > 0, "preset": …, "applied": …, "total": …, "detail": …}
   *
   * — recorded verbatim at docs/api/openapi.yaml under /api/fleet/preset. There
   * is no `hosts` key in it at all. The console reads `result.hosts ?? []`
   * (useFleetControls.ts) and hands that to summarizeFanout (fleetLogic.ts), so
   * the `applied`/`total` the control plane actually reported are dropped on
   * the floor and every multi-tenant fleet write renders "0/0 hosts succeeded".
   *
   * THIS TEST pins the honest reading of THIS envelope: a preset that reached
   * two of two agents must say so. Until 2026-09-02 the console printed
   * "Preset default applied0/0 hosts succeeded."
   *
   * FIXED 2026-09-02 on both sides: the control plane now returns a `hosts`
   * array built from the per-agent acks, and the console normalises the
   * envelope before summarizeFanout — reading `applied`/`total` when `hosts`
   * is absent, and never reading an absent list as full coverage.
   *
   * WHY IT IS SPLIT FROM THE TEST BELOW: this envelope describes a fan-out that
   * REACHED EVERY AGENT, so asserting "no hosts" over it would pin an end state
   * the fix must never produce — the cheapest way to green it would be to tell
   * an operator that a write reaching two agents reached none. The zero-coverage
   * case has its own envelope and its own test.
   */
  test("a multi-tenant fan-out reports the coverage the control plane gave it", async ({ page }) => {
    const recorder = new RequestLog();
    await installMockApi(page, {
      recorder,
      // The control plane's documented 200 for this route: the write reached
      // two of two agents. Note what is NOT in it — a `hosts` array.
      routes: { "/api/fleet/preset": { ok: true, preset: "default", applied: 2, total: 2, detail: "" } }
    });
    await page.goto("/fleet");
    await fleetReady(page);

    await preset(page, /Everyday Default/).click();

    await expect.poll(
      () => writes(recorder, PRESET).length,
      "the preset never reached the server, so no fan-out result was rendered"
    ).toBe(1);

    const toast = page.locator(".fleet-toast");
    await expect(toast, "the fan-out result was not reported at all").toBeVisible();
    await expect(
      toast,
      "the control plane said this reached 2 of 2 agents; the console must report that coverage rather than inventing its own"
    ).toContainText(/2\s*\/\s*2/);
    await expect(
      toast,
      "the console reported 0/0 for a write the control plane said reached every agent"
    ).not.toContainText(/0\s*\/\s*0/);
    await expect(
      page.locator(".fleet-toast--ok"),
      "a fan-out that reached every agent must be toned as the success it was"
    ).toHaveCount(1);
  });

  /**
   * KNOWN DEFECT (half 2 of 2) — a fan-out that reached NOBODY reads as applied.
   *
   * `summarizeFanout` (fleetLogic.ts) derives success from `failed === 0`:
   *
   *     const failed = total - success;
   *     if (failed === 0) return { ok: true, title: `${label} applied`, ... }
   *
   * An EMPTY host list satisfies that. So a write the console could account for
   * on zero hosts raises a green "applied" toast, identical to one that reached
   * every host. During an incident the operator moves on believing containment
   * is in place across a fleet the write never touched.
   *
   * The envelope here is the ENGINE's shape with an empty list — a genuinely
   * zero-coverage fan-out — so this pins only the `total === 0` half and is
   * unaffected by the control-plane normalisation the test above requires.
   *
   * FIXED 2026-09-02: `total === 0` is not success — summarizeFanout reports a
   * zero-coverage fan-out as a failure and says so in the toast.
   *
   * NOTE ON SHAPE: the assertions are POSITIVE — the toast must SAY it reached
   * no hosts, and must be error-toned — rather than a
   * `.not.toContainText(/applied/i)`, which any toast lacking the word
   * "applied" satisfies, including the "Preset failed" toast the catch arm
   * raises when the request never completed at all.
   */
  test("a fan-out that reached no hosts must not report as applied", async ({ page }) => {
    const recorder = new RequestLog();
    await installMockApi(page, {
      recorder,
      // Engine-shaped, and genuinely empty: the write was issued and reached
      // no peer at all.
      routes: { "/api/fleet/preset": { hosts: [] } }
    });
    await page.goto("/fleet");
    await fleetReady(page);

    await preset(page, /Everyday Default/).click();

    await expect.poll(
      () => writes(recorder, PRESET).length,
      "the preset never reached the server, so no fan-out result was rendered"
    ).toBe(1);

    const toast = page.locator(".fleet-toast");
    await expect(toast, "the fan-out result was not reported at all").toBeVisible();
    await expect(
      toast,
      "a write the console could account for on zero hosts was still reported as applied; it must say it reached no hosts"
    ).toContainText(/no hosts/i);
    await expect(
      page.locator(".fleet-toast--err"),
      "a fan-out that touched no host must be toned as a failure, not as routine confirmation"
    ).toHaveCount(1);
    await expect(
      page.locator(".fleet-toast--ok"),
      "a success-toned toast was raised over a fan-out that touched no host at all"
    ).toHaveCount(0);
  });
});
