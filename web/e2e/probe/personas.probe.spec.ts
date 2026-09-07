import type { Browser, BrowserContext, Locator, Page } from "@playwright/test";

import {
  expect,
  hasCredentials,
  hasCrossTenantResponder,
  hasReadOnlyOperator,
  readProbeEnv,
  readWhoami,
  signedInContext,
  test,
  type ProbeEnv,
  type Whoami
} from "./support/live";

/**
 * The two roles the platform defines and nothing has ever exercised.
 *
 * authz.go names four (authz.go:24-29): `read-only`, `tenant-analyst`,
 * `msoc-admin`, `cross-tenant-responder`. Only the middle two are provisioned
 * on any deployment, so only the middle two are covered — by the Go tests, by
 * the mocked e2e suite, and by every other probe in this directory. The two
 * that are not covered are the two whose whole reason for existing is a
 * DIFFERENCE in capability, which is precisely the thing an untested role gets
 * wrong.
 *
 * WHAT THIS PINS.
 *
 *  1. THE READ-ONLY OPERATOR IS SHOWN A FULLY ARMED CONSOLE. roleCan()
 *     authorizes `read-only` for ActionRead and nothing else (authz.go), so
 *     authorizeRespond denies every write route before it decodes a body.
 *     handleWhoami publishes that as `can_respond:false`, and authz.CanRespond
 *     exists for one stated purpose — its own comment reads "The console uses
 *     it to enable/disable action controls". The console does not use it:
 *     normalizeWhoami (web/src/features/soc/api.ts:479) picks user, host, role,
 *     can_push_policy and policy_scope, and `can_respond` appears nowhere in
 *     web/src at all. So a read-only operator is offered the kill-switch, the
 *     enforcement toggle, the per-process sever, the threshold commit and the
 *     whole fleet write rail — every one of which the server answers 404. The
 *     operator learns their permissions by pressing an emergency control in
 *     front of someone and watching nothing happen.
 *
 *  2. `role` IN WHOAMI IS A BOOLEAN WEARING A ROLE NAME. handleWhoami computes
 *     it as `if HasCrossTenant(p) { "msoc-admin" } else { "tenant-analyst" }`.
 *     That is wrong for HALF the roles the platform defines: a read-only
 *     operator is published as `tenant-analyst`, and a cross-tenant-responder
 *     as `msoc-admin`. It is the only role signal the console has — the account
 *     surface renders it verbatim — so the one place the console names an
 *     operator's authority names it wrongly for both personas here.
 *
 *  3. THE CROSS-TENANT-RESPONDER INHERITS THE TENANT-PINNING DEFECT
 *     msoc.probe.spec.ts pins. identity.PrincipalFromClaims stamps the
 *     account's `tenant` attribute onto EVERY realm role in the token,
 *     including Keycloak's capability-less default composites; TenantScope
 *     skips the cross-tenant role but keeps those, so whoami hands a
 *     cross-tenant principal a one-tenant scope and handleWhoami's `host`
 *     becomes that customer's name. Predicted here from the same source, for
 *     the second cross-tenant role, before the account exists.
 *
 * The read-only half deliberately asserts what WORKS as well: whoami answers,
 * the reads succeed, the dashboard and the choke table render. A persona spec
 * that only records what is broken would leave "read-only is unusable" as a
 * live reading of a green run.
 *
 * WHY A PROBE AND NOT A MOCKED E2E. Every claim here is about a decision made
 * outside the frontend. Which realm roles Keycloak put in the token, what
 * PrincipalFromClaims made of them, what roleCan() then permits, and what
 * status authorizeRespond returns — `page.route()` deletes all four layers and
 * answers whatever the console asked for. The Go tests cover the other end:
 * they prove roleCan(RoleReadOnly, ActionRespond) is false for a hand-built
 * Principal. Neither can see the thing that actually harms an operator, which
 * is a real session driving the real console and being offered a control the
 * real server will refuse. Only a live read-only session shows that.
 *
 * IDENTITIES IT NEEDS, AND HOW TO PROVISION THEM.
 *   PROBE_USER / PROBE_PASSWORD      a tenant-analyst — the CONTROL. Every
 *                                    comparison here needs a principal that
 *                                    CAN respond on the same deployment in the
 *                                    same second, or "the read-only operator
 *                                    was refused" is indistinguishable from
 *                                    "the route is broken for everybody" and
 *                                    "the control is disabled" from "the
 *                                    estate is idle".
 *   PROBE_RO_USER / PROBE_RO_PASSWORD    Keycloak account, realm role
 *                                    `read-only`, `attributes.tenant=<tenant>`.
 *   PROBE_XR_USER / PROBE_XR_PASSWORD    Keycloak account, realm role
 *                                    `cross-tenant-responder`. It will also be
 *                                    given a tenant attribute by
 *                                    scripts/deploy/lib.sh; that is the input
 *                                    to defect 3, not a mistake to correct
 *                                    before running this.
 *   PROBE_OTHER_TENANT               a tenant the analyst may NOT read, for
 *                                    the responder's positive control.
 * Each describe skips cleanly when its persona is absent, and the file skips
 * off the control plane entirely — the single-tenant engine has one operator
 * and no RBAC roles to distinguish.
 *
 * WRITES. This runs against production and changes no estate state. The only
 * non-GET requests in the file are in ONE test, sent from the read-only session
 * ONLY, and only after that session's whoami has been proved to report
 * `can_respond:false`. That is safe by construction rather than by hope:
 * authorizeRespondMethods checks the verb, resolves the principal, resolves the
 * tenant and calls authz.Authorize BEFORE any handler decodes a body, so a
 * denial returns 404 with the dispatcher never reached and the request body
 * never read (controlplane/choke.go:90-122). No write is ever sent from the
 * analyst or the responder session: both CAN respond, and a manual choke whose
 * exec_id resolves to no single owner fans the rung out to every agent in the
 * tenant (resolveTarget). There is no aimable no-op for a principal that is
 * authorized, so none is attempted.
 *
 * AUDIT FOOTPRINT — READ BEFORE PUTTING THIS IN CI. authz.Authorize records
 * through the auditor atomically with each decision, and on this deployment the
 * auditor is Postgres. A DENIED decision is recorded (RecordAccess early-returns
 * only on allowed && !crossTenant), so the refusal test appends TWENTY durable
 * `operator_audit` rows per run — subject = the read-only operator, tenant =
 * their own, action = respond/approve, allowed = false — into a table with no
 * retention, and into the customer-visible view of it. That is the price of the
 * claim being per-route: a write route left out of the list is a write route
 * nothing checks. The GET half of each pair costs nothing (the method guard
 * returns before Authorize is called, and authorizeRead on an own-tenant read
 * is not recorded). The responder's cross-tenant reads and its console's own
 * boot-time polling cost rows exactly as msoc.probe.spec.ts documents, which is
 * why its page is parked at about:blank the moment sign-in is proved.
 *
 * MECHANICS. `toBeVisible()` is not "this opened" in this app: SocModals mounts
 * every modal body permanently and withholds `is-open`, and SlideOver hides its
 * aside with translateX(102%), which Playwright still counts as visible. Modal
 * assertions here use toHaveClass(/is-open/) and every content assertion is
 * scoped inside a proven-open element.
 */

const env = readProbeEnv();

/** whoami with the fields `readWhoami` normalises away — `role` in particular. */
async function readWhoamiRaw(page: Page): Promise<Record<string, unknown>> {
  const response = await page.request.get("/api/whoami");
  expect(response.status(), "whoami must answer for a signed-in operator").toBe(200);
  return (await response.json()) as Record<string, unknown>;
}

interface Session {
  context: BrowserContext;
  page: Page;
  who: Whoami;
  raw: Record<string, unknown>;
}

/**
 * A persona session and the tenant-analyst control, side by side.
 *
 * The control is not decoration. Half of what this file claims is a DIFFERENCE
 * — refused where the analyst is granted, offered where the analyst is offered
 * — and a difference measured against nothing is an absolute measurement
 * dressed up as a comparison. It also closes the trap `signedInContext` was
 * written for: `browser.newContext()` inherits the config's `use.storageState`,
 * which carries the run's shared analyst session, so a hand-built context would
 * have compared that operator with ITSELF. The subject assertion below is what
 * makes that impossible to miss.
 */
async function personaAndControl(
  browser: Browser,
  probe: ProbeEnv,
  who: { user: string; password: string }
): Promise<{ persona: Session; analyst: Session }> {
  const open = async (creds: { user: string; password: string }): Promise<Session> => {
    const { context, page } = await signedInContext(browser, probe, creds);
    const raw = await readWhoamiRaw(page);
    return { context, page, who: await readWhoami(page), raw };
  };

  const persona = await open(who);
  const analyst = await open({ user: probe.user!, password: probe.password! });

  expect(persona.who.user, "the persona session has no subject").toBeTruthy();
  expect(analyst.who.user, "the control session has no subject").toBeTruthy();
  expect(
    persona.who.user,
    "both contexts resolved to the SAME subject — the persona context inherited the run's shared session, " +
      "so every comparison below would be one operator measured against itself"
  ).not.toBe(analyst.who.user);
  // The control must genuinely be able to respond, or "the persona is refused"
  // says nothing about the persona.
  expect(
    analyst.who.canRespond,
    `${analyst.who.user} is not a responding operator, so it cannot serve as the control for a role that cannot respond`
  ).toBe(true);

  return { persona, analyst };
}

async function closeAll(...sessions: Array<Session | null | undefined>): Promise<void> {
  for (const session of sessions) {
    if (session) await session.context.close();
  }
}

/**
 * What the console is OFFERING for one control.
 *
 * "offered" means a real, enabled control an operator can press. `null` means
 * the reading itself failed — a detached node, a navigation mid-read — and is
 * never folded into a verdict: a swallowed harness error reported as a
 * permission verdict is a claim about a boundary nothing measured.
 */
type ControlState = "absent" | "disabled" | "offered";

async function offeredState(locator: Locator): Promise<ControlState | null> {
  try {
    if ((await locator.count()) === 0) return "absent";
    return (await locator.first().isDisabled()) ? "disabled" : "offered";
  } catch {
    return null;
  }
}

/** Reads a named set of controls on one page. */
async function readControls(
  page: Page,
  controls: ReadonlyArray<{ name: string; locator: (page: Page) => Locator }>
): Promise<Array<{ name: string; state: ControlState | null }>> {
  const out: Array<{ name: string; state: ControlState | null }> = [];
  for (const control of controls) {
    out.push({ name: control.name, state: await offeredState(control.locator(page)) });
  }
  return out;
}

const offeredNames = (readings: Array<{ name: string; state: ControlState | null }>): string[] =>
  readings.filter((reading) => reading.state === "offered").map((reading) => reading.name);

/** Waits for a locator without throwing — a sentinel, not an assertion. */
async function appeared(locator: Locator, timeout = 60_000): Promise<boolean> {
  return locator
    .first()
    .waitFor({ state: "visible", timeout })
    .then(() => true)
    .catch(() => false);
}

/* ───────────────────────────────────────────────────────────── read-only ── */

test.describe("read-only operator", () => {
  test.skip(env.kind !== "controlplane", "RBAC roles are a control-plane property");
  test.skip(!hasCredentials(env), "Set PROBE_URL, PROBE_USER and PROBE_PASSWORD");
  test.skip(
    !hasReadOnlyOperator(env),
    "Set PROBE_RO_USER and PROBE_RO_PASSWORD — a Keycloak account holding the realm role `read-only`. " +
      "Without a real read-only session nothing can observe what that operator is shown."
  );
  test.describe.configure({ mode: "serial" });
  test.setTimeout(240_000);

  const readOnly = (probe: ProbeEnv) => ({
    user: probe.readOnlyUser!,
    password: probe.readOnlyPassword!
  });

  /**
   * IDENTITY. What the server says this principal IS — and the field the
   * console was given for exactly this and never read.
   */
  test("whoami reports a read-only operator as unable to respond", async ({ browser, probe }) => {
    const { persona, analyst } = await personaAndControl(browser, probe, readOnly(probe));

    try {
      // The capability, from the server's own mouth. roleCan(RoleReadOnly, …)
      // returns true for ActionRead alone, so CanRespond is false and
      // handleWhoami publishes it.
      expect(
        persona.raw.can_respond,
        `${persona.who.user} is published as able to respond — either the account does not hold the ` +
          "`read-only` realm role, or roleCan has been widened and every write route now accepts it"
      ).toBe(false);
      // can_push_policy is CanRespond under a second name (handleWhoami:120).
      // It is the SAME capability, and the console reads this one — which is
      // the whole proof that the fix is one line.
      expect(
        persona.raw.can_push_policy,
        "a principal that cannot respond cannot push a detection policy either — they are one capability in handleWhoami"
      ).toBe(false);
      expect(persona.raw.cross_tenant, "a read-only operator was granted cross-tenant reach").toBe(false);
      // policy_scope is a DEPLOYMENT capability, not a permission: handleWhoami
      // emits the literal "fleet" for every principal. Asserted on both, since
      // that — and not anything about this persona — is what it states.
      expect(persona.raw.policy_scope, "the control plane must state its policy scope").toBe("fleet");
      expect(analyst.raw.policy_scope, "policy scope is per-deployment, not per-principal").toBe("fleet");

      // The tenant-bound half: a read-only role is NOT cross-tenant, so
      // TenantScope must name the tenant it is bound to. Without this the
      // refusal test's writes would be refused for want of a tenant (a 400 from
      // the `tenant required` branch) rather than for want of the capability.
      expect(
        persona.who.tenants?.length ?? 0,
        `${persona.who.user} carries no tenant scope — the account is missing its \`tenant\` attribute, ` +
          "and every read below would be denied for the wrong reason"
      ).toBeGreaterThan(0);

      // THE CONTROL. The same field, same deployment, same second, for a
      // principal that can respond. Without it, `can_respond:false` is
      // consistent with a server that answers false for everyone.
      expect(
        analyst.raw.can_respond,
        "can_respond reads false for the analyst too — the field is not reporting a capability at all"
      ).toBe(true);

      test.info().annotations.push({
        type: "note",
        description:
          `read-only whoami: role=${JSON.stringify(persona.raw.role)}, ` +
          `can_respond=${String(persona.raw.can_respond)}, tenants=${JSON.stringify(persona.raw.tenants)}, ` +
          `host=${String(persona.raw.host)}`
      });
    } finally {
      await closeAll(persona, analyst);
    }
  });

  /**
   * THE SERVER HOLDS. This is the half that should pass, and the reason the
   * console defect below is a usability failure rather than a breach.
   *
   * Each route is checked TWICE, and the pair is what makes the 404 mean
   * something. A bare 404 on a write is indistinguishable from a path this
   * build does not register — ServeMux answers unrouted paths with exactly the
   * same status. So:
   *
   *   · a write-ONLY route is first sent a GET, which must answer 405: the
   *     method guard in authorizeRespondMethods runs before authentication and
   *     before Authorize, so a 405 proves the route is registered and that this
   *     handler — not the mux's fallback — produced the answer;
   *   · a route that also serves reads is first sent its GET, which must not be
   *     404: the same path answering a read and refusing a write from the SAME
   *     session cannot be explained by routing at all.
   *
   * SAFETY. The writes are sent only after `can_respond:false` is asserted
   * above them, and that assertion throws before the loop when it fails, so a
   * misprovisioned persona cannot reach the POSTs. authorizeRespondMethods
   * denies before any handler decodes a body: the bodies are `{}` and are never
   * read.
   */
  test("the server refuses every containment write a read-only session attempts", async ({
    browser,
    probe
  }) => {
    const { context, page } = await signedInContext(browser, probe, readOnly(probe));

    try {
      const raw = await readWhoamiRaw(page);
      // THE INTERLOCK. Nothing below sends a request until the server itself
      // has said this principal cannot respond. A persona pointed at the wrong
      // account fails HERE, before a single write leaves the browser.
      expect(
        raw.can_respond,
        `${String(raw.user)} reports can_respond=${String(raw.can_respond)} — refusing to send write probes ` +
          "as a principal the server would authorize"
      ).toBe(false);
      expect(raw.cross_tenant, "refusing to send write probes as a cross-tenant principal").toBe(false);
      // Without a tenant scope, authorizeRespondMethods returns 400 from its
      // `tenant required` branch before it ever reaches authz.Authorize — the
      // right refusal for the wrong reason, and it would pin nothing.
      expect(
        Array.isArray(raw.tenants) ? (raw.tenants as string[]).length : 0,
        `${String(raw.user)} carries no tenant scope, so a write would be refused for want of a tenant ` +
          "rather than for want of the capability — the account is missing its `tenant` attribute"
      ).toBeGreaterThan(0);

      // Write-only routes: every one of these is `authorizeRespond` on the
      // first line of its handler, and each is a distinct containment
      // capability. A route missing from this list is a route nothing checks.
      const writeOnly: ReadonlyArray<{ path: string; method: "POST" | "PUT" }> = [
        { path: "/api/choke/manual", method: "POST" }, // per-process jail/thaw
        { path: "/api/choke/jail", method: "POST" }, // dashboard alert jail
        { path: "/api/choke/thaw", method: "POST" }, // release
        { path: "/api/choke/bulk-manual", method: "POST" }, // multi-target jail
        { path: "/api/choke/forget", method: "POST" }, // stop tracking
        { path: "/api/choke/mode", method: "POST" }, // fleet enforcement mode
        { path: "/api/choke/kill-switch", method: "POST" }, // fleet break-glass
        { path: "/api/choke/thresholds", method: "POST" }, // the ladder itself
        { path: "/api/choke/preset", method: "POST" }, // mass-choke preset
        { path: "/api/choke/device-jail", method: "POST" }, // network plane
        { path: "/api/choke/device-thaw", method: "POST" },
        { path: "/api/choke/device-mode", method: "POST" },
        { path: "/api/choke/device-kill-switch", method: "POST" },
        { path: "/api/policies/push", method: "POST" }, // signed detection push
        { path: "/api/verify-chain/repair", method: "POST" }, // audit-chain replay
        { path: "/api/approvals/decide", method: "POST" } // ActionApprove, not respond
      ];
      // Read+write routes: the GET branch is authorizeRead and must answer,
      // the write branch is authorizeRespondMethods and must not.
      const readWrite: ReadonlyArray<{ path: string; method: "POST" | "PUT" }> = [
        { path: "/api/settings/suppressions", method: "POST" },
        { path: "/api/settings/protected", method: "PUT" },
        { path: "/api/settings/change-control", method: "PUT" },
        { path: "/api/settings/retention", method: "PUT" }
      ];

      for (const route of writeOnly) {
        const probeGet = await page.request.get(route.path, { failOnStatusCode: false });
        expect(
          probeGet.status(),
          `GET ${route.path} answered ${probeGet.status()}, not the 405 its method guard promises — ` +
            "this build may not register the route at all, in which case the 404 below proves nothing"
        ).toBe(405);

        const denied = await page.request.fetch(route.path, {
          method: route.method,
          data: {},
          failOnStatusCode: false
        });
        // Exactly 404, not "404 or 403". authorizeRespondMethods answers
        // http.NotFound on denial deliberately (§6 side channels): a 403 would
        // confirm the resource exists to a caller who may not touch it.
        expect(
          denied.status(),
          `${route.method} ${route.path} answered ${denied.status()} for a principal the server says ` +
            "cannot respond — a read-only operator can change estate state"
        ).toBe(404);
      }

      for (const route of readWrite) {
        const readBranch = await page.request.get(route.path, { failOnStatusCode: false });
        expect(
          readBranch.status(),
          `GET ${route.path} answered 404 — the route is not registered on this build, so the refusal below ` +
            "cannot be attributed to authorization"
        ).not.toBe(404);

        const denied = await page.request.fetch(route.path, {
          method: route.method,
          data: {},
          failOnStatusCode: false
        });
        expect(
          denied.status(),
          `${route.method} ${route.path} answered ${denied.status()} while GET on the SAME path answered ` +
            `${readBranch.status()} for the SAME session — the write branch is not gated on ActionRespond`
        ).toBe(404);
      }

      test.info().annotations.push({
        type: "note",
        description:
          `${writeOnly.length + readWrite.length} denied write attempts were recorded in operator_audit ` +
          `for ${String(raw.user)} on tenant ${JSON.stringify(raw.tenants)}`
      });
    } finally {
      await context.close();
    }
  });

  /**
   * AND IT CAN STILL DO ITS JOB.
   *
   * The role exists to give someone the estate without giving them the
   * controls. If the reads were refused too, the correct fix would be to delete
   * the role rather than to gate the buttons — so this is not a courtesy test,
   * it is what makes the defect below a UI defect.
   */
  test("a read-only operator can still read the estate the role exists for", async ({ browser, probe }) => {
    const { context, page } = await signedInContext(browser, probe, readOnly(probe));

    try {
      const who = await readWhoami(page);
      expect(who.canRespond, "this session is not the read-only persona").toBe(false);
      expect(who.tenants?.length ?? 0, "the read-only operator carries no tenant scope").toBeGreaterThan(0);
      const tenant = who.tenants![0];

      for (const path of [
        // Named EXPLICITLY, unlike every other path here. handleTelemetry
        // (controlplane/http.go:157-171) does its own inline
        // `tenant := query("tenant"); if tenant == "" -> 400` and never falls
        // back to authz.TenantScope the way authorizeRead does. That is
        // deliberate — it is the API-only route for "read tenant X", and the
        // console never calls it (grep /api/telemetry over web/src is empty) —
        // so passing the operator's own tenant is the honest way to ask it
        // whether a read-only principal may read. Asserting 200 without the
        // parameter tested the route's argument handling, not the role.
        `/api/telemetry?limit=25&tenant=${encodeURIComponent(tenant)}`,
        "/api/alerts?limit=25",
        "/api/choke/circuits",
        "/api/choke/state",
        "/api/fleet/hosts",
        "/api/sensor-health"
      ]) {
        const response = await page.request.get(path, { failOnStatusCode: false });
        expect(
          response.status(),
          `${path} answered ${response.status()} for a read-only operator — the role grants ActionRead ` +
            "and a role that cannot read is not a role"
        ).toBe(200);
      }

      // A 200 with nothing in it would satisfy the loop above while the console
      // rendered an empty estate, so the fleet is required to have content.
      const fleet = (await (await page.request.get("/api/fleet/hosts")).json()) as {
        hosts?: Array<{ name: string }>;
      };
      expect(
        fleet.hosts?.length ?? 0,
        `${tenant} reported no agents to its read-only operator — an empty console is not a proof of read access`
      ).toBeGreaterThan(0);

      // And the console renders it: the dashboard names the tenant, the triage
      // queue is present, and the Choke workbench — the surface this persona is
      // most likely to be given — draws its table rather than an empty shell.
      await page.goto("/", { waitUntil: "domcontentloaded" });
      await expect(
        page.locator('[data-panel="top-bar"]'),
        "the dashboard does not name the tenant a read-only operator is scoped to"
      ).toContainText(tenant);
      await expect(page.locator('[data-panel="alert-triage-queue"]')).toBeVisible();

      await page.goto("/choke", { waitUntil: "domcontentloaded" });
      await expect(page.locator('[data-panel="containment-ladder"]')).toBeVisible();
      await expect(
        page.locator('[data-panel="tracked-processes-list"]'),
        "the Choke workbench did not render for a read-only operator"
      ).toBeVisible();
    } finally {
      await context.close();
    }
  });

  /**
   * WHAT BUG THIS PINS — the console offered containment to an operator the
   * server refuses. Live until 2026-09-02.
   *
   * ROOT CAUSE. handleWhoami publishes `can_respond`, authz.CanRespond's own
   * comment says the console uses it to enable/disable action controls, and
   * normalizeWhoami never reads it — grep `can_respond` across web/src and the
   * only hits are in this suite. The choke surface's `disabled` prop comes from
   * `loadState.kind === "disabled"` (useChokePosture.ts), which is about
   * whether the deployment is serving data, not about who is asking.
   *
   * FIXED 2026-09-02: normalizeWhoami reads `can_respond` (beside the
   * `can_push_policy` line that already did exactly this) and every containment
   * control is gated on one shared predicate — which also distinguishes "the
   * server has not answered yet" from "the server said no", because a control
   * armed while the answer is in flight is the same defect in a smaller window.
   * `can_push_policy` is the same capability under a different name and was
   * always read, which is why the Detections authoring button was correctly
   * withheld from this persona while the kill-switch was not.
   *
   * WHY IT MATTERS. A kill-switch that does nothing is worse than no
   * kill-switch: the operator who presses it believes enforcement is bypassed.
   * The failure is silent at the console — the server answers 404 and the
   * fan-out summary reports what it reached, which is nothing.
   *
   * WHY THE GUARDS. Nothing on the way to the expectation is allowed to throw:
   * both sign-ins skip on failure, the workbench is waited for tolerantly and
   * skips if it never draws, every control reading is `null` on error and a
   * `null` skips, and the ANALYST control must show the same controls as
   * offered before the persona's reading is allowed to mean anything —
   * otherwise a fleet in dry-run or a disabled poll would present itself as a
   * fixed permission model. Add a step above the expectation and it has to skip
   * on failure too, or a harness fault gets reported as a permission boundary.
   */
  test("the containment controls a read-only operator must not be offered are offered anyway", async ({
    browser,
    probe
  }) => {
    const opened = await personaAndControl(browser, probe, readOnly(probe)).catch(() => null);
    test.skip(opened === null, "could not open both sessions — a harness fault, not the defect");
    const { persona, analyst } = opened!;

    try {
      const canRespond = persona.raw.can_respond;
      test.skip(
        canRespond !== false,
        "the persona session does not report can_respond=false — wrong account, not the defect"
      );

      // The four containment controls the Choke workbench offers. The ladder
      // rungs themselves are deliberately NOT here: ContainmentLadder's buttons
      // filter the table, they do not contain anything.
      const CONTROLS = [
        {
          name: "kill-switch (fleet break-glass)",
          locator: (page: Page) => page.locator("button.cc-ctl-kill")
        },
        {
          name: "enforcement mode toggle",
          locator: (page: Page) => page.locator("button.cc-ctl-mode")
        },
        {
          name: "threshold commit",
          locator: (page: Page) =>
            page.locator('[data-panel="thresholds-panel"] button.choke-action-button.warn')
        },
        {
          name: "per-process sever/quarantine",
          locator: (page: Page) =>
            page
              .locator('[data-panel="tracked-processes-list"] .choke-row-actions button')
              .filter({ hasText: /^(sev|qua)$/ })
        }
      ] as const;

      const workbench = async (session: Session): Promise<boolean> => {
        await session.page.goto("/choke", { waitUntil: "domcontentloaded" }).catch(() => undefined);
        return appeared(session.page.locator('[data-panel="containment-ladder"]'));
      };

      const personaReady = await workbench(persona);
      const analystReady = await workbench(analyst);
      test.skip(
        !personaReady || !analystReady,
        "the Choke workbench never rendered for one of the sessions — a harness fault, not the defect"
      );

      const analystReadings = await readControls(analyst.page, CONTROLS);
      const personaReadings = await readControls(persona.page, CONTROLS);
      test.info().annotations.push({
        type: "note",
        description:
          `read-only: ${personaReadings.map((r) => `${r.name}=${r.state}`).join("; ")} | ` +
          `analyst control: ${analystReadings.map((r) => `${r.name}=${r.state}`).join("; ")}`
      });
      test.skip(
        [...personaReadings, ...analystReadings].some((reading) => reading.state === null),
        "a control could not be read — a harness fault, not the defect"
      );

      // THE CONTROL. Only controls the responding operator is actually offered
      // can be evidence here: one that is absent or disabled for BOTH is
      // withheld by posture, load state or an empty table, and says nothing
      // about permissions.
      const armedForAnalyst = new Set(offeredNames(analystReadings));
      test.skip(
        armedForAnalyst.size === 0,
        "no containment control is offered to the responding analyst either — the estate, not the role, " +
          "is withholding them, so nothing here can be attributed to permissions"
      );

      const offeredToReadOnly = offeredNames(personaReadings).filter((name) => armedForAnalyst.has(name));
      expect(
        offeredToReadOnly,
        `${persona.who.user} reports can_respond=false and the server 404s every one of these routes, yet the ` +
          `console offers it: ${offeredToReadOnly.join(", ")}. An operator finds out by pressing an emergency ` +
          "control and watching nothing happen."
      ).toEqual([]);
    } finally {
      await closeAll(persona, analyst);
    }
  });

  /**
   * THE SAME DEFECT ON THE FLEET SURFACE, which is the worse half: these
   * controls apply to EVERY host in the tenant at once.
   *
   * Separate from the choke test because the cause is a different line —
   * useFleetControls.ts:110 computes `writesDisabled = pollStatus ===
   * "disabled" || pendingAction !== null || totalHosts === 0`, three conditions
   * about the estate and none about the operator. Fixing the choke surface
   * alone would leave the fleet rail armed, and one test covering both would
   * have gone green on half a fix.
   */
  test("the fleet write rail is offered to a read-only operator", async ({ browser, probe }) => {
    const opened = await personaAndControl(browser, probe, readOnly(probe)).catch(() => null);
    test.skip(opened === null, "could not open both sessions — a harness fault, not the defect");
    const { persona, analyst } = opened!;

    try {
      test.skip(
        persona.raw.can_respond !== false,
        "the persona session does not report can_respond=false — wrong account, not the defect"
      );

      // `totalHosts === 0` disables the rail for a reason that has nothing to do
      // with permissions, so an empty fleet makes this unmeasurable.
      const fleet = await persona.page.request.get("/api/fleet/hosts", { failOnStatusCode: false });
      const hosts = fleet.status() === 200
        ? ((await fleet.json()) as { hosts?: unknown[] }).hosts?.length ?? 0
        : 0;
      test.skip(hosts === 0, "this tenant has no agents, so the rail is disabled by host count, not by role");

      const CONTROLS = [
        {
          name: "kill-switch on (whole fleet)",
          locator: (page: Page) => page.locator(".fleet-rail button.fleet-btn--danger")
        },
        {
          name: "kill-switch off",
          locator: (page: Page) =>
            page.locator(".fleet-rail button").filter({ hasText: /^Kill-switch off$/ })
        },
        {
          name: "thaw quarantine",
          locator: (page: Page) =>
            page.locator(".fleet-rail button").filter({ hasText: /^Thaw quarantine$/ })
        },
        {
          name: "posture preset",
          locator: (page: Page) => page.locator(".fleet-rail button.fleet-posture")
        }
      ] as const;

      // Waiting for `.fleet-rail` to be VISIBLE is not enough, and reading at
      // that moment is why this test could not fail. useFleetControls.ts:110
      // sets `writesDisabled = pollStatus === "disabled" || pendingAction !==
      // null || totalHosts === 0`, and the rail paints before
      // /api/fleet/hosts resolves — so at first paint every control is
      // disabled FOR EVERYONE. Measured live: kill-switch disabled=true at
      // t=0, disabled=false from t≈5s. Reading then would have shown the
      // analyst's controls disabled too, the comparison would have found no
      // difference, and the test would have reported "not armed for a
      // read-only operator" while measuring the load state.
      //
      // So the rail is only READY once the host count has landed, which is
      // exactly when the estate-derived half of `writesDisabled` goes false.
      const railReady = async (session: Session): Promise<boolean> => {
        await session.page.goto("/fleet", { waitUntil: "domcontentloaded" }).catch(() => undefined);
        if (!(await appeared(session.page.locator(".fleet-rail")))) return false;
        // The host count is what gates the estate-derived disable. Poll the
        // table rather than sleeping: a fixed wait would be a guess about the
        // poll interval and would rot the first time it changed.
        return session.page
          .waitForFunction(
            () => document.querySelectorAll(".fleet-table tbody tr, .fleet-host-row").length > 0,
            null,
            { timeout: 30_000 }
          )
          .then(() => true)
          .catch(() => false);
      };

      const personaReady = await railReady(persona);
      const analystReady = await railReady(analyst);
      test.skip(
        !personaReady || !analystReady,
        "the fleet control rail never rendered for one of the sessions — a harness fault, not the defect"
      );

      const analystReadings = await readControls(analyst.page, CONTROLS);
      const personaReadings = await readControls(persona.page, CONTROLS);
      test.info().annotations.push({
        type: "note",
        description:
          `read-only fleet rail: ${personaReadings.map((r) => `${r.name}=${r.state}`).join("; ")} | ` +
          `analyst control: ${analystReadings.map((r) => `${r.name}=${r.state}`).join("; ")}`
      });
      test.skip(
        [...personaReadings, ...analystReadings].some((reading) => reading.state === null),
        "a control could not be read — a harness fault, not the defect"
      );

      const armedForAnalyst = new Set(offeredNames(analystReadings));
      test.skip(
        armedForAnalyst.size === 0,
        "the responding analyst is offered no fleet write either — the estate is withholding the rail"
      );

      const offeredToReadOnly = offeredNames(personaReadings).filter((name) => armedForAnalyst.has(name));
      expect(
        offeredToReadOnly,
        `the fleet rail offers ${persona.who.user} — a principal the server 404s — ${offeredToReadOnly.join(", ")}. ` +
          "These apply to every host in the tenant at once."
      ).toEqual([]);
    } finally {
      await closeAll(persona, analyst);
    }
  });

  /**
   * WHERE THE CONSOLE DOES GATE, IT GIVES THE WRONG REASON.
   *
   * DetectionsBody hides the authoring control when `canPush` is false — the
   * one containment-adjacent capability the console reads, because handleWhoami
   * sends CanRespond a SECOND time under the name `can_push_policy` and
   * normalizeWhoami picks that one up. So this persona correctly gets no push
   * button, and is told: "This deployment has no Tetragon connection, so it
   * cannot load or unload a detection."
   *
   * That sentence is false, and it is false in the direction that costs
   * something. The operator is told the platform is broken when they are
   * merely not permitted, and the natural next step — the one the copy names,
   * "Check the agent on Sensor Health" — sends them to investigate an outage
   * that is not happening. The analyst control below is what makes the claim
   * checkable: the SAME deployment reports can_push_policy=true for a
   * responding operator, so a Tetragon connection demonstrably exists.
   *
   * THE FIX: distinguish the two states. `can_push_policy:false` on a principal
   * whose `can_respond` is false is a permission; on one that can respond it is
   * a deployment capability. Both are already on the wire.
   */
  test("the withheld authoring control blames the deployment rather than the permission", async ({
    browser,
    probe
  }) => {
    const opened = await personaAndControl(browser, probe, readOnly(probe)).catch(() => null);
    test.skip(opened === null, "could not open both sessions — a harness fault, not the defect");
    const { persona, analyst } = opened!;

    try {
      test.skip(
        persona.raw.can_push_policy !== false,
        "the persona can push policy, so no explanatory copy is shown — wrong account, not the defect"
      );
      // The control that turns the copy into a false statement rather than an
      // unlucky truth: this deployment CAN push.
      test.skip(
        analyst.raw.can_push_policy !== true,
        "this deployment reports no policy-push capability for anyone, so the copy is accurate — nothing to pin"
      );

      await persona.page.goto("/", { waitUntil: "domcontentloaded" }).catch(() => undefined);
      const opener = persona.page.getByRole("button", { name: "Policies", exact: true }).first();
      const openerReady = await appeared(opener);
      test.skip(!openerReady, "the Policies control never appeared — a harness fault, not the defect");
      await opener.click().catch(() => undefined);

      // is-open, not toBeVisible: SocModals mounts every modal body permanently
      // and hides it by withholding this class, so the copy below is queryable
      // whether or not anything opened.
      const modal = persona.page.locator('[data-panel="detections-modal"]');
      const modalOpen = await modal
        .first()
        .evaluate((node) => node.classList.contains("is-open"))
        .catch(() => false);
      test.skip(!modalOpen, "the Detections surface did not open — a harness fault, not the defect");

      const copy = (await modal.innerText().catch(() => "")).trim();
      test.skip(copy === "", "the Detections surface rendered no text — a harness fault, not the defect");
      test.info().annotations.push({
        type: "note",
        description: `Detections copy shown to the read-only operator: ${JSON.stringify(copy.slice(0, 400))}`
      });

      expect(
        copy,
        "a read-only operator is told the deployment has no Tetragon connection. It has one — the same " +
          "control plane reports can_push_policy=true for the analyst — so the operator is sent to Sensor " +
          "Health to investigate an outage that is not happening."
      ).not.toMatch(/no Tetragon connection/i);
    } finally {
      await closeAll(persona, analyst);
    }
  });

  /**
   * THE ROLE NAME ITSELF. handleWhoami's `role` is
   * `HasCrossTenant(p) ? "msoc-admin" : "tenant-analyst"` — a two-valued
   * function standing in for a four-valued fact. A read-only operator is
   * therefore published, and rendered on the account surface, as
   * `tenant-analyst`: the name of the role directly above it, the one that CAN
   * respond.
   *
   * This is the server's defect, not the console's; the console renders
   * faithfully what it is sent. Fixing it means emitting the principal's actual
   * grant rather than deriving a name from a boolean.
   */
  test("whoami publishes a read-only operator under the tenant-analyst role name", async ({
    browser,
    probe
  }) => {
    const session = await signedInContext(browser, probe, readOnly(probe)).catch(() => null);
    test.skip(session === null, "could not sign the read-only operator in — a harness fault, not the defect");

    try {
      const raw = await readWhoamiRaw(session!.page).catch(() => null);
      test.skip(raw === null, "whoami did not answer — a harness fault, not the defect");
      test.skip(
        raw!.can_respond !== false,
        "this session is not the read-only persona — wrong account, not the defect"
      );

      test.info().annotations.push({
        type: "note",
        description: `whoami.role for ${String(raw!.user)}: ${JSON.stringify(raw!.role)}`
      });

      expect(
        raw!.role,
        `whoami names ${String(raw!.user)} a ${JSON.stringify(raw!.role)} while reporting can_respond=false. ` +
          "The account surface renders that string verbatim, so the one place the console states an operator's " +
          "authority states the authority of the role above them."
      ).toBe("read-only");
    } finally {
      await session?.context.close();
    }
  });
});

/* ──────────────────────────────────────────────────── cross-tenant responder ── */

test.describe("cross-tenant responder", () => {
  test.skip(env.kind !== "controlplane", "a cross-tenant role only exists on the control plane");
  test.skip(!hasCredentials(env), "Set PROBE_URL, PROBE_USER and PROBE_PASSWORD");
  test.skip(
    !hasCrossTenantResponder(env),
    "Set PROBE_XR_USER and PROBE_XR_PASSWORD — a Keycloak account holding the realm role " +
      "`cross-tenant-responder`. It is the only way to show the console keys off capability rather than " +
      "off the one cross-tenant role name it knows."
  );
  test.describe.configure({ mode: "serial" });
  test.setTimeout(240_000);

  const responder = (probe: ProbeEnv) => ({
    user: probe.responderUser!,
    password: probe.responderPassword!
  });

  /**
   * IDENTITY. isCrossTenant() covers RoleMSOCAdmin and RoleCrossTenantResponder
   * alike, and roleCan gives them the same three actions, so every capability
   * flag must match an admin's. The DIFFERENCE is supposed to be the role name
   * — and that is the one field that does not differ.
   */
  test("whoami reports the responder as cross-tenant and able to respond", async ({ browser, probe }) => {
    const { persona, analyst } = await personaAndControl(browser, probe, responder(probe));

    try {
      expect(
        persona.raw.cross_tenant,
        `${persona.who.user} is not flagged cross-tenant — the account is missing the ` +
          "`cross-tenant-responder` realm role, and isCrossTenant() never saw it"
      ).toBe(true);
      expect(persona.raw.can_respond, "a cross-tenant responder cannot respond").toBe(true);
      expect(persona.raw.can_push_policy, "a responding principal cannot push policy").toBe(true);
      expect(persona.raw.policy_scope, "the control plane must state its policy scope").toBe("fleet");
      expect(analyst.raw.cross_tenant, "an ordinary analyst was granted cross-tenant access").toBe(false);

      test.info().annotations.push({
        type: "note",
        description:
          `cross-tenant-responder whoami: role=${JSON.stringify(persona.raw.role)}, ` +
          `tenants=${JSON.stringify(persona.raw.tenants)}, host=${String(persona.raw.host)}`
      });
    } finally {
      await closeAll(persona, analyst);
    }
  });

  /**
   * THE POSITIVE CONTROL, for the second cross-tenant role.
   *
   * msoc.probe.spec.ts settles the boundary for `msoc-admin`. That says nothing
   * about `cross-tenant-responder`: they are separate constants, and the
   * grant depends on isCrossTenant() naming both — a one-word omission there
   * would leave this role reading exactly one tenant while every existing test
   * stayed green.
   *
   * Both requests are issued inside ONE test from two live sessions, so the two
   * answers describe the same server in the same second; split across tests
   * they would leave room for "the route was fixed in between".
   */
  test("the read a tenant analyst is refused is the read a cross-tenant responder is granted", async ({
    browser,
    probe
  }) => {
    test.skip(!probe.otherTenant, "Set PROBE_OTHER_TENANT to name the estate to reach into");
    const foreign = probe.otherTenant!;
    const { persona, analyst } = await personaAndControl(browser, probe, responder(probe));

    try {
      expect(analyst.who.tenants, `the analyst is already scoped to ${foreign}`).not.toContain(foreign);

      const scoped = (path: string) =>
        `${path}${path.includes("?") ? "&" : "?"}tenant=${encodeURIComponent(foreign)}`;
      const telemetryPath = scoped("/api/telemetry?limit=25");

      for (const path of [telemetryPath, scoped("/api/alerts?limit=5"), scoped("/api/fleet/hosts")]) {
        const refused = await analyst.page.request.get(path, { failOnStatusCode: false });
        const allowed = await persona.page.request.get(path, { failOnStatusCode: false });
        expect(refused.status(), `${path} was not refused for ${analyst.who.user}`).toBe(404);
        expect(
          allowed.status(),
          `${path} answered ${allowed.status()} for the cross-tenant responder — the analyst's 404 proves ` +
            "nothing if the route is simply broken, and a role that cannot reach a second tenant is not cross-tenant"
        ).toBe(200);
      }

      // A 200 is not evidence on its own: an empty body, or the caller's own
      // tenant served under someone else's name, both answer 200. The envelope's
      // `tenant` field is not the evidence either — handleTelemetry echoes the
      // query parameter straight back. The per-RECORD stamp is the fact: it
      // comes from centralstore.Row.TenantID, written at ingest from the
      // agent's client certificate.
      const rows = (await (await persona.page.request.get(telemetryPath)).json()) as {
        records?: Array<{ tenant?: string }>;
      };
      expect(
        rows.records?.length ?? 0,
        `${foreign} returned no rows — a 200 with nothing in it is not a positive control`
      ).toBeGreaterThan(0);
      expect(
        [...new Set((rows.records ?? []).map((row) => row.tenant))],
        `the responder's read of ${foreign} returned rows belonging to another tenant`
      ).toEqual([foreign]);
    } finally {
      await closeAll(persona, analyst);
    }
  });

  /**
   * WHAT BUG THIS PINS — the console cannot tell the two cross-tenant roles
   * apart, because the server does not tell it.
   *
   * handleWhoami: `role = HasCrossTenant(p) ? "msoc-admin" : "tenant-analyst"`.
   * A `cross-tenant-responder` therefore arrives at the console as
   * `msoc-admin`, and the account surface renders that string. The two roles
   * are distinct constants in authz.go and a deployment that separates them —
   * administration from response — has no way to show which one is signed in,
   * and no way to audit-review a screenshot of it.
   *
   * This is the same one-line derivation the read-only test pins from the other
   * side, and one fix closed both: since 2026-09-02 handleWhoami emits the principal's
   * actual grant — read-only, tenant-analyst, cross-tenant-responder or
   * msoc-admin — rather than a two-valued function of HasCrossTenant.
   *
   * GUARDS: every step before the expectation skips on failure, so a harness
   * fault cannot be reported as a wrong role name.
   */
  test("whoami publishes a cross-tenant responder under the msoc-admin role name", async ({
    browser,
    probe
  }) => {
    const session = await signedInContext(browser, probe, responder(probe)).catch(() => null);
    test.skip(session === null, "could not sign the responder in — a harness fault, not the defect");

    try {
      const raw = await readWhoamiRaw(session!.page).catch(() => null);
      test.skip(raw === null, "whoami did not answer — a harness fault, not the defect");
      test.skip(
        raw!.cross_tenant !== true,
        "this session is not a cross-tenant principal — wrong account, not the defect"
      );
      // Parked: signIn lands on "/", and every tenant-less read the SPA then
      // makes is resolved to this principal's pinned tenant and recorded as an
      // ALLOWED CROSS-TENANT access in that customer's durable trail.
      await session!.page.goto("about:blank").catch(() => undefined);

      test.info().annotations.push({
        type: "note",
        description: `whoami.role for ${String(raw!.user)}: ${JSON.stringify(raw!.role)}`
      });

      expect(
        raw!.role,
        `whoami names ${String(raw!.user)} an ${JSON.stringify(raw!.role)}. It holds ` +
          "`cross-tenant-responder`; the console has no other role signal, so nothing on screen distinguishes " +
          "a responder from an administrator."
      ).toBe("cross-tenant-responder");
    } finally {
      await session?.context.close();
    }
  });

  /**
   * WHAT BUG THIS PINS — the tenant-pinning defect, predicted for the second
   * cross-tenant role from the same source that produces it for the first.
   *
   * identity.PrincipalFromClaims stamps the account's `tenant` attribute onto
   * EVERY realm role in the token, Keycloak's default composites included
   * (offline_access, uma_authorization, default-roles-…), which roleCan()
   * authorizes for nothing. authz.TenantScope skips the cross-tenant role but
   * keeps those, so the principal comes back with a one-tenant scope built
   * entirely out of grants that cannot authorize a single read — and
   * handleWhoami sets `host = scope[0]`. The console's tenant-less reads then
   * resolve to that same tenant.
   *
   * The consequence for THIS role is the sharper of the two: a cross-tenant
   * RESPONDER acts. Shown one customer's estate as though it were the whole
   * book of business, the containment they fire is aimed by a console that has
   * silently chosen the tenant for them.
   *
   * handleWhoami's own comment stated the opposite — "a cross-tenant MSOC admin
   * has no tenant list, so tenants is null" — and the console was corrected to
   * match it; the deployment was not.
   *
   * FIXED 2026-09-02: TenantScope stops fabricating a scope from grants that authorize
   * nothing, so the list is genuinely empty, and the console names the tenant
   * it is showing instead of presenting it as the estate.
   */
  test("the cross-tenant responder's console is not pinned to one customer", async ({ browser, probe }) => {
    test.skip(!probe.otherTenant, "Set PROBE_OTHER_TENANT");
    const foreign = probe.otherTenant!;

    const session = await signedInContext(browser, probe, responder(probe)).catch(() => null);
    test.skip(session === null, "could not sign the responder in — a harness fault, not the defect");

    try {
      const raw = await readWhoamiRaw(session!.page).catch(() => null);
      test.skip(raw === null, "whoami did not answer — a harness fault, not the defect");
      test.skip(
        raw!.cross_tenant !== true,
        "this session is not a cross-tenant principal — wrong account, not the defect"
      );
      const subject = String(raw!.user ?? raw!.subject ?? "");
      const tenants = Array.isArray(raw!.tenants) ? (raw!.tenants as string[]) : [];

      await session!.page.goto("/", { waitUntil: "domcontentloaded" }).catch(() => undefined);
      // Wait for the REAL whoami before reading the pill. Until the first
      // snapshot lands the pill renders EMPTY_WHOAMI.host — "localhost" — which
      // is not any tenant's name, so reading it early reports the defect as
      // fixed. A timeout here is not failed on: the sentinel below skips.
      await session!.page
        .getByRole("button", { name: subject, exact: true })
        .first()
        .waitFor({ state: "visible", timeout: 60_000 })
        .catch(() => undefined);
      const shown = (
        await session!.page
          .locator(".soc-host-pill")
          .first()
          .innerText()
          .catch(() => "")
      ).trim();

      test.info().annotations.push({
        type: "note",
        description:
          `responder host pill: ${JSON.stringify(shown)}; whoami.tenants: ${JSON.stringify(raw!.tenants)}; ` +
          `whoami.host: ${String(raw!.host)}`
      });

      test.skip(
        shown === "" || shown === "localhost" || shown === "control-plane",
        `the host pill read ${JSON.stringify(shown)} rather than any tenant name — harness problem, not the defect`
      );

      const realTenants = [...tenants, foreign].filter(Boolean);
      expect(
        realTenants,
        `the cross-tenant responder's console names "${shown}" as the estate on screen — one customer, ` +
          "identical to what that customer's own analyst sees, and the estate any containment fired from " +
          "this console is aimed at"
      ).not.toContain(shown);
    } finally {
      await session?.context.close();
    }
  });
});
