import type { APIResponse, Browser, Page } from "@playwright/test";

import {
  expect,
  hasCredentials,
  hasCrossTenantAdmin,
  readProbeEnv,
  readWhoami,
  signedInContext,
  test,
  type ProbeEnv
} from "./support/live";

/**
 * The cross-tenant MSOC admin — the POSITIVE CONTROL for tenant isolation.
 *
 * WHAT THIS PINS. `isolation.probe.spec.ts` proves a tenant analyst is REFUSED
 * another tenant's data. On its own that is weak evidence: a 404 for
 * op-adanian on /api/telemetry?tenant=acme-corp looks exactly the same whether
 * Layer-4 authz refused it or the route is simply broken for everybody, and a
 * route that 404s for every caller would pass the isolation suite while
 * proving nothing about the boundary. The MSSP's own cross-tenant operator is
 * the control that settles it: SAME path, SAME query, SAME deployment, a 200
 * carrying rows demonstrably stamped with the tenant that was named. Refusal
 * plus that success is a proven authorization DECISION rather than an absence.
 *
 * The second half is the other side of the MSSP bargain. Cross-tenant access is
 * ALLOWED here — it is what an MSOC is for — so the control that matters is not
 * prevention but ACCOUNTABILITY: every such read is booked in the durable
 * operator trail, and the customer can read the rows that name their own
 * estate. A provider read that leaves no record is indistinguishable from
 * routine work.
 *
 * WHY A PROBE AND NOT A MOCKED E2E. A mock cannot see any of this. The whole
 * claim lives in parts of the system the frontend never touches: which realm
 * roles Keycloak actually put in the token, how identity.PrincipalFromClaims
 * turned them into grants, what authz.TenantScope makes of those grants, and
 * what the Postgres operator_audit table durably recorded as a side effect of
 * the decision. `page.route()` deletes every one of those layers. Nor can the
 * Go tests stand in: they prove the decision function is correct for a
 * hand-built Principal, not that THIS deployment's OIDC mapping produces the
 * Principal anyone intended — and it is precisely there that this run found a
 * defect (see the last test).
 *
 * IDENTITIES IT NEEDS.
 *   PROBE_USER / PROBE_PASSWORD          a tenant-bound analyst
 *   PROBE_OTHER_TENANT                   a tenant that analyst may NOT read
 *   PROBE_ADMIN_USER / PROBE_ADMIN_PASSWORD   the cross-tenant msoc-admin
 * Every test skips cleanly when the admin credentials are absent, and the
 * whole file skips off the control plane — the single-tenant engine has no
 * second tenant to be admin OF.
 *
 * SHAPE. Two independent BrowserContexts per comparison, via signedInContext,
 * which sets `storageState: { cookies: [], origins: [] }` explicitly.
 * `browser.newContext()` inherits the config's `use.storageState` — the run's
 * shared op-adanian session — so a hand-built context would have compared that
 * operator with ITSELF and reported a passing positive control while both
 * "identities" were the same principal.
 *
 * NO ESTATE WRITES. This runs against production. There is not one non-GET
 * request in the file and the single click opens a read-only profile modal. No
 * write probe appears here on purpose: unlike the analyst's, a cross-tenant
 * admin's containment write would be AUTHORIZED, and a manual choke whose
 * exec_id resolves to no single owner fans the reversible rung out to every
 * agent in the tenant (resolveTarget). There is no way to aim one at a
 * production estate and be certain it changes nothing, so it is not attempted.
 *
 * BUT IT IS NOT SIDE-EFFECT FREE — THE AUDIT FOOTPRINT. READ THIS BEFORE
 * PUTTING IT IN CI.
 *
 * authz.Authorize records through the auditor ATOMICALLY with each decision,
 * and on this deployment the auditor is the Postgres store. Every refusal and
 * every cross-tenant grant this file provokes therefore appends a durable row
 * to `operator_audit`, a table with NO retention (centralstore/retention.go
 * prunes `telemetry` only) — including into the CUSTOMER-VISIBLE view of it.
 * Reading the trail is free (handleOperatorAudit calls Authorize only when a
 * tenant-bound caller passes ?tenant=); the reads under test are not.
 *
 * MEASURED, console.adanianlabs.io, 2026-08-27, by differencing the trail's
 * own `total` across two consecutive full runs: 96 rows per run, 78 of which
 * name the analyst's tenant and are therefore visible to that customer.
 *
 *   19 are DELIBERATE, one per claim, and none of them repeats a read whose
 *      answer is already in hand:
 *        12 denied, subject = PROBE_USER — 8 naming PROBE_OTHER_TENANT (4 in
 *           the positive control, 4 in the enumeration test) and 4 naming this
 *           run's unique tag, the only rows that identify themselves
 *         7 allowed cross-tenant, subject = PROBE_ADMIN_USER — 6 naming
 *           PROBE_OTHER_TENANT, 1 naming the analyst's own tenant
 *   77 are the ADMIN'S OWN CONSOLE booting: five sign-ins land on "/", and
 *      every tenant-less read the SPA makes is resolved to the admin's pinned
 *      tenant and recorded as an allowed cross-tenant access. That bulk is not
 *      incidental — it IS the defect the final test pins, seen from the trail
 *      side, and it is why a customer's access trail fills with provider reads.
 *      `twoPrincipals` parks the SPA (about:blank) the moment sign-in is
 *      proved, which is what keeps this number at 77 rather than several
 *      hundred; the last two tests need the console alive and pay for it.
 *
 * An operator reading their own trail and wondering what the noise is: rows
 * whose tenant_id starts `msoc-probe-no-such-tenant-` are this probe and
 * nothing else. The rest is identifiable only by timestamp, because the API
 * gives a caller no way to stamp a row — operator_audit stores subject,
 * tenant_id, action, allowed and detail, and `detail` carries the DENIAL
 * REASON, not anything the request supplies.
 *
 * That indistinguishability is also why the accountability test correlates on
 * a WATERMARK taken from the trail's own `at` values rather than on
 * subject+tenant: with a bare subject+tenant match it passed with the very
 * read it claims to audit DELETED, satisfied by a row from an earlier run.
 */

const env = readProbeEnv();

/**
 * This run's tag, and the tenant id used for the enumeration side-channel test.
 *
 * Unique per run on purpose. It is the one field of an operator_audit row a
 * caller controls, so it is the only way the probe's own rows can be told
 * apart from real MSOC activity — and from an EARLIER probe run's rows, which
 * is what made the accountability test below vacuous when the tenant id was a
 * constant. The prefix is stable so an operator can grep the whole class out.
 */
const RUN_TAG = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
const IMPOSSIBLE_TENANT = `msoc-probe-no-such-tenant-${RUN_TAG}`;

/** whoami with the fields `readWhoami` normalises away — `role` in particular. */
async function readWhoamiRaw(page: Page): Promise<Record<string, unknown>> {
  const response = await page.request.get("/api/whoami");
  expect(response.status(), "whoami must answer for a signed-in operator").toBe(200);
  return (await response.json()) as Record<string, unknown>;
}

/**
 * Opens two isolated sessions — the tenant analyst and the MSOC admin — and
 * refuses to hand them back unless they are genuinely different principals.
 *
 * This is the guard the whole file rests on. Comparing a 404 with a 200 proves
 * nothing at all if both requests came from the same cookie jar, and that is
 * not hypothetical: it is the exact trap `signedInContext` was written to
 * close after an isolation test compared one session with itself.
 */
async function twoPrincipals(browser: Browser, probe: ProbeEnv) {
  const analyst = await signedInContext(browser, probe, {
    user: probe.user!,
    password: probe.password!
  });
  const admin = await signedInContext(browser, probe, {
    user: probe.adminUser!,
    password: probe.adminPassword!
  });

  const analystWho = await readWhoami(analyst.page);
  const adminWho = await readWhoami(admin.page);

  expect(analystWho.user, "the analyst session has no subject").toBeTruthy();
  expect(adminWho.user, "the admin session has no subject").toBeTruthy();
  expect(
    adminWho.user,
    "both contexts resolved to the SAME subject — the admin context inherited the shared session"
  ).not.toBe(analystWho.user);
  expect(analystWho.crossTenant, `${analystWho.user} holds a cross-tenant role`).toBe(false);
  expect(adminWho.crossTenant, `${adminWho.user} is not a cross-tenant principal`).toBe(true);
  expect(analystWho.tenants?.[0], "the analyst carries no tenant scope").toBeTruthy();

  // PARK THE ADMIN'S CONSOLE. This is a correctness measure, not tidiness.
  //
  // signIn lands on "/", so the SPA boots and then keeps polling — TENANT-LESSLY,
  // which authorizeRead resolves to the admin's pinned tenant and authz records
  // as an ALLOWED CROSS-TENANT access (that is the defect the last test pins,
  // seen from the trail side). Those rows are indistinguishable in
  // operator_audit from a deliberate provider read of that same tenant: same
  // subject, same tenant_id, same action, same allowed. An accountability
  // assertion made while the SPA is alive can therefore be satisfied by console
  // noise — PROVED by mutation: with the page left open, deleting the
  // deliberate read of the customer estate still passed.
  //
  // No caller of this helper drives the admin's UI, and page.request keeps the
  // session either way, so parking costs nothing and removes both the false
  // evidence and the bulk of this file's audit footprint.
  await admin.page.goto("about:blank");

  return { analyst, admin, analystWho, adminWho };
}

test.describe("cross-tenant MSOC admin", () => {
  test.skip(env.kind !== "controlplane", "a cross-tenant admin only exists on the control plane");
  test.skip(!hasCredentials(env), "Set PROBE_URL, PROBE_USER and PROBE_PASSWORD");
  test.skip(
    !hasCrossTenantAdmin(env),
    "Set PROBE_ADMIN_USER and PROBE_ADMIN_PASSWORD — without the cross-tenant operator there is no positive control"
  );
  test.describe.configure({ mode: "serial" });
  test.setTimeout(240_000);

  /**
   * THE POSITIVE CONTROL.
   *
   * Both requests are issued inside one test, from two live sessions, so the
   * two answers describe the same server in the same second. Running them as
   * separate tests would leave room for "the route was fixed in between", which
   * is the doubt this test exists to remove.
   */
  test("the read a tenant analyst is refused is the read the MSOC admin is granted", async ({
    browser,
    probe
  }) => {
    test.skip(!probe.otherTenant, "Set PROBE_OTHER_TENANT to name the estate to reach into");
    const foreign = probe.otherTenant!;
    const { analyst, admin, analystWho } = await twoPrincipals(browser, probe);

    try {
      expect(analystWho.tenants, `the analyst is already scoped to ${foreign}`).not.toContain(foreign);

      const scoped = (path: string) => `${path}${path.includes("?") ? "&" : "?"}tenant=${encodeURIComponent(foreign)}`;
      const telemetryPath = scoped("/api/telemetry?limit=25");
      const fleetPath = scoped("/api/fleet/hosts");
      // Every admin response is kept: the corroborating checks below read these
      // bodies instead of issuing the same reads a second time. Each repeat
      // would be another durable cross-tenant row in a customer's access trail
      // for evidence already in hand.
      const granted = new Map<string, APIResponse>();

      for (const path of [
        telemetryPath,
        scoped("/api/alerts?limit=5"),
        fleetPath,
        scoped("/api/sensor-health")
      ]) {
        const refused = await analyst.page.request.get(path, { failOnStatusCode: false });
        const allowed = await admin.page.request.get(path, { failOnStatusCode: false });
        granted.set(path, allowed);

        expect(refused.status(), `${path} was not refused for ${analystWho.user}`).toBe(404);
        // The load-bearing half. Without it a 404 for everyone would pass.
        expect(
          allowed.status(),
          `${path} answered ${allowed.status()} for the cross-tenant admin — ` +
            `the analyst's 404 proves nothing if this route is simply broken`
        ).toBe(200);
      }

      // A 200 is not yet evidence: an empty body, or the caller's OWN tenant
      // served under someone else's name, would both answer 200.
      //
      // The envelope's own `tenant` field is NOT the evidence — handleTelemetry
      // echoes the request's query parameter straight back
      // (`{"tenant": tenant, ...}`), so it would read `foreign` whatever the
      // store returned. The per-RECORD stamp is the fact: it comes from
      // centralstore.Row.TenantID, which is written at ingest from the agent's
      // client certificate.
      const rows = (await granted.get(telemetryPath)!.json()) as {
        count?: number;
        records?: Array<{ tenant?: string }>;
      };
      expect(rows.records?.length ?? 0, `${foreign} returned no rows — a 200 with nothing in it is not a positive control`).toBeGreaterThan(0);
      expect(
        [...new Set((rows.records ?? []).map((row) => row.tenant))],
        `the admin's read of ${foreign} returned rows belonging to another tenant`
      ).toEqual([foreign]);

      // And the fleets are genuinely different estates: the admin is looking at
      // machines the analyst has never been shown.
      const hostsIn = (body: { hosts?: Array<{ name: string }> }) =>
        new Set((body.hosts ?? []).map((host) => host.name));
      const ownFleetResponse = await analyst.page.request.get("/api/fleet/hosts");
      const ownFleet = hostsIn((await ownFleetResponse.json()) as { hosts?: Array<{ name: string }> });
      const foreignFleet = hostsIn(
        (await granted.get(fleetPath)!.json()) as { hosts?: Array<{ name: string }> }
      );
      expect(ownFleet.size, "the analyst's own tenant reported no agents").toBeGreaterThan(0);
      expect(foreignFleet.size, `${foreign} reported no agents to the admin`).toBeGreaterThan(0);
      expect(
        [...foreignFleet].filter((agent) => ownFleet.has(agent)),
        `the admin's view of ${foreign} returned the analyst's own agents — the tenant parameter was ignored`
      ).toEqual([]);
    } finally {
      await analyst.context.close();
      await admin.context.close();
    }
  });

  /**
   * IDENTITY — what the server says the two principals ARE.
   *
   * `role` is computed in handleWhoami straight from authz.HasCrossTenant, and
   * it is the only field the console has to tell an MSOC admin from an analyst.
   */
  test("whoami reports the admin as cross-tenant, and its tenant list understates its reach", async ({
    browser,
    probe
  }) => {
    test.skip(!probe.otherTenant, "Set PROBE_OTHER_TENANT");
    const foreign = probe.otherTenant!;
    const { analyst, admin } = await twoPrincipals(browser, probe);

    try {
      const adminRaw = await readWhoamiRaw(admin.page);
      const analystRaw = await readWhoamiRaw(analyst.page);

      expect(adminRaw.cross_tenant, "the admin is not flagged cross-tenant").toBe(true);
      expect(adminRaw.role, "the admin does not carry the msoc-admin role").toBe("msoc-admin");
      expect(analystRaw.role, "the analyst is not a tenant-analyst").toBe("tenant-analyst");
      expect(analystRaw.cross_tenant, "an ordinary analyst was granted cross-tenant access").toBe(false);
      expect(adminRaw.can_respond, "a cross-tenant MSOC admin cannot respond").toBe(true);

      // policy_scope is a DEPLOYMENT capability, not a permission: handleWhoami
      // emits the literal "fleet" for every principal it serves, and the console
      // uses it to decide whether a policy push reaches a fleet (dispatched, not
      // converged) or one host (applied). Asserted on BOTH principals, because
      // that — and not anything about the admin — is what it states. It replaced
      // the console's old "tenants is an array" guess, which was wrong for
      // exactly the operator most likely to push policy.
      expect(adminRaw.policy_scope, "the control plane must state its policy scope").toBe("fleet");
      expect(
        analystRaw.policy_scope,
        "policy scope differs per principal — it is a deployment capability and the console reads it as one"
      ).toBe("fleet");

      // authz.TenantScope EXCLUDES cross-tenant roles by design: they must name
      // a tenant explicitly and be audited, never be enumerated. So whatever
      // `tenants` holds, it is not the admin's reach — proved here rather than
      // asserted, by reading a tenant the list does not mention.
      const tenants = Array.isArray(adminRaw.tenants) ? (adminRaw.tenants as string[]) : [];
      expect(
        tenants,
        `whoami advertised ${foreign} as the admin's own scope — a cross-tenant role must not be enumerated as a tenant list`
      ).not.toContain(foreign);
      const reach = await admin.page.request.get(
        `/api/telemetry?tenant=${encodeURIComponent(foreign)}&limit=1`,
        { failOnStatusCode: false }
      );
      expect(
        reach.status(),
        `the admin cannot read ${foreign}, so there is nothing for the tenant list to understate`
      ).toBe(200);
    } finally {
      await analyst.context.close();
      await admin.context.close();
    }
  });

  /**
   * THE REFUSAL MUST NOT BE A SIDE CHANNEL.
   *
   * An MSSP's customer list is itself confidential. If naming a real tenant
   * answered differently from naming an invented one, any analyst with a
   * console session could enumerate the provider's customers by guessing names
   * — without ever reading a single row of their data. handleTelemetry and
   * authorizeRead both answer 404 on denial for exactly this reason (§6 side
   * channels); this asserts the deployment actually behaves that way.
   *
   * All four routes are checked with BOTH names. The claim is per-route — each
   * one independently must not leak — and a route checked only with the real
   * name says nothing about side channels, so the audit rows this costs are the
   * price of the claim rather than avoidable noise.
   */
  test("a real customer name and an invented one are refused identically", async ({ browser, probe }) => {
    test.skip(!probe.otherTenant, "Set PROBE_OTHER_TENANT to name a tenant that exists");
    const real = probe.otherTenant!;
    const analyst = await signedInContext(browser, probe, {
      user: probe.user!,
      password: probe.password!
    });

    try {
      const who = await readWhoami(analyst.page);
      expect(who.tenants, `the analyst can already reach ${real}`).not.toContain(real);
      expect(who.tenants, "the impossible tenant is somehow this analyst's").not.toContain(IMPOSSIBLE_TENANT);
      test.info().annotations.push({
        type: "note",
        description: `this run's denied operator_audit rows name tenant_id "${IMPOSSIBLE_TENANT}"`
      });

      for (const path of [
        "/api/telemetry?limit=5&tenant=",
        "/api/alerts?limit=5&tenant=",
        "/api/fleet/hosts?tenant=",
        "/api/choke/circuits?tenant="
      ]) {
        const exists = await analyst.page.request.get(path + encodeURIComponent(real), {
          failOnStatusCode: false
        });
        const invented = await analyst.page.request.get(path + encodeURIComponent(IMPOSSIBLE_TENANT), {
          failOnStatusCode: false
        });

        expect(
          exists.status(),
          `${path}${real} answered ${exists.status()} while ${path}${IMPOSSIBLE_TENANT} answered ${invented.status()} — ` +
            `the refusal confirms which tenants exist, so an analyst can enumerate the customer list`
        ).toBe(invented.status());
        // 403 would confirm existence on its own, whatever the other answer was.
        expect(exists.status(), `${path}${real} answered 403, which is itself a disclosure`).not.toBe(403);
        // Exactly 404, not "404 or 401". For an AUTHENTICATED principal the
        // source promises one status: handleTelemetry and authorizeRead both
        // answer 404 on denial and never 401. readWhoami above already proved
        // this session live, so a 401 here would mean the session died mid-loop
        // — under which every request answers 401, the equality above is
        // satisfied by 401===401, and a test that authorised nothing at all
        // reports a proven side-channel-free refusal.
        expect(exists.status(), `${path}${real} answered ${exists.status()}, not the promised 404`).toBe(404);
      }
    } finally {
      await analyst.context.close();
    }
  });

  /**
   * ACCOUNTABILITY — the control that actually applies here.
   *
   * Cross-tenant access is permitted, so nothing is proved by it succeeding.
   * What must hold is that it cannot happen quietly: authz.Authorize records
   * through the auditor atomically with the grant, and operatoraudit.go serves
   * the durable table back — to the admin in full, and to the customer filtered
   * to their own estate, which is the more important of the two views because
   * it is the customer asking who from the provider opened their console.
   *
   * WHY A WATERMARK. operator_audit is never pruned, so "some row names this
   * subject and this tenant" is satisfied by a row from an earlier run or from
   * real MSOC activity — an earlier version of this test passed with the
   * cross-tenant read it claims to audit DELETED. Both polls below therefore
   * require a row strictly NEWER than a watermark taken from the same trail,
   * from the server's own `at` values, immediately before the reads. (Runs must
   * not overlap; the probe config is single-worker and serial for other reasons
   * too.)
   *
   * WHY NOT `cross_tenant`. The field is real but DERIVED: RecordAccess
   * early-returns on (allowed && !crossTenant), so an own-tenant allowed read
   * is never written, and scanOperatorAudit can therefore set
   * `CrossTenant = Allowed` for every row it reads. That derivation is sound by
   * construction — and it means `row.cross_tenant === true` is `row.allowed
   * === true` restated. The invariant with content is the one asserted here:
   * that a row EXISTS AT ALL for this read, since the only reads that produce
   * one are denials and boundary crossings.
   */
  test("the admin's cross-tenant reads land in the durable trail, and the customer sees the ones naming their estate", async ({
    browser,
    probe
  }) => {
    test.skip(!probe.otherTenant, "Set PROBE_OTHER_TENANT");
    const foreign = probe.otherTenant!;
    const { analyst, admin, analystWho, adminWho } = await twoPrincipals(browser, probe);

    try {
      const supported = await admin.page.request.get("/api/operator-audit?limit=1", { failOnStatusCode: false });
      test.skip(supported.status() !== 200, "this deployment does not serve the operator audit");
      const probeBody = (await supported.json()) as { supported?: boolean };
      test.skip(
        probeBody.supported === false,
        "this deployment has no durable operator-audit store — the in-memory ring is not a trail"
      );

      type AuditRow = {
        subject?: string;
        tenant_id?: string;
        action?: string;
        allowed?: boolean;
        at?: string;
      };
      type Trail = {
        records?: AuditRow[];
        scope?: string;
        total?: number;
        cross_tenant?: boolean;
      };
      const trailOf = async (page: Page): Promise<Trail> => {
        const response = await page.request.get("/api/operator-audit?limit=200");
        expect(
          response.status(),
          "the operator access trail stopped answering mid-poll — the assertion below cannot conclude anything"
        ).toBe(200);
        return (await response.json()) as Trail;
      };
      // Reading the trail is itself unaudited: handleOperatorAudit calls
      // Authorize only for a tenant-bound caller passing ?tenant=, which neither
      // of these does. Polling it costs no rows.
      const atOf = (row: AuditRow): number => {
        const parsed = Date.parse(row.at ?? "");
        return Number.isFinite(parsed) ? parsed : 0;
      };
      const newestAt = (trail: Trail): number =>
        (trail.records ?? []).reduce((newest, row) => Math.max(newest, atOf(row)), 0);
      const seenAfter = (trail: Trail, after: number, tenant: string) =>
        (trail.records ?? []).some(
          (row) =>
            row.subject === adminWho.user &&
            row.tenant_id === tenant &&
            row.allowed === true &&
            atOf(row) > after
        );

      const analystTenant = analystWho.tenants![0];

      // The admin's trail needs no settling: nothing but the deliberate read
      // below produces a msoc row naming PROBE_OTHER_TENANT, because the parked
      // console can only ever read the admin's own pinned tenant.
      const adminMark = newestAt(await trailOf(admin.page));

      // The CUSTOMER's trail does need it. Rows naming the analyst's tenant are
      // exactly what a still-live provider console emits, so the watermark is
      // taken only once the tenant-scoped trail has stopped moving — otherwise a
      // request already in flight when the console was parked lands after the
      // mark and satisfies the assertion on its own.
      const settled = async (): Promise<number> => {
        let previous = -1;
        for (let attempt = 0; attempt < 10; attempt += 1) {
          const now = newestAt(await trailOf(analyst.page));
          if (now === previous) return now;
          previous = now;
          await new Promise((resolve) => setTimeout(resolve, 2_000));
        }
        return -1;
      };
      const analystMark = await settled();
      // Not a failure: it means some OTHER provider session is reading this
      // customer's estate right now, and a new row cannot then be attributed to
      // this probe. Saying so is honest; asserting anyway would be the vacuity
      // this test exists to avoid.
      test.skip(
        analystMark < 0,
        `${analystTenant}'s access trail never went quiet — another cross-tenant session is reading it, ` +
          "so a new row cannot be attributed to this probe"
      );

      // TWO accesses to account for, made AFTER both watermarks.
      //
      // The first is the provider reaching into a customer the admin's own
      // tenant list demonstrably does not name (asserted in the identity test),
      // so it is cross-tenant by construction.
      //
      // The second is the one that matters to a customer: the provider opening
      // the ANALYST'S OWN estate. It is still cross-tenant — the msoc account's
      // grants on that tenant are Keycloak's inert default composites, which
      // roleCan authorizes nothing for, so Authorize falls through to the
      // cross-tenant branch and records — and it is the row the analyst must be
      // able to find in their own trail below.
      const foreignRead = await admin.page.request.get(
        `/api/telemetry?tenant=${encodeURIComponent(foreign)}&limit=5`,
        { failOnStatusCode: false }
      );
      expect(foreignRead.status(), `the admin could not read ${foreign}, so there is nothing to audit`).toBe(200);
      const customerRead = await admin.page.request.get(
        `/api/telemetry?tenant=${encodeURIComponent(analystTenant)}&limit=5`,
        { failOnStatusCode: false }
      );
      expect(
        customerRead.status(),
        `the admin could not read ${analystTenant}, so there is no provider access for its analyst to be shown`
      ).toBe(200);

      // The write is a side effect of the decision, so allow it a moment.
      await expect
        .poll(async () => seenAfter(await trailOf(admin.page), adminMark, foreign), {
          timeout: 30_000,
          message:
            `${adminWho.user} read ${foreign} just now and no record of THAT read reached the operator trail ` +
            "(rows older than the watermark do not count) — a provider read of a customer estate is " +
            "indistinguishable from routine work"
        })
        .toBe(true);

      // THE CUSTOMER-FACING HALF. Same table, cut to one tenant, read by the
      // customer's own analyst. An MSSP that cannot answer "who from the
      // provider opened my estate, and when" has asked its customers to take
      // provider access on faith.
      await expect
        .poll(async () => seenAfter(await trailOf(analyst.page), analystMark, analystTenant), {
          timeout: 30_000,
          message:
            `${adminWho.user} read ${analystTenant} just now and ${analystWho.user}'s own access trail does not ` +
            "show it. Either the read was not recorded, or the tenant-scoped view does not serve it — " +
            "and if the provider now holds a capability-bearing OWN-TENANT grant on this customer, its " +
            "reads are by design not recorded at all, which is the same loss of transparency"
        })
        .toBe(true);

      const adminTrail = await trailOf(admin.page);
      const analystTrail = await trailOf(analyst.page);
      test.info().annotations.push({
        type: "note",
        description:
          `operator_audit rows visible to ${adminWho.user}: ${adminTrail.total ?? "unknown"}; ` +
          `to ${analystWho.user} for ${analystTenant}: ${analystTrail.total ?? "unknown"}`
      });

      // WHICH QUERY RAN, asserted structurally rather than through the prose
      // label beside it. `scope` is what selects the SQL: empty runs
      // OperatorAuditRecent (every tenant), non-empty runs OperatorAuditForTenant
      // (WHERE tenant_id = $1). The human-readable "viewing" string is derived
      // from exactly this, so pinning the copy instead would turn a reword into
      // a reported regression.
      expect(adminTrail.cross_tenant, "the trail does not report the admin as cross-tenant").toBe(true);
      expect(
        adminTrail.scope ?? "",
        "the admin's trail ran a tenant-scoped query — a cross-tenant operator must see every tenant's rows"
      ).toBe("");
      expect(analystTrail.cross_tenant, "the analyst is reported as cross-tenant").toBe(false);
      expect(
        analystTrail.scope,
        "the analyst's trail did not run scoped to their own tenant"
      ).toBe(analystTenant);

      // An MSOC-wide trail spans customers. Guaranteed by this test's OWN two
      // reads of two different tenants rather than by residue from the tests
      // that happen to run before it — running this test alone must not fail
      // for want of a precondition it did not establish.
      const spanned = [...new Set((adminTrail.records ?? []).map((row) => row.tenant_id).filter(Boolean))];
      expect(
        spanned,
        `the admin's trail names only ${spanned.join(", ") || "nothing"} — both tenants read above must appear in it`
      ).toEqual(expect.arrayContaining([foreign, analystTenant]));

      // The customer's view carries nothing about anyone else. The server-side
      // cut is a WHERE clause, so this is a guard on the HANDLER choosing the
      // scoped query for a tenant-bound principal — the failure it catches is a
      // handler that reports scope=<tenant> while serving the unscoped rows.
      const foreignRows = (analystTrail.records ?? []).filter(
        (row) => row.tenant_id && !analystWho.tenants?.includes(row.tenant_id)
      );
      expect(
        foreignRows.map((row) => row.tenant_id),
        "the access trail handed a tenant analyst another tenant's access records"
      ).toEqual([]);
    } finally {
      await analyst.context.close();
      await admin.context.close();
    }
  });

  /**
   * WHAT THE ADMIN SEES — the one place the console does say it.
   *
   * SocModals mounts every modal body permanently and hides it by withholding
   * `is-open`, and a SlideOver is pushed off-screen with translateX(102%) —
   * both of which Playwright still counts as visible. `toHaveClass(/is-open/)`
   * is the assertion that means "this opened"; toBeVisible() would pass against
   * a modal that never opened at all.
   */
  test("the console names the operator's role, so an MSOC admin is not shown as an analyst", async ({
    browser,
    probe
  }) => {
    const admin = await signedInContext(browser, probe, {
      user: probe.adminUser!,
      password: probe.adminPassword!
    });

    try {
      const who = await readWhoami(admin.page);
      expect(who.crossTenant, "this session is not the cross-tenant admin").toBe(true);

      await admin.page.goto("/", { waitUntil: "domcontentloaded" });
      await admin.page.getByRole("button", { name: who.user, exact: true }).first().click();
      const account = admin.page.locator('[data-panel="account-profile-modal"]');
      await expect(account, "the account surface did not open").toHaveClass(/is-open/);
      await expect(
        account,
        "the account surface does not name the role, so nothing on screen distinguishes a cross-tenant admin"
      ).toContainText("msoc-admin");
    } finally {
      await admin.context.close();
    }
  });

  /**
   * WHAT BUG THIS PINS — a live one, hence `test.fail`.
   *
   * The MSOC admin's dashboard is byte-for-byte a tenant analyst's. The top
   * bar's host pill names ONE customer — measured 2026-08-27 on
   * console.adanianlabs.io: "adanian-internal", identical to what op-adanian
   * sees — and every KPI, timeline and feed below it is that one customer's,
   * because the console makes tenant-less reads and authorizeRead falls back to
   * TenantScope(p)[0].
   *
   * ROOT CAUSE, and it is not the frontend. authz.TenantScope skips
   * cross-tenant roles but keeps every OTHER grant, and
   * identity.PrincipalFromClaims stamps the account's `tenant` attribute onto
   * EVERY realm role in the token — including Keycloak's default composites
   * (offline_access, uma_authorization, default-roles-ebpf-soc), which
   * roleCan() authorizes for nothing. So the msoc account, provisioned with
   * `attributes.tenant=[<first tenant>]` by scripts/deploy/lib.sh, comes back
   * with a one-tenant scope built entirely out of grants that cannot authorize
   * a single read. handleWhoami's own comment states the opposite ("a
   * cross-tenant MSOC admin has no tenant list, so tenants is null") and the
   * console was corrected to match it; the deployment does not.
   *
   * WHY IT MATTERS. The provider's estate-wide operator opens the console and
   * is silently shown one customer as though it were everything: an all-clear
   * across the whole book of business while another tenant is on fire. The
   * server agrees it is not that operator's tenant — every one of those reads
   * is booked in operator_audit as an allowed cross-tenant access, so the
   * customer's access trail fills with provider reads that the provider
   * believes are their own, which is also how the records that matter get
   * buried.
   *
   * WHY THE GUARDS BELOW EXIST. `test.fail(true, …)` makes ANY throw in this
   * body count as the expected failure — a Keycloak flake, a renamed selector,
   * a timeout. All of those would report green while saying nothing about the
   * defect. So NOTHING on the way to the measurement is allowed to throw:
   * sign-in and the whoami read are wrapped and SKIP on failure, the wait is
   * tolerant, the pill is read defensively, and a reading that is not a real
   * host name SKIPS. Only a genuine customer name on screen reaches the
   * expectation and satisfies the `fail`.
   *
   * That list is exhaustive as written; if you add a step above the
   * expectation, it has to skip on failure too, or this test starts reporting
   * green for reasons that have nothing to do with the defect.
   *
   * Delete this `test.fail` when whoami stops handing a cross-tenant principal
   * a tenant list (or the console stops pinning itself to element 0).
   */
  test("the cross-tenant admin's console does not present one customer as the whole estate", async ({
    browser,
    probe
  }) => {
    test.fail(true, "known defect: TenantScope hands the msoc-admin a one-tenant scope built from capability-less default realm roles, so its console is pinned to one customer");
    test.skip(!probe.otherTenant, "Set PROBE_OTHER_TENANT");
    const foreign = probe.otherTenant!;

    // Sign-in is a harness step, not the claim. Under `test.fail` a Keycloak
    // flake here would otherwise be indistinguishable from the defect.
    const admin = await signedInContext(browser, probe, {
      user: probe.adminUser!,
      password: probe.adminPassword!
    }).catch(() => null);
    test.skip(admin === null, "could not sign the cross-tenant admin in — a harness fault, not the defect");

    try {
      const session = admin!;
      const raw = await readWhoamiRaw(session.page).catch(() => null);
      test.skip(raw === null, "whoami did not answer for the admin — a harness fault, not the defect");
      const subject = String(raw!.user ?? raw!.subject ?? "");
      const tenants = Array.isArray(raw!.tenants) ? (raw!.tenants as string[]) : [];
      await session.page.goto("/", { waitUntil: "domcontentloaded" });
      // Wait for the console to have the REAL whoami before reading the pill.
      // Until the first snapshot lands the pill renders EMPTY_WHOAMI.host,
      // "localhost", which is not any tenant's name — reading it that early
      // makes this test report the defect as fixed. The account button carries
      // the operator's name only once whoami has resolved, and the preceding
      // test (not `test.fail`) is what proves that button appears at all. A
      // timeout here is NOT failed on: it is handed to the sentinel guard
      // below, which skips rather than passing the defect off as pinned.
      await session.page
        .getByRole("button", { name: subject, exact: true })
        .first()
        .waitFor({ state: "visible", timeout: 60_000 })
        .catch(() => undefined);
      const shown = (
        await session.page
          .locator(".soc-host-pill")
          .first()
          .innerText()
          .catch(() => "")
      ).trim();

      // Recorded whatever the outcome, so a future run's report says what this
      // console actually displayed rather than only that an expectation moved.
      test.info().annotations.push({
        type: "note",
        description: `msoc host pill: "${shown}"; whoami.tenants: ${JSON.stringify(raw!.tenants)}; whoami.host: ${String(raw!.host)}`
      });

      // The pill never rendered a real host: the selector moved, the shell did
      // not boot, or whoami never resolved. That is a harness problem and it
      // must not be reported as the pinned defect.
      test.skip(
        shown === "" || shown === "localhost" || shown === "control-plane",
        `the host pill read ${JSON.stringify(shown)} rather than any tenant name — harness problem, not the defect`
      );

      // The estate identity on screen must not be one customer's name. Any
      // real tenant id here means the whole dashboard beneath it is that one
      // customer's data, presented to the provider as the whole picture.
      const realTenants = [...tenants, foreign].filter(Boolean);
      expect(
        realTenants,
        `the cross-tenant console's host pill reads "${shown}" — one customer's name, identical to what that customer's own analyst sees`
      ).not.toContain(shown);
    } finally {
      await admin?.context.close();
    }
  });
});
