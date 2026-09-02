import { installMockApi, RequestLog } from "./support/mock-api";
import { expect, test } from "./support/test";

/**
 * Change control: the second pair of eyes on a destructive action.
 *
 * WHAT THESE PIN, and every one of them is a safety property rather than a
 * feature:
 *
 *  1. A GATED ACTION HAS NOT HAPPENED. The queue must say so in as many words.
 *     An operator who believes a sever landed, and it is sitting in a queue,
 *     will stop responding to a live intrusion.
 *  2. THE REQUESTER CANNOT APPROVE THEIR OWN REQUEST. That is the entire
 *     mechanism; if it can be self-approved it is a speed bump, not a control.
 *  3. THE REQUESTER CAN ALWAYS WITHDRAW. Dual control exists to stop one
 *     operator CAUSING a destructive action. It has nothing to protect by
 *     trapping a mistyped sever in a queue until someone else clears it — the
 *     way OUT of a bad state never waits for a quorum, which is the same rule
 *     that keeps thaw and the kill-switch ungated.
 *  4. AN EMPTY QUEUE RENDERS NOTHING. A visible "0 pending" box on a
 *     deployment with no gating implies a control that is not switched on.
 *
 * WHY IT IS HERE AND NOT IN UNIT TESTS: the queue is rendered on the live
 * Choke route above the containment surface it governs, and what matters is
 * which BUTTONS a given operator is offered on a given request. That is a
 * rendered-per-row decision, not a pure function.
 */

/**
 * `status: "pending"` is not optional decoration — the route filters on it
 * (useChokePosture.ts). A fixture without it renders an empty queue and every
 * assertion below fails for a reason that has nothing to do with the feature.
 */
const PENDING = [
  {
    id: "req-someone-else",
    status: "pending",
    action: "sever",
    scope: "process",
    exec_id: "exec-fixture-1",
    pid: 4242,
    agent_id: "agent-fixture",
    requester: "op-other",
    reason: "confirmed c2 beacon",
    mine: false
  },
  {
    id: "req-mine",
    status: "pending",
    action: "quarantine",
    scope: "fleet",
    requester: "operator",
    reason: "mistyped, withdrawing",
    mine: true
  }
];

test.describe("change control", () => {
  test.use({ viewport: { width: 1600, height: 1000 } });

  test("renders nothing when nothing is pending", async ({ page }) => {
    await installMockApi(page);
    await page.goto("/choke");
    await expect(page.locator('[data-panel="containment-ladder"]')).toBeVisible();

    await expect(
      page.locator('[data-panel="approvals-queue"]'),
      "an empty queue box implies a control that may not even be switched on"
    ).toHaveCount(0);
  });

  test("says plainly that a gated action has NOT been applied", async ({ page }) => {
    await installMockApi(page, { routes: { "/api/approvals": { approvals: PENDING, pending: 2, you: "operator" } } });
    await page.goto("/choke");

    const queue = page.locator('[data-panel="approvals-queue"]');
    await expect(queue).toBeVisible();
    await expect(queue).toContainText("Awaiting approval");
    await expect(
      queue,
      "an operator who believes a sever landed will stop responding to a live intrusion"
    ).toContainText(/have not been applied|not.*been applied/i);
    await expect(queue).toContainText("2");
  });

  test("denying someone else's request is one click and reaches the server", async ({ page }) => {
    const recorder = new RequestLog();
    await installMockApi(page, {
      recorder,
      routes: { "/api/approvals": { approvals: PENDING, pending: 2, you: "operator" } }
    });
    await page.goto("/choke");

    const row = page.locator('[data-panel="approvals-queue"] li').filter({ hasText: "op-other" });
    await row.getByRole("button", { name: "Deny" }).click();

    // Deny is not gated: refusing to apply a destructive action can never
    // itself be dangerous, and putting a confirm in front of it only teaches
    // operators to click through dialogs.
    const decisions = recorder.matching(/^\/api\/approvals\/decide$/).filter((r) => r.method !== "GET");
    expect(decisions.length, "the denial never reached the server").toBeGreaterThan(0);
    expect(decisions[decisions.length - 1].body ?? "").toContain("req-someone-else");
  });

  test("approving is confirmed, shows what is being authorized, and needs a reason", async ({ page }) => {
    const recorder = new RequestLog();
    await installMockApi(page, {
      recorder,
      routes: { "/api/approvals": { approvals: PENDING, pending: 2, you: "operator" } }
    });
    await page.goto("/choke");

    const row = page.locator('[data-panel="approvals-queue"] li').filter({ hasText: "op-other" });
    await expect(row).toContainText("SEVER");
    // The requester's stated reason is on the row — an approver deciding
    // without one is rubber-stamping, which is worse than no control because
    // it manufactures an audit trail that implies review.
    await expect(row).toContainText("confirmed c2 beacon");
    await expect(row.getByRole("button", { name: "Approve & apply" })).toBeVisible();
    await expect(row.getByRole("button", { name: "Deny" })).toBeVisible();

    await row.getByRole("button", { name: "Approve & apply" }).click();

    const confirm = page.locator('[data-panel="confirm-modal"]');
    await expect(confirm, "approving a sever must not be a single click").toBeVisible();
    await expect(confirm).toContainText("APPROVE SEVER");
    // The confirm restates WHO asked, WHAT for, and that approving applies it
    // NOW — the three things an approver needs and would otherwise have to
    // remember from the row behind the dialog.
    await expect(confirm).toContainText("op-other");
    await expect(confirm).toContainText("confirmed c2 beacon");
    await expect(confirm).toContainText(/applies it now/i);

    const approve = confirm.getByRole("button", { name: "approve" });
    await approve.click();
    // Still nothing sent: the approver's own reason is required and is what
    // distinguishes their audit row from the requester's.
    expect(
      recorder.matching(/^\/api\/approvals\/decide$/).filter((r) => r.method !== "GET"),
      "an approval was sent without the approver's reason"
    ).toEqual([]);

    await confirm.getByPlaceholder("audit reason").fill("reviewed the chain, agree");
    await approve.click();

    const decisions = recorder.matching(/^\/api\/approvals\/decide$/).filter((r) => r.method !== "GET");
    expect(decisions.length, "the approval never reached the server").toBeGreaterThan(0);
    const body = decisions[decisions.length - 1].body ?? "";
    expect(body).toContain("req-someone-else");
    expect(body, "the approver's reason must travel with the decision").toContain("reviewed the chain, agree");
  });

  test("refuses to let the requester approve their own request, but lets them withdraw it", async ({ page }) => {
    const recorder = new RequestLog();
    await installMockApi(page, {
      recorder,
      routes: { "/api/approvals": { approvals: PENDING, pending: 2, you: "operator" } }
    });
    await page.goto("/choke");

    const mine = page.locator('[data-panel="approvals-queue"] li').filter({ hasText: "mistyped, withdrawing" });
    await expect(mine).toBeVisible();

    // The whole mechanism. If this button exists, dual control is a speed bump.
    await expect(
      mine.getByRole("button", { name: "Approve & apply" }),
      "the requester was offered a button that would defeat dual control"
    ).toHaveCount(0);
    await expect(mine).toContainText(/another operator must approve/i);

    // …and the way out is never blocked.
    const withdraw = mine.getByRole("button", { name: "Withdraw" });
    await expect(withdraw, "a mistyped request must not be trapped until a quorum clears it").toBeEnabled();
    await withdraw.click();

    const decisions = recorder.matching(/^\/api\/approvals\/decide$/).filter((r) => r.method !== "GET");
    expect(decisions.length, "the withdrawal never reached the server").toBeGreaterThan(0);
    expect(decisions[decisions.length - 1].body ?? "").toContain("req-mine");
  });

  test("names a fleet-scoped request as reaching the whole tenant", async ({ page }) => {
    await installMockApi(page, { routes: { "/api/approvals": { approvals: PENDING, pending: 2, you: "operator" } } });
    await page.goto("/choke");

    // Blast radius, in words. "quarantine exec-fixt…" and "quarantine the
    // entire tenant" are the same button with very different consequences.
    await expect(page.locator('[data-panel="approvals-queue"]')).toContainText("the entire tenant");
  });
});
