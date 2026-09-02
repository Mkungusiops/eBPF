import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ApprovalsQueue } from "../features/choke/sections";

/**
 * Dual control stops one operator CAUSING a destructive action. It was also
 * stopping them from taking one BACK: the four-eyes check sat above the
 * approve/deny branch, so an operator who mistyped a sever had to find a
 * second person to clear their own mistake, or wait out the TTL with the
 * action parked in the queue.
 */
const REQ = {
  id: "apr-1",
  tenant: "acme",
  action: "sever",
  exec_id: "abc123",
  pid: 4021,
  scope: "target",
  reason: "wrong pid",
  requester: "op@example.com",
  status: "pending",
  mine: true
};

function renderQueue(req: Record<string, unknown>, onDecide = vi.fn()) {
  render(<ApprovalsQueue pendingApprovals={[req] as never} onDecide={onDecide} />);
  return onDecide;
}

describe("your own parked request", () => {
  it("can be withdrawn, and still cannot be approved", async () => {
    const user = userEvent.setup();
    const onDecide = renderQueue(REQ);

    // No approve path for the requester — the rule the queue exists for.
    expect(screen.queryByRole("button", { name: /Approve/i })).toBeNull();

    const withdraw = screen.getByRole("button", { name: /Withdraw/i });
    await user.click(withdraw);

    // approve=false: a withdrawal removes a destructive action, it never applies one.
    expect(onDecide).toHaveBeenCalledTimes(1);
    expect(onDecide.mock.calls[0][1]).toBe(false);
  });

  it("still says a second operator is needed to approve", async () => {
    renderQueue(REQ);
    expect(screen.getByText(/another operator must approve/)).toBeTruthy();
  });
});

describe("someone else's parked request", () => {
  it("offers approve and deny, and no withdraw", async () => {
    renderQueue({ ...REQ, mine: false });
    expect(screen.getByRole("button", { name: /Approve/i })).toBeTruthy();
    expect(screen.getByRole("button", { name: /^Deny$/i })).toBeTruthy();
    // Withdraw is for your own request only; on someone else's it would be a
    // deny wearing a friendlier word.
    expect(screen.queryByRole("button", { name: /Withdraw/i })).toBeNull();
  });
});
