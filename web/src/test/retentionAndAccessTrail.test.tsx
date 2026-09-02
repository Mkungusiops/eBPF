import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AccessTrailPanel } from "../features/soc/SettingsAccessTrail";
import { RetentionControls, validateRetentionDays } from "../features/soc/SettingsRetention";

/**
 * Both of these panels render a control whose characteristic failure is
 * silence: a retention horizon that was stored and does nothing, and an access
 * trail that is empty because it was never written rather than because nobody
 * accessed anything. Each has to say which.
 */
function stub(body: unknown, status = 200) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }))
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("retention", () => {
  it("shows the effective horizon, not the requested one, when the request was ignored", async () => {
    // The tenant asked for 10 years; the deployment keeps 30 days and has
    // already pruned the rest. Rendering "3650" here is how a data-residency
    // sign-off gets made against a setting that never took effect.
    stub({
      editable: true,
      policy: {
        deployment_event_days: 30,
        deployment_alert_days: 90,
        tenant_days: 3650,
        effective_event_days: 30,
        effective_alert_days: 90,
        floor_days: 14,
        clamped: false,
        ignored: true
      },
      note: "this tenant asked to keep data longer than the deployment does."
    });

    render(<RetentionControls />);

    await waitFor(() => expect(screen.getByText(/Events for 30 days/)).toBeTruthy());
    expect(screen.getByText(/not what is in force/)).toBeTruthy();
    expect(screen.getByText(/not doing what it says/i)).toBeTruthy();
  });

  it("does not render a blank control when the read failed", async () => {
    // Absent is not "no retention set" — a blank field would invite an operator
    // to set a horizon believing none exists.
    stub({ error: "boom" }, 500);
    render(<RetentionControls />);
    await waitFor(() => expect(screen.getByText(/could not be read/i)).toBeTruthy());
    expect(screen.queryByLabelText(/Retention in days/)).toBeNull();
  });

  it("warns that a sub-floor request will be raised", () => {
    expect(validateRetentionDays("3", 14)).toMatch(/raised to 14/);
    expect(validateRetentionDays("20", 14)).toBe("");
    expect(validateRetentionDays("", 14)).toBe("");
    expect(validateRetentionDays("abc", 14)).toMatch(/whole number/);
  });
});

describe("access trail", () => {
  it("states that an empty trail is not proof nobody read anything", async () => {
    stub({
      supported: true,
      records: [],
      total: 0,
      returned: 0,
      records_kept: "cross-tenant access and every refused attempt."
    });
    render(<AccessTrailPanel />);
    await waitFor(() => expect(screen.getByText(/does not mean nobody read anything/i)).toBeTruthy());
  });

  it("marks refused attempts, which are the rows a review looks for", async () => {
    stub({
      supported: true,
      records: [
        { subject: "eng@mssp", tenant_id: "acme", action: "read", allowed: true, cross_tenant: true, at: "2026-08-25T09:00:00Z" },
        {
          subject: "eng@mssp",
          tenant_id: "safaricom",
          action: "respond",
          allowed: false,
          cross_tenant: false,
          detail: "no grant for this tenant",
          at: "2026-08-25T09:01:00Z"
        }
      ],
      total: 2,
      returned: 2
    });
    render(<AccessTrailPanel />);
    await waitFor(() => expect(screen.getByText(/1 refused/)).toBeTruthy());
    expect(screen.getByText(/no grant for this tenant/)).toBeTruthy();
  });

  it("says the trail is not durable rather than showing an empty list", async () => {
    // A memory ring erased by the last restart must never be presented as an
    // audit record.
    stub({ supported: false, records: [], detail: "no durable operator-audit store" });
    render(<AccessTrailPanel />);
    await waitFor(() => expect(screen.getByText(/No durable access trail/i)).toBeTruthy());
  });

  it("does not claim an empty trail when the read failed", async () => {
    stub({ error: "boom" }, 500);
    render(<AccessTrailPanel />);
    await waitFor(() => expect(screen.getByText(/could not be read/i)).toBeTruthy());
  });
});
