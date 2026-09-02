import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ChokeBanners } from "../features/choke/sections";
import type { LoadState } from "../features/choke/types";

/**
 * Setting a ladder on one host is supported; the tenant policy is authoritative,
 * so the reconciler puts that host back within two minutes. Correct — and until
 * now silent, so the operator watched their change apply and then vanish with
 * the only explanation in a control-plane log they cannot reach.
 */
const BASE = {
  loadState: { kind: "ready" } as LoadState,
  staleSeconds: 0,
  onReconnect: () => {},
  mode: "detect-only",
  divergedAgents: [],
  kernelFired: 0
};

describe("ladder corrections", () => {
  it("names the host and both ladders, not just a count", () => {
    render(
      <ChokeBanners
        {...BASE}
        ladderCorrections={[
          { agent: "agent-7", from: "10/20/30/40", to: "20/50/120/200", at: "2026-08-25T10:00:00Z" }
        ]}
      />
    );
    expect(screen.getByText(/put back to tenant policy/i)).toBeTruthy();
    expect(screen.getByText("agent-7")).toBeTruthy();
    expect(screen.getByText("10/20/30/40")).toBeTruthy();
    expect(screen.getByText("20/50/120/200")).toBeTruthy();
  });

  it("says where to make the change stick", () => {
    // Without this the banner reports a loss and offers no route out of it.
    render(
      <ChokeBanners
        {...BASE}
        ladderCorrections={[{ agent: "a1", from: "1/2/3/4", to: "20/50/120/200", at: "" }]}
      />
    );
    expect(screen.getByText(/tenant-wide setting/i)).toBeTruthy();
  });

  it("renders nothing when no host was corrected", () => {
    const { container } = render(<ChokeBanners {...BASE} ladderCorrections={[]} />);
    expect(container.querySelector('[data-panel="ladder-correction-banner"]')).toBeNull();
  });

  it("does not throw when an older control plane omits the field", () => {
    // The Sensor Health panel crashed on exactly this: a field the server
    // simply did not send, mapped over without a guard.
    const { container } = render(<ChokeBanners {...BASE} />);
    expect(container.querySelector('[data-panel="ladder-correction-banner"]')).toBeNull();
  });
});
