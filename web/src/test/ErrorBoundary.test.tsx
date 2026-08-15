import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ErrorBoundary } from "../components/ErrorBoundary";

function Boom(): React.ReactElement {
  throw new Error("map.get(...) is undefined");
}

describe("ErrorBoundary", () => {
  it("renders children when nothing throws", () => {
    render(
      <ErrorBoundary>
        <p>alerts</p>
      </ErrorBoundary>
    );
    expect(screen.getByText("alerts")).toBeTruthy();
  });

  // Before this existed, one throw anywhere in SocRoute's ~5,900 lines took the
  // whole console to a blank page — no message, no reload, mid-incident.
  it("shows a recoverable fallback instead of blanking the console", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    render(
      <ErrorBoundary surface="the SOC console">
        <Boom />
      </ErrorBoundary>
    );

    expect(screen.getByRole("alert")).toBeTruthy();
    expect(screen.getByText(/stopped rendering/i)).toBeTruthy();
    // Names the failing surface and surfaces the actual fault.
    expect(screen.getByText(/the SOC console/)).toBeTruthy();
    expect(screen.getByText(/map\.get/)).toBeTruthy();
    // Offers a way out.
    expect(screen.getByRole("button", { name: /reload/i })).toBeTruthy();
    spy.mockRestore();
  });

  // An operator staring at a failed console needs to know the host is still
  // defended before anything else.
  it("states that enforcement is unaffected", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    render(
      <ErrorBoundary>
        <Boom />
      </ErrorBoundary>
    );
    expect(screen.getByText(/Enforcement is unaffected/i)).toBeTruthy();
    spy.mockRestore();
  });
});
