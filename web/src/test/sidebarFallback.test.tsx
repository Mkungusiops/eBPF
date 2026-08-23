import { render, screen } from "@testing-library/react";
import type * as React from "react";
import { describe, expect, it } from "vitest";
import { SocSidebar } from "../features/soc/Sidebar";

/**
 * Behaviour & Intel is opened from inside the Assistant, so it has no nav entry
 * of its own — EXCEPT where there is no assistant to open it from.
 *
 * That exception is the common case, not the edge case: enrichment is on by
 * default and the assistant is opt-in and off by default. Without the fallback,
 * a deployment that never configured a model could not see whether its
 * behavioural baseline was ready or its threat-intel feeds had loaded — which is
 * precisely the silent-detector failure the panel exists to prevent.
 */
function props(over: Record<string, unknown> = {}) {
  return {
    labMode: false,
    sidebarOpen: true,
    onToggleSidebar: () => {},
    onCloseSidebar: () => {},
    openSurface: null,
    onOpenSurface: () => {},
    onOpenAssistant: () => {},
    assistantOpen: false,
    assistantAvailable: true,
    watchlistCount: 0,
    notificationBadge: 0,
    userName: "admin",
    ...over
  } as React.ComponentProps<typeof SocSidebar>;
}

describe("Behaviour & Intel nav entry", () => {
  it("is hidden when the assistant can open it", () => {
    render(<SocSidebar {...props({ assistantAvailable: true })} />);
    expect(screen.getByText("Assistant")).toBeTruthy();
    expect(screen.queryByText("Behaviour & Intel")).toBeNull();
  });

  it("comes back when there is no assistant, so the panel is never orphaned", () => {
    render(<SocSidebar {...props({ assistantAvailable: false })} />);
    expect(screen.getByText("Behaviour & Intel")).toBeTruthy();
  });
});
