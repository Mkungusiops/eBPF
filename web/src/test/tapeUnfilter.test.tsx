import { createRef } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { DecisionTape } from "../features/choke/DecisionTape";

/**
 * Clicking "filter" on a decision row pins the tape to one process. The clear
 * chip existed only in the page-level filter strip, which renders at the top
 * of a long scroll while the tape sits at the bottom — so from where the
 * operator clicked, there was no way back. An undo that is off-screen from the
 * action is, in practice, a one-way door.
 */
function tape(props: { filterExec?: string; onClearFilterExec?: () => void }) {
  const noop = () => {};
  render(
    <DecisionTape
      refEl={createRef<HTMLDivElement>()}
      rows={[]}
      selected={new Set()}
      acked={new Set()}
      onSelect={noop}
      onDrill={noop}
      onFilterExec={noop}
      onAck={noop}
      onUnack={noop}
      onCopy={noop}
      {...(props as Record<string, unknown>)}
    />
  );
}

describe("a pinned decision tape can be unpinned from the tape itself", () => {
  it("offers a clear control when pinned", async () => {
    const onClear = vi.fn();
    const user = userEvent.setup();
    tape({ filterExec: "NTY5Njk2ODUyNW", onClearFilterExec: onClear });

    await user.click(screen.getByRole("button", { name: /Clear the process filter/i }));
    expect(onClear).toHaveBeenCalledTimes(1);
  });

  it("says the empty tape is pinned rather than blaming the filters generally", () => {
    // "The tape is filtered by time, action, search, and ack state" sends the
    // operator looking at four controls, none of which is the one that did it.
    tape({ filterExec: "NTY5Njk2ODUyNW", onClearFilterExec: () => {} });
    expect(screen.getByText(/pinned to one process\. Clear the pin above/)).toBeTruthy();
  });

  it("shows no clear control when nothing is pinned", () => {
    tape({});
    expect(screen.queryByRole("button", { name: /Clear the process filter/i })).toBeNull();
  });
});
