import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { CommandPalette, paletteCommands } from "../features/soc/SocModals";
import { LAB_ONLY_SURFACES, surfaceOffered } from "../features/soc/Sidebar";

// cmdk observes its list to keep the selected item in view, and jsdom has no
// ResizeObserver. Without this stub every render below throws before the
// component under test has done anything.
class NoopResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver = globalThis.ResizeObserver ?? (NoopResizeObserver as unknown as typeof ResizeObserver);

/**
 * The command palette is a second door onto every surface, and it was neither
 * focused nor gated.
 *
 * FOCUS: every modal body USED TO BE mounted at route load inside a shell that
 * is `display: none` until it opens, so cmdk's `autoFocus` fired once on a
 * hidden input and did nothing. Ctrl+K opened the palette with focus still on
 * <body>, the next keystroke went nowhere, and the operator had to reach for
 * the mouse — which defeats the only reason a palette exists.
 *
 * ModalShell now mounts a body at FIRST OPEN, so that account is history for
 * the first Ctrl+K of a session: the palette mounts in the same commit that
 * adds `is-open`, onto an input that is already visible. It is NOT history
 * after that. A shell stays mounted once opened, so from the second Ctrl+K
 * onward the palette is exactly what it always was — a mounted, hidden
 * component whose `autoFocus` will never fire again — and the layout effect
 * below is the only thing that focuses it. The bug survives lazy mounting for
 * every operator who opens the palette twice, which is all of them.
 *
 * GATE: the rail hides Attack Sim, Honeypots and the Rule Simulator unless the
 * SERVER reports lab_mode, because Attack Sim runs a script as root on the host
 * being defended and, on the control plane, writes fabricated alerts into the
 * tenant's real evidence store. The palette's item list was gated on nothing,
 * so those surfaces were reachable by name on a production deployment that
 * deliberately hides them.
 */

function Harness({ open }: { open: boolean }) {
  return (
    <>
      <button type="button">Ctrl+K trigger</button>
      {/* The shell this palette really lives in mounts its body at first open
          and then KEEPS it mounted across every later close and reopen. This
          harness models that steady state — mounted once, toggled open and
          shut — because it is the state the focus bug lives in, and the one
          an operator is in for every Ctrl+K after their first. */}
      <div aria-hidden={!open}>
        <CommandPalette
          open={open}
          value=""
          onValueChange={() => {}}
          items={paletteCommands(true)}
          onSelect={() => {}}
        />
      </div>
    </>
  );
}

describe("the command palette takes focus when it opens", () => {
  it("leaves focus alone while it is closed", () => {
    render(<Harness open={false} />);
    expect(document.activeElement).toBe(document.body);
  });

  it("focuses its input on open, not on mount", () => {
    const { rerender } = render(<Harness open={false} />);
    const input = screen.getByPlaceholderText("Type a command");
    expect(document.activeElement).not.toBe(input);

    rerender(<Harness open />);
    expect(document.activeElement).toBe(input);
  });

  it("hands focus back to where the operator was when it closes", () => {
    // Escape closes the palette from the route's window handler. If focus stayed
    // on the input, every keystroke afterwards would land in a field inside a
    // display:none shell — invisible, and still swallowing input.
    const { rerender } = render(<Harness open={false} />);
    const trigger = screen.getByRole("button", { name: "Ctrl+K trigger" });
    trigger.focus();

    rerender(<Harness open />);
    expect(document.activeElement).toBe(screen.getByPlaceholderText("Type a command"));

    rerender(<Harness open={false} />);
    expect(document.activeElement).toBe(trigger);
  });

  it("does not steal focus back from a surface the palette opened", () => {
    // Selecting a command swaps the open surface. If something there has taken
    // focus deliberately, closing the palette must not drag it back.
    const { rerender } = render(<Harness open={false} />);
    const trigger = screen.getByRole("button", { name: "Ctrl+K trigger" });
    trigger.focus();
    rerender(<Harness open />);

    const elsewhere = document.createElement("input");
    document.body.appendChild(elsewhere);
    elsewhere.focus();
    rerender(<Harness open={false} />);
    expect(document.activeElement).toBe(elsewhere);
    elsewhere.remove();
  });
});

describe("the palette is gated on the same lab_mode the rail is", () => {
  it("withholds the lab surfaces when the server says this is not a lab", () => {
    const labels = paletteCommands(false).map((item) => item.label);
    expect(labels).not.toContain("Open attacks");
    expect(labels).not.toContain("Show honeypots");
    // And the surfaces an analyst always needs are still on offer.
    expect(labels).toContain("Show policies");
    expect(labels).toContain("Show help");
  });

  it("offers them again on a deployment the server reports as a lab", () => {
    const labels = paletteCommands(true).map((item) => item.label);
    expect(labels).toContain("Open attacks");
    expect(labels).toContain("Show honeypots");
  });

  it("renders only the gated list", () => {
    const onSelect = vi.fn();
    render(
      <CommandPalette open value="" onValueChange={() => {}} items={paletteCommands(false)} onSelect={onSelect} />
    );
    expect(screen.queryByText("Open attacks")).toBeNull();
    expect(screen.queryByText("Show honeypots")).toBeNull();
    expect(screen.getByText("Show sensor health")).toBeTruthy();
  });

  it("gates the palette on the predicate the rail asks, not a second list", () => {
    // Only the shared predicate is exercised here. Whether the RAIL honours it
    // — including the Rule Simulator, which has no palette entry — is proven by
    // pressing both doors in chrome2LabGateBehaviour.test.tsx. This file used to
    // assert that over a 400-character lookback in Sidebar.tsx source, which
    // passed or failed on formatting and pressed nothing.
    for (const surface of LAB_ONLY_SURFACES) {
      expect(surfaceOffered(surface, false)).toBe(false);
      expect(surfaceOffered(surface, true)).toBe(true);
    }
    expect(surfaceOffered("policies", false)).toBe(true);
    expect(paletteCommands(false).every((item) => surfaceOffered(item.surface, false))).toBe(true);
  });
});
