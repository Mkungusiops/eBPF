import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ConfirmModal, type ConfirmOptions } from "../features/devices/ConfirmModal";

/**
 * THE CONFIRM IDIOM FOR A REQUIRED REASON, PINNED.
 *
 * The device kill-switch and the device mode switch both go through this one
 * modal, and its rule is: while a required reason is empty the confirm button
 * is DISABLED, and the requirement is already stated on screen when the dialog
 * opens so the dead button is never bare. The alternative — a live button that
 * sets an inline error on click — is the idiom this file deliberately does not
 * use, because the shared EnforcementLadder on the same page disables a gated
 * rung and explains it in a title, and two grammars for one rule is how a spec
 * ends up asserting one thing while the code does another.
 *
 * These tests hold both halves. Disabling without the standing explanation is
 * its own usability failure — the operator cannot tell WHAT is missing — so the
 * explanation is asserted as hard as the gate.
 */

const REQUIREMENT = "A reason is required for the audit log.";

function open(overrides: Partial<ConfirmOptions> = {}) {
  const onClose = vi.fn();
  const options: ConfirmOptions = {
    title: "Engage kill-switch",
    message: "This bypasses all device enforcement immediately.",
    confirmLabel: "Engage kill-switch",
    danger: true,
    requireReason: true,
    reasonPlaceholder: "Why are you halting device enforcement?",
    ...overrides
  };
  render(<ConfirmModal options={options} onClose={onClose} />);
  return {
    onClose,
    confirm: () => screen.getByRole("button", { name: options.confirmLabel }) as HTMLButtonElement,
    cancel: () => screen.getByRole("button", { name: /cancel/i }) as HTMLButtonElement,
    reason: () => screen.getByLabelText(/reason/i) as HTMLInputElement
  };
}

describe("a confirm that requires a reason disables its button until one is typed", () => {
  it("states the requirement on open, before anything is pressed", () => {
    open();
    // Not after a rejected click — now, while the operator is still reading.
    expect(screen.getByText(REQUIREMENT)).toBeTruthy();
  });

  it("holds the confirm button closed while the reason is empty or blank", () => {
    const ui = open();
    expect(ui.confirm().disabled).toBe(true);
    // A dead button that does not say why is the failure mode of this choice,
    // so the sentence is on the button as well as beside the field.
    expect(ui.confirm().title).toBe(REQUIREMENT);

    fireEvent.change(ui.reason(), { target: { value: "   " } });
    expect(ui.confirm().disabled, "whitespace is not a justification").toBe(true);
  });

  it("opens the gate on a typed reason and hands back the trimmed sentence", () => {
    const ui = open();
    fireEvent.change(ui.reason(), { target: { value: "  lateral movement, INC-4471  " } });
    expect(ui.confirm().disabled).toBe(false);
    expect(ui.confirm().title).toBeFalsy();

    fireEvent.click(ui.confirm());
    expect(ui.onClose).toHaveBeenCalledWith({ reason: "lateral movement, INC-4471" });
  });

  it("cannot be confirmed by pressing the empty button", () => {
    const ui = open();
    fireEvent.click(ui.confirm());
    expect(ui.onClose, "an empty reason reached the caller").not.toHaveBeenCalled();
  });

  it("describes the reason field with the requirement, for the operator who cannot see the colour", () => {
    const ui = open();
    const describedBy = ui.reason().getAttribute("aria-describedby");
    expect(describedBy).toBeTruthy();
    expect(document.getElementById(describedBy!)?.textContent).toBe(REQUIREMENT);
    expect(ui.reason().getAttribute("aria-required")).toBe("true");
  });

  it("leaves an unrequired confirm alone: enabled, and with no requirement text", () => {
    const ui = open({ requireReason: false, confirmLabel: "Disengage", danger: false });
    expect(ui.confirm().disabled).toBe(false);
    expect(screen.queryByText(REQUIREMENT)).toBeNull();
    fireEvent.click(ui.confirm());
    expect(ui.onClose).toHaveBeenCalledWith({ reason: "" });
  });

  it("keeps Tab inside the dialog even though the last control is disabled", () => {
    // The disabled confirm button is the last element in the dialog. Counting
    // it as the wrap point made the trap hand focus to something the browser
    // then skips, and Tab from Cancel walked out of the modal to the page
    // behind it — with a plane-wide kill-switch still open.
    const ui = open();
    ui.cancel().focus();
    expect(document.activeElement).toBe(ui.cancel());

    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement, "focus escaped the dialog past the disabled button").toBe(ui.reason());
  });

  it("still cancels on Escape while the gate is closed", () => {
    const ui = open();
    fireEvent.keyDown(document, { key: "Escape" });
    // null, not an empty reason: an abandoned confirmation is not a reasonless one.
    expect(ui.onClose).toHaveBeenCalledWith(null);
  });
});
