import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ConfirmModal } from "../features/fleet/ConfirmModal";
import type { ConfirmState } from "../features/fleet/types";

/**
 * THE FLEET CONFIRM'S REQUIRED-REASON IDIOM, PINNED — BOTH HALVES OF IT.
 *
 * The estate-wide writes (containment, maintenance, kill-switch, thaw) all go
 * through this modal, and on 2026-09-08 it moved onto the device plane's
 * grammar: while a required reason is empty the confirm button is DISABLED.
 *
 * That conversion shipped with only half the idiom, which is what these tests
 * exist to stop coming back:
 *
 *  • the requirement was stated ONLY in the button's `title`. A browser
 *    suppresses pointer events on a disabled control, so that tooltip never
 *    opens — the operator saw a dead "Apply preset" and no reason for it
 *    anywhere on screen. The sentence must be RENDERED.
 *  • focus was put on the confirm button on mount, i.e. on the button the same
 *    rule had just disabled. Focusing a disabled control does nothing at all
 *    (`document.activeElement` stays on <body>), so the operator's first Tab
 *    started at the top of the document behind an `aria-modal` dialog.
 *
 * The device plane's equivalent is src/test/confirmIdiomRequiredReason.test.tsx;
 * the two surfaces are separate components on purpose, so each is pinned where
 * it lives.
 */

const REQUIREMENT = "A reason is required for the audit log.";

function open(overrides: Partial<ConfirmState> = {}) {
  const onConfirm = vi.fn(async () => undefined);
  const onClose = vi.fn();
  const state: ConfirmState = {
    title: "Apply containment preset?",
    body: "Containment lowers thresholds across targeted hosts and can immediately choke suspicious chains.",
    tone: "danger",
    confirmLabel: "Apply preset",
    reasonLabel: "Audit reason",
    reasonRequired: true,
    onConfirm,
    ...overrides
  };
  render(<ConfirmModal state={state} onClose={onClose} />);
  return {
    onConfirm,
    onClose,
    confirm: () => screen.getByRole("button", { name: state.confirmLabel ?? "Confirm" }) as HTMLButtonElement,
    cancel: () => screen.getByRole("button", { name: /cancel/i }) as HTMLButtonElement,
    reason: () => screen.getByLabelText(/audit reason/i) as HTMLInputElement
  };
}

describe("the fleet confirm states its reason requirement before anything is pressed", () => {
  it("renders the requirement as text on open, not only as a tooltip on a dead control", () => {
    const ui = open();
    // Visible text, queried the way an operator reads it. A `title` on a
    // disabled button is not this: the browser never opens it.
    expect(screen.getByText(REQUIREMENT)).toBeTruthy();
    expect(ui.confirm().disabled, "the gate is not closed, so the sentence above is decoration").toBe(true);
  });

  it("keeps the sentence on screen when the operator blanks a prefilled reason", () => {
    // Every fleet confirm opens with a boilerplate default, so the dead-button
    // state is reached by CLEARING the box rather than by opening the dialog.
    const ui = open({ defaultReason: "fleet UI preset: containment" });
    expect(ui.confirm().disabled, "the prefilled default did not arm the button").toBe(false);

    fireEvent.change(ui.reason(), { target: { value: "   " } });
    expect(ui.confirm().disabled, "whitespace is not a justification").toBe(true);
    expect(
      screen.getByText(REQUIREMENT),
      "the button went dead with nothing on screen explaining why"
    ).toBeTruthy();
    // The title is the third copy of the sentence, not the only one.
    expect(ui.confirm().title).toBe(REQUIREMENT);
    // ...and the field the operator is standing in points at it.
    const describedBy = ui.reason().getAttribute("aria-describedby");
    expect(describedBy).toBeTruthy();
    expect(document.getElementById(describedBy!)?.textContent).toBe(REQUIREMENT);
  });

  it("says nothing about a reason when none is required", () => {
    open({ reasonRequired: false, confirmLabel: "Thaw", tone: "default" });
    expect(
      screen.queryByText(REQUIREMENT),
      "a confirm that does not need a reason still demanded one on screen"
    ).toBeNull();
  });
});

describe("the fleet confirm puts focus somewhere it can actually land", () => {
  it("focuses the reason input, because the confirm button is disabled on first render", () => {
    const ui = open();
    // Not the confirm button: it is disabled here, and focusing a disabled
    // control leaves activeElement on <body> — which is what shipped.
    expect(document.activeElement, "focus went nowhere; the next Tab starts outside the dialog").toBe(
      ui.reason()
    );
    expect(document.activeElement).not.toBe(document.body);
  });

  it("selects the boilerplate default so it can be typed over", () => {
    const ui = open({ defaultReason: "fleet UI preset: containment" });
    expect(document.activeElement).toBe(ui.reason());
    expect(ui.reason().selectionStart).toBe(0);
    expect(ui.reason().selectionEnd).toBe("fleet UI preset: containment".length);
  });

  it("still focuses the confirm button when there is no reason to type", () => {
    const ui = open({ reasonRequired: false, reasonLabel: undefined, confirmLabel: "Thaw" });
    expect(document.activeElement, "an ungated confirm should still open ready to press").toBe(ui.confirm());
  });

  it("keeps Tab inside the dialog while the confirm button is dead", () => {
    // Cancel is the last control the browser will focus once the confirm
    // button is disabled. Without a trap, Tab from there walks into the SOC
    // dashboard rendered behind this aria-modal dialog.
    const ui = open();
    ui.cancel().focus();
    fireEvent.keyDown(window, { key: "Tab" });
    expect(document.activeElement, "focus escaped the dialog past the disabled confirm button").toBe(
      ui.reason()
    );
  });
});

describe("the fleet confirm arms on a real reason and refuses without one", () => {
  it("opens the gate on a typed reason and hands the write the trimmed sentence", async () => {
    const ui = open();
    fireEvent.change(ui.reason(), { target: { value: "  beaconing confirmed on alpha-edge  " } });
    expect(ui.confirm().disabled).toBe(false);
    expect(ui.confirm().title, "the requirement is still hanging off an armed button").toBeFalsy();

    fireEvent.click(ui.confirm());
    expect(ui.onConfirm).toHaveBeenCalledWith("beaconing confirmed on alpha-edge");
    await waitFor(() => expect(ui.onClose, "the confirm stayed open after the write went").toHaveBeenCalled());
  });

  it("cannot be confirmed by pressing the dead button", () => {
    // What holds this up is the `disabled` attribute, not the component's
    // `reasonMissing` early return: React does not deliver a click to a
    // disabled button, so this case stays green with that guard deleted
    // (measured). The guard is belt and braces for a future edit that relaxes
    // the attribute, and no DOM-level test can reach it.
    const ui = open();
    fireEvent.click(ui.confirm());
    expect(ui.onConfirm, "an estate-wide preset was applied with no audit reason").not.toHaveBeenCalled();
    expect(ui.onClose, "the confirm closed as though the write had gone").not.toHaveBeenCalled();
  });
});
