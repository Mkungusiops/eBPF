/**
 * The fleet console's confirmation gate.
 *
 * It stands in front of writes that fan out across the whole estate — the
 * containment and maintenance presets, the kill-switch, the thaw — and collects
 * the audit reason the engine will record alongside them. `reasonRequired` is
 * what stops an estate-wide containment landing in the audit log with no
 * explanation of who ordered it or why.
 *
 * DISABLED UNTIL VALID — AND IT SAYS SO IN TEXT, NOT ONLY IN A TOOLTIP.
 *
 * While a required reason is empty the confirm button is `disabled`, which is
 * the grammar the device confirm and the shared EnforcementLadder already use.
 * A `title` alone cannot carry the explanation for that: browsers suppress
 * pointer events on a disabled control, so its tooltip never opens, and the
 * operator is left with a dead "Apply preset" and no reason anywhere on screen.
 * So the requirement sentence is RENDERED beside the field, from the moment the
 * dialog opens, and the input is `aria-describedby` it — the title repeats what
 * is already on screen rather than being the only place it exists.
 *
 * The device console has its own modal. It looks similar and is not the same
 * component: different class namespace (`fleet-modal*` vs `devices-modal*`) and
 * a different element order. Both now share the reason idiom above, and both
 * focus the reason input when one is required and the confirm button otherwise
 * — that button is disabled on first render for every reason-required confirm,
 * and focusing a disabled control leaves `document.activeElement` on <body>.
 * Both keep Tab inside the dialog. They are deliberately NOT shared, so the
 * duplication below is the price of that decision rather than an oversight.
 */
import { AlertTriangle, ChevronRight } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import type { ConfirmState } from "./types";

/** The requirement sentence — rendered beside the field, and on the dead button. */
const REASON_REQUIRED_TEXT = "A reason is required for the audit log.";
const REASON_HINT_ID = "fleet-confirm-reason-hint";

export function ConfirmModal({ state, onClose }: { state: ConfirmState; onClose: () => void }) {
  const [reason, setReason] = useState(state.defaultReason ?? "");
  const dialogRef = useRef<HTMLElement | null>(null);
  const reasonRef = useRef<HTMLInputElement | null>(null);
  const confirmRef = useRef<HTMLButtonElement | null>(null);

  // FOCUS LANDS WHERE THE WORK IS, AND WHERE IT CAN LAND AT ALL.
  //
  // This focused the confirm button unconditionally until 2026-09-08. That is
  // the button the reason rule disables, and a disabled button cannot take
  // focus: `activeElement` stayed on <body>, so the operator's first Tab
  // started at the top of the document — behind an `aria-modal` dialog — rather
  // than inside the dialog. When a reason is required the input is also simply
  // where the operator must go next, since nothing else in here is live yet.
  useEffect(() => {
    if (state.reasonRequired && reasonRef.current) {
      reasonRef.current.focus();
      // The default reason is boilerplate the operator is meant to replace
      // ("fleet UI preset: containment"), so it starts selected.
      reasonRef.current.select();
      return;
    }
    confirmRef.current?.focus();
  }, [state.reasonRequired]);

  // ESCAPE BELONGS TO THE TOPMOST THING ON SCREEN, AND THAT IS THIS DIALOG.
  //
  // Capture phase, and it stops the event. The fleet view is a surface inside
  // the SOC console now, and that console has its own window-level Escape
  // handler that closes whatever surface is open (SocRoute). Both listeners are
  // on window, so a plain bubble-phase listener here left BOTH to run: escaping
  // out of "apply containment to the estate?" dismissed the confirm AND shut
  // the fleet view behind it, putting the operator back on the dashboard
  // mid-incident with no idea whether the write had gone. Capturing first and
  // stopping the propagation means the confirm answers Escape while it is up,
  // and the surface answers it again the moment the confirm is gone.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.stopPropagation();
      onClose();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [onClose]);

  // TAB STAYS IN THE DIALOG, WHICH `aria-modal="true"` ALREADY PROMISES.
  //
  // It is load-bearing here precisely because of the rule above: the confirm
  // button is the last control in the dialog and is dead while the reason is
  // empty, so without a trap the first Tab out of Cancel walked into the SOC
  // dashboard behind an estate-wide containment prompt. Disabled controls are
  // excluded from the ring for the same reason — counting the dead confirm
  // button as the wrap point hands focus to something the browser then skips.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Tab") return;
      const root = dialogRef.current;
      if (!root) return;
      const focusable = root.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      );
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, []);

  // ONE GRAMMAR FOR "A REASON IS REQUIRED", ACROSS EVERY CONFIRM.
  //
  // The device plane settled this on 2026-09-07: the confirm button is
  // DISABLED until the reason is there, with the requirement stated on the
  // control rather than revealed by pressing it. This modal kept the older
  // grammar — press, then an inline error — so the same rule wore two
  // behaviours depending on which containment surface an operator happened to
  // open. That is the kind of drift that makes an operator learn one console
  // and be wrong about the other, on the surfaces that fire containment.
  const reasonMissing = Boolean(state.reasonRequired) && reason.trim() === "";

  const confirm = async () => {
    // Belt and braces, and unreachable through the DOM: React does not deliver
    // a click to a disabled button, and this input is in no form, so there is
    // no Enter path around it either. Kept so that relaxing the disabled rule
    // cannot silently start shipping an empty explanation into an audit row.
    if (reasonMissing) return;
    await state.onConfirm(reason.trim());
    onClose();
  };

  return (
    <div
      className="fleet-modal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <section
        ref={dialogRef}
        className="fleet-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="fleet-confirm-title"
      >
        <div className={`fleet-modal__icon fleet-modal__icon--${state.tone === "danger" ? "danger" : "default"}`}>
          {state.tone === "danger" ? <AlertTriangle size={20} /> : <ChevronRight size={20} />}
        </div>
        <div className="fleet-modal__body">
          <h2 id="fleet-confirm-title">{state.title}</h2>
          <p>{state.body}</p>
          {state.reasonLabel ? (
            <label className="fleet-modal__reason">
              <span>{state.reasonLabel}</span>
              <input
                ref={reasonRef}
                value={reason}
                aria-required={state.reasonRequired ? "true" : undefined}
                aria-describedby={state.reasonRequired ? REASON_HINT_ID : undefined}
                onChange={(event) => setReason(event.target.value)}
              />
            </label>
          ) : null}
          {/* On screen from the open, not after a rejected press — see the
              header. It turns danger-red while the requirement is unmet, which
              is also exactly while the confirm button is dead. The two classes
              are the styled half: fleet.css has no rule for `__req` itself. */}
          {state.reasonRequired ? (
            <div
              id={REASON_HINT_ID}
              className={`fleet-modal__req ${reasonMissing ? "fleet-modal__error" : "fleet-muted"}`}
            >
              {REASON_REQUIRED_TEXT}
            </div>
          ) : null}
          <div className="fleet-modal__actions">
            <button className="fleet-btn" type="button" onClick={onClose}>
              Cancel
            </button>
            <button
              className={`fleet-btn ${state.tone === "danger" ? "fleet-btn--danger" : "fleet-btn--primary"}`}
              ref={confirmRef}
              type="button"
              disabled={reasonMissing}
              title={reasonMissing ? REASON_REQUIRED_TEXT : undefined}
              onClick={() => void confirm()}
            >
              {state.confirmLabel ?? "Confirm"}
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}
