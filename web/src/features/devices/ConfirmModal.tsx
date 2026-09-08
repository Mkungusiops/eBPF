/**
 * The blocking confirmation layer for the device plane.
 *
 * Every irreversible-looking device control (mode change, kill-switch) routes
 * through `useConfirmDialog`, which turns the modal into an awaitable promise:
 * the caller writes `const result = await requestConfirm({...})` and reads back
 * the operator's reason, instead of threading callbacks through the action.
 * A cancelled dialog resolves `null`, so an abandoned confirmation can never be
 * mistaken for an empty reason.
 *
 * THE CONFIRM IDIOM FOR A REQUIRED REASON: DISABLED UNTIL VALID.
 *
 * While `requireReason` is set and the box is empty, the confirm button is
 * `disabled`. It is NOT a live button that scolds on click. Three reasons:
 *
 *  1. It is the idiom this product already has. The shared EnforcementLadder
 *     disables a rung that needs a reason and puts the WHY in its `title`, on
 *     the graph, the Choke Gateway and Devices alike. A modal that instead let
 *     the press through and answered with an error would be a second grammar
 *     for the same rule, on the same page as the ladder.
 *  2. The press is the destructive act. Engaging the device kill-switch halts
 *     every containment on the plane; the operator should not be able to fire
 *     the button at all until the row it will write is complete.
 *  3. A disabled button is only defensible if it explains itself BEFORE the
 *     press, so it is never bare here: the requirement sentence is rendered
 *     the moment the dialog opens (not after a failed click), the reason input
 *     is `aria-describedby` it and takes focus on open, and the dead button
 *     carries the same sentence in its `title`.
 *
 * What a test can query: the requirement text "A reason is required for the
 * audit log." is present from the moment a `requireReason` dialog opens; the
 * confirm button (role button, accessible name = `confirmLabel`) is disabled
 * while the trimmed reason is empty and enabled once anything is typed.
 *
 * The Fleet console has a modal of its own that looks similar and is not: it
 * renders `fleet-modal-*` classes and a different element order. It adopted
 * this idiom on 2026-09-08 — disabled while a required reason is empty, the
 * requirement rendered beside the field and repeated in the button's `title`,
 * focus on the reason input, Tab kept inside — so the two now behave alike and
 * differ only in markup. They are still deliberately NOT shared, so a change to
 * the idiom is two edits: this file and features/fleet/ConfirmModal.tsx.
 */
import { AlertTriangle, X } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

/** The requirement sentence — rendered on open, and the dead button's title. */
const REASON_REQUIRED_TEXT = "A reason is required for the audit log.";
const REASON_HINT_ID = "devices-confirm-reason-hint";

export interface ConfirmOptions {
  title: string;
  message: string;
  confirmLabel: string;
  danger?: boolean;
  requireReason?: boolean;
  reasonPlaceholder?: string;
  defaultReason?: string;
}

export interface ConfirmResult {
  reason: string;
}

export interface ConfirmDialog {
  options: ConfirmOptions | null;
  requestConfirm: (options: ConfirmOptions) => Promise<ConfirmResult | null>;
  closeConfirm: (result: ConfirmResult | null) => void;
}

export function useConfirmDialog(): ConfirmDialog {
  const [confirm, setConfirm] = useState<ConfirmOptions | null>(null);
  const confirmResolverRef = useRef<((result: ConfirmResult | null) => void) | null>(null);

  const requestConfirm = useCallback((options: ConfirmOptions) => {
    return new Promise<ConfirmResult | null>((resolve) => {
      confirmResolverRef.current = resolve;
      setConfirm(options);
    });
  }, []);

  const closeConfirm = useCallback((result: ConfirmResult | null) => {
    confirmResolverRef.current?.(result);
    confirmResolverRef.current = null;
    setConfirm(null);
  }, []);

  return { options: confirm, requestConfirm, closeConfirm };
}

export function ConfirmModal({
  options,
  onClose
}: {
  options: ConfirmOptions | null;
  onClose: (result: ConfirmResult | null) => void;
}) {
  const [reason, setReason] = useState("");
  const dialogRef = useRef<HTMLElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const confirmRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    if (!options) return;
    setReason(options.defaultReason ?? "");
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose(null);
      if (event.key === "Tab") trapFocus(event, dialogRef.current);
      if (event.key === "Enter" && document.activeElement === inputRef.current) {
        event.preventDefault();
        confirmRef.current?.click();
      }
    };
    document.addEventListener("keydown", handleKey);
    window.setTimeout(() => {
      if (options.requireReason) {
        inputRef.current?.focus();
        inputRef.current?.select();
      } else {
        confirmRef.current?.focus();
      }
    }, 0);
    return () => document.removeEventListener("keydown", handleKey);
  }, [onClose, options]);

  if (!options) return null;

  const reasonMissing = Boolean(options.requireReason) && reason.trim() === "";

  const confirm = () => {
    // Unreachable while the button below is disabled — and Enter in the reason
    // box goes through that same button, so a disabled one swallows it too.
    // Kept so that relaxing the disabled rule cannot silently start shipping an
    // empty explanation into a tamper-evident audit row.
    if (reasonMissing) return;
    onClose({ reason: options.requireReason ? reason.trim() : "" });
  };

  return (
    <div
      className="devices-modal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.currentTarget === event.target) onClose(null);
      }}
    >
      <section
        ref={dialogRef}
        className="devices-modal-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="devices-confirm-title"
      >
        <div className="devices-modal-head">
          <div className={`devices-modal-icon${options.danger ? " devices-modal-icon--danger" : ""}`}>
            <AlertTriangle size={18} aria-hidden="true" />
          </div>
          <div>
            <h2 className="devices-modal-title" id="devices-confirm-title">{options.title}</h2>
            <p className="devices-modal-message">{options.message}</p>
          </div>
        </div>
        {options.requireReason ? (
          <div className="devices-modal-body">
            <label className="devices-label">
              Reason
              <input
                ref={inputRef}
                className="devices-input"
                value={reason}
                placeholder={options.reasonPlaceholder ?? "reason"}
                aria-required="true"
                aria-describedby={REASON_HINT_ID}
                onChange={(event) => setReason(event.target.value)}
              />
            </label>
            {/* Stated on open, not after a rejected press: this sentence is
                what makes the disabled confirm button legible, so it must be
                on screen — and in the focused input's accessible description —
                before the operator reaches for it. */}
            <div
              id={REASON_HINT_ID}
              className={`devices-field-req${reasonMissing ? " devices-field-req--unmet" : ""}`}
            >
              {REASON_REQUIRED_TEXT}
            </div>
          </div>
        ) : null}
        <div className="devices-modal-actions">
          <button type="button" className="devices-button" onClick={() => onClose(null)}>
            <X size={15} aria-hidden="true" />
            Cancel
          </button>
          <button
            ref={confirmRef}
            type="button"
            className={`devices-button${options.danger ? " devices-button--danger" : " devices-button--primary"}`}
            disabled={reasonMissing}
            title={reasonMissing ? REASON_REQUIRED_TEXT : undefined}
            onClick={confirm}
          >
            {options.confirmLabel}
          </button>
        </div>
      </section>
    </div>
  );
}

function trapFocus(event: KeyboardEvent, root: HTMLElement | null): void {
  if (!root) return;
  // Disabled controls are excluded deliberately. The confirm button is the last
  // element in the dialog and is disabled while a required reason is empty; a
  // disabled button cannot take focus, so counting it as the wrap point made
  // the trap hand focus to something the browser then skipped — Tab from Cancel
  // walked straight out of the modal to the page behind it.
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
}
