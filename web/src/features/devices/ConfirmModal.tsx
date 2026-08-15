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
 * The Fleet console has a modal of its own that looks similar and is not: it
 * renders `fleet-modal-*` classes, a different element order and a different
 * focus contract. The two are deliberately NOT shared.
 */
import { AlertTriangle, X } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

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
  const [showReasonError, setShowReasonError] = useState(false);
  const dialogRef = useRef<HTMLElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const confirmRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    if (!options) return;
    setReason(options.defaultReason ?? "");
    setShowReasonError(false);
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

  const confirm = () => {
    if (options.requireReason && reason.trim() === "") {
      setShowReasonError(true);
      inputRef.current?.focus();
      return;
    }
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
                onChange={(event) => {
                  setReason(event.target.value);
                  setShowReasonError(false);
                }}
              />
            </label>
            {showReasonError ? (
              <div className="devices-field-error">A reason is required for the audit log.</div>
            ) : null}
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
  const focusable = root.querySelectorAll<HTMLElement>(
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
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
