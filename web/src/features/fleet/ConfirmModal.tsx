/**
 * The fleet console's confirmation gate.
 *
 * It stands in front of writes that fan out across the whole estate — the
 * containment and maintenance presets, the kill-switch, the thaw — and collects
 * the audit reason the engine will record alongside them. `reasonRequired` is
 * what stops an estate-wide containment landing in the audit log with no
 * explanation of who ordered it or why.
 *
 * The device console has its own modal. It looks similar and is not the same
 * component: different class namespace (`fleet-modal*` vs `devices-modal*`),
 * different element order, and a different focus contract — this one focuses
 * the confirm button, the device one focuses the reason field and traps Tab.
 * They are deliberately NOT shared.
 */
import { AlertTriangle, ChevronRight } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import type { ConfirmState } from "./types";

export function ConfirmModal({ state, onClose }: { state: ConfirmState; onClose: () => void }) {
  const [reason, setReason] = useState(state.defaultReason ?? "");
  const [error, setError] = useState("");
  const confirmRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    confirmRef.current?.focus();
  }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const confirm = async () => {
    if (state.reasonRequired && reason.trim() === "") {
      setError("A reason is required for the audit log.");
      return;
    }
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
      <section className="fleet-modal" role="dialog" aria-modal="true" aria-labelledby="fleet-confirm-title">
        <div className={`fleet-modal__icon fleet-modal__icon--${state.tone === "danger" ? "danger" : "default"}`}>
          {state.tone === "danger" ? <AlertTriangle size={20} /> : <ChevronRight size={20} />}
        </div>
        <div className="fleet-modal__body">
          <h2 id="fleet-confirm-title">{state.title}</h2>
          <p>{state.body}</p>
          {state.reasonLabel ? (
            <label className="fleet-modal__reason">
              <span>{state.reasonLabel}</span>
              <input value={reason} onChange={(event) => setReason(event.target.value)} />
            </label>
          ) : null}
          {error ? <div className="fleet-modal__error">{error}</div> : null}
          <div className="fleet-modal__actions">
            <button className="fleet-btn" type="button" onClick={onClose}>
              Cancel
            </button>
            <button
              className={`fleet-btn ${state.tone === "danger" ? "fleet-btn--danger" : "fleet-btn--primary"}`}
              ref={confirmRef}
              type="button"
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
