/**
 * Fan-out results, stacked.
 *
 * A fleet write can succeed on four hosts and fail on the fifth, so toasts here
 * queue rather than replace: losing the failure notice behind the next success
 * would hide the only place a partial fan-out is reported.
 */
import { X } from "lucide-react";
import { useCallback, useRef, useState, useEffect } from "react";

import type { ToastMessage } from "./types";

export interface FleetToasts {
  toasts: ToastMessage[];
  pushToast: (kind: ToastMessage["kind"], title: string, body?: string) => void;
  dismissToast: (id: number) => void;
}

export function useFleetToasts(): FleetToasts {
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const toastId = useRef(0);
  // Every auto-dismiss timer, so unmount can cancel them.
  //
  // Without this, a toast fired just before the operator leaves the Fleet route
  // keeps a timer alive that calls setToasts on an unmounted component. React
  // logs a warning and the timer holds the closure — harmless individually,
  // and the kind of leak that only shows up on a console left open for a shift.
  const timers = useRef<number[]>([]);

  useEffect(() => {
    return () => {
      timers.current.forEach((t) => window.clearTimeout(t));
      timers.current = [];
    };
  }, []);

  const pushToast = useCallback((kind: ToastMessage["kind"], title: string, body?: string) => {
    const id = ++toastId.current;
    setToasts((current) => [...current, { id, kind, title, body }]);
    const timer = window.setTimeout(() => {
      setToasts((current) => current.filter((toast) => toast.id !== id));
      timers.current = timers.current.filter((t) => t !== timer);
    }, 6500);
    timers.current.push(timer);
  }, []);

  const dismissToast = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  return { toasts, pushToast, dismissToast };
}

export function ToastContainer({
  toasts,
  onDismiss
}: {
  toasts: ToastMessage[];
  onDismiss: (id: number) => void;
}) {
  return (
    <div className="fleet-toasts" aria-live="polite">
      {toasts.map((toast) => (
        <div className={`fleet-toast fleet-toast--${toast.kind}`} key={toast.id}>
          <span className={`fleet-dot fleet-dot--${toast.kind === "ok" ? "ok" : toast.kind === "err" ? "err" : "warn"}`} />
          <div>
            <strong>{toast.title}</strong>
            {toast.body ? <p>{toast.body}</p> : null}
          </div>
          <button aria-label="Dismiss toast" type="button" onClick={() => onDismiss(toast.id)}>
            <X size={14} />
          </button>
        </div>
      ))}
    </div>
  );
}
