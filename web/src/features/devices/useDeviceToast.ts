/**
 * The device console's transient status line.
 *
 * The timer is held in a ref and cleared both when a new toast replaces the old
 * one and when the route unmounts — a stray `setTimeout(setToast)` firing after
 * unmount is a React state update on a dead component, and the console is
 * navigated away from mid-action often enough for that to matter.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import type { Dispatch, SetStateAction } from "react";

export type ToastTone = "ok" | "error" | "warn";

export interface ToastState {
  message: string;
  tone: ToastTone;
}

export interface DeviceToast {
  toast: ToastState | null;
  /**
   * Set a toast without arming the auto-dismiss timer. The assurance exports
   * use this; `pushToast` is what the action path wants.
   */
  setToast: Dispatch<SetStateAction<ToastState | null>>;
  pushToast: (message: string, tone: ToastTone) => void;
}

export function useDeviceToast(): DeviceToast {
  const [toast, setToast] = useState<ToastState | null>(null);
  const toastTimerRef = useRef<number | null>(null);

  const pushToast = useCallback((message: string, tone: ToastTone) => {
    setToast({ message, tone });
    if (toastTimerRef.current !== null) {
      window.clearTimeout(toastTimerRef.current);
    }
    toastTimerRef.current = window.setTimeout(() => setToast(null), 4500);
  }, []);

  useEffect(() => {
    return () => {
      if (toastTimerRef.current !== null) window.clearTimeout(toastTimerRef.current);
    };
  }, []);

  return { toast, setToast, pushToast };
}
