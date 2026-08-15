// Low-level React plumbing shared by the Choke Gateway surfaces.
//
// These are deliberately Choke-local copies rather than imports from
// features/common: the gateway is the surface that fires SIGKILL, and its
// polling/persistence primitives are pinned here so a refactor in a sibling
// feature cannot silently change how often this page re-reads containment
// state. Cross-feature deduplication is a separate exercise.
import { useCallback, useEffect, useRef, useState } from "react";
import { useOSTheme } from "../../lib/theme";
import { readJsonStorage, writeJsonStorage } from "./utils";

// Interval whose callback is read through a ref, so a poll never has to be
// torn down and re-established just because the closure it runs changed.
export function useInterval(callback: () => void, delayMs: number | null, enabled = true): void {
  const ref = useRef(callback);
  useEffect(() => {
    ref.current = callback;
  }, [callback]);
  useEffect(() => {
    if (!enabled || delayMs == null) return;
    const id = window.setInterval(() => ref.current(), delayMs);
    return () => window.clearInterval(id);
  }, [delayMs, enabled]);
}

// Acknowledgement sets survive a reload but are capped on write: an operator
// who leaves the tape running for a week must not push an unbounded array into
// localStorage and lose the whole key to a quota failure.
export function useStoredSet(key: string): [Set<number>, (next: Set<number>) => void] {
  const [value, setValue] = useState<Set<number>>(() => new Set(readJsonStorage<number[]>(key, [])));
  const setStored = useCallback(
    (next: Set<number>) => {
      setValue(new Set(next));
      writeJsonStorage(key, Array.from(next).slice(-5000));
    },
    [key],
  );
  return [value, setStored];
}

export function useStoredBoolean(key: string, fallback: boolean): [boolean, (next: boolean | ((prev: boolean) => boolean)) => void] {
  const [value, setValue] = useState<boolean>(() => Boolean(readJsonStorage<boolean>(key, fallback)));
  const setStored = useCallback(
    (next: boolean | ((prev: boolean) => boolean)) => {
      setValue((prev) => {
        const resolved = typeof next === "function" ? (next as (current: boolean) => boolean)(prev) : next;
        writeJsonStorage(key, resolved);
        return resolved;
      });
    },
    [key],
  );
  return [value, setStored];
}

// Choke's stylesheet keys off its own "choke-theme-light" class, so on top of
// the shared OS theme (which sets .theme-light/.theme-dark + the favicon) this
// mirrors the state onto Choke's class.
export function useChokeTheme(): "dark" | "light" {
  const theme = useOSTheme();
  useEffect(() => {
    const light = theme === "light";
    document.documentElement.classList.toggle("choke-theme-light", light);
    document.body.classList.toggle("choke-theme-light", light);
  }, [theme]);
  return theme;
}
