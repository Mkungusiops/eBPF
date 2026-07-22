// Theme is derived from the operating system, and only from the operating
// system. There is no in-app toggle and no stored preference: the console
// follows `prefers-color-scheme` and re-renders live when the OS flips.
//
// This module is the single source of truth. Every console page (SOC, Choke,
// Devices, Fleet, Login) previously kept its own copy of the resolution logic
// plus its own hard-coded "dark" default, which meant they could disagree with
// each other. They all call useOSTheme() now.

import { useEffect, useState } from "react";

export type Theme = "dark" | "light";

const DARK_QUERY = "(prefers-color-scheme: dark)";

// jsdom (and very old browsers) have no matchMedia. Fall back to dark rather
// than throwing — dark is the platform's house style, so it is the safe default.
function darkMediaQuery(): MediaQueryList | null {
  return typeof window !== "undefined" && typeof window.matchMedia === "function"
    ? window.matchMedia(DARK_QUERY)
    : null;
}

/** The OS colour scheme right now. */
export function osTheme(): Theme {
  return darkMediaQuery()?.matches === false ? "light" : "dark";
}

/**
 * Push a theme onto the document: the CSS custom properties in styles.css are
 * keyed off .theme-dark / .theme-light, and the favicon has a light variant so
 * the tab icon stays legible on a light chrome.
 */
export function applyTheme(theme: Theme): void {
  const light = theme === "light";
  for (const el of [document.documentElement, document.body]) {
    el?.classList.toggle("theme-light", light);
    el?.classList.toggle("theme-dark", !light);
  }
  const favicon = document.getElementById("appFavicon") as HTMLLinkElement | null;
  if (favicon) favicon.href = light ? "/favicon-light.svg" : "/favicon.svg";
}

/**
 * Subscribe to OS colour-scheme changes. Returns an unsubscribe function.
 * Exported for the non-React entry points that need to react before mount.
 */
export function onOSThemeChange(cb: (theme: Theme) => void): () => void {
  const mq = darkMediaQuery();
  if (!mq) return () => {};
  const handler = (event: MediaQueryListEvent) => cb(event.matches ? "dark" : "light");
  mq.addEventListener("change", handler);
  return () => mq.removeEventListener("change", handler);
}

/**
 * Apply the OS theme immediately. Call this from an entry point before React
 * mounts so the first paint is already the right colour (no flash of dark on a
 * light desktop).
 */
export function initTheme(): Theme {
  const theme = osTheme();
  applyTheme(theme);
  return theme;
}

/**
 * The console's only theme hook: reports the OS colour scheme, keeps the
 * document classes in sync, and re-renders when the user changes their OS
 * appearance while the page is open. Read-only by design — there is no setter,
 * because the OS is the sole authority.
 */
export function useOSTheme(): Theme {
  const [theme, setTheme] = useState<Theme>(() => osTheme());

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  useEffect(() => onOSThemeChange(setTheme), []);

  return theme;
}
