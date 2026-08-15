import React from "react";
import { createRoot } from "react-dom/client";
import { ErrorBoundary } from "../components/ErrorBoundary";
import { registerServiceWorker } from "../lib/pwa";
import "../styles.css";

/**
 * Mounts a route. Every entry goes through here so the ErrorBoundary cannot be
 * forgotten by a new one — previously there was no boundary at all, and a single
 * render throw blanked the whole console.
 */
export function renderApp(node: React.ReactNode, surface?: string) {
  const root = document.getElementById("root");
  if (!root) throw new Error("missing #root");
  createRoot(root).render(
    <React.StrictMode>
      <ErrorBoundary surface={surface}>{node}</ErrorBoundary>
    </React.StrictMode>
  );
  registerServiceWorker();
}
