import React from "react";
import { createRoot } from "react-dom/client";
import { ErrorBoundary } from "../components/ErrorBoundary";
import { AssistantChatProvider } from "../features/assistant/AssistantChatProvider";
import { registerServiceWorker } from "../lib/pwa";
import "../styles.css";

/**
 * Mounts a route. Every entry goes through here so the ErrorBoundary cannot be
 * forgotten by a new one — previously there was no boundary at all, and a single
 * render throw blanked the whole console.
 *
 * The assistant provider is mounted here for the same reason: this console is a
 * multi-page app with no shared router, so the shell is the only place a drill
 * panel on ANY page can hand a conversation over to the sidebar. It sits INSIDE
 * the boundary, so a fault in the assistant is caught like any other rather than
 * taking the page with it.
 */
export function renderApp(node: React.ReactNode, surface?: string) {
  const root = document.getElementById("root");
  if (!root) throw new Error("missing #root");
  createRoot(root).render(
    <React.StrictMode>
      <ErrorBoundary surface={surface}>
        <AssistantChatProvider>{node}</AssistantChatProvider>
      </ErrorBoundary>
    </React.StrictMode>
  );
  registerServiceWorker();
}
