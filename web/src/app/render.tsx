import React from "react";
import { createRoot } from "react-dom/client";
import { ErrorBoundary } from "../components/ErrorBoundary";
import { AssistantChatProvider } from "../features/assistant/AssistantChatProvider";
import { registerServiceWorker } from "../lib/pwa";
import { pendingTenantHydration } from "../lib/tenantScope";
import { TenantScopeBanner, type TenantScopeBannerMode } from "./TenantScopeBanner";
import { startTenantScopeHydration } from "./tenantHydration";
import "../styles.css";

export interface RenderAppOptions {
  /**
   * WHO SAYS WHICH CUSTOMER THIS PAGE IS SHOWING, and whether the selection is
   * hydrated at all.
   *
   *   "shell"     — the default, and the default on purpose. The entry has no
   *                 scope caption of its own, so the shell hydrates the
   *                 selection and captions it. A new entry added years from now
   *                 is scoped and captioned before anyone thinks about it;
   *                 THREE entries silently missing both is the defect this
   *                 option exists to make impossible to repeat. /fleet was one
   *                 of the three and is no longer an entry that renders: it
   *                 redirects into the SOC console, which hydrates and captions
   *                 for the fleet surface as it does for every other.
   *   "dashboard" — the SOC route renders its own banner next to the switcher,
   *                 so the shell hydrates but only shows what that banner
   *                 cannot say (see TenantScopeBanner).
   *   "none"      — the page has no scope to hydrate. Login only: nobody is
   *                 signed in, so whoami would answer 401 and the roster is
   *                 not a question an unauthenticated page may ask.
   */
  tenantScope?: TenantScopeBannerMode | "none";
}

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
 *
 * THE CUSTOMER SCOPE IS HYDRATED HERE for exactly that reason too. It used to be
 * hydrated inside the SOC route, so /choke, /devices and the fleet console —
 * the pages that actually fire containment — booted with no selection and sent
 * every read and every containment write to the account's default customer,
 * with no banner on screen. (The fleet console is a surface of the SOC route
 * now and /fleet only redirects to it, so three of those pages are two; the
 * rule and the reason for it are unchanged.)
 *
 * THE ROUTE IS NOT MOUNTED UNTIL THAT SETTLES, and that is not a nicety. The
 * funnel holds a scoped request until hydration settles (lib/api.ts), but the
 * clients that issue those requests put each read under a deadline of their own
 * — features/choke/api.ts gives every read eight seconds — and that deadline
 * starts when the READ IS CALLED, not when it reaches the wire. With the route
 * mounted first, a slow control plane spent the read's entire budget inside the
 * funnel's hold and the route reported "choke gateway unreachable: /api/choke/
 * state did not answer within 8s" — the console blaming the gateway for a
 * request it had never sent. Mounting after the barrier settles means no
 * caller's clock is ever running during the wait: every read starts with its
 * full budget, against the gateway, so a gateway that really is slow still times
 * out and still says so.
 *
 * What the operator looks at meanwhile is the shell banner, which renders
 * immediately and names the customer being confirmed. The wait is bounded by
 * TENANT_HYDRATION_DEADLINE_MS, which is what guarantees the route mounts at all
 * on a hung control plane. A console with nothing to hydrate — every
 * tenant-bound operator, the single-tenant engine, and the login page — opens no
 * barrier, so it mounts in this call with no extra render and no delay.
 */
export function renderApp(node: React.ReactNode, surface?: string, options: RenderAppOptions = {}) {
  const rootEl = document.getElementById("root");
  if (!rootEl) throw new Error("missing #root");
  const scope = options.tenantScope ?? "shell";
  if (scope !== "none") void startTenantScopeHydration();
  // Read back rather than trusted from the return value: startTenantScopeHydration
  // resolves immediately when there is no claim to confirm, and a barrier that
  // was already running (a second entry-level call) is the same hold.
  const held = scope === "none" ? null : pendingTenantHydration();

  const root = createRoot(rootEl);
  const paint = (mounted: boolean) =>
    root.render(
      <React.StrictMode>
        <ErrorBoundary surface={surface}>
          <AssistantChatProvider>
            {scope === "none" ? null : <TenantScopeBanner mode={scope} />}
            {mounted ? node : null}
          </AssistantChatProvider>
        </ErrorBoundary>
      </React.StrictMode>
    );

  paint(held === null);
  if (held) void held.then(() => paint(true));
  registerServiceWorker();
}
