import { useEffect, useState, type ReactNode } from "react";

import { logoutUrl } from "../lib/console";
import { loadSession, type SessionStatus } from "../lib/session";
import { useTenantStore } from "../stores/tenant";
import { TenantSwitcher } from "../components/TenantSwitcher";
import "./ConsoleShell.css";

// ConsoleShell is the console v2 app frame: it bootstraps the OIDC session
// (via the BFF), renders the tenant switcher in the header, and only mounts its
// children once an authenticated identity is present. Each multi-tenant entry
// wraps its route in this shell during the v2 cutover.
export function ConsoleShell({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<"loading" | SessionStatus>("loading");
  const identity = useTenantStore((s) => s.identity);

  useEffect(() => {
    let live = true;
    loadSession().then((s) => {
      if (live) setStatus(s);
    });
    return () => {
      live = false;
    };
  }, []);

  if (status === "loading") {
    return <div className="console-shell__status">Loading…</div>;
  }
  if (status === "redirecting") {
    return <div className="console-shell__status">Redirecting to sign in…</div>;
  }
  if (status === "error" || !identity) {
    return <div className="console-shell__status console-shell__status--error">Unable to load your session.</div>;
  }

  return (
    <div className="console-shell">
      <header className="console-shell__header">
        <span className="console-shell__brand">eBPF-SOC</span>
        <div className="console-shell__actions">
          <TenantSwitcher />
          {/*
            A link, not a fetch: signing out must NAVIGATE so the browser follows
            the BFF's redirect to the IdP's end-session endpoint, which clears the
            SSO cookie. Fetching would end the local session but leave the IdP
            logged in, making the next login silent.
          */}
          <a className="console-shell__signout" href={logoutUrl()}>
            Sign out
          </a>
        </div>
      </header>
      <main className="console-shell__main">{children}</main>
    </div>
  );
}
