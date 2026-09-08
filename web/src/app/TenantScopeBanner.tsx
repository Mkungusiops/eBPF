// WHICH CUSTOMER THIS PAGE IS SHOWING — said on every entry, not just the one
// that grew the switcher.
//
// The dashboard has said this since the switcher shipped (SocRoute's
// .soc-scope-banner). /choke, /devices and /fleet are separate entries with
// separate React trees and said nothing, so a provider pointed at customer B
// reached the containment ladder, the device jails and the fleet kill switch
// with no caption at all — and, before the funnel and the hydration this
// component is mounted alongside, those pages were still aimed at the account's
// default customer while the dashboard's banner promised otherwise.
//
// It renders for a cross-tenant principal and for nobody else. A tenant-bound
// operator has one customer, has never selected one, and never reads a whoami
// that says otherwise, so this returns null and their page is unchanged.
import { AlertTriangle, Server } from "lucide-react";
import { useTenantScope } from "../lib/tenantScope";
import { startTenantScopeHydration } from "./tenantHydration";
import "./tenantScopeBanner.css";

/**
 * "shell" — the entry has no scope caption of its own (choke, devices, fleet).
 * "dashboard" — the SOC route renders its own banner beside the switcher, so
 * only the state that banner cannot describe is shown here: a remembered
 * customer this console could not confirm, which is holding writes back.
 */
export type TenantScopeBannerMode = "shell" | "dashboard";

export function TenantScopeBanner({ mode }: { mode: TenantScopeBannerMode }) {
  const scope = useTenantScope();

  // THE HOLD, stated wherever the operator is. Containment is being refused by
  // the funnel (tenantScopeRefusal), and a refusal an operator cannot see reads
  // as a broken console. Shown on the dashboard too, because its own banner
  // names a customer and cannot say that writes are not reaching one.
  if (scope.unconfirmed) {
    return (
      <div className="console-scope-banner console-scope-banner--unconfirmed" role="alert">
        <AlertTriangle size={16} />
        <span>
          <b>Customer unconfirmed.</b>{" "}
          {scope.claimed ? (
            <>
              This console last showed <b>{scope.claimed}</b>, and could not confirm your account still reaches
              it.
            </>
          ) : (
            <>This console could not confirm which customer it is pointed at.</>
          )}{" "}
          Reads below are the customer your account resolves to by default. Containment is being refused until a
          customer is chosen.
        </span>
        <button type="button" onClick={() => void startTenantScopeHydration({ retry: true })}>
          Retry
        </button>
      </div>
    );
  }

  if (mode === "dashboard") return null;

  // Still deciding, and at this moment this banner is the ENTIRE page: the shell
  // does not mount the route until the barrier settles (app/render.tsx), so that
  // the wait is not spent out of some read's own deadline and reported as a
  // gateway that never answered. Naming the customer being confirmed is what
  // keeps that empty page from reading as a broken console.
  if (scope.hydrating) {
    return (
      <div className="console-scope-banner" role="status">
        <Server size={16} />
        <span>
          Confirming that your account still reaches{" "}
          {scope.claimed ? <b>{scope.claimed}</b> : <>the customer this console last showed</>}…
        </span>
      </div>
    );
  }

  // A customer the operator picked. This is the sentence the blocker was about:
  // it is true because lib/api.ts names this customer on every read AND every
  // write that leaves this page, not because the page happens to be showing it.
  if (scope.selected) {
    return (
      <div className="console-scope-banner" role="status">
        <Server size={16} />
        <span>
          <b>Provider view.</b> Showing <b>{scope.selected}</b> only — not your whole book of business — and any
          containment fired from this page lands there.
        </span>
      </div>
    );
  }

  // A provider who has not picked anyone. Nothing is wrong, but "the customer
  // your account defaults to" is still ONE customer, and the numbers on these
  // pages are not the estate's. `crossTenant` is undefined until some whoami
  // has answered, and only an explicit true says a customer had to be resolved.
  if (scope.crossTenant === true) {
    return (
      <div className="console-scope-banner" role="status">
        <Server size={16} />
        <span>
          <b>Provider view.</b> No customer chosen, so this page shows the one your account resolves to
          {scope.serverTenant ? (
            <>
              {" — "}
              <b>{scope.serverTenant}</b>
            </>
          ) : null}
          , and any containment fired here lands there. Pick a customer on the dashboard to point it elsewhere.
        </span>
      </div>
    );
  }

  return null;
}
