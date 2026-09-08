/**
 * WHOSE FLEET IS THIS? — asked and answered ON THE SURFACE, because nothing
 * behind it is visible while the surface is up.
 *
 * The fleet view is a full-screen surface inside the SOC console now, and the
 * move deleted the topbar that carried this caption on the assumption that the
 * shell would go on saying it. It does not, and could not: the surface's
 * backdrop (.soc-modal-back.is-fullscreen) is a fixed, opaque, viewport-filling
 * layer, so the SOC route's own in-flow scope banner is COVERED, and the shell
 * banner renderApp mounts is TenantScopeBanner in "dashboard" mode, which
 * renders nothing at all unless the scope is unconfirmed. The result was the
 * exact defect the caption was written to prevent, one layer up: an MSSP
 * operator pointed at customer B opened this surface, read customer B's hosts,
 * and armed an estate-wide kill-switch with no customer named anywhere on
 * screen. A full-screen page captions itself.
 *
 * ONE SOURCE, THE SHELL'S. Which customer is named here is NOT this surface's
 * own answer — it is lib/tenantScope's, the same store the shell banner and
 * lib/api.ts read, so the caption cannot disagree with what is on the wire. The
 * deleted topbar's caption was built from whoami's `viewing_tenant` instead,
 * which is what the control plane resolves a TENANT-LESS request to; whoami is
 * unscoped by design (UNSCOPED_PATHS), so that field keeps reporting the
 * account's default customer however the console is pointed. The words are the
 * shell banner's too (app/TenantScopeBanner.tsx), compressed to one line,
 * rather than a second vocabulary for the same states.
 *
 * WHY THIS IS NOT app/TenantScopeBanner ITSELF: that component is silent for a
 * tenant-bound operator and for the single-tenant engine — correctly, on the
 * SOC route, where the rest of the chrome names the deployment. This surface is
 * the whole screen, so the two states it is silent about still need a line: an
 * operator on the control plane sees the customer whose hosts these are, and an
 * operator on the single-tenant engine sees the product label rather than an
 * invented tenant. Those two are the reason this is a component of its own and
 * not a `<TenantScopeBanner mode="shell" />` mounted here.
 */
import { Server } from "lucide-react";

import { useTenantScope } from "../../lib/tenantScope";

export function FleetScopeCaption() {
  const scope = useTenantScope();

  // A SELECTION IS A PROVIDER'S ANSWER, and it is also the evidence that this
  // is a provider account: only a cross-tenant principal is offered the
  // switcher, and lib/api.ts is naming this customer on every fleet read and
  // every fleet write at the moment it is set. `scope.crossTenant` is undefined
  // until some whoami has answered, so it is not required to light this branch
  // — waiting for it would caption the page with the server's default customer
  // while the rows below are the selected one's.
  const selected = scope.selected;

  // Still deciding, and the reads are HELD while it decides (the hydration
  // barrier in lib/tenantScope.ts). Naming the server's default here would
  // caption the page with a customer whose rows are not being fetched and are
  // about to be replaced by another's. Say what is actually happening instead.
  const confirming = !selected && scope.hydrating ? scope.claimed : null;

  // THE STATE WHERE EVERY WRITE FROM THIS SURFACE IS REFUSED. `unconfirmed`
  // means the boot driver finished and could NOT settle which customer this
  // console is pointed at — a remembered customer the roster no longer offers,
  // or a roster that never answered. lib/api.ts refuses every unsafe request in
  // that state (tenantScopeRefusal), so this surface's presets, thresholds,
  // kill-switch and thaw all fail closed. The caption has to name the state the
  // operator is actually in, or it contradicts the rail beside it.
  const unconfirmed = !selected && !confirming && scope.unconfirmed;

  // Trimmed at BOTH ends of the pipe, deliberately. lib/tenantScope's
  // noteScopeFromResponse now trims whoami's `viewing_tenant` before it stores
  // it, so a server answering "   " never reaches a reader — that is the fix,
  // and it protects every reader rather than this one. This second trim is kept
  // because a caption naming a customer is the last thing an operator reads
  // before firing containment from this surface, and it costs one call to be
  // certain rather than dependent on a store two modules away. The old reader
  // (readWhoami, deleted with the topbar) trimmed too.
  const serverTenant = (scope.serverTenant ?? "").trim();

  // Named from what the server said, for the account that has selected nobody.
  // A cross-tenant account with no `viewing_tenant` is a control plane that did
  // not resolve the scope, and saying so is more honest than naming a customer
  // the surface guessed at.
  const serverLine = serverTenant
    ? scope.crossTenant === true
      ? `Provider view · no customer chosen, so this page shows ${serverTenant} only — the customer your account resolves to`
      : `Tenant ${serverTenant}`
    : scope.crossTenant === true
      ? "Provider view · this server has not named the customer these hosts belong to"
      : "";

  const line = selected
    ? `Provider view · showing ${selected} only`
    : confirming
      ? `Provider view · confirming that your account still reaches ${confirming}…`
      : unconfirmed
        ? `Customer unconfirmed · ${
            scope.claimed
              ? `this console last showed ${scope.claimed} and could not confirm your account still reaches it, so writes`
              : "this console cannot say which customer it is pointed at, so writes"
          } from this page are refused until a customer is chosen`
        : serverLine;

  // The tooltip is a claim about the wire, so it is offered only when a
  // customer is actually named and the requests carry it — not while hydration
  // is still working out which one that is, and not while the scope is
  // unconfirmed, where the writes are not going anywhere at all.
  const namesCustomer = Boolean(selected) || (!confirming && !unconfirmed && Boolean(serverTenant));

  return (
    <div
      className="fleet-scope-caption"
      role="status"
      title={namesCustomer ? "Every host below, and every write from this page, belongs to this customer" : undefined}
    >
      <Server size={14} aria-hidden="true" />
      <span>{line || "eBPF Threat Gateway · Tier 1"}</span>
    </div>
  );
}
