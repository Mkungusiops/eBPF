// WHICH CUSTOMER THIS CONSOLE IS POINTED AT, DECIDED ONCE PER PAGE LOAD.
//
// This console is a multi-page app: five HTML entries, five React trees, no
// shared router (see vite.config.ts's rollup input). The customer switcher was
// built inside the SOC dashboard's route, so the selection was only ever
// hydrated there — and a provider who switched customers on the dashboard and
// then walked to /choke, /devices or /fleet got a page whose every read and
// every containment write went out tenant-less, which the control plane
// resolves to the account's DEFAULT customer, with nothing on screen saying so.
// A wrong reading is bad; a sever aimed by that page is the defect this whole
// line of work exists to prevent.
//
// So the decision moved out of the feature and into the shell (app/render.tsx
// calls this before it mounts anything), where every entry gets it, including
// the one added next year by someone who has never read this file.
//
// It lives in app/ rather than beside the store in lib/tenantScope.ts because
// confirming a remembered customer means reading the SOC feature's roster, and
// lib/ must not import a feature — lib/api.ts imports lib/tenantScope.ts, so a
// feature import there would be a cycle through every module in the console.
import { fetchTenantRoster } from "../features/soc/api";
import { getJSON } from "../lib/api";
import {
  adoptPersistedTenant,
  beginTenantHydration,
  crossTenantAccountNow,
  persistedTenantClaim,
  resolveTenantScope
} from "../lib/tenantScope";

/**
 * How long the console will wait to find out which customer it is pointed at.
 *
 * Long enough for whoami and the roster to answer in sequence over a slow link
 * — they cannot be issued in parallel, because asking the roster before whoami
 * has said this account is cross-tenant would put a request on every
 * tenant-bound console in the estate that the control plane can only refuse.
 *
 * IT IS THE PAGE'S DEADLINE, NOT ONLY THE FUNNEL'S. app/render.tsx holds the
 * route unmounted while this runs — that is what stops the wait being spent out
 * of some read's own eight-second budget and reported as a gateway that never
 * answered — so this is also the longest an operator can be looking at the
 * shell's "confirming…" banner with nothing under it, and the reason a hung
 * control plane cannot withhold the page for good.
 *
 * On expiry the route mounts and its reads go out unscoped (the server's own
 * default, captioned as unconfirmed by the shell banner) while writes stay
 * refused, and a late answer still settles the question through
 * resolveTenantScope.
 */
export const TENANT_HYDRATION_DEADLINE_MS = 8000;

/**
 * Confirm the customer this browser remembers, holding scoped requests until it
 * is settled.
 *
 * NOTHING HAPPENS FOR A TENANT-BOUND OPERATOR, and that is a requirement rather
 * than an optimisation. With no remembered customer there is no claim to check:
 * asking whoami would add a request to every page of every single-tenant
 * console in the estate, asking the roster would add one the control plane
 * refuses by design, and no barrier is started, so the requests that follow are
 * byte-for-byte the ones this console sent before any of this existed. Only a
 * console that has been pointed at a customer pays for pointing at one.
 *
 * The one thing a remembered name may NOT do is scope a request on its own: it
 * is a stale claim about reach (grants are revoked, customers are offboarded,
 * browser profiles are shared), and scoping to a customer this account can no
 * longer read answers 404, which the console renders as an empty dashboard —
 * indistinguishable from a quiet customer. See adoptPersistedTenant.
 */
export function startTenantScopeHydration(options: { retry?: boolean } = {}): Promise<void> {
  if (!persistedTenantClaim()) return Promise.resolve();
  return beginTenantHydration(() => confirmRememberedCustomer(), options.retry === true);
}

/**
 * True when the question is ANSWERED — including answered "no". A tenant-bound
 * account, or a remembered customer the roster no longer offers, both leave the
 * console honestly pointed at the server's own default. False means the console
 * could not find out, which is the only state in which a write is refused.
 */
async function confirmRememberedCustomer(): Promise<boolean> {
  const decided = confirmAgainstServer();
  // The late answer still counts: adoptPersistedTenant runs inside the promise
  // whatever the deadline did, and this releases the writes the deadline held.
  void decided.then(
    (confirmed) => {
      if (confirmed) resolveTenantScope();
    },
    () => undefined
  );
  return Promise.race([
    decided,
    new Promise<boolean>((resolve) => {
      setTimeout(() => resolve(false), TENANT_HYDRATION_DEADLINE_MS);
    })
  ]);
}

async function confirmAgainstServer(): Promise<boolean> {
  // redirectOn401 is off because this is a scope probe, not the session's
  // keeper: an expired cookie is answered identically by the page's own reads,
  // which are released the moment this settles and bounce to /login themselves.
  // Bouncing from here would make a boot probe responsible for navigation and
  // would race the entry's first render to do it.
  const who = await getJSON<unknown>("/api/whoami", { redirectOn401: false }).catch(() => null);
  if (who === null) return false;
  // What `cross_tenant` means is decided in one place, by the funnel that has
  // just recorded this answer (noteScopeFromResponse).
  if (crossTenantAccountNow() !== true) return true;
  const roster = await fetchTenantRoster();
  // A roster that did not answer is no evidence either way — adoptPersistedTenant
  // would neither adopt nor forget, so the remembered customer is still
  // unconfirmed and this must not report otherwise.
  if (!roster.answered) return false;
  adoptPersistedTenant(roster);
  return true;
}
