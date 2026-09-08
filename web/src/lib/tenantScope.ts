// WHICH CUSTOMER THIS CONSOLE IS POINTED AT — the choice, and the rule that
// puts it on the wire.
//
// A cross-tenant (provider) principal belongs to no tenant, so the control
// plane resolves every tenant-less request it makes to ONE customer
// (authz.DefaultTenant). The switcher lets the operator point somewhere else,
// and this module is the single place that both HOLDS that choice and puts it
// on the wire — lib/api.ts applies tenantScopedPath to every request it sends,
// and lib/stream.tsx to the SSE URL.
//
// It lives in lib/ rather than in the SOC feature that grew it for two
// reasons. The first is mechanical: lib/api.ts is imported by every feature and
// must not import one back. The second is the defect that put it here — the
// selection was read by the dashboard's own reads and by nothing else, so the
// panels showed customer B while choke, devices, fleet and settings kept
// reading and WRITING customer A, under a banner asserting that everything
// fired from this console landed on B. Read-scoped and write-unscoped in one
// screen is worse than scoping neither, because the operator has been given a
// reason to believe the aim.
//
// WHAT IS *NOT* HERE. The selection is held and applied here, but the boot-time
// decision of WHICH customer to hold — read whoami, read the roster, adopt or
// forget the persisted claim — is driven from src/app/tenantHydration.ts,
// because it has to reuse the SOC feature's roster reader and lib/ may not
// import a feature. This module owns the state and the rule; app/ owns the
// driver and calls it on every entry. What crosses between them is the barrier
// below: while that driver is deciding, this module holds scoped requests back.
import { useSyncExternalStore } from "react";

const TENANT_SELECTION_KEY = "soc.selectedTenant";

/**
 * The selection is MODULE state, not React state, because it is not only a
 * rendering input: requests are issued from handlers, effects and timers that
 * no provider wraps, and the funnel that scopes them is a plain function. One
 * value read by the request builder and by the surfaces that caption the answer
 * is what stops the dashboard and the kill-switch from being aimed at two
 * different customers.
 *
 * `null` means NO SELECTION, which is emphatically NOT "all customers": the
 * request goes out unscoped and the server resolves its own default. No
 * endpoint answers across customers, so the switcher never offers an aggregate.
 */
let selectedTenant: string | null = null;
const scopeListeners = new Set<() => void>();

/** The customer every request from this console currently names, or null. */
export function selectedTenantNow(): string | null {
  return selectedTenant;
}

function subscribeScope(listener: () => void): () => void {
  scopeListeners.add(listener);
  return () => scopeListeners.delete(listener);
}

/** Re-renders the surfaces that caption the selection when it changes. */
export function useSelectedTenant(): string | null {
  return useSyncExternalStore(subscribeScope, selectedTenantNow, selectedTenantNow);
}

/**
 * Point the console at one customer, or (with null) back at the server's own
 * default.
 *
 * Persisted the way the rest of this console persists per-operator state — a
 * JSON value under a "soc." key in localStorage — so an operator who works one
 * customer all shift does not re-pick them on every load. Storage failures are
 * swallowed for the same reason they are in useLocalJsonState: the choice is a
 * convenience, and a browser with storage disabled must still get a console.
 */
export function setSelectedTenant(next: string | null): void {
  const value = next || null;
  // NAMING A CUSTOMER ANSWERS THE QUESTION HYDRATION MAY HAVE FAILED TO ANSWER.
  // scopeUnconfirmed holds writes back while the console cannot say which
  // customer they would reach (see beginTenantHydration); an operator picking a
  // customer — or the roster forgetting an unreachable one — settles it. It is
  // cleared before the no-change early return on purpose: re-picking the
  // customer already selected must lift the hold, or a provider whose roster
  // read failed would have no way back to a working console.
  const wasUnconfirmed = scopeUnconfirmed;
  scopeUnconfirmed = false;
  if (value === selectedTenant) {
    if (wasUnconfirmed) notifyScopeChanged();
    return;
  }
  selectedTenant = value;
  try {
    if (typeof window !== "undefined") {
      if (value) window.localStorage.setItem(TENANT_SELECTION_KEY, JSON.stringify(value));
      else window.localStorage.removeItem(TENANT_SELECTION_KEY);
    }
  } catch {
    // Persistence is convenience; the selection still applies to this session.
  }
  notifyScopeChanged();
}

function persistedTenant(): string | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(TENANT_SELECTION_KEY);
    if (raw == null) return null;
    const parsed = JSON.parse(raw) as unknown;
    return typeof parsed === "string" && parsed ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * The customer this browser LAST pointed at, before anything has confirmed it.
 *
 * A claim, not a selection: nothing is scoped to it until a roster that has
 * just answered still offers it (adoptPersistedTenant). It is exported because
 * two callers outside this module need to know a claim exists before it can be
 * checked — the boot driver, which only asks the server anything when there is
 * one (app/tenantHydration.ts), and the banner, which names the customer whose
 * confirmation failed.
 */
export function persistedTenantClaim(): string | null {
  return persistedTenant();
}

/* ------------------------------------- what the console knows, and when yet */

/**
 * HYDRATION IS ASYNCHRONOUS AND REQUESTS ARE NOT POLITE ENOUGH TO WAIT.
 *
 * Every entry boots its own React tree and starts reading immediately. The
 * selection, meanwhile, cannot be trusted until the server has answered twice
 * — whoami (is this account cross-tenant at all?) and the roster (may it still
 * reach the customer this browser remembers?). In between there is a window in
 * which the console HAS a remembered customer and cannot yet name it, and a
 * request issued in that window goes out tenant-less, which the control plane
 * resolves to the account's default customer (authz.DefaultTenant).
 *
 * That window is not cosmetic. A tenant-less READ fills the page with the
 * default customer's rows under a banner about to name a different one. A
 * tenant-less WRITE is the defect this whole line of work exists to prevent: a
 * sever fired at a host belonging to a customer nobody named.
 *
 * So while the driver is deciding, lib/api.ts holds back exactly the requests
 * that WOULD have carried the selection (tenantScopeApplies) and lets the rest
 * — whoami, the roster, the build, the estate summary — straight through, which
 * is also what stops the barrier from blocking the two reads that lift it.
 *
 * THE SSE TAIL WAITS ON THE SAME BARRIER, from the other side. lib/stream.tsx
 * opens an EventSource rather than going through the funnel, so nothing here
 * can hold it; it asks pendingTenantHydration() itself and defers connect()
 * until this settles. It used to connect straight away, name no customer, and
 * deliver the default customer's frames into a console on its way to another
 * one — healed by the re-open on the selection it then saw, but not for the
 * operator who had already read them.
 *
 * There is no barrier at all until a driver starts one, so a console with no
 * remembered customer (every tenant-bound operator, and the single-tenant
 * engine) waits for nothing and sends exactly what it sent before.
 */
let hydration: Promise<void> | null = null;

/**
 * A remembered customer that could NOT be confirmed — whoami failed, the roster
 * failed, or the pair took longer than the driver's deadline.
 *
 * Reads are let go unscoped once hydration settles: the server's own default is
 * a real, honest scope, the shell banner says the console could not confirm the
 * customer, and a page that renders nothing at all teaches an operator nothing.
 * WRITES ARE REFUSED, because there is no honest version of firing containment
 * at "whichever customer the server picks for me" when this console has been
 * told to point somewhere else and cannot prove it may.
 */
let scopeUnconfirmed = false;

/** whoami's `cross_tenant`; undefined until some whoami has answered. */
let crossTenantAccount: boolean | undefined;
/** whoami's `viewing_tenant`: what the server resolves a tenant-less request to. */
let serverDefaultTenant: string | undefined;

/**
 * The banner needs several of these facts at once, so they are published as ONE
 * frozen object rebuilt only when something changes. useSyncExternalStore compares
 * snapshots by identity: a fresh object per read would re-render forever.
 */
export interface TenantScopeView {
  /** The customer every scoped request now names, or null for the server's default. */
  selected: string | null;
  /** Whether this account reaches customers by naming them. undefined = no whoami yet. */
  crossTenant: boolean | undefined;
  /** What the server resolves a tenant-less request to, when whoami has said. */
  serverTenant: string | undefined;
  /** True while the boot driver is still deciding which customer to point at. */
  hydrating: boolean;
  /** True when a remembered customer could not be confirmed; writes are refused. */
  unconfirmed: boolean;
  /**
   * The customer this browser REMEMBERS, confirmed or not. Read by the banner
   * for the two sentences that are about the claim rather than the selection —
   * "confirming X" while hydration runs, and "could not confirm X" when it
   * failed. Never a scope: only `selected` is on the wire.
   */
  claimed: string | null;
}

let scopeView: TenantScopeView = buildScopeView();

function buildScopeView(): TenantScopeView {
  return Object.freeze({
    selected: selectedTenant,
    crossTenant: crossTenantAccount,
    serverTenant: serverDefaultTenant,
    hydrating: hydration !== null,
    unconfirmed: scopeUnconfirmed,
    claimed: persistedTenant()
  });
}

function notifyScopeChanged(): void {
  scopeView = buildScopeView();
  for (const listener of scopeListeners) listener();
}

function readScopeView(): TenantScopeView {
  return scopeView;
}

/**
 * Everything the shell needs to caption the scope: the customer, who chose it,
 * and whether the console is still working it out.
 */
export function useTenantScope(): TenantScopeView {
  return useSyncExternalStore(subscribeScope, readScopeView, readScopeView);
}

let hydrationHasRun = false;

/**
 * Hold scoped requests until `work` has settled which customer this console is
 * pointed at.
 *
 * `work` resolves TRUE when the question is answered — including "answered no":
 * a tenant-bound account, or a remembered customer the roster no longer offers,
 * both leave the console honestly unscoped. It resolves FALSE (or throws) when
 * the console could not find out, which leaves writes refused until an operator
 * names a customer themselves.
 *
 * Only the first call starts a barrier. A second entry-level call is a no-op
 * rather than a second hold, and the retry path passes `retry` to replace a
 * settled attempt — never to stack another one underneath requests already
 * waiting.
 */
export function beginTenantHydration(work: () => Promise<boolean>, retry = false): Promise<void> {
  if (hydration) return hydration;
  if (!retry && hydrationHasRun) return Promise.resolve();
  hydrationHasRun = true;
  const settle = (confirmed: boolean) => {
    hydration = null;
    scopeUnconfirmed = !confirmed;
    notifyScopeChanged();
  };
  hydration = work().then(
    (confirmed) => settle(confirmed),
    // A thrown driver is a driver that did not answer. Swallowed rather than
    // rethrown: nothing awaits this promise for its value — every waiter is a
    // request that must be released whatever happened — and an unhandled
    // rejection here would be reported as a console fault rather than as the
    // unconfirmed scope it is.
    () => settle(false)
  );
  notifyScopeChanged();
  return hydration;
}

/** The barrier scoped requests wait on, or null when nothing is being decided. */
export function pendingTenantHydration(): Promise<void> | null {
  return hydration;
}

/**
 * Why a write must not leave, or null when it may.
 *
 * Only a request that WOULD have carried the selection is held: a caller that
 * named a tenant on the path has already said which customer it means, and the
 * account-level endpoints are not about a customer at all.
 */
export function tenantScopeRefusal(): string | null {
  if (!scopeUnconfirmed) return null;
  // An explicit selection is an answer, whatever hydration made of the roster.
  if (selectedTenant) return null;
  const claim = persistedTenant();
  return (
    `this console cannot confirm which customer it is pointed at${claim ? ` (it last showed ${claim})` : ""}, ` +
    "so the write was not sent. Pick a customer and try again."
  );
}

/**
 * Whether whoami has said this account reaches customers by naming them —
 * undefined until one has answered.
 *
 * The boot driver asks this instead of re-reading `cross_tenant` off the
 * response it just received, so ONE piece of code decides what that field
 * means. Two readers of the same flag is how a console ends up asking the
 * roster for a tenant-bound operator on one page and not on another.
 */
export function crossTenantAccountNow(): boolean | undefined {
  return crossTenantAccount;
}

/**
 * The scope is known after all — the answer the deadline gave up waiting for
 * arrived.
 *
 * beginTenantHydration bounds the wait so a hung control plane cannot leave the
 * console unable to read anything; when the slow answer does land it settles
 * the question for real, and the writes held back by that deadline are released
 * without the operator having to re-pick a customer they never changed.
 */
export function resolveTenantScope(): void {
  if (!scopeUnconfirmed) return;
  scopeUnconfirmed = false;
  notifyScopeChanged();
}

/**
 * Record what a whoami answer said about SCOPE, wherever in the console it was
 * read.
 *
 * The shell has to caption the customer on /choke, /devices and /fleet, and the
 * only fact that says whether there is anything to caption is whoami's
 * `cross_tenant`. Rather than add a whoami read per entry — which every
 * tenant-bound console in the estate would pay for, on pages that ask for no
 * such thing today — lib/api.ts hands the answers it is already carrying to
 * this. A page that never reads whoami simply never lights the banner.
 *
 * Nothing here grants anything: the selection is still only ever adopted
 * against a roster (adoptPersistedTenant). These two fields caption a screen.
 */
export function noteScopeFromResponse(path: string, body: unknown): void {
  if (basePath(path) !== "/api/whoami") return;
  if (!body || typeof body !== "object") return;
  const record = body as Record<string, unknown>;
  const cross = record.cross_tenant ?? record.crossTenant;
  const viewing = record.viewing_tenant ?? record.viewingTenant;
  const nextCross = typeof cross === "boolean" ? cross : crossTenantAccount;
  // TRIMMED, because every reader of this value RENDERS it as a customer's
  // name. "   " is a truthy string, so an untrimmed store would hand the fleet
  // caption and app/TenantScopeBanner three spaces to print in bold after the
  // word "Tenant" — a caption naming a customer that is not there, on the
  // surfaces whose whole job is saying whose telemetry is on screen. A server
  // answering whitespace is answering nothing, and is treated as such.
  const named = typeof viewing === "string" ? viewing.trim() : "";
  const nextServer = named || serverDefaultTenant;
  if (nextCross === crossTenantAccount && nextServer === serverDefaultTenant) return;
  crossTenantAccount = nextCross;
  serverDefaultTenant = nextServer;
  notifyScopeChanged();
}

/**
 * The evidence a persisted choice is checked against: the roster the server has
 * just answered with.
 *
 * Described structurally, and generically in the row, rather than as the SOC
 * feature's TenantRoster: lib/ must not import a feature, and the row a caller
 * actually holds carries more than an id (display name, agent counts). The
 * generic lets those rows through unchanged — a plain `{ tenantId: string }`
 * would reject the roster literal every caller and test already builds.
 */
export interface TenantSelectionRoster<T extends { tenantId: string } = { tenantId: string }> {
  answered: boolean;
  offered: readonly T[];
}

/**
 * Apply a persisted choice ONLY against a roster that has just answered.
 *
 * A stored tenant is a stale claim about reach: grants are revoked, customers
 * are offboarded, and the same browser profile is used by more than one
 * operator. Applying it unchecked would scope every read and every containment
 * to a customer this account may no longer reach — and because a refused read
 * answers 404, not 403, the console would show an empty dashboard rather than
 * an error, which reads exactly like a quiet customer.
 *
 * So the stored name only becomes a selection when the roster the server has
 * just returned still offers it. When it does not, it is forgotten outright:
 * the console falls back to the server's own default, which is the one scope it
 * knows this account resolves to. A roster that did NOT answer (offline, 404,
 * a transient 500) is no evidence either way — nothing is adopted and nothing
 * is forgotten, so a flaky poll cannot silently drop a working selection.
 */
export function adoptPersistedTenant<T extends { tenantId: string }>(roster: TenantSelectionRoster<T>): void {
  if (!roster.answered) return;
  const stored = persistedTenant();
  if (!stored || stored === selectedTenant) return;
  if (roster.offered.some((entry) => entry.tenantId === stored)) {
    setSelectedTenant(stored);
    return;
  }
  // Not offered any more. Forget it rather than leave it to be adopted by a
  // later roster read that happens to include the name again.
  setSelectedTenant(null);
  try {
    if (typeof window !== "undefined") window.localStorage.removeItem(TENANT_SELECTION_KEY);
  } catch {
    // See setSelectedTenant.
  }
}

/**
 * Endpoints that describe the ACCOUNT, the BUILD or the WHOLE ESTATE rather
 * than one customer's rows. Naming a tenant on these would state a scope the
 * endpoint does not honour, and on the estate summary it would be actively
 * dangerous.
 *
 *   /api/whoami         — the principal: who is asking, what they may do, and
 *                         which customer the server resolves their tenant-less
 *                         requests to. Scoping it would ask the one endpoint
 *                         that reports the server's own default to report the
 *                         console's guess back at it.
 *   /api/version        — the deployment's build. There is no per-customer
 *                         answer to give.
 *   /api/tenants        — the roster of customers this ACCOUNT may reach. It is
 *                         the switcher's own source; scoping it to the current
 *                         selection would narrow the list you switch with to
 *                         the customer you already switched to.
 *   /api/estate/summary — the cross-customer aggregate, and the entry that must
 *                         not be got wrong. It enumerates every customer this
 *                         principal can read (controlplane/estate.go resolves
 *                         reach from the principal and ignores ?tenant=), so a
 *                         tenant here is a scope claim the handler does not
 *                         honour today and would turn one customer's numbers
 *                         into the estate's the day it did.
 *
 * /api/login and /api/logout are account-level too and are deliberately absent:
 * they are reached by a form POST and an anchor, never through the funnel, so
 * listing them would be an entry no request can exercise.
 */
export const UNSCOPED_PATHS = ["/api/whoami", "/api/version", "/api/tenants", "/api/estate/summary"];

/**
 * Name the selected customer on a request, on BOTH planes.
 *
 * The control plane reads `?tenant=` from the query string for reads
 * (authorizeRead) and for writes alike (authorizeRespondAs), so a containment
 * POST is scoped by its URL, not by its body — which is why this is applied to
 * the path rather than merged into a JSON payload that the write handlers never
 * look at. /api/stream goes through authorizeRead like any other read, so the
 * live tail is scoped by exactly the same rule.
 *
 * With no selection the path comes back untouched, so every deployment that has
 * no switcher — the single-tenant engine, and every tenant-bound operator on
 * the control plane — sends exactly the requests it always did, byte for byte.
 *
 * Applied by lib/api.ts as the request goes out rather than by each caller, so
 * the tenant on the wire is the selection AT THAT MOMENT. A path scoped early
 * and sent later would carry the customer the operator had left.
 */
export function tenantScopedPath(path: string): string {
  const tenant = selectedTenant;
  if (!tenant) return path;
  if (!tenantScopeApplies(path)) return path;
  return `${path}${path.includes("?") ? "&" : "?"}tenant=${encodeURIComponent(tenant)}`;
}

/** The path with its query string cut off, for matching against UNSCOPED_PATHS. */
function basePath(path: string): string {
  const query = path.indexOf("?");
  return query === -1 ? path : path.slice(0, query);
}

/**
 * Whether the selection WOULD be named on this path — asked independently of
 * whether there is a selection yet.
 *
 * That independence is the point. lib/api.ts holds a request back while
 * hydration is deciding, and at that moment `selectedTenant` is exactly the
 * thing not yet known: a predicate that answered "no scope applies" because
 * nothing is selected would wave through the very requests the barrier exists
 * to catch, and would deadlock the whoami and roster reads that lift it.
 */
export function tenantScopeApplies(path: string): boolean {
  // This console's own API only. The funnel also carries absolute URLs and
  // non-API paths, and a `tenant` parameter on one of those is a query string
  // the server it reaches has never heard of.
  if (!path.startsWith("/api/")) return false;
  if (UNSCOPED_PATHS.includes(basePath(path))) return false;
  // A caller that already named a tenant keeps it, and needs no barrier: it has
  // said which customer it means. Appending a second `tenant=` would leave the
  // request self-contradictory, with Go's Query().Get answering the first and
  // any reader of the URL the last.
  const query = path.indexOf("?");
  if (query !== -1 && new URLSearchParams(path.slice(query + 1)).has("tenant")) return false;
  return true;
}
