import { ApiError, api as sharedApi, copyToClipboard, getJSON, postJSON, putJSON, readCookie } from "../../lib/api";
import { pendingTenantHydration, tenantScopeApplies, tenantScopedPath } from "../../lib/tenantScope";
import type {
  Alert,
  BucketEntry,
  CgroupMap,
  ChokeAction,
  ChokeState,
  CircuitEntry,
  Decision,
  ProcessDetailPayload,
  SysProcDetail,
  SysProcEntry,
  Thresholds,
  Whoami,
} from "./types";

export { ApiError as ChokeApiError, copyToClipboard };

export function isDisabledError(error: unknown): error is ApiError {
  return error instanceof ApiError && error.status === 503;
}

/**
 * How long ONE read may stay open before this client stops waiting on it.
 *
 * Nothing here had a deadline, and the browser gives none worth relying on: a
 * half-open connection through a load balancer — the shape of control-plane
 * outage this estate has actually seen — leaves a fetch pending indefinitely.
 * `useChokeData.refreshAll` awaits these reads and clears `refreshing` in its
 * finally, so ONE hung read left the Refresh button spinning and DISABLED (see
 * sections.tsx) for the rest of the session, and a page reload was the
 * operator's only way back. A bounded read turns silence into a failure the
 * route can report and retry from.
 */
export const CHOKE_READ_TIMEOUT_MS = 8000;

/**
 * A longer deadline for the two reads that legitimately take a while: the audit
 * chain is verified row by row and a forensic snapshot is built on demand. The
 * point of a deadline is to end silence, not to fail slow-but-working work — an
 * eight-second cap here would report a healthy engine as unreachable.
 */
export const CHOKE_SLOW_READ_TIMEOUT_MS = 30000;

/**
 * What every read accepts: the caller's AbortSignal — the route cancels its
 * reads on unmount the way the fleet and device clients do — and a per-call
 * deadline. `timeoutMs: 0` waives the deadline for a caller that imposes its
 * own.
 */
export interface ChokeReadOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
}

/**
 * A read that ran past its deadline without ever answering.
 *
 * Kept distinct from every other failure on purpose: a 503 means the gateway
 * ANSWERED and said it is not enabled, which is what the disabled banner
 * reports. Silence is not that answer, and reporting it as one would tell the
 * operator a reachable gateway had been switched off. The message is written to
 * be read on screen — useChokeData surfaces it verbatim in the route banner.
 */
/**
 * The word every unreachable-gateway message opens with.
 *
 * Exported because it is a CONTRACT and not prose: useChokePosture reads it
 * back off the route's load state to decide whether the header host pill may
 * still claim "ok" before the first probe has landed. Rewording the sentence
 * without this constant would silently return that pill to a confident green.
 */
export const CHOKE_UNREACHABLE = "choke gateway unreachable";

export class ChokeTimeoutError extends Error {
  readonly path: string;
  readonly timeoutMs: number;

  constructor(path: string, timeoutMs: number) {
    super(`${CHOKE_UNREACHABLE}: ${path} did not answer within ${Math.round(timeoutMs / 100) / 10}s`);
    this.name = "ChokeTimeoutError";
    this.path = path;
    this.timeoutMs = timeoutMs;
  }
}

export function isTimeoutError(error: unknown): error is ChokeTimeoutError {
  return error instanceof ChokeTimeoutError;
}

/**
 * A read the CALLER cancelled — a route unmount, or a refresh superseded by a
 * newer one. Checked at every catch site: an aborted fetch rejects like any
 * other failure, so an unchecked catch renders a teardown as a gateway error in
 * the operator's face.
 */
export function isAbortError(error: unknown): boolean {
  if (typeof DOMException !== "undefined" && error instanceof DOMException) return error.name === "AbortError";
  return error instanceof Error && error.name === "AbortError";
}

/**
 * Run one read under a deadline, cancelling the request when it expires.
 *
 * The deadline is a RACE as well as an abort, because the abort alone is not
 * enough: aborting only rejects the promise if the transport honours the
 * signal, and the failure being defended against is precisely a connection that
 * is not behaving. The race guarantees the caller's await ends either way; the
 * abort stops a socket being held open behind it.
 *
 * The caller's own signal is relayed rather than raced, so a caller abort still
 * surfaces as an AbortError and not as a fabricated timeout.
 */
async function readWithDeadline<T>(
  path: string,
  options: ChokeReadOptions,
  run: (signal: AbortSignal | undefined) => Promise<T>,
  defaultTimeoutMs: number = CHOKE_READ_TIMEOUT_MS,
): Promise<T> {
  const timeoutMs = options.timeoutMs ?? defaultTimeoutMs;
  const caller = options.signal;
  if (!(timeoutMs > 0)) return run(caller);
  const controller = new AbortController();
  if (caller?.aborted) controller.abort();
  const relay = () => controller.abort();
  caller?.addEventListener("abort", relay);
  let deadline: number | null = null;
  const request = run(controller.signal);
  // Once the deadline wins the race nothing awaits this promise, and the abort
  // above rejects it. An unclaimed rejection would surface as an unhandled one.
  request.catch(() => {});
  try {
    return await Promise.race([
      request,
      new Promise<never>((_, reject) => {
        deadline = window.setTimeout(() => {
          controller.abort();
          reject(new ChokeTimeoutError(path, timeoutMs));
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (deadline !== null) window.clearTimeout(deadline);
    caller?.removeEventListener("abort", relay);
  }
}

function readJSON<T>(path: string, options: ChokeReadOptions = {}, defaultTimeoutMs?: number): Promise<T> {
  return readWithDeadline<T>(path, options, (signal) => getJSON<T>(path, { signal }), defaultTimeoutMs);
}

/**
 * A request whose ANSWER IS A FILE, not JSON — the forensic snapshot download.
 *
 * It cannot go through lib/api's `api()`, which parses every response body into
 * JSON or text; a blob has to come off the Response itself. So this repeats the
 * funnel's mechanics (same-origin credentials, no-store on GETs, the CSRF
 * header on unsafe methods, the 401 login bounce) — and, critically, the funnel
 * SCOPING: `tenantScopedPath` names the selected customer on the URL exactly as
 * lib/api.ts does.
 *
 * WHAT THE SCOPING HERE IS AND IS NOT DOING, stated precisely because an
 * earlier version of this comment overstated it. NO SERVER IN THIS TREE CAN
 * CURRENTLY LEAK ANOTHER CUSTOMER'S SNAPSHOT THROUGH THIS PATH: the control
 * plane answers /api/choke/forensic-snapshot with an honest 501 stub
 * (controlplane/choke.go registers handleChokeWriteStub for it), and the
 * single-tenant engine — the only one that builds a snapshot — has exactly one
 * tenant, so there is no other customer for a tenant-less request to resolve
 * to. The scoping is therefore DEFENSIVE, not a fix for a live egress.
 *
 * It is still worth having, and the reason is the direction of travel: the
 * moment the control plane implements this endpoint it inherits authz's
 * tenant-less default like every other read, and an evidence file is the worst
 * place to discover that. A wrong reading on screen is corrected by the next
 * glance at the banner; a file has already left the building and carries no
 * banner with it — this estate shipped that shape once, as a PDF headed "all
 * tenants" over one customer's rows. Anything added here that fetches must keep
 * going through tenantScopedPath, and through the BARRIER below.
 */
async function apiBlob(path: string, init: RequestInit = {}): Promise<Blob> {
  const headers = new Headers(init.headers);
  const method = init.method || "GET";
  if (!["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase()) && path.startsWith("/api/")) {
    const csrf = readCookie("csrf_token");
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  // WAIT FOR THE SELECTION THE WAY THE FUNNEL DOES. It takes two round trips
  // (whoami, then the roster) to become trustworthy and the snapshot button is
  // live before they land, so a request sent inside that window names no
  // customer. Same standing as the scoping above: defensive today, because the
  // only server that builds a snapshot serves one tenant. It is here so this
  // helper cannot drift from the funnel it deliberately mirrors — a GET added
  // beside it later would otherwise inherit the gap. Only a path that would have carried the
  // selection waits, decided by the same predicate lib/api.ts uses, so the
  // single-tenant engine and every tenant-bound operator wait for nothing.
  //
  // The funnel additionally REFUSES unsafe methods when hydration settled
  // without confirming the customer (tenantScopeRefusal). There is no
  // counterpart here because every request through this helper is a GET; a
  // write added here must copy that refusal as well.
  if (tenantScopeApplies(path)) {
    const hydrating = pendingTenantHydration();
    if (hydrating) await hydrating;
  }
  // Scoped at the moment the request goes out, not when the caller built the
  // path, for the reason lib/api.ts gives: a path scoped early and sent late
  // would carry the customer the operator has already switched away from — and
  // after the wait above, which is when the selection is finally knowable.
  const response = await fetch(tenantScopedPath(path), {
    credentials: "same-origin",
    cache: method === "GET" ? "no-store" : "default",
    ...init,
    headers,
  });
  if (response.status === 401) {
    window.location.href = "/login";
    throw new ApiError("unauthorized", response.status, null);
  }
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new ApiError(body || response.statusText || `HTTP ${response.status}`, response.status, body);
  }
  return response.blob();
}

export function getWhoami(options?: ChokeReadOptions): Promise<Whoami> {
  return readJSON<Whoami>("/api/whoami", options);
}

export function getChokeState(options?: ChokeReadOptions): Promise<ChokeState> {
  return readJSON<ChokeState>("/api/choke/state", options);
}

export function getCircuits(options?: ChokeReadOptions): Promise<CircuitEntry[]> {
  return readJSON<CircuitEntry[]>("/api/choke/circuits", options);
}

export function getBuckets(options?: ChokeReadOptions): Promise<BucketEntry[]> {
  return readJSON<BucketEntry[]>("/api/choke/buckets", options);
}

export function getCgroups(options?: ChokeReadOptions): Promise<CgroupMap> {
  return readJSON<CgroupMap>("/api/choke/cgroups", options);
}

export function getDecisions(limit = 200, options?: ChokeReadOptions): Promise<Decision[]> {
  return readJSON<Decision[]>(`/api/decisions?limit=${encodeURIComponent(String(limit))}`, options);
}

export function getAlerts(limit = 200, options?: ChokeReadOptions): Promise<Alert[]> {
  return readJSON<Alert[]>(`/api/alerts?limit=${encodeURIComponent(String(limit))}`, options);
}

export function getSystemHealth(options?: ChokeReadOptions): Promise<Record<string, unknown>> {
  return readJSON<Record<string, unknown>>("/api/system-health", options);
}

export function getProcess(execId: string, options?: ChokeReadOptions): Promise<ProcessDetailPayload> {
  return readJSON<ProcessDetailPayload>(`/api/choke/process/${encodeURIComponent(execId)}`, options);
}

export function getProcesses(options?: ChokeReadOptions): Promise<SysProcEntry[]> {
  return readJSON<SysProcEntry[]>("/api/choke/processes", options);
}

export function getProc(pid: number, options?: ChokeReadOptions): Promise<SysProcDetail> {
  return readJSON<SysProcDetail>(`/api/choke/proc/${encodeURIComponent(String(pid))}`, options);
}

export function updateThresholds(thresholds: Thresholds): Promise<unknown> {
  return putJSON("/api/choke/thresholds", thresholds);
}

/**
 * Outcome of a containment command, as the fleet control plane reports it.
 *
 * `ok` is the only thing that means the action actually landed. It is false
 * when every agent disowned the target (status STATUS_NOT_TARGET) — the
 * process is not on this fleet — and the request 409s with AMBIGUOUS_TARGET
 * when a sever could not be pinned to a single host.
 */
export interface ChokeActionResult {
  ok?: boolean;
  status?: string;
  detail?: string;
  agent?: string;
  applied_by?: string[];
  candidates?: string[];
  /**
   * Set when the action was HELD for change-control (threat-model EN-2): a
   * quarantine/sever needs a second operator to approve it. `ok` is false and
   * nothing has been applied — the action is queued, not done.
   */
  approval_required?: boolean;
  approval?: ApprovalRequest;
}

/**
 * A destructive action awaiting a second operator, and its audit record: who
 * asked, who decided, and what actually happened when it ran.
 */
export interface ApprovalRequest {
  id: string;
  tenant?: string;
  action: string;
  exec_id?: string;
  pid?: number;
  agent_id?: string;
  scope?: "target" | "fleet";
  reason?: string;
  requester?: string;
  created_at?: string;
  expires_at?: string;
  status: "pending" | "approved" | "denied" | "expired";
  /**
   * The BLAST RADIUS of a parked fleet change, as the control plane recorded it
   * when the request was made (handleApprovals in
   * engine/internal/controlplane/approvals.go).
   *
   * `targets` names the hosts a scoped request will touch and is absent for an
   * untargeted one; `radius` says the same thing in words ("the whole tenant",
   * "no host", or the host list). BOTH are absent when the server no longer
   * knows — the ledger is bounded, and the server deliberately renders nothing
   * rather than claim a radius it cannot support.
   *
   * The console read neither, and told every approver of a `scope: "fleet"`
   * request that they were approving "the entire tenant" — including for a
   * one-host containment. Approving is what fires the kill, so the sentence in
   * the confirm has to be the request's own radius, never the widest one.
   */
  targets?: string[];
  radius?: string;
  approver?: string;
  decided_at?: string;
  decide_note?: string;
  outcome?: string;
  executed?: boolean;
  /** True when the viewer is the requester — they may not approve their own. */
  mine?: boolean;
}

export function getApprovals(
  options?: ChokeReadOptions,
): Promise<{ approvals?: ApprovalRequest[]; pending?: number; you?: string }> {
  return readJSON("/api/approvals", options);
}

export function decideApproval(id: string, approve: boolean, note?: string): Promise<ChokeActionResult> {
  return postJSON("/api/approvals/decide", { id, approve, note }) as Promise<ChokeActionResult>;
}

/**
 * Did a choke action actually land?
 *
 * The two deployments answer differently and BOTH must read correctly, because
 * this same bundle is served by the fleet console and by the single-host engine:
 *
 *   - the control plane returns an explicit `ok`, false when no agent applied
 *     (or `approval_required` when it was held for a second operator);
 *   - the engine has no `ok` at all — it returns `{applied: {...}}` and a
 *     non-2xx throws before we get here.
 *
 * So absence of `ok` means the legacy engine contract (applied), and only an
 * explicit `ok: false` means it did not land. Treating undefined as failure
 * would make the engine console report every successful sever as "NOT applied"
 * — the mirror image of the containment lie this reporting exists to remove.
 */
export function chokeApplied(result: ChokeActionResult | undefined): boolean {
  if (result?.approval_required) return false;
  return result?.ok !== false;
}

export function manualAction(body: {
  exec_id?: string;
  pid?: number;
  binary?: string;
  agent_id?: string;
  action: ChokeAction;
  reason: string;
  revert_after_seconds?: number;
}): Promise<ChokeActionResult> {
  return postJSON("/api/choke/manual", body) as Promise<ChokeActionResult>;
}

export function bulkManualAction(body: {
  targets: Array<{ exec_id?: string; pid?: number; binary?: string; agent_id?: string }>;
  action: ChokeAction;
  reason: string;
  revert_after_seconds?: number;
}): Promise<{ results?: Array<{ exec_id?: string; ok?: boolean; error?: string; detail?: string; agent?: string }> }> {
  return postJSON("/api/choke/bulk-manual", body);
}

export function forgetCircuits(execIds: string[]): Promise<unknown> {
  return postJSON("/api/choke/forget", { exec_ids: execIds });
}

/**
 * What a release achieved. The control plane counts PROCESSES, not just hosts:
 * `released` of `contained` across `total` hosts, from each agent's latest
 * heartbeat snapshot. The single-host engine answers `{thawed, scope}` and none
 * of these, which is why every field is optional and `chokeApplied` (absence of
 * `ok` = the engine contract) still decides whether it landed.
 */
export interface ThawResult extends ChokeActionResult {
  scope?: string;
  released?: number;
  contained?: number;
  already_exited?: number;
  applied?: number;
  total?: number;
  routed_to?: string[];
}

/**
 * Release containment WITHOUT naming a process — the "Thaw containment" control.
 *
 * `targets` is the blast radius, and is not decoration. On the control plane a
 * body with no targets releases every contained process on EVERY agent in the
 * tenant (handleChokeThaw → writeFleetRelease), so the console names the hosts
 * it can attribute containment to and the release is scoped to exactly those.
 * Omitting it keeps the tenant-wide shape, which is also the only shape the
 * single-host engine understands — there it releases that host's quarantine
 * tier. Callers must state in the confirm which of the two they are sending.
 *
 * An empty list is never sent: the control plane resolves absent targets as
 * "the whole tenant", and `[]` would be the widest possible request wearing the
 * narrowest possible intent.
 */
export function thawQuarantine(reason: string, targets?: string[]): Promise<ThawResult> {
  const body: { reason: string; targets?: string[] } = { reason };
  if (targets && targets.length > 0) body.targets = targets;
  return postJSON("/api/choke/thaw", body) as Promise<ThawResult>;
}

/**
 * Release ONE process back to pristine.
 *
 * Distinct from thawQuarantine above: without an exec_id the engine unfreezes
 * the whole quarantine tier and moves nobody out of it, so a per-process
 * "release" reported success and left the process quarantined. Passing the
 * target makes it a real per-process release.
 */
export function releaseProcess(
  execId: string,
  pid: number | undefined,
  reason: string,
  agentId?: string
): Promise<ChokeActionResult> {
  return postJSON("/api/choke/thaw", { exec_id: execId, pid, reason, agent_id: agentId }) as Promise<ChokeActionResult>;
}

export function toggleKillSwitch(on: boolean): Promise<unknown> {
  return postJSON("/api/choke/kill-switch", { on });
}

export function applyPreset(name: string, reason: string): Promise<unknown> {
  return postJSON("/api/choke/preset", { name, reason });
}

export function setMode(enforcing: boolean, reason: string): Promise<unknown> {
  return postJSON("/api/choke/mode", { enforcing, reason });
}


export function annotateCircuit(execId: string, note: string): Promise<unknown> {
  return postJSON("/api/choke/annotate", { exec_id: execId, note });
}

export function jailProcesses(body: {
  pids?: number[];
  binary?: string;
  descendants?: boolean;
  action: ChokeAction;
  reason: string;
  revert_after_seconds?: number;
}): Promise<{ results?: Array<{ pid?: number; exec_id?: string; ok?: boolean; error?: string; state?: string }> }> {
  return postJSON("/api/choke/jail", body);
}

export function verifyChain(options?: ChokeReadOptions): Promise<Record<string, unknown>> {
  return readJSON<Record<string, unknown>>("/api/verify-chain", options, CHOKE_SLOW_READ_TIMEOUT_MS);
}

export function forensicSnapshot(options: ChokeReadOptions = {}): Promise<Blob> {
  return readWithDeadline(
    "/api/choke/forensic-snapshot",
    options,
    (signal) => apiBlob("/api/choke/forensic-snapshot", { signal }),
    CHOKE_SLOW_READ_TIMEOUT_MS,
  );
}

export function getRaw<T = unknown>(path: string, options: ChokeReadOptions = {}): Promise<T> {
  return readWithDeadline(path, options, (signal) => sharedApi<T>(path, { signal }));
}

/** What one reachability probe learned: the endpoint answered, and with what. */
export interface HostProbeResult {
  ok: boolean;
  status: number;
}

/**
 * Probe ONE endpoint for reachability, on the same deadline as every read.
 *
 * A bare fetch rather than a JSON read because the probe measures the response
 * itself — did it come back, how fast, with what status — and never parses a
 * body; a 401 does not redirect here either, since a login bounce is not what a
 * reachability check should do to the operator's session.
 *
 * It goes through readWithDeadline for the reason the deadlines exist at all:
 * unbounded, the probe never settles against a half-open connection through a
 * load balancer, so `hostPings` kept whatever it last held and the header pill
 * went on reading "host ok" while every other read on the route had already
 * timed out — the pill an operator glances at before firing containment.
 * `cache: "no-store"` for the same honesty: a probe answered from the browser
 * cache would report a gateway that has stopped serving as healthy.
 *
 * IT IS AN AUTHENTICATED REQUEST, whatever the absent `credentials` key
 * suggests: the Fetch default credentials mode is `same-origin`, so this GET
 * carries the session cookie exactly as the shared client's explicit
 * `same-origin` does. That is required, not incidental — three of the four
 * probed endpoints answer 401 without a session, and an unauthenticated probe
 * would paint the header host pill DOWN for a gateway answering everything
 * correctly. The flag is nonetheless left off on purpose: it is the only thing
 * that tells this probe's /api/whoami GET apart from the route's real authority
 * read of the same path, and the self-disarming whoami retry is pinned by
 * counting the identity reads that set it (chokeRadius3WhoamiRetry). Setting it
 * here made every probe read as an answered authority read. The difference is
 * in the RequestInit, not on the wire.
 *
 * It is also the one fetch in this module that is EXEMPT from the customer
 * scoping apiBlob applies, and that is deliberate rather than an oversight for
 * the next reader to tidy up. Nothing here is a data read: the probe never
 * touches the response BODY, only whether one arrived and with what status. So
 * although the server does answer it with a customer's rows, none of them reach
 * the operator and there is no answer for a `?tenant=` to mis-attribute — where
 * apiBlob hands over a FILE whose contents belong to one customer, this hands
 * back a boolean about a socket.
 *
 * Scoping it would therefore buy no safety, and would cost. `useChokeData`'s
 * `pingHost` calls this over the whole HOST_ENDPOINTS list (constants.ts):
 * /api/whoami, /api/choke/state, /api/choke/circuits and /api/decisions?limit=1.
 * The first is in tenantScope's UNSCOPED_PATHS — scoping it would ask the one
 * endpoint that reports the SERVER'S OWN default to echo the console's guess
 * back at it — and naming a customer on the other three would let a selection
 * the server refuses (404/403) read on the pill as a host that has stopped
 * answering, which is the same lie about reachability these deadlines exist to
 * remove.
 */
export function probeEndpoint(path: string, options: ChokeReadOptions = {}): Promise<HostProbeResult> {
  return readWithDeadline(path, options, async (signal) => {
    const response = await fetch(path, { method: "GET", cache: "no-store", signal });
    return { ok: response.ok, status: response.status };
  });
}
