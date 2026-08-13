# Console v2 parity — folding the rich SOC into the SSO console ("C")

> **Goal.** Bring the rich, interactive single-host console
> (`soc.adanianlabs.io`, served by `cmd/engine`) into the multi-tenant SSO
> console (`console.adanianlabs.io`, served by the control plane), **tenant-scoped
> and RBAC-gated**, so the two eventually converge to one pane of glass.
>
> **Hard constraint (this cut).** `soc.adanianlabs.io` and the `ebpf-engine`
> monolith are **NOT touched** — they keep running as-is. Every item here is
> *additive* to the control plane, the agent's central reporting, and the
> `console.html` SPA. Retiring the monolith is a **separate, later** step
> (migration runbook §4–5), explicitly deferred.

> **Estate note (2026-08-03).** This document was written while the rich console
> lived on the Azure host `soc.adanianlabs.io`. That box is retired and the
> domain no longer resolves — references to it below are historically accurate,
> not current infrastructure. The single-tenant engine now runs on the rig's
> `single_tenant_engine` host (`engine.adanianlabs.io`); the multi-tenant console
> is `console.adanianlabs.io`. The parity work itself is complete.

## ⭐ FINALIZED STATUS — 2026-07-15 (authoritative; supersedes the sections below)

**The approach pivoted.** The original plan (a bespoke 4-tab console with custom
`/api/posture|timeline|graph|mitre` endpoints) was scrapped after the rebuilt
panels "didn't look anything close to the SOC UI." The finalized approach:
**`console.adanianlabs.io` serves soc's *actual* React frontend** (`index.html`
/`soc`, `choke`, `devices`, `fleet` pages from `web/dist`, via the console nginx
block), and **the control plane answers soc's *real* `/api/*` contract,
tenant-scoped** by the operator's OIDC session (`authorizeRead` defaults the
tenant from `TenantScope[0]`). Identical UI, because it is the same frontend.
The engine (`soc.adanianlabs.io`) stays untouched throughout.

### ✅ DONE — live + verified (analyst + msoc sessions)

- **Serving + auth** — nginx console block serves the rich multi-page app
  (`try_files $uri $uri.html /index.html`); `= /login → /auth/login` and
  `= /api/logout → /auth/logout` (SOC app hardcodes engine paths); Keycloak
  login, RP-initiated logout, tenant isolation (analyst→other tenant = 404,
  msoc cross-tenant = 200).
- **SOC dashboard** (`/`) — the whole main page renders with real tenant data:
  KPI row, severity timeline, alert triage + drill-down, top-processes, live
  event stream (SSE), policy viewer, system health, version, account. CP serves
  `whoami` (+`user`/`host`/`role`/`can_respond` aliases), `version`, `alerts`
  (bare array), `events`, `decisions` (bare array), `policies` + `policy-stats`
  (derived from distinct `policy_name`+counts — no agent change),
  `process/{execId}` (event-based drill), `system-health`, and **`/api/stream`
  (tenant-scoped SSE store-poll bridge** emitting event/alert/decision frames +
  heartbeats).
- **Choke Gateway** (`/choke`) — renders; CP serves `choke/state`, `circuits`,
  `buckets`, `cgroups`, `processes`, `verify-chain`, `choke/process/`, `proc/`
  (`internal/controlplane/choke.go`), tenant-scoped from heartbeat summaries.
- **Devices** (`/devices`) — renders; CP serves `choke/device-state`,
  `choke/devices`, `choke/device-flows` (`links_attached=0` so no false
  bridge-master warning).

### ✅ NOW DONE (2026-07-16) — C is functionally complete

1. **Fleet page** (`/fleet`) — mapped (`internal/controlplane/fleet.go`): each
   tenant agent = one host; `/api/fleet/hosts|state|cgroups|decisions|alerts|`
   `devices` in the `FleetEnvelope`/`HostResult` shape.
2. **All interactive write-actions wired** to the signed command dispatcher, RBAC
   `ActionRespond` (`choke.go`): per-process `manual`/`jail`/`thaw`, multi-target
   `bulk-manual`, `forget`; fleet-wide `mode` (SetMode), `kill-switch`,
   `thresholds` (PUT), `preset`; device `device-jail`/`thaw`/`mode`/`kill-switch`.
   The **sim-agent gained a command Processor** (`simApplier`) that verifies
   fleet-signed commands and mutates its choke/device/mode state, so actions are
   reflected in the next heartbeat. Verified: jail→severed, SetMode→`enforcing`,
   device-jail→severed, all others ack `STATUS_APPLIED`. (`policy/preview` +
   `forensic-snapshot` remain a clean 501 — engine-local, no fleet command.)
3. **Attacks / Honeypots** (`attacks.go`) — `/api/attacks` + `/api/honeypots`
   catalogs; `/api/run-attack` stamps a synthetic alert into the tenant store so
   the dashboard reacts. (Demo surface, "remove later".)
4. **Data-fidelity — MITRE + network** — added `mitre_id`/`tactic` to `Alert` and
   `dest_ip`/`dest_port`/`proto`/`remote_ip` to `ProcessEvent` (proto regen); the
   sim emits them; the CP serves them on `/api/alerts`, `/api/events`, and the SSE
   frames → the **MITRE coverage, IOCs, and Network-connections** panels populate.
5. **Cleanup** — the dead console-v2 subsystem removed (13 files:
   `console.tsx`/`console.html`, `ConsoleShell`, `TenantSwitcher`, tenant store,
   `session.ts`/`tenantCore.ts`/`console.ts` + tests); `vite.config.ts` entry
   dropped; web typecheck/tests/build green.

### ⏳ Residual (nice-to-have, not blocking)

- **Full correlation-graph tree** — the alert drill (`/api/process/{execId}`)
  works; the full graph *modal* wants richer parent-exec-id lineage (the sim
  emits `parent_pid` but not linked exec chains). Choke token-buckets / cgroup
  map / full `/proc` table / per-device flows / per-tenant decision hash-chain
  also remain valid-empty (agents don't report them).
- **MSOC tenant switcher UI** — msoc reads any tenant via `?tenant=`; there is no
  in-app selector yet (would be a small addition to the reused frontend).

**The read/observability + interactive-response halves are complete; every page
renders and every button works, tenant-scoped and RBAC-gated.**

---

## Original plan (pre-pivot — retained for reference)

> The sections below describe the superseded 4-tab approach and its bespoke
> endpoint names. Kept for provenance; the finalized status above is current.

C is the work to reach **feature parity with the rich panels** of the engine
console.

---

## Workstream 1 — Agent: report the data the rich panels need

The agent already reports telemetry + choke/device/fleet summaries. The rich
panels need more, reported centrally (capped so the uplink stays lean):

- **Rich alerts** — full alert objects (severity, MITRE technique, suspicious
  chain, score, origin, timestamp), not just `kind=alert` telemetry rows.
- **Scored process tree** — parent/exec chains + scores (feeds the Correlation
  Graph and Top-Processes panels).
- **Applied policies** — the agent's active TracingPolicies + ChokePolicies
  (feeds the Policies panel).

## Workstream 2 — Control plane: tenant-scoped read endpoints

All `authz.ActionRead`, denial → 404 (side-channel rule), aggregated across the
tenant's agents:

| Endpoint | Panel it powers | Source |
| --- | --- | --- |
| `/api/alerts` | Alert triage queue | reported alerts |
| `/api/posture` | Posture gauge + KPI tiles (P1/P2/P3, events/s, active procs, throughput, top technique, ops health) | derived from alerts/telemetry |
| `/api/timeline` | Severity timeline (buckets + anomaly markers) | derived |
| `/api/graph` | Correlation Graph | process tree |
| `/api/processes` | Top processes by score | process tree |
| `/api/mitre` | ATT&CK coverage | alert technique tags |
| `/api/policies` | Policies panel | reported policies |

## Workstream 3 — Control plane: interactive/write endpoints (RBAC `respond`)

Extends the existing signed command channel:

- **Choke actions** — jail / thaw / set-mode / set-thresholds / apply-preset
  (dispatcher already supports these; wire the remaining actions + endpoint).
- **Device actions** — jail/thaw a MAC (needs devchoke command support).
- **Fleet actions** — promote rollout ring, publish policy bundle (fleet service
  already has `Publish`/`Promote`; needs endpoints).
- **Triage state** — per-operator/tenant alert ack + pin, and a per-tenant
  **Watchlist** (new central state).

## Workstream 4 — Console frontend: port the panels, tenant-scoped

Reuse the existing `web/src/features/` components so the look and feel match,
rewired to the endpoints above and RBAC-gated (read-only operators see panels;
action buttons disabled unless the operator holds `respond` on the tenant):

- Executive summary + posture gauge + KPI tiles
- Severity timeline
- Alert triage queue + alert drill-down
- Correlation Graph
- Choke Gateway (interactive jail/thaw/set-mode)
- Devices, Fleet, MITRE coverage, Top processes, Policies
- Watchlist, Export view, Notifications, Command Palette
- Left-nav shell + tenant switcher (extends today's 4-tab console)

## Workstream 5 — Cross-cutting

- **RBAC on every write** — tenant-bound `respond`; verify the target agent
  belongs to the tenant before dispatch.
- **Tests** — Go endpoint/integration tests + web vitest per panel; CI stays green.
- **Deploy** — agent + control-plane binaries + console bundle, verified live per
  increment.
- **Docs** — update `wire-contract.md`; add a "console v2 panels" reference.

## Out of scope (stays on soc / agent-local)

Single-host lab/dev tooling — **Attacks** (quick-fire), **Honeypots**,
**Kprobe Perf**, **Rule Simulator**, **Time Machine**. Not multi-tenant
production features; they remain on `soc.adanianlabs.io`.

---

## Recommended sequence (each increment shippable)

1. **Interactive Choke** (~½ session) — mechanism exists; fastest visible win.
2. **Rich alerts → triage queue + drill + severity timeline** (~1–1.5 sessions).
3. **Posture + KPI tiles + MITRE coverage** (~1 session; derived, no new agent data).
4. **Correlation Graph + Top-Processes** (~1–1.5 sessions; needs process-tree reporting).
5. **Fleet/Devices actions + Policies + Watchlist** (~1 session).
6. **RBAC hardening + tests + polish** (~½ session, woven throughout).

**Total: ~5–7 focused sessions.**

## Definition of done

An operator logs into `console.adanianlabs.io` and, for their tenant, sees the
posture/KPIs, severity timeline, triage queue with drill-down, and correlation
graph, and can take choke/fleet actions gated by their role — matching the engine
console's **core** panels, tenant-scoped and access-controlled. `soc.adanianlabs.io`
keeps running untouched throughout; its retirement is a later, separate step.
