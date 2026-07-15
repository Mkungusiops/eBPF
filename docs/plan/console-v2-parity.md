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

## Status when this doc was written (2026-07-15)

Already live on `console.adanianlabs.io` (read-only, tenant-scoped, behind OIDC):
SOC telemetry, Choke, Devices, Fleet — four tabs. Central command channel
(`POST /api/admin/command`, `SetMode`/`SetThresholds`) is proven live. Agents
report compact choke/device snapshots on the heartbeat; the control plane serves
`/api/telemetry`, `/api/fleet`, `/api/choke`, `/api/devices`.

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
