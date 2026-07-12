# Enterprise Conversion Plan — eBPF Threat Choke Gateway → Multi-Tenant SOC Platform

> **Deliverable:** convert the single-host PoC running at
> [`soc.adanianlabs.io`](https://soc.adanianlabs.io/) into an enterprise, multi-tenant
> security operations platform for Linux server fleets.
>
> **Status:** planning. This folder is the source of truth for the conversion.
> **Author context:** written against the current `feat/enterprise-gradeI` branch after a
> full read of the engine (`engine/`), console (`web/`), and docs (`docs/`).

## How to read this folder

| File | What it is |
|------|-----------|
| **`plan.md`** (this file) | The master plan: strategy, current-state assessment, gap analysis, phasing summary, migration, risk. Read this first. |
| [`architecture.md`](architecture.md) | Target architecture deep-dive: the agent / control-plane split, each service, the data model, the wire protocol, tenancy isolation. |
| [`roadmap.md`](roadmap.md) | Phase-by-phase execution board: workstreams, concrete deliverables mapped to code, exit gates, sizing. |

---

## 1. Locked decisions & assumptions

These three product decisions (confirmed with the owner) drive every architectural choice below:

1. **Deployment model — Multi-tenant SaaS.** One central control plane hosts many customer
   organisations; agents on customer hosts phone home. Full tenant isolation is a day-one
   requirement, not a retrofit.
2. **Primary operator — MSSP / Telco MSOC.** A security team monitoring *many customers'*
   Linux server fleets from one console. Cross-tenant analyst workflows, case management, and
   SLA/tenant reporting are first-class.
3. **Scope — Broaden toward a fuller platform.** The Linux eBPF runtime-defense engine is
   flagship **sensor #1** and the differentiator, but the platform (control plane, data platform,
   detection engine, response, integrations) is built as a *general* security-operations backbone
   that can ingest additional telemetry sources over time.

**Working assumptions** (revisit if wrong):

- Telco/enterprise customers in the target market (East Africa first) will demand **data
  residency** and some will demand **on-prem/regional** hosting even though the primary model is
  SaaS. The architecture keeps a single-tenant self-hosted deployment as a *packaging variant* of
  the same code, not a fork. (This hedges the "Both" option we did not pick.)
- Regulatory anchor is the **Kenya Data Protection Act 2019** plus **SOC 2 / ISO 27001** as the
  commercial trust bar.
- The team is small today; the plan is sequenced so a lean team can ship the spine before the
  breadth.

---

## 2. Strategy in one paragraph

Keep the sharp edge — **in-kernel, post-compromise runtime defense with active containment on
Linux servers, which works even when the host is offline** — and wrap it in the platform an MSSP
needs to run it for hundreds of tenants: a multi-tenant control plane, a scalable data platform,
central detection and case management, and enterprise identity. We do **not** dilute the agent to
chase the "cannot solve" list; we *broaden the platform* so those capabilities arrive later as
**additional sensors and integrations** feeding the same backbone. The single most important
change is an **architectural split**: today's monolith becomes a thin, autonomous **agent** and a
horizontally-scalable **control plane**.

---

## 3. Where we are today (grounded assessment)

The PoC is unusually well-built for its stage — this is a strong foundation, not a rewrite target.
What exists and is *reusable*:

| Asset | Where | Why it matters for enterprise |
|------|-------|-------------------------------|
| eBPF detection + graduated enforcement (throttle→tarpit→quarantine→sever) | `engine/internal/choke/`, `engine/internal/enforce/` | This is the product. It ships largely intact into the agent. |
| Stable `exec_id` process tree + chain scoring | `engine/internal/tree/`, `engine/internal/score/` | Local correlation & autonomy; the basis for cross-host correlation later. |
| **Hash-chained, tamper-evident audit** of every enforcement decision | `engine/internal/store/decisions.go`, `GET /api/verify-chain` | A genuine compliance asset — most EDRs don't have this. Build on it. |
| Storage already **dialect-abstracted** (SQLite \| Postgres) | `engine/internal/store/sqlite.go` (`Store.dialect`) | The seam for moving central data to Postgres + ClickHouse. |
| **Push-model OTel** metrics with resource attributes | `engine/internal/metrics/metrics.go` | Explicitly designed "so the same binary fans out cleanly when we go multi-host." |
| Config file surface + flag/file merge | `engine/internal/config/config.go`, `cmd/engine/main.go` | Grows into agent config + signed remote policy. (The file the owner has open.) |
| React multi-entry console (SOC/Choke/Devices/Fleet) | `web/src/` | Evolves into the multi-tenant console; no rewrite of the panels. |
| Device (MAC) choke + inline-bridge data plane | `engine/internal/enforce/devbpf/`, `internal/device/` | A second sensor/enforcer class already proven (`make netns-smoke`). |
| A **fleet fan-out** proving the multi-host control pattern | `engine/internal/api/fleet.go` | Becomes the *degraded/fallback* control path once the real control channel exists. |
| A live, TLS-fronted deployment with a real ops runbook | `docs/deployment/live-soc-adanianlabs.md`, `docs/production-rollout/` | We have production scar tissue and honest limitations documented. |

The project's own honest limitations (`README.md` §Limitations) are exactly the enterprise gaps:

1. **Single host** — one engine ↔ one Tetragon socket; *"no central fan-in collector yet."*
2. **Single-user auth** — one admin credential; no multi-user/RBAC (`engine/internal/api/auth.go`).
3. **HTTP only** — TLS is a reverse-proxy concern.
4. **Fixed scoring rules** — no baseline learning; manual tuning in `score/scorer.go`.
5. **Device choke is operator-driven** — no automatic score path for the MAC gateway.

Two more, from the live runbook, that are *operational* red flags to fix early:

6. The live engine runs as a **bare root background process, not even a systemd unit** — no
   auto-restart, no supervision (`docs/deployment/live-soc-adanianlabs.md` §1).
7. **Enforcement blast radius is real**: in enforcing mode the process choke SIGKILLs `sudo`
   (~120+ score) and can lock an operator out (`live-soc-adanianlabs.md` §3). Enterprise
   enforcement needs central guardrails, protected-process lists, approvals, and a fleet kill-switch.

---

## 4. What "enterprise" requires — pillar-by-pillar gap analysis

Ten pillars an MSSP-grade platform needs. For each: where we are, where we must get to, and the
phase that delivers it (see [`roadmap.md`](roadmap.md)).

| # | Pillar | Today | Enterprise target | Phase |
|---|--------|-------|-------------------|:---:|
| 1 | **Identity & tenancy** | Single admin, HMAC cookie (`auth.go`) | Orgs/tenants, users, RBAC, SSO (OIDC/SAML), SCIM, API tokens, session mgmt, per-tenant data isolation | 1 |
| 2 | **Fleet architecture** | Client-driven fan-out over shared admin creds (`fleet.go`) | Agent/control-plane split; mTLS enrollment; central registry, config push, secure command channel, heartbeat, offline buffering | 1 |
| 3 | **Data platform** | SQLite per host, optional Postgres | Central ingest → message bus → **ClickHouse** (events/telemetry) + **Postgres** (control state) + object store (cold/forensic); retention tiers, tenant-partitioned | 1–3 |
| 4 | **Detection engineering** | Fixed heuristics (`scorer.go`), local only | Cross-host correlation, Sigma→rule pipeline, detection-as-code + versioning + tuning, threat-intel enrichment, MITRE coverage, later ML/baselining | 2, 4 |
| 5 | **Response & SOAR** | Manual jail/thaw via UI, audited | Case management, incident workflow, **enforcement approvals/change-control**, playbooks, notifications, fleet kill-switch | 2 |
| 6 | **Integrations** | OTel metrics out; no SIEM/ticketing | SIEM export (**OCSF**/CEF/syslog), webhooks, Slack/PagerDuty/Teams, Jira/ServiceNow, threat-intel feeds | 2 |
| 7 | **Reliability / HA** | Single bare process, no supervision | Multi-AZ HA control plane, autoscaling, DR/backup, agent fleet upgrade/rollback, SLOs | 3 |
| 8 | **Security & supply chain** | Bcrypt+HMAC, hash-chain audit; plaintext demo creds | Hardened authN/Z, secrets mgmt (Vault/KMS), encryption in transit+at rest, signed artifacts + SBOM + provenance, pen-test | 0, 3 |
| 9 | **Compliance & residency** | Audit chain only | Kenya DPA program, SOC 2 / ISO 27001, data-residency options, retention/DSAR tooling, tenant data-export/delete | 3 |
| 10 | **Product & operations** | `make deploy`, tarball, manual runbook | Container/Helm + agent `.deb`/`.rpm`, CI/CD, IaC, onboarding/tenant provisioning, billing/metering, observability (traces+logs+metrics) | 0, 3 |

---

## 5. Target architecture (summary)

Full detail in [`architecture.md`](architecture.md). The essence is the split:

```
   PER CUSTOMER HOST (many, per tenant)          CENTRAL CONTROL PLANE (multi-tenant SaaS, HA)
 ┌──────────────────────────────────┐          ┌───────────────────────────────────────────────┐
 │  Choke Agent (root, autonomous)   │          │  ┌────────────┐   ┌──────────────┐             │
 │  • Tetragon + local scorer/tree   │  mTLS    │  │  Ingest /  │──▶│ Message bus  │──┐          │
 │  • process + device choke gateways│ ───────▶ │  │ Collector  │   │ (Kafka/NATS) │  │          │
 │  • local SQLite = offline buffer  │  events  │  └────────────┘   └──────────────┘  ▼          │
 │  • ENFORCES even when OFFLINE ◀───┼──┐       │        ▲            ┌──────────────────────────┐│
 │  • pulls signed policy bundles    │  │cmds   │        │            │ Detection engine         ││
 └──────────────────────────────────┘  └───────┼── Fleet/command ◀───┤ (cross-host correlation, ││
                                                │   service           │  Sigma rules, TI enrich) ││
                                                │        │            └──────────────────────────┘│
   Analyst / MSOC operator                      │  ┌─────▼─────┐  ┌───────────┐  ┌──────────────┐ │
        │  browser (OIDC/SSO)                   │  │ ClickHouse│  │ Postgres  │  │ Object store │ │
        ▼                                       │  │ (events)  │  │ (control) │  │ (cold/forense)│ │
 ┌────────────────────┐   HTTPS   ┌─────────────┼──┴───────────┴──┴───────────┴──┴──────────────┘ │
 │ Multi-tenant React │ ────────▶ │ API gateway │  Identity/Tenancy · Cases · Integrations/SOAR   │
 │ console (org switch)│          └─────────────┴─────────────────────────────────────────────────┘
 └────────────────────┘
```

Key principles:

- **Agent autonomy is sacred.** The cloud link is for *visibility, policy, and coordination* —
  never a prerequisite for kernel containment. A disconnected agent keeps enforcing its last
  signed policy and buffers evidence locally. This is the moat; we do not trade it away.
- **The control plane is a general SOC backbone.** Ingest, bus, data platform, detection, cases,
  and integrations are sensor-agnostic. Sensor #1 is the eBPF agent; Windows/cloud/network
  sensors (the "broaden" mandate) plug into the same pipeline in Phase 4 without re-architecting.
- **Tenant isolation is structural.** Tenant ID is carried from the agent's mTLS identity through
  the bus, into every ClickHouse partition and Postgres row, and enforced at the API and query
  layer. No cross-tenant read is possible without an explicit MSOC "cross-tenant" role.
- **The monolith stays buildable during the transition** (strangler pattern): `agent` and
  `controlplane` become two build targets over shared `internal/` packages, so the live demo never
  goes dark.

---

## 6. Phased roadmap (summary)

Detail, deliverables, and exit gates in [`roadmap.md`](roadmap.md). Indicative horizon: **~12–18
months to GA** with a lean team, then broaden.

| Phase | Theme | Outcome (kills which gap) | Rough size |
|:---:|------|---------------------------|:---:|
| **0** | Foundations & don't-break-the-demo | CI/CD, IaC, packaging, secrets, threat model, systemd-ify the live box, rotate creds, split build targets scaffolded | 4–6 wks |
| **1** | **Multi-tenant spine** | Identity/tenancy + RBAC + SSO; ingest collector + bus + ClickHouse + Postgres; agent mTLS enrollment + uplink; central console. Kills #1 (single host) & #2 (single-user). | 3–4 mo |
| **2** | Detection & response at scale | Cross-host correlation, Sigma pipeline, case management, enforcement approvals, notifications, SIEM/OCSF export, ticketing. MSOC workflows. | 3–4 mo |
| **3** | Reliability, compliance, GA | HA/DR, autoscaling, agent fleet upgrade, retention tiers; SOC2/ISO/DPA program, pen-test, supply-chain; billing/onboarding. **GA.** | 3–4 mo |
| **4** | Broaden | Additional sensors (Windows/endpoint, cloud connectors, network/NDR), SIEM ingestion, ML/baseline anomaly, auto score path for device gateway. | ongoing |

Sequencing rule: **the spine before the breadth.** Do not add sensor types (Phase 4) until the
tenancy + data + isolation spine (Phase 1) is solid, or we multiply an un-isolated blast radius.

---

## 7. Migration — keeping `soc.adanianlabs.io` alive throughout

The live box is a single-NIC Azure VM running a bare root process. We use a **strangler**
migration so there is never a flag-day rewrite:

1. **Stabilise first (Phase 0, week 1).** Put the existing engine under **systemd** with restart
   policy (the unit already exists at `deploy/ebpf-engine.service`), rotate the `admin /
   ebpf-soc-demo` demo credential, confirm TLS + backups. Zero new architecture — just close the
   operational holes in `live-soc-adanianlabs.md`.
2. **Introduce the control plane beside it (Phase 1).** Stand up the control plane in a new
   environment. The existing box becomes **agent #0 of tenant "adanian-internal"**: run the new
   agent build alongside (or the monolith in dual-write mode) so it streams to the control plane
   while still serving its own console.
3. **Cut the console over.** Once the central multi-tenant console renders the same tenant's data,
   point `soc.adanianlabs.io` at the control plane (or make it a tenant login). The old per-host
   console becomes a localhost-only debug surface.
4. **Retire the monolith path.** When agents everywhere report centrally, drop the embedded
   console from the agent build and delete the client-fanout fleet path.

Every step is independently shippable and reversible (the runbook's atomic-swap + rollback
artifacts pattern carries over).

---

## 8. Security, compliance & data residency

This is a *security product* — our own posture is part of the product.

- **Tenant isolation** is the #1 risk. Enforce it at four layers: mTLS agent identity → tenant;
  tenant-scoped tokens at the API; row/partition-level tenant filters in every query; separate
  encryption context (per-tenant keys/prefixes) at rest. Add automated cross-tenant leakage tests
  to CI.
- **Enforcement guardrails.** Central protected-process/allow-lists, per-tenant enforcement mode
  (detect-only default), **change-controlled/approved** destructive actions, and a fleet-wide
  kill-switch. The `sudo`-lockout incident (`live-soc-adanianlabs.md` §3) is the canonical failure
  to design against.
- **Supply chain.** Signed release artifacts, SBOM, build provenance (SLSA-style), pinned
  dependencies. Agents auto-update only from signed bundles; policy bundles are signed too.
- **Secrets.** No plaintext creds anywhere (kill the demo default). Vault/cloud KMS for control
  plane; agent bootstrap tokens are short-lived and one-time.
- **Compliance program.** Build toward **SOC 2 Type II** and **ISO 27001**; treat the existing
  **hash-chained decision audit** as a control we already have. Map controls in Phase 3.
- **Kenya DPA + residency.** Device-flow and process telemetry are personal/sensitive data
  (already flagged in `production-rollout/README.md` §Privacy). Provide per-tenant retention,
  data-export/delete (DSAR), documented data flows, and a **regional/in-country hosting** option
  (the same code deployed single-tenant) for telcos that cannot use shared SaaS.

---

## 9. Risks & mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Losing agent autonomy by making the cloud a hard dependency | Kills the differentiator | Offline-first agent; cloud is optional for enforcement; test disconnected enforcement in CI |
| Cross-tenant data leak | Company-ending for a security vendor | Structural tenant scoping at 4 layers + automated leakage tests + external pen-test |
| Enforcement blast radius across a fleet | Take down a customer's servers | Detect-only default, approvals, protected lists, staged rollout, kill-switch (patterns already in `production-rollout/`) |
| eBPF/kernel fragmentation across customer fleets | Agent won't attach / crashes hosts | Conservative attach, graceful degrade to detect-only, kernel version matrix testing, canary rings |
| Scope creep from "broaden" before the spine is ready | Never ship anything solid | Hard gate: no new sensor types until Phase 1 tenancy+data spine passes exit criteria |
| Data platform cost at telco scale | Margin erosion | Retention tiers (hot ClickHouse → cold object store), per-tenant quotas, sampling for high-volume `process_exec` |
| Small team vs. large surface | Burnout / half-built pillars | Phase discipline; buy don't build for identity (SSO), bus, and observability where sensible |

---

## 10. Team, sizing & the first two weeks

**Indicative team to run Phases 0–3:** 2–3 backend (Go, distributed systems), 1 frontend (the
existing React app owner), 1 platform/SRE (IaC, CI/CD, K8s), 0.5 security/compliance, 0.5 product.
Detection engineering ramps up in Phase 2.

**Do this in the first two weeks (no architecture required, high leverage):**

1. Put the live engine under **systemd**; rotate the demo credential; verify backup + TLS renew.
2. Stand up **CI** (build/test/lint for `engine/` and `web/`, already have `make test` + vitest +
   playwright) and produce **signed release artifacts** + a container image.
3. Write the **threat model** and the **tenant-isolation invariant** doc (what "one tenant can
   never see another" means, concretely) — it constrains every later design.
4. Scaffold the **`agent` vs `controlplane` build split** as two `cmd/` targets over today's
   `internal/` packages (no behaviour change yet) — this de-risks all of Phase 1.
5. Design the **agent↔control-plane wire contract** (enrollment, event uplink, command channel)
   as the first artifact of Phase 1 (see [`architecture.md`](architecture.md)).

---

## 11. Definition of "enterprise-ready" (GA exit criteria)

We are done with the core conversion when:

- One control plane serves **≥ N tenants** with proven isolation (leakage tests green, pen-test
  passed).
- A new customer can **enroll an agent in minutes** via a bootstrap token; the agent appears,
  streams telemetry, and takes central commands — and **still enforces if disconnected**.
- An MSOC analyst can **triage cross-tenant, open a case, approve an enforcement action, and
  export to SIEM (OCSF)** without touching a host.
- The platform runs **HA with DR**, agents **upgrade fleet-wide safely**, and there is a
  **compliance story** (SOC 2 in progress, DPA satisfied, residency option available).
- **RBAC + SSO** gate everything; the single-admin/plaintext-cred era is gone.

Everything beyond that — Windows/cloud/network sensors, ML baselining — is Phase 4 breadth on a
spine that already holds.
