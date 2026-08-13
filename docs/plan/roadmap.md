# Execution Roadmap

Companion to [`plan.md`](plan.md) and [`architecture.md`](architecture.md). Phase-by-phase
workstreams, concrete deliverables mapped to the codebase, and **exit gates** (a phase is not done
until its gate passes). Sizes are indicative for a lean team; sequence matters more than dates.

Guiding rule: **the spine (Phase 1) before the breadth (Phase 4).** Never multiply blast radius or
data volume across an un-isolated, un-scaled platform.

---

## Phase 0 — Foundations & don't-break-the-demo · ~4–6 weeks

**Goal:** close operational holes, get engineering hygiene in place, and de-risk the split — with
zero user-visible architecture change.

**Workstreams & deliverables**

- **Stabilise the live box** — put the running engine under **systemd** (unit exists at
  `deploy/ebpf-engine.service`) with restart-on-failure; **rotate the `admin/ebpf-soc-demo`
  credential**; verify TLS renewal + DB backup. Fixes the "bare root process" and default-cred
  holes in `docs/deployment/live-soc-adanianlabs.md`.
- **CI/CD** — pipeline running `make test`, `go vet`, web `vitest` + `playwright` + `lint.mjs` on
  every PR; produce **signed** release artifacts + a container image; SBOM generation.
- **IaC baseline** — Terraform for the future control-plane environment (network, K8s, managed
  Postgres); nothing production yet, just the substrate.
- **Build-target split scaffolding** — add `cmd/agent/` and `cmd/controlplane/` as thin
  entrypoints over existing `internal/` packages; `cmd/engine` still builds. No behaviour change.
- **Threat model + tenant-isolation invariant doc** — write down what isolation means concretely
  (see `architecture.md` §5); it constrains all of Phase 1.
- **Secrets** — remove plaintext credential defaults from config/flags; document Vault/KMS usage.

**Exit gate**
- Live demo supervised, credentialled, backed up.
- Green CI producing signed artifacts + container + SBOM.
- `cmd/agent` and `cmd/controlplane` build from shared packages; tests pass.
- Threat model + isolation invariant reviewed and merged.

---

## Phase 1 — Multi-tenant spine · ~3–4 months

**Goal:** N agents across M tenants report to one control plane with real identity and isolation.
Kills README limitations **#1 (single host)** and **#2 (single-user auth)**.

**Workstreams & deliverables**

- **Wire contract** (first artifact) — enrollment, telemetry uplink, command channel, policy pull,
  heartbeat (see `architecture.md` §4). Protobuf/gRPC definitions + dedup/resume semantics.
- **Agent v1** — refactor the monolith into the autonomous agent: local WAL becomes an offline
  buffer; add mTLS enrollment, uplink client, heartbeat, signed-policy pull. **Prove offline
  enforcement** (agent enforces while disconnected, drains buffer on reconnect).
- **Ingest/Collector** — mTLS termination, tenant derivation from cert, normalise + stamp
  tenant_id, publish to bus. Horizontally scalable.
- **Message bus + data platform** — stand up the bus; **ClickHouse** for events (tenant+time
  partitioned, retention TTLs); **Postgres** for control state (extend `internal/store` Postgres
  dialect); object store for forensic snapshots/exports.
- **Identity & tenancy** — orgs/tenants, users, **RBAC**, **SSO (OIDC)**, API tokens, sessions.
  Replaces `internal/api/auth.go`. Tenant-scoped tokens consumed by every service.
- **Fleet/command service** — agent registry, signed policy-bundle distribution, command dispatch
  with audit. Reduce `api/fleet.go` fan-out to a fallback path.
- **Console v2** — org/tenant switcher + tenant-scoped SOC/Choke/Devices/Fleet reading from the
  central store; OIDC login; RBAC-gated. Reuses `web/src/` panels.
- **Isolation tests** — automated cross-tenant read-denial tests in CI.

**Exit gate** — ✅ **MET** (2026-08-03; see the note below on where each is proven)
- Enroll an agent with a bootstrap token in minutes; it streams telemetry, takes central commands,
  and **still enforces when disconnected**. *(Fresh-host enrolment measured at 166s on the AWS rig.
  The autonomy half is proven twice: `internal/e2e/autonomy_test.go` in CI — it stops the control
  plane and requires enforcement, evidence-keeping and unaided re-convergence — and
  `scripts/e2e/agent-autonomy.sh` against the real rig by stopping systemd.)*
- Two tenants' data provably isolated (leakage tests green). *(`scripts/e2e/multi-tenant.sh` runs
  from both sides; Postgres RLS integration test in CI.)*
- SSO + RBAC gate the console; single-admin/plaintext era removed.
- The live single-host deployment served as a tenant of the control plane (migration step 3 in
  `plan.md` §7). *(Superseded by the full migration to the AWS estate — the Azure box that step
  named is decommissioned and `soc.adanianlabs.io` no longer resolves.
  `console.adanianlabs.io` serves the rich console from the control plane, tenant-scoped.)*

---

## Phase 2 — Detection & response at scale · ~3–4 months

**Goal:** the MSOC workflow — detect across a fleet, triage cross-tenant, respond with control, and
integrate with the customer's stack. Addresses **#4 (fixed rules)** and delivers response tooling.

**Workstreams & deliverables**

- **Cross-host correlation** — detection engine consumes the bus and correlates chains spanning
  hosts within a tenant (lateral movement), superset of `score/scorer.go`.
- **Detection-as-code + Sigma pipeline** — versioned rules, **Sigma → rule** translation (stated
  "what's next"), tuning/suppression workflow, MITRE coverage view.
- **Threat-intel enrichment** — IP/hash/domain reputation on ingest/detection.
- **Case management** — group alerts into cases, assign, status, SLA clocks, timeline; per-tenant
  and cross-tenant analyst queues.
- **Enforcement approvals / change-control** — destructive fleet actions (quarantine/sever,
  device jail, kill-switch) require approval; centrally-managed protected-process lists; staged
  rollout rings (reuse `production-rollout/README.md` model).
- **Integrations (outbound)** — **OCSF** SIEM export (stated "what's next"), CEF/syslog, webhooks,
  Slack/PagerDuty/Teams, Jira/ServiceNow.
- **Notifications & reporting** — per-tenant alert routing, scheduled reports, SLA dashboards.

**Exit gate**
- Analyst can triage cross-tenant, open a case, **approve** an enforcement action, and export to a
  SIEM via OCSF — all without touching a host.
- Sigma rules import and fire; tuning/suppression works end-to-end.
- A destructive action is blocked without approval and audited when approved.

---

## Phase 3 — Reliability, compliance & GA · ~3–4 months

**Goal:** run it like a product an MSSP bets its customers on.

**Workstreams & deliverables**

- **HA & scale** — multi-AZ control plane, autoscaling ingest/detection, no SPOF, load testing at
  target fleet size; per-tenant quotas.
- **DR & retention** — backup/restore, cross-region DR drill, hot→cold retention tiers, tenant
  data export/delete (DSAR).
- **Agent fleet lifecycle** — safe fleet-wide upgrade/rollback with canary rings, version matrix,
  graceful degrade (detect-only) on kernel/BPF incompatibility.
- **Observability** — traces + logs + metrics across the control plane (extend existing OTel),
  SLOs + alerting on the platform itself.
- **Security & supply chain** — signed agents/bundles, provenance (SLSA-style), dependency
  pinning, external **pen-test**, secrets in Vault/KMS.
- **Compliance program** — **SOC 2 Type II** + **ISO 27001** control mapping (leverage the
  hash-chained audit), **Kenya DPA** data-flow docs + retention/DSAR, **residency/in-country
  hosting option** (same code, single-tenant packaging).
- **Commercialisation** — tenant onboarding/provisioning automation, billing/metering, licensing.

**Exit gate (== GA / "enterprise-ready" in `plan.md` §11)**
- HA with a passed DR drill; agents upgrade fleet-wide safely.
- Pen-test passed; SOC 2 in progress; DPA satisfied; residency option available.
- Self-serve tenant onboarding + metering live.

---

## Phase 4 — Broaden the platform · ongoing

**Goal:** deliver the "broaden toward a fuller platform" mandate on the now-solid spine. Each item
is a new **sensor** or **integration** feeding the same ingest → bus → detection → cases pipeline.

**Candidate workstreams (prioritise by customer pull)**

- **Windows / endpoint sensor** — biggest coverage gap for a telco estate (README notes Linux-only).
- **Cloud connectors** — cloud audit-log ingestion, CSPM-lite posture checks.
- **Network / NDR telemetry** — extend beyond the device-choke MAC gateway.
- **SIEM/telemetry ingestion (inbound)** — accept third-party events into the detection engine.
- **ML / baseline anomaly detection** — the "no baseline learning" gap; per-tenant behavioural
  baselines layered on the chain scorer.
- **Auto score path for the device (MAC) gateway** — the last stated "what's next"; closes
  limitation **#5** with real automated device scoring.

**Discipline:** treat the honest **"cannot solve" list** as integration boundaries, not build
targets — integrate with WAF/CSPM/DLP/fraud tools rather than reimplementing them, until customer
pull justifies owning a category.

---

## Dependency map (why this order)

```
Phase 0 hygiene ─┬─▶ Phase 1 spine ──┬─▶ Phase 2 detection+response ──┬─▶ Phase 3 GA ──▶ Phase 4 breadth
  (split, CI,    │   (tenancy, data, │   (needs central data + RBAC   │   (needs the whole
   isolation doc)│    ingest, mTLS)  │    to be meaningful)           │    thing to harden)
                 │                   │                                 │
   live-demo ────┘   isolation ──────┘   approvals/change-control ─────┘
   stays up          invariant             gate destructive fleet actions
```

- Phase 1 needs Phase 0's build split + isolation invariant.
- Phase 2's cross-host detection and case management are meaningless without Phase 1's central data
  and identity.
- Phase 3 hardens what Phases 1–2 built.
- Phase 4 breadth only pays off on a spine that already isolates tenants and scales — hence last.
