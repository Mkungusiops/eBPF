# Threat Model — Multi-Tenant SOC Platform

> **What this is:** the security threat model for the platform we are building
> in [`plan.md`](plan.md) / [`architecture.md`](architecture.md). It enumerates
> what can go wrong across the four highest-risk surfaces — the **control
> plane**, the **agent↔cloud channel**, **enforcement blast radius**, and the
> **supply chain** — and the mitigations, tagged with the phase that delivers
> them.
>
> **Why now (Phase 0):** *"this is a security product — our own posture is part
> of the product"* ([`plan.md`](plan.md) §8). The model is written before the
> spine so that Phase 1 designs against named threats, not in hindsight.
>
> **Companion:** cross-tenant data leakage is modelled in depth in
> [`tenant-isolation-invariant.md`](tenant-isolation-invariant.md); this document
> references it rather than repeating it.
>
> **Status:** living document (Phase 0). Revisit each phase and before the
> pre-GA pen-test.

---

## 1. Scope, method, and trust boundaries

**Method.** Per surface: assets → adversaries → threats (STRIDE-tagged) →
mitigations (existing / planned, with phase). STRIDE = **S**poofing,
**T**ampering, **R**epudiation, **I**nfo-disclosure, **D**enial-of-service,
**E**levation-of-privilege.

**Trust boundaries** (data crosses a boundary ⇒ it is validated + re-authorized):

```
 [ customer host ]              boundary 1              [ CONTROL PLANE ]        boundary 3
  ┌──────────────┐   mTLS uplink / command channel   ┌──────────────────┐   HTTPS + OIDC
  │ choke-agent  │ ───────────────────────────────▶ │ ingest → bus →   │ ◀──────────────  operator
  │ (root)       │ ◀─────────────────────────────── │ data / detection │        browser / API
  └──────────────┘        (boundary 2: the wire)     │ / fleet / API    │
        │                                            └──────────────────┘
   boundary 0:                                              │  boundary 4:
   kernel ⇄ userspace                              CP ⇄ datastores / object store / bus
```

**Primary assets.** (1) Tenant telemetry, alerts, and the **hash-chained
decision audit** (`internal/store/decisions.go`); (2) enforcement authority over
customer hosts (the ability to throttle/quarantine/**kill** processes); (3)
tenant isolation; (4) enrollment/identity credentials and signing keys; (5)
platform availability.

**Cardinal invariants** (violating any is a critical finding):
- **Agent autonomy** — kernel enforcement never depends on the cloud being
  reachable ([`architecture.md`](architecture.md) §2/§6).
- **Derived tenant identity** — never trust a client-supplied `tenant_id`
  ([`tenant-isolation-invariant.md`](tenant-isolation-invariant.md) §3).
- **Signed-only downstream** — agents apply only signed policy/command bundles.
- **Untouched audit chain** — the tamper-evident decision log is append-only and
  verifiable, mirrored per tenant.

---

## 2. Adversaries

| # | Adversary | Capability assumed |
|---|-----------|--------------------|
| A1 | **Malicious/curious tenant insider** | Valid creds + agents in *their own* tenant; crafts uplink payloads and API calls. Wants another tenant's data or to abuse enforcement. |
| A2 | **Compromised agent host** | Root on one customer host; can send arbitrary bytes over that host's mTLS session. |
| A3 | **Network adversary** | On-path between agent and cloud (MITM, replay, downgrade). |
| A4 | **External attacker on the control plane** | Unauthenticated internet access to the CP edge; hunts web/API vulns. |
| A5 | **Malicious operator / rogue MSOC analyst** | Legitimate console access; abuses privilege or destructive actions. |
| A6 | **Supply-chain attacker** | Can attempt to poison a dependency, build, image, or policy bundle. |
| A7 | **Stolen-credential attacker** | Holds a leaked agent cert, bootstrap token, session, or signing key. |

---

## 3. Surface A — Control plane

Assets: all tenant data, identity, signing authority, availability.

| ID | Threat (STRIDE) | Adversary | Mitigation | Phase |
|----|-----------------|-----------|------------|:---:|
| CP-1 | **AuthN/Z bypass**; single-admin era's HMAC cookie is not multi-tenant (E,S) | A4,A5 | Replace `internal/api/auth.go` with OIDC/SSO + **RBAC**; tenant-scoped tokens on every service; sessions server-verified. Crypto in `auth.go` is sound and **left untouched** in Phase 0. | 1 |
| CP-2 | **Plaintext / default credentials** shipped (I,S) | A7 | **Done (Phase 0, this change):** the built-in `-pass` default is removed; a missing password **fails fast**. No known credential ships. Secrets move to Vault/KMS. | 0,3 |
| CP-3 | **Cross-tenant data leak** via API/query (I) | A1,A5 | The full four-layer invariant + required cross-tenant CI matrix — see [`tenant-isolation-invariant.md`](tenant-isolation-invariant.md). | 1 |
| CP-4 | **Web/API exploitation** — injection, SSRF, deserialization, path traversal (T,E) | A4 | Parameterized queries via the single data-access layer; input validation at the gateway; SSRF egress controls; dependency scanning (Phase 0 SBOM). | 1–3 |
| CP-5 | **Privilege abuse by operators** — unlogged destructive actions (R,E) | A5 | RBAC least-privilege; **change-control/approvals** for destructive fleet actions; every action written to audit; cross-tenant grants explicitly logged. | 2 |
| CP-6 | **Datastore / object-store compromise** (I,T) | A4,A7 | Network segmentation; encryption at rest with **per-tenant context**; least-priv DB roles; no CP-wide DB superuser in the request path. | 1,3 |
| CP-7 | **DoS / resource exhaustion** (D) | A1,A4 | Per-tenant quotas + rate limits; bus backpressure; autoscaling + HA (Phase 3). | 1,3 |
| CP-8 | **Compromised CP container** (E,T) | A6 | **Distroless + nonroot** image (Phase 0 `deploy/controlplane.Dockerfile`); signed image + SBOM (Phase 0 CI); minimal CVE surface; read-only FS where possible. | 0,3 |

---

## 4. Surface B — Agent ↔ cloud channel (the wire)

Assets: uplink telemetry integrity, command authenticity, tenant identity,
availability. The wire contract is the first Phase-1 artifact
([`architecture.md`](architecture.md) §4); it must be designed against this table.

| ID | Threat (STRIDE) | Adversary | Mitigation | Phase |
|----|-----------------|-----------|------------|:---:|
| CH-1 | **Eavesdrop / MITM / downgrade** (I,T) | A3 | **mTLS both directions**, modern TLS floor, cert pinning to the platform CA; no plaintext fallback. | 1 |
| CH-2 | **Tenant spoofing** — agent forges `tenant_id` in payload (S,E) | A1,A2 | Tenant derived **only** from the mTLS client-cert subject at ingest; payload tenant fields ignored for authz (isolation invariant R1/Layer 2). | 1 |
| CH-3 | **Telemetry replay / duplication** after reconnect (T,R) | A2,A3 | Idempotent uplink with **agent-assigned dedup keys**; at-least-once + dedup so replays don't double-count; resumable from last-acked WAL offset. | 1 |
| CH-4 | **Compromised agent floods ingest**, starving other tenants (D) | A2 | Per-tenant rate limits + backpressure at the collector; a noisy/hostile fleet cannot degrade neighbours. | 1 |
| CH-5 | **Forged / spoofed commands** to an agent (S,T,E) | A3,A7 | Command channel is mTLS; **every command is signed**, carries an id, is acked, and is **audited both ends**; agent verifies provenance before acting. | 1 |
| CH-6 | **Stolen agent certificate** reused elsewhere (S) | A7 | **Short-lived, auto-rotated** certs; **one-time** bootstrap tokens scoped to a tenant; revocation + re-enrollment; anomaly on duplicate agent_id check-ins. | 1,3 |
| CH-7 | **Cloud outage weaponized** to disable enforcement (D→E) | A3 | **Autonomy invariant:** channel down ⇒ agent keeps enforcing last **signed** policy and buffers evidence locally. The cloud is never a prerequisite for containment. Tested in CI (offline enforcement). | 1 |

---

## 5. Surface C — Enforcement blast radius

This platform can **SIGKILL processes and sever network devices across a fleet**.
That authority is the product *and* the largest self-inflicted risk. The canonical
failure is documented and real.

### 5.1 The canonical failure: the sudo-lockout trap

In **ENFORCING** mode the process choke scores `/usr/bin/sudo` at ~120+ and
**severs it**, so every `sudo` — and any deploy step needing root — is
**SIGKILL'd (exit 137)** and the host looks "locked"
([`docs/deployment/live-soc-adanianlabs.md`](../deployment/live-soc-adanianlabs.md)
§3). Two compounding traps from the live box:

1. Boot mode comes **only** from the `-enforce` flag, not the store; the UI
   toggle is runtime-only and **does not survive restart** — a restart can
   silently re-arm severing.
2. **Tetragon's own TracingPolicies enforce independently** of the engine's mode
   (§4 of the same runbook): flipping the *engine* to detect-only does **not**
   disable Tetragon `Sigkill` policies (e.g. `override-credential-read`,
   `sever-pipe-to-shell`). This already **breaks `apt`** on the live box. There
   are *two* enforcement authorities on a host, and they must be reasoned about
   together.

Now multiply that by a fleet of tenants' production servers. A bad threshold, a
bad bundle, or a careless "enforce all" is a **customer-wide outage**.

### 5.2 Threats & guardrails

| ID | Threat (STRIDE) | Adversary | Mitigation | Phase |
|----|-----------------|-----------|------------|:---:|
| EN-1 | **Self-lockout** — enforcement kills recovery paths (`sudo`, `sshd`, `systemd`, package mgmt) (D) | operator error, A5 | **Detect-only default** everywhere; central **protected-process / system-critical allow-lists** (the seam exists today: `choke.DefaultSystemCriticalBinaries()` bypasses score-driven enforce) covering sudo/ssh/init/pkg-mgmt; mode is explicit and its persistence is well-defined. | 2 |
| EN-2 | **Fleet-wide destructive action** — one command quarantines/severs many hosts (D) | A5, compromised CP | **Approvals / change-control** on destructive actions; **staged rollout rings** (canary→limited→fleet, reusing `production-rollout/`); a **fleet kill-switch** to halt enforcement instantly. | 2 |
| EN-3 | **Two enforcement authorities diverge** — engine detect-only but Tetragon still Sigkills (D,R) | operator confusion | Model host enforcement as *engine mode ∪ active Tetragon enforce policies*; surface both in agent self-report/health; central policy management owns both; document the coupling. | 1,2 |
| EN-4 | **Malicious/erroneous policy bundle** raises severity or removes exemptions (T,D,E) | A6,A7 | **Signed** bundles only (agent verifies before apply); bundle diffs reviewed/approved; local conservative guardrails (protected lists, kill-switch) apply **regardless** of what a bundle says. | 1,2 |
| EN-5 | **Restart re-arms enforcing mode** unexpectedly (D) | operator error | Make boot mode explicit and observable; default detect-only; alert when a host boots into enforcing; per-tenant enforcement mode is centrally recorded. | 1,2 |
| EN-6 | **kernel/BPF incompatibility** crashes or fails-open on a host (D) | environment | Conservative attach; **graceful degrade to detect-only** on incompatible kernels; kernel-version matrix testing; canary rings. | 3 |

**Guiding rule:** enforcement escalates *toward* destructive only through
detect-only defaults, protected lists, approvals, staged rings, and a
kill-switch — never in one fleet-wide step, and never able to kill its own
recovery path.

---

## 6. Surface D — Supply chain & bundle signing

Assets: integrity + provenance of everything that runs on a customer host or in
the control plane — the agent binary, the CP image, dependencies, **policy
bundles**, and **commands**.

| ID | Threat (STRIDE) | Adversary | Mitigation | Phase |
|----|-----------------|-----------|------------|:---:|
| SC-1 | **Tampered release artifact / image** (T) | A6 | **Signed** artifacts + container image via **cosign keyless** (Sigstore/Fulcio + Rekor transparency log) — Phase 0 CI; verify-on-deploy. | 0,3 |
| SC-2 | **Unknown / vulnerable dependencies** (T,I) | A6 | **SBOM** generated + attested in CI (Phase 0); pinned deps (`go.sum`, `package-lock.json`); dependency/vuln scanning; review of new deps. | 0,3 |
| SC-3 | **Build provenance forgery** (T,R) | A6 | **SLSA-style provenance** attestation on the image (Phase 0 CI `provenance:`); reproducible, `-trimpath` builds; hermetic CI. | 0,3 |
| SC-4 | **Malicious policy bundle** distributed to agents (T,E) | A6,A7 | Bundles are **signed by the fleet service**; the agent **verifies the signature before applying** (architecture.md §2); local files are bootstrap/fallback only; see EN-4. | 1 |
| SC-5 | **Malicious auto-update** of the agent (T,E) | A6,A7 | Agents update **only from signed bundles**; staged rollout rings; rollback; version pinning per ring. | 3 |
| SC-6 | **Stolen signing key** (S,T) | A7 | **Keyless** signing (ephemeral Fulcio certs, no long-lived private key to steal) with transparency-log inclusion; scoped OIDC identities; key/rotation policy for any non-keyless secrets (Vault/KMS). | 0,3 |
| SC-7 | **Compromised bootstrap/enrollment token** (S,E) | A7 | Short-lived, **one-time**, tenant-scoped bootstrap tokens; enrollment issues certs bound to `tenant_id`+`agent_id`; anomalous-enrollment alerting. | 1 |

---

## 7. Cross-cutting controls

- **Tenant isolation** — the dedicated invariant + CI gate
  ([`tenant-isolation-invariant.md`](tenant-isolation-invariant.md)).
- **Auditability** — the hash-chained decision log is the tamper-evident record
  of *what enforcement did*; mirrored centrally **per tenant**; a compliance
  control we already have ([`plan.md`](plan.md) §8). Operator/command actions are
  audited too (CP-5, CH-5).
- **Secrets** — no plaintext credentials anywhere (CP-2, done in Phase 0);
  Vault/cloud-KMS for the control plane; short-lived agent material.
- **Least privilege** — distroless/nonroot CP containers (Phase 0); scoped RBAC;
  scoped OIDC identities in CI.

---

## 8. Residual risks & assumptions

- **Root agent on the host.** The agent runs as root next to Tetragon; a fully
  root-compromised host (A2) can lie about *its own* telemetry and evade its own
  enforcement locally. Mitigation is limited to blast-radius containment (it
  cannot reach other tenants — CH-2/CH-4 — and cannot forge the central audit
  chain retroactively) and cross-host correlation (Phase 2).
- **Full control-plane compromise** (DB root, CP RCE, stolen keyless-signing
  OIDC identity) breaks tenancy by definition; defended by CP hardening, HA,
  least privilege, and the external **pen-test** (Phase 3), not by this model
  alone.
- **Infrastructure side channels** on the shared substrate — see
  [`tenant-isolation-invariant.md`](tenant-isolation-invariant.md) §6; deferred
  to the pen-test.
- **Kernel/eBPF fragmentation** across customer fleets (EN-6) — an availability
  risk managed by graceful degrade + canary rings, not eliminated.

---

## 9. What Phase 0 already delivers (from this model)

- **CP-2 / SC-6:** removed the plaintext credential default; missing password
  fails fast — no known credential ships.
- **CP-8:** distroless + nonroot control-plane image.
- **SC-1 / SC-2 / SC-3:** CI produces a **signed** container image, an **SBOM**,
  and **provenance** attestation.
- **Autonomy (CH-7):** the agent build target carries no cloud dependency for
  enforcement — the split is introduced without ever wiring enforcement to a
  network service.

Everything else is scheduled by phase in the tables above and gated by
[`roadmap.md`](roadmap.md).
