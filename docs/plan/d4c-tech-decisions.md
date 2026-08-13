# D4c Infrastructure Decisions (ADR)

> **What this is:** the technology choices for the Phase 1 data platform + identity
> tier ("D4c"): message bus, event store, control-state DB, object store, identity
> provider, and console. Companion to [`architecture.md`](architecture.md) §3 and
> [`roadmap.md`](roadmap.md) Phase 1. Status: **accepted**.

---

## 1. The overriding constraint

The dominant driver is **data residency**, not SaaS velocity. [`plan.md`](plan.md)
§1 commits to shipping the *same code* single-tenant on-prem for telcos who
cannot use shared SaaS. Therefore:

> **Every component on the critical path must be OSI open source under a
> permissive license (Apache-2.0 / MIT / BSD / PostgreSQL) and self-hostable,
> while also offering a managed service for the SaaS plane. No source-available
> (BSL), no strong copyleft (AGPL), and no cloud-proprietary component (Aurora,
> Kinesis, Cognito) anywhere we redistribute.**

"Buy don't build" (plan.md §9) is honoured for the SaaS plane via managed
offerings of the *same* OSS engines — never by adopting a component we cannot
also ship on-prem.

---

## 2. The stack

| Layer | Decision | License | SaaS (managed) | On-prem (self-hosted) |
|------|----------|---------|----------------|-----------------------|
| **Message bus** | **NATS JetStream** | Apache-2.0 | Synadia Cloud | single binary |
| **Events (firehose)** | **ClickHouse (OSS engine)** | Apache-2.0 | ClickHouse Cloud | self-hosted |
| **Control state** | **PostgreSQL + RLS** | PostgreSQL | RDS / Cloud SQL | self-hosted PG |
| **Object store** | **SeaweedFS** | Apache-2.0 | cloud S3 | SeaweedFS |
| **Identity** | **Keycloak** (broker) | Apache-2.0 | Cloud-IAM / PhaseTwo | self-hosted |
| **Console** | evolve React/Vite + BFF auth | MIT | CDN | `go:embed` in control plane |

Everything shipped is permissive OSS — **no BSL, no AGPL, no proprietary** in the
redistributed artifact. Managed cloud services (ClickHouse Cloud, RDS, S3) are
proprietary by nature but are SaaS-plane convenience only; they are never shipped.

---

## 3. Decisions & rationale

### 3.1 Message bus → NATS JetStream (Apache-2.0)
Decouples ingest from processing, absorbs spikes, and enables replay for
reprocessing/new detections (architecture.md §3.2).

- **Why NATS:** Go-native single binary (trivial ops for a lean team, embeddable
  in-process for real tests); **NATS accounts give hard per-tenant isolation at
  the transport layer** — a defense-in-depth reinforcement of the platform's #1
  risk (tenant isolation); Apache-2.0 with no copyleft.
- **Cost:** not Kafka-protocol, so the ClickHouse consumer is a small Go service
  we own (rather than ClickHouse's native Kafka table engine). Acceptable — we
  want that seam under our control anyway, and it wires to `centralstore` today
  and ClickHouse later.
- **Alternative — Apache Kafka (KRaft), Apache-2.0:** choose this if the
  Kafka-native ClickHouse engine + Sigma/OCSF ecosystem outweighs NATS's ops
  simplicity and tenancy. Kept as the documented fallback; the `bus.Bus`
  interface (see §4) makes the swap a single adapter.
- **Rejected:** Redpanda (BSL — source-available, redistribution friction);
  WarpStream (proprietary); RabbitMQ (wrong tool — a broker, weak at
  replay/retention); Pulsar (native multi-tenancy is attractive but the ops
  weight — brokers + BookKeeper + metadata store — is unjustified for a lean team
  now).

### 3.2 Events → ClickHouse, OSS engine (Apache-2.0)
Because the engine is Apache-2.0, the **same schemas/queries run in ClickHouse
Cloud (SaaS) and self-hosted (on-prem)** — no fork. Design tenant+time
partitioning with **TTL tiers (hot → cold object storage)** from day one to
answer the "data-platform cost at telco scale" risk (plan.md §9). Avoid
Cloud-only features to preserve parity. **Sequencing:** not required to *exit*
Phase 1 — Postgres handles early `process_exec` volume; add ClickHouse when the
firehose demands it.

### 3.3 Control state → PostgreSQL + Row-Level Security (PostgreSQL License)
Vanilla Postgres, **not Aurora** (Aurora cannot ship on-prem). Managed for SaaS
(RDS/Cloud SQL), self-hosted on-prem — same schema. Fits the existing
`internal/store` Postgres dialect. **Turn on Postgres RLS** as a *second*
enforcement of tenant scoping beneath the app-layer `internal/authz` (Layer 4) and
`internal/centralstore` (Layer 3) — defense in depth, so a missing tenant filter
cannot leak.

### 3.4 Object store → SeaweedFS (Apache-2.0)
S3-compatible, lightweight, lean ops — the permissive-OSS pick for self-hosted
cold/forensic snapshots + exports. Cloud S3 for the SaaS plane (same API → same
code). **Rejected for the shipped artifact:** MinIO and Garage (AGPL-3.0 — strong
copyleft). Ceph/RGW (LGPL-2.1) is an acceptable scale alternative if a customer
already runs it. Lowest-urgency component (cold path, S3-abstracted).

### 3.5 Identity → Keycloak (Apache-2.0), as an OIDC broker
Only **humans** hit the IdP — agents authenticate by **mTLS cert** (already built:
`internal/mtls`), so the user population is a handful of MSOC analysts + tenant
admins, not the fleet. Residency rules out Auth0/Entra as the *primary* (cannot
self-host). Keycloak is OSS, self-hostable, does OIDC/SAML/**SCIM**, and — the key
win — **brokers/federates to each customer's own IdP** (Entra/Okta/Google), so
"SSO with our directory" works without integrating each one. `internal/authz`
stays the RBAC authority (built IdP-agnostic on purpose); Keycloak supplies authN
+ group/role claims that map into `authz.Principal`.
- **Rejected for primary:** Auth0/Entra/WorkOS (managed-only → would force a
  second identity backend for on-prem).

### 3.6 Console → evolve the existing React app, BFF auth
Keep React/Vite/zustand/Radix/d3 (all MIT/ISC) and reuse the SOC/Choke/Devices/
Fleet panels — a rewrite would burn the one frontend engineer's runway. Add:
(a) **BFF / token-handler auth** — OIDC handled server-side, tokens never in the
browser (right call for a security product); (b) **TanStack Query + Router + a
`TenantProvider`** where the tenant switcher is UX only and the server (`authz`)
is the sole scope authority; (c) keep it **`go:embed`-served by the control-plane
binary** for single-artifact on-prem deploys (CDN optional for SaaS).

---

## 4. How this slots into what's built

The Phase 1 spine was built with these seams so D4c is adapter work, not rework:

- `ingest.Sink` (interface) → becomes the **bus publisher**; the bus consumer
  writes to the store. See `internal/bus`.
- `centralstore` (dialect seam, tenant in PK, fail-closed) → the **Postgres/
  ClickHouse** backend behind the same tenant-scoped API.
- `internal/authz` (IdP-agnostic RBAC) → consumes **Keycloak** claims.
- `internal/mtls` → already the agent identity layer; Keycloak is humans-only.

---

## 5. Sequencing (don't stand it all up at once)

Ship the spine on the minimum, add scale components by need:

1. **Keycloak + Postgres/RLS + evolved console** — the Phase 1-minimum control plane.
2. **NATS JetStream** — decouple ingest from processing.
3. **ClickHouse** — when `process_exec` volume demands it (cost/scale, not correctness).
4. **SeaweedFS + cold-tier retention** — forensic/export/archive.

A lean team should not operate five stateful systems on day one.
