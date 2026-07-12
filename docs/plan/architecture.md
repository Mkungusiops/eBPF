# Target Architecture — Multi-Tenant SOC Platform

Companion to [`plan.md`](plan.md). This document specifies the target system: the agent /
control-plane split, each control-plane service, the wire contract, the data model, and how tenant
isolation is enforced end-to-end.

---

## 1. The split — from monolith to agent + control plane

Today `engine/cmd/engine/main.go` wires *everything* into one root process: gRPC client to
Tetragon, scorer, process tree, both choke gateways, the store, the OTel meter, and the embedded
HTTP console. Enterprise requires cutting this along one seam:

```
                     TODAY (monolith)                          TARGET (two build targets, shared internal/)

  ┌───────────────────────────────────────┐        ┌─────────────────────┐     ┌───────────────────────────┐
  │ engine (root, one host)               │        │ choke-agent (root)  │     │ control-plane (K8s, HA)   │
  │  Tetragon client ─┐                   │        │  Tetragon client    │     │  ingest / detection /     │
  │  scorer, tree     ├─ correlate        │  ───▶  │  scorer, tree       │────▶│  fleet / identity /       │
  │  choke gateways   ┘                   │        │  choke gateways     │ mTLS│  cases / integrations /   │
  │  store (SQLite)                       │        │  store = local WAL  │     │  console API              │
  │  api (console + fleet fan-out)        │        │  uplink client      │◀────│  command channel          │
  └───────────────────────────────────────┘        └─────────────────────┘     └───────────────────────────┘
```

**What moves where:**

| Package (today) | Destination | Notes |
|-----------------|-------------|-------|
| `internal/choke/`, `internal/enforce/`, `internal/score/`, `internal/tree/`, `internal/device/`, `internal/origin/`, `internal/sysproc/` | **Agent** | The sensing + enforcing core. Ships largely intact. |
| `internal/store/` (SQLite path) | **Agent** (as offline buffer) **and** control plane (as central, on Postgres+ClickHouse) | The `dialect` seam in `store/sqlite.go` splits cleanly. |
| `internal/config/` | **Both** | Splits into agent config (local + pulled signed policy) and control-plane config. This is the file currently open — expect it to grow and fork. |
| `internal/metrics/` | **Both** | Already push-model OTel; agent exports to the control-plane collector. |
| `internal/api/` (console, auth, fleet) | **Control plane** | Auth becomes multi-tenant identity; fleet fan-out becomes the fallback path behind the real command channel. |
| `cmd/engine/main.go` | **Split** into `cmd/agent/` and `cmd/controlplane/` | Strangler: keep `cmd/engine` building during the transition. |

**Migration mechanic:** introduce `cmd/agent` and `cmd/controlplane` as thin new entrypoints over
the *same* `internal/` packages in Phase 0 (no behaviour change). Then hollow out `cmd/engine`
until it can be deleted.

---

## 2. The Choke Agent (per host)

Runs as root next to Tetragon on every protected Linux host. Design goal: **autonomous by default,
coordinated when connected.**

**Responsibilities**

- Everything the current engine does *locally*: subscribe to Tetragon gRPC, build the `exec_id`
  process tree, score chains, drive both choke gateways (process cgroup + device tc/MAC), seed
  honeypots, attribute SSH origins.
- **Local persistence as an offline buffer.** The current SQLite WAL store becomes a durable queue:
  events/alerts/decisions are written locally, then shipped upstream; unshipped rows survive
  restarts and network partitions and drain on reconnect.
- **Uplink client** to the control plane (see §4): stream telemetry up, receive policy/config/
  commands down, heartbeat.
- **Policy pull.** Instead of reading `policies/` from local disk only, the agent pulls **signed
  policy bundles** (Tetragon TracingPolicies + ChokePolicy DSL + thresholds + protected-process
  lists) from the control plane, verifies the signature, and applies them. Local files remain a
  bootstrap/fallback.
- **Self-report**: agent version, kernel, BTF availability, data-plane state (`plane=tc|noop`,
  links, frames), enforcement mode.

**Non-goals for the agent**

- No embedded multi-tenant console (that leaves for the control plane). A minimal **localhost-only**
  debug/health endpoint stays for field diagnostics.
- No direct DB other than its local buffer.

**Autonomy contract (the moat, do not break):**

- If the control plane is unreachable, the agent **keeps enforcing** its last-applied signed policy
  and **keeps buffering** evidence. Kernel containment never depends on the cloud being up.
- Enforcement mode changes and destructive fleet commands are *received* from the control plane but
  the agent applies conservative local guardrails (protected lists, kill-switch) regardless.

**Enrollment (mTLS):**

1. Operator generates a short-lived, one-time **bootstrap token** in the console (scoped to a
   tenant).
2. Agent starts, presents the token, generates a keypair, sends a CSR.
3. Control plane's enrollment service verifies the token, issues a **client certificate** whose
   subject encodes `tenant_id` + `agent_id`.
4. All subsequent uplink is mTLS with that cert. Certs are short-lived and auto-rotated.

---

## 3. Control-plane services

Deployed on Kubernetes, multi-AZ, behind an API gateway / load balancer. Each is independently
scalable; all are tenant-aware.

### 3.1 Ingest / Collector
- Terminates agent **mTLS**, extracts `tenant_id` + `agent_id` from the cert (never trusts a
  client-supplied tenant field).
- Validates, normalises, and **stamps tenant_id** onto every record, then publishes to the message
  bus. Stateless and horizontally scalable — this is the **central fan-in collector** the README
  says is missing.
- Backpressure + per-tenant rate limits protect the platform from a noisy/compromised fleet.

### 3.2 Message bus (Kafka / NATS JetStream / Redpanda)
- Decouples ingest from processing, absorbs spikes, enables **replay** for reprocessing and new
  detections. Topics partitioned by tenant.

### 3.3 Data platform
- **ClickHouse** — high-volume events/telemetry (`process_exec` is firehose-scale). Partitioned by
  `tenant_id` + time; TTL-based retention tiers (hot → cold). This is the SQLite/Postgres successor
  the README names.
- **Postgres** — control-plane relational state: tenants, users, roles, agents, enrollment, cases,
  policies, integrations, billing, and the **central mirror of the hash-chained decisions audit**.
  Extends today's `internal/store` Postgres dialect.
- **Object storage (S3-compatible)** — cold archive, forensic snapshots (the existing
  `forensic-snapshot` action lands here), and tenant data exports.

### 3.4 Detection engine
- Consumes the bus and runs **cross-host correlation** within a tenant (lateral movement, chains
  that span hosts) — a superset of today's single-host `score/scorer.go`.
- **Rule pipeline:** native chain rules + **Sigma → rule** translation (a stated "what's next"),
  versioned as **detection-as-code** with a tuning/suppression workflow.
- **Threat-intel enrichment** (IP/hash/domain reputation) and **MITRE ATT&CK** mapping (already
  present per-event) at tenant scope.
- Emits **alerts** and **case candidates**; later hosts **ML/baseline anomaly** models (Phase 4).
- Sensor-agnostic: the same engine will score non-eBPF telemetry when new sensors arrive.

### 3.5 Fleet / command service
- Authoritative **agent registry** (identity, version, kernel, health, last check-in, mode,
  data-plane state).
- **Config/policy distribution**: builds and **signs policy bundles**, targets them by tenant /
  group / ring, tracks rollout status.
- **Command channel**: dispatches operator actions (jail/thaw/kill-switch/preset/threshold) to
  specific agents with **approval gates** and full audit. Replaces the client-driven fan-out in
  `api/fleet.go`; that fan-out survives only as a degraded fallback.
- Staged rollout rings (canary → limited → fleet) reuse the model in `production-rollout/README.md`.

### 3.6 Identity & tenancy
- **Orgs/tenants**, users, **RBAC** (roles: MSOC-admin, tenant-analyst, read-only, cross-tenant
  responder, etc.), **SSO via OIDC/SAML**, **SCIM** provisioning, **API tokens**, session
  management. Replaces the single-user `api/auth.go`.
- Issues tenant-scoped access tokens consumed by every other service. **Cross-tenant** visibility
  is an explicit, audited privilege for MSOC roles only.

### 3.7 Cases & response (SOAR-lite)
- **Case management**: group alerts into incidents, assign, status, timeline, SLA clocks per tenant.
- **Playbooks & approvals**: destructive enforcement runs through change-control; notifications and
  ticketing are actions.

### 3.8 Integrations
- **Outbound**: SIEM export via **OCSF** (a stated "what's next"), plus CEF/syslog; webhooks;
  Slack/PagerDuty/Teams; Jira/ServiceNow.
- **Inbound (Phase 4)**: SIEM/telemetry ingestion, threat-intel feeds, and new sensor classes.

### 3.9 Console (multi-tenant React app)
- Evolves `web/src/` — the SOC/Choke/Devices/Fleet panels are reused. Adds an **org/tenant
  switcher**, admin surfaces (users/roles/integrations/billing), case management, and reporting.
- AuthN via OIDC; AuthZ via RBAC; every API call is tenant-scoped by the gateway.

---

## 4. Agent ↔ control-plane wire contract (first Phase-1 artifact)

Define this before building either side. Sketch:

| Channel | Direction | Transport | Purpose |
|---------|-----------|-----------|---------|
| **Enroll** | agent → CP | mTLS bootstrap → CSR | One-time cert issuance, binds `tenant_id`+`agent_id` |
| **Telemetry uplink** | agent → CP | mTLS gRPC stream (or OTLP for metrics) | Events, alerts, decisions; batched, resumable, at-least-once with dedup keys |
| **Command channel** | CP → agent | mTLS bi-di gRPC stream (or long-poll fallback) | jail/thaw/kill-switch/preset/threshold/mode; each command carries an id, is acked, and is audited both ends |
| **Policy pull** | agent → CP | mTLS HTTPS | Signed policy bundle by version/etag; agent verifies signature before apply |
| **Heartbeat** | agent → CP | mTLS gRPC | Health, version, kernel, data-plane state, buffer depth |

Design requirements: **idempotent** telemetry (dedup on agent-assigned ids so replays after
reconnect don't double-count), **backpressure** (control plane can throttle a flooding agent),
**resumability** (agent tracks last-acked offset in its local WAL), and **signed everything**
downstream (policy + command provenance).

---

## 5. Tenant isolation — the invariant

Isolation is enforced at four layers so no single bug leaks data:

1. **Identity:** tenant_id is derived from the agent's **mTLS client cert**, not from any
   client-supplied field. Operators get tenant scope from their **RBAC role**.
2. **Ingest:** every record is stamped with the derived tenant_id at the collector before it hits
   the bus.
3. **Storage:** ClickHouse partitions and Postgres rows are keyed by tenant_id; every query is
   tenant-filtered by a shared data-access layer (no raw queries bypass it). Per-tenant encryption
   context at rest.
4. **API:** the gateway injects tenant scope into each request; handlers cannot widen it except via
   an explicit, audited cross-tenant MSOC role.

**Test the invariant:** automated CI tests that attempt cross-tenant reads through every API and
query path and assert denial; external pen-test before GA.

---

## 6. What stays sacred (do not regress in the rewrite)

- **In-kernel graduated enforcement** (throttle→tarpit→quarantine→sever) keyed on `exec_id`.
- **Offline autonomy** — enforcement without the cloud.
- **Hash-chained, verifiable audit** (`store/decisions.go`, `/api/verify-chain`) — now mirrored
  centrally and used as a compliance control.
- **Device (MAC) choke** data plane — becomes a second sensor/enforcer class under the same fleet
  control.
- **Single-binary agent ergonomics** — the agent stays a statically-linked, dependency-free Go
  binary; only the *console/data* tier gets heavier.
