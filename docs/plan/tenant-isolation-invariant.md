# Tenant Isolation Invariant

> **What this is:** the precise, testable specification of what *"one tenant can
> never read another tenant's data"* means for this platform, and the strategy
> that proves it. It expands [`architecture.md`](architecture.md) §5 into an
> engineering contract that **constrains all of Phase 1** — no multi-tenant code
> merges unless it satisfies this document.
>
> **Why it is a Phase 0 artifact:** isolation is structural, not a feature you
> bolt on later ([`plan.md`](plan.md) §8, risk table: *"cross-tenant data leak —
> company-ending for a security vendor"*). Writing the invariant down before the
> spine is built is what stops it from being retrofitted.
>
> **Status:** specification (Phase 0). The mechanisms it describes (ingest,
> central store, identity/RBAC) are built in Phase 1; this doc is their
> acceptance test.

---

## 1. The invariant, stated

> **INV-TENANT.** For any two distinct tenants `A ≠ B`, no principal acting in
> tenant `A`'s scope can cause the platform to return, export, enforce on, or
> otherwise observe data owned by tenant `B` — through any API, query, stream,
> file, log, metric label, error message, or side effect — **unless** that
> principal holds an explicit, audited cross-tenant MSOC grant that names `B`.

The guarantee is **default-deny**: cross-tenant visibility does not exist unless
a specific role explicitly creates it, and every use of that role is logged.

**What "data" covers.** Events (`process_exec`/`process_kprobe`), alerts,
enforcement **decisions** (including the hash-chained audit), device records,
agent inventory/health, policies and policy bundles, cases, forensic snapshots,
exports, billing/usage, and any derived aggregate (counts, dashboards, metrics)
computed from the above.

**What "principal" covers.** Two kinds, with two different sources of tenant
identity (see §3):

| Principal | Is | Tenant identity comes from |
|-----------|----|-----------------------------|
| **Agent** | a host running the choke-agent | its **mTLS client certificate** |
| **Operator** | a human/API client in the console | its authenticated session's **RBAC role bindings** |

---

## 2. Threat model for this invariant

The invariant must hold against a **motivated, authenticated insider to one
tenant**, not merely accidental bugs. Assume the adversary can:

- Enroll/operate agents in **their own** tenant and craft arbitrary uplink
  payloads (including forged `tenant_id` fields, oversized batches, malformed
  records).
- Call every API with a valid session for **their own** tenant, with crafted
  parameters (IDs, filters, pagination cursors, path traversal, injection).
- Observe timing, error codes, and response sizes.

They must **not** be able to read, infer, or affect another tenant's data. A
single defensive layer failing (a missing `WHERE tenant_id = …`, a handler that
trusts a request field) must **not** be sufficient to leak — hence four layers.

Out of scope for *this* document (covered by [`threat-model.md`](threat-model.md)):
platform-wide compromise (control-plane RCE, DB root, stolen signing keys),
which by definition breaks any tenancy model. This doc assumes the platform
itself is not fully compromised and specifies isolation of *legitimate but
adversarial tenant principals*.

---

## 3. Tenant identity: provenance rules (Layer 1 — Identity)

Everything downstream depends on `tenant_id` being **derived, never asserted**.

- **R1 — Agents.** `tenant_id` (and `agent_id`) are read **only** from the
  verified mTLS client-certificate subject at the ingest/command edge. The
  certificate is issued by the enrollment service, which binds the tenant at
  issue time (architecture.md §2 enrollment). Any `tenant_id`/`agent_id` field
  present in an uplink *payload* is **ignored for authorization** — it may be
  compared to the cert for tamper-detection/telemetry, but the cert always wins.
- **R2 — Operators.** An operator's reachable tenants are the set named by their
  **RBAC role bindings**, resolved server-side from the session. The client
  never supplies its own tenant scope; a `tenant_id` in a request body or query
  is treated as a *filter within the already-authorized set*, never as a grant.
- **R3 — No ambient tenant.** There is no "default", "system", or "null" tenant
  that widens scope. Records with an unresolved tenant are quarantined, not
  broadcast.
- **R4 — Enrollment binding is immutable.** An agent cannot change its tenant by
  re-sending a CSR or editing config; re-tenanting requires re-enrollment
  through an audited operator action.

---

## 4. The four layers (defense in depth)

Isolation is enforced at four independent layers so that **no single bug leaks**.
Each layer assumes the others might fail.

### Layer 1 — Identity (derive tenant)
Specified in §3. **Guarantee:** every request/record entering the platform
carries a `tenant_id` the caller could not forge.

### Layer 2 — Ingest (stamp tenant)
The collector terminates agent mTLS, derives `tenant_id` per R1, and **stamps it
onto every normalized record** before publishing to the bus. Client-supplied
tenant fields are stripped/overwritten here. Per-tenant rate limits and
backpressure live here too (a noisy/compromised tenant cannot starve others).
**Guarantee:** nothing reaches the bus or storage without a trusted stamp.

### Layer 3 — Storage (filter by tenant)
- Every table (Postgres) and every partition key (ClickHouse) includes
  `tenant_id`; it is part of the **primary/partition key**, not an incidental
  column.
- **All** reads and writes go through a **single tenant-scoped data-access
  layer** that injects `tenant_id` into every query. Raw/ad-hoc queries that
  bypass it are prohibited (enforced by review + a lint/static check; see §7).
  This layer is the successor to today's `internal/store` dialect seam
  (`Store.dialect`, sqlite|postgres) — the same chokepoint, now tenant-aware.
- The **hash-chained decisions audit** (`internal/store/decisions.go`, preserved
  untouched in Phase 0) is mirrored centrally **per tenant**: one chain per
  tenant, so verification and export never cross tenants.
- Per-tenant **encryption context** at rest (distinct keys/prefixes) so a raw
  storage read of tenant `A`'s bytes is useless for `B` and vice-versa.

**Guarantee:** a query written without an explicit tenant filter returns
*nothing* (fails closed), not another tenant's rows.

### Layer 4 — API (scope every request)
- The API gateway resolves the operator's authorized tenant set (R2) and injects
  it into a request context that handlers **cannot widen**.
- Handlers filter *within* that set. Requesting a resource by ID that belongs to
  another tenant returns **404, not 403** (do not confirm existence across
  tenants — see §6 on side channels).
- **Cross-tenant is the sole explicit exception:** an operator with the MSOC
  `cross-tenant` role may query across a *named* set of tenants. Every such call
  is authorized against that role and **written to the audit log** (who, which
  tenants, what query, when). Absence of the role ⇒ single-tenant scope, always.

**Guarantee:** the widest scope any request can reach is exactly the caller's
authorized tenant set; widening requires a role that leaves an audit trail.

---

## 5. Composite property

The four layers compose into the property CI must defend:

```
INV-TENANT holds  ⟺  for every data path P and tenants A ≠ B:
    identity(P) is derived, not asserted           (Layer 1)
  ∧ every record on P is stamped at ingest         (Layer 2)
  ∧ every storage access on P is tenant-filtered   (Layer 3)
  ∧ every API response on P is scope-clamped        (Layer 4)
  ∧ any cross-tenant read on P requires an audited MSOC grant
```

Each conjunct is independently testable. A violation of any one is a release
blocker.

---

## 6. Side channels & honest non-goals

Structural row/partition scoping is necessary but not sufficient. The invariant
also requires we do **not** leak `B`'s data through:

- **Existence oracles** — 403-vs-404, "already exists" errors, or differing
  latencies that reveal another tenant's IDs. Rule: unauthorized cross-tenant
  access is indistinguishable from "not found".
- **Aggregates & metrics** — dashboard counts, OTel metric **labels**, and log
  lines must be tenant-scoped; `tenant_id` must never appear as a *high-value*
  cross-tenant metric dimension an operator of `A` can read for `B`.
- **Shared caches / connection pools** — cache keys and prepared-statement reuse
  must include `tenant_id`.
- **Exports & forensic snapshots** — the object-store path/prefix and any signed
  URL are tenant-scoped; a snapshot of `A` can never be enumerated by `B`.
- **Error messages** — must not echo another tenant's identifiers or data.

Explicitly **out of scope** (documented, not solved here): infrastructure-level
side channels (CPU/cache timing across the shared K8s substrate), and full
platform compromise. Those belong to [`threat-model.md`](threat-model.md) and the
Phase 3 pen-test.

---

## 7. Test strategy (how we prove it)

Isolation is only real if it is **continuously tested**. Layered tests mirror
the layered defense; the cross-tenant suite is a **required CI gate** ([`roadmap.md`](roadmap.md)
Phase 1 exit: *"Two tenants' data provably isolated (leakage tests green)"*).

**T1 — Identity unit tests (Layer 1).**
Forged payload `tenant_id` is ignored; the cert subject governs. Operator scope
derives only from RBAC bindings. Unresolved tenant ⇒ quarantine, never broadcast.

**T2 — Ingest tests (Layer 2).**
A record whose payload claims tenant `B`, delivered over tenant `A`'s mTLS cert,
is stamped `A` (or rejected) — never `B`. Per-tenant rate limits engage without
affecting other tenants.

**T3 — Storage tests (Layer 3).**
- Property test: for a store seeded with tenants `{A,B}`, **every** data-access
  method called in `A`'s scope returns only `A`'s rows — enumerated over all
  methods so new methods must opt in.
- Negative test: a query constructed without a tenant filter returns empty (fails
  closed), asserted at the data-access layer.
- **Static check / lint:** raw SQL or store access that bypasses the tenant-scoped
  layer fails the build. Per-tenant audit-chain verification never spans tenants.

**T4 — API cross-tenant matrix (Layer 4) — the headline CI gate.**
A generated matrix drives **every** API route and query path with an `A`-scoped
session attempting to reach `B`'s resources (by ID, filter, cursor, path, export
URL). Assert: denial as **404/empty**, never `B`'s data, never a distinguishing
signal. Symmetrically for `B`→`A`. The matrix is generated from the route table
so a newly added route with no isolation test **fails CI** (coverage ratchet).

**T5 — Cross-tenant role tests.**
The MSOC `cross-tenant` role reaches the named tenants **and writes an audit
record** for each access; without the role the same call is single-tenant.
Assert the audit entry exists and is complete.

**T6 — Side-channel tests (§6).**
403-vs-404 uniformity, latency parity on authorized-miss vs cross-tenant-miss,
metric-label scoping, cache-key tenant inclusion, export-prefix scoping.

**T7 — External pen-test (pre-GA).**
Independent adversarial validation of cross-tenant isolation ([`plan.md`](plan.md)
§8), including infra side channels this doc scopes out.

**Fixtures.** A shared two-tenant fixture (`A`, `B`) with overlapping-looking
IDs (same PIDs, same exec_ids, same MACs across tenants) so tests catch code that
keys on a natural identifier instead of `(tenant_id, id)`.

---

## 8. Definition of done (for the invariant, in Phase 1)

- [ ] `tenant_id` is derived from mTLS/RBAC only; no code path trusts a
      client-supplied tenant for authorization (T1, T2 green).
- [ ] A single tenant-scoped data-access layer mediates all storage; the bypass
      lint passes; per-tenant audit chains verify independently (T3 green).
- [ ] The generated cross-tenant API matrix (T4) is a required check and ratchets
      with new routes.
- [ ] Cross-tenant access exists only via the audited MSOC role (T5 green).
- [ ] Side-channel checks (T6) pass; residual infra risks are logged for the
      pen-test.
- [ ] A pre-GA external pen-test targets this invariant (T7 scheduled).

Until every box is checked, the platform is single-tenant only.
