# Agent ↔ Control-Plane Wire Contract

> **What this is:** the first artifact of Phase 1 ([`roadmap.md`](roadmap.md)) —
> the protocol between the autonomous choke-agent and the control plane. It
> specifies the five channels of [`architecture.md`](architecture.md) §4, their
> delivery semantics, and how the contract structurally upholds
> [`tenant-isolation-invariant.md`](tenant-isolation-invariant.md) and defends the
> threats in [`threat-model.md`](threat-model.md) §4.
>
> **Why first:** *"Define this before building either side"* (architecture.md §4).
> Agent v1 and the ingest/fleet services are both written against this contract;
> pinning it down prevents the two halves from drifting.
>
> **Where the IDL lives:** [`engine/proto/ebpfsoc/v1/`](../../engine/proto/ebpfsoc/v1/)
> (proto3 / gRPC). Code generation is wired in Deliverable 2 (this deliverable is
> the contract itself, not the generated stubs).
>
> **Status:** draft for review. Message field mappings marked *"mirrors …"* are
> finalized against the concrete Go types in Deliverable 2.

---

## 1. Transport & security

- **All channels are gRPC over mTLS**, except the single bootstrap call on the
  Enrollment service (server-auth TLS + a one-time token — it exists precisely
  to obtain the client cert).
- **Identity is derived from the mTLS client certificate, never from a payload
  field.** The cert subject encodes `tenant_id` + `agent_id`; the ingest/command
  edge reads them from the verified cert. **No request message in this contract
  carries `tenant_id`** — that is deliberate and load-bearing (isolation
  invariant R1 / Layer 1–2; threat CH-2). A record that *did* carry a tenant
  field could only ever be used for tamper-detection telemetry, never authz.
- **TLS floor:** modern TLS only; no plaintext fallback (threat CH-1).
- **Downstream artifacts are signed** (commands, policy bundles) so a compromised
  transport or a rogue intermediary cannot forge instructions (threats CH-5, EN-4,
  SC-4). The agent verifies signatures before acting.

---

## 2. The five channels

| Channel | Service / RPC | Direction | Shape | Purpose |
|---------|---------------|-----------|-------|---------|
| **Enroll** | `EnrollmentService.Enroll` | agent → CP | unary (bootstrap TLS) | One-time cert issuance; binds `tenant_id`+`agent_id` |
| **Telemetry** | `TelemetryService.StreamTelemetry` | agent → CP | bidi stream | Events/alerts/decisions; batched, deduped, resumable |
| **Command** | `CommandService.Commands` | CP → agent | bidi stream | mode/jail/thaw/thresholds/preset/kill-switch/protected-list; signed, acked, audited |
| **Policy pull** | `PolicyService.GetBundle` | agent → CP | unary | Signed policy bundle by etag; verify before apply |
| **Heartbeat** | `HeartbeatService.Heartbeat` | agent → CP | unary | Health, version, kernel, data-plane state, buffer depth |

The command stream is agent-initiated (the agent dials out and holds the stream)
so it works through customer NAT/firewalls without inbound connectivity to the
host — the CP pushes commands down the agent-opened stream.

---

## 3. Enrollment flow

```
operator                agent                         EnrollmentService
   │  create one-time,      │                                  │
   │  tenant-scoped token   │                                  │
   ├───────────────────────▶│                                  │
   │                        │  generate keypair, build CSR     │
   │                        │  Enroll{ bootstrap_token,        │
   │                        │          csr_pem, agent_info } ──▶│  verify token (one-time,
   │                        │                                  │  unexpired, tenant X)
   │                        │                                  │  sign cert: subject =
   │                        │                                  │  tenant=X, agent=<id>
   │                        │◀── EnrollResponse{ cert, ca,     │
   │                        │      agent_id, not_after,        │
   │                        │      uplink/command endpoints }  │
   │  all later channels: mTLS with the issued client cert     │
```

- Bootstrap tokens are **short-lived, one-time, tenant-scoped** (threat SC-7).
- The issued cert is **short-lived and auto-rotated**; re-enrollment is an
  audited path (threat CH-6). An agent cannot change its tenant by re-issuing a
  CSR (isolation R4).

---

## 4. Delivery semantics (telemetry)

The uplink is the firehose; it must survive reconnects without double-counting
and without unbounded memory.

- **At-least-once + idempotent.** Every `TelemetryRecord` carries an
  agent-assigned `dedup_key` that is **stable across resends**. The collector
  dedups on `(agent_id from cert, dedup_key)` (threat CH-3). Replaying a batch
  after a reconnect is therefore safe.
- **Resumable.** Each `TelemetryBatch` has a monotonic `agent_seq`. The server
  returns `TelemetryAck.acked_through_seq` (cumulative); the agent may free WAL
  rows up to that sequence. On reconnect the agent resumes from the last acked
  sequence held in its local WAL — the same SQLite store that is the offline
  buffer. Nothing is lost across a partition.
- **Backpressure.** `TelemetryAck.backpressure` lets the collector throttle a
  flooding or compromised agent (`max_in_flight_batches`, `pause_ms`) without
  affecting other tenants (threat CH-4). Per-tenant rate limits live at the
  collector (isolation Layer 2).
- **Ordering.** Batches are ordered by `agent_seq`; within a batch, records are
  independent (dedup makes reordering harmless). The **hash-chained `Decision`
  records** carry their own `seq`/`prev_hash`/`hash` so the central mirror
  re-verifies the tamper-evident chain **per tenant** without trusting transport
  order (isolation Layer 3; audit stays authoritative).

---

## 5. Commands & policy (signed-everything-downstream)

- Every `Command` carries a `signature` + `signer_key_id` over its canonical
  bytes, an `issued_at`, and an `expires_at`. The agent:
  1. verifies the signature against the fleet signer key,
  2. rejects expired commands (`STATUS_EXPIRED`),
  3. applies **local conservative guardrails regardless** of the command —
     protected-process/MAC lists and the kill-switch cannot be overridden by a
     command that would, say, remove `sudo`/`sshd` from the protected set
     (threats EN-1, EN-4; the sudo-lockout trap).
- Every command is **acked** (`CommandAck` with ACCEPTED/APPLIED/REJECTED/EXPIRED)
  and **audited on both ends** (threat CH-5, CP-5). The `KillSwitch` command is
  the fleet-wide emergency halt (threat EN-2).
- `PolicyService.GetBundle` returns a **signed** bundle (TracingPolicies +
  ChokePolicy DSL + thresholds + protected lists) addressed by `etag`;
  `not_modified` avoids re-shipping. The agent verifies the signature **before
  apply**; local files remain bootstrap/fallback (threat SC-4).

---

## 6. Autonomy contract in the protocol (the moat)

Nothing in this contract makes enforcement depend on the channel being up
(architecture.md §2/§6; threat CH-7):

- If the CP is unreachable, the agent **keeps enforcing** its last-applied signed
  policy and **keeps buffering** telemetry in the WAL; it drains on reconnect via
  the resume semantics above.
- Heartbeat/command/policy timeouts degrade to "operate on last known good" —
  never to "stop enforcing."
- This property is a **required CI test** (roadmap Phase 1 exit: *"still enforces
  when disconnected"*).

---

## 7. Versioning & compatibility

- Package is versioned (`ebpfsoc.v1`); breaking changes bump the package version
  and run both during migration.
- Proto3 field-add is backward compatible; fields are never renumbered or reused.
- `AgentInfo.agent_version` + a negotiated minimum let the CP refuse or
  soft-degrade incompatible agents (threat EN-6: graceful degrade to detect-only
  on kernel/BPF mismatch is an agent-side decision, reported via heartbeat).

---

## 8. Isolation & threat-model traceability

| Contract decision | Upholds |
|-------------------|---------|
| No `tenant_id` in any request; derived from cert | invariant R1 / Layer 1–2; CH-2 |
| Dedup key + cumulative ack + WAL resume | CH-3; no double-count on replay |
| Per-agent backpressure at collector | CH-4; isolation Layer 2 |
| Signed commands, acked + audited both ends | CH-5, CP-5 |
| Local guardrails override any command | EN-1, EN-4 (sudo-lockout); EN-2 kill-switch |
| Signed policy bundles, verified before apply | SC-4 |
| One-time tenant-scoped bootstrap; short-lived certs | SC-7, CH-6 |
| Per-tenant hash-chain fields carried verbatim | isolation Layer 3; audit integrity |
| No channel is a prerequisite for enforcement | CH-7; autonomy invariant |

---

## 9. Build integration (Deliverable 2, not now)

- IDL: `engine/proto/ebpfsoc/v1/*.proto`, proto3, `go_package` →
  `github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1`.
- Generation via `protoc` (installed) or `buf`; generated stubs land under
  `engine/gen/` and are wired into the agent (client) and control plane (server)
  in D2. A `buf.gen.yaml` + a `make proto` target are added then.
- This deliverable adds **no generated code and no runtime imports**, so
  `go build ./...` is unaffected; the `.proto` files are validated for syntax
  with `protoc --descriptor_set_out`.

---

## 10. Deferred / non-goals (later in Phase 1+)

- OTLP path for metrics (architecture.md §4 notes metrics may go via OTLP rather
  than this telemetry stream) — decided when the collector lands.
- Exact `Decision` field mapping to `internal/store/decisions.go` — finalized in
  D2 against the real type (the audit chain itself is **not** modified).
- Long-poll fallback for the command channel (architecture.md §4) — added only if
  a customer environment cannot hold the bidi stream.
- Bus topic layout, ClickHouse/Postgres schemas — these consume this contract but
  are separate deliverables.

---

## 11. Acceptance (what the next deliverables must satisfy)

- [ ] `.proto` compiles and lints clean; stubs generate for Go.
- [ ] Agent v1 (D2) implements enroll → uplink(resume/dedup) → command(verify/ack)
      → policy(verify) → heartbeat against these definitions, and **passes the
      offline-enforcement test**.
- [ ] Ingest (D3) derives tenant from the cert, stamps it, and **ignores any
      payload tenant field**, with a test proving a cross-tenant-labelled payload
      is stamped by cert (isolation T2).
- [ ] No message on any path carries an authoritative `tenant_id`.
