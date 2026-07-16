# Developer onboarding

Everything a new developer needs to understand this codebase, build it, run it,
and start contributing. Read this first, then follow the links into the deeper
docs.

---

## 1. What this project is

An eBPF-based runtime **detection + enforcement** platform, mid-migration from a
single-host proof-of-concept into a **multi-tenant SaaS SOC platform**.

- **Engine** (the original monolith, `cmd/engine`) — Tetragon emits kernel
  events; a Go correlation engine scores chains of suspicious behaviour; two
  **Choke Gateways** turn scores + operator actions into graduated, audited
  enforcement (process choke: throttle→tarpit→quarantine→sever; network/device
  choke: per-MAC on an inline bridge). Ships as one static Go binary with the
  React console embedded via `go:embed`. This is what runs at `soc.adanianlabs.io`.
- **Control plane + agents** (the multi-tenant future, `cmd/controlplane` +
  `cmd/agent`) — the engine split via the **strangler-fig** pattern: agents
  enroll (mTLS), stream tenant-stamped telemetry to a central control plane, take
  signed commands, and enforce offline; the control plane serves a tenant-scoped,
  OIDC/RBAC-gated console at `console.adanianlabs.io`. See
  [../plan/plan.md](../plan/plan.md) for the full conversion plan.

Both coexist until the console reaches parity; see
[../plan/console-v2-parity.md](../plan/console-v2-parity.md).

## 2. The binaries (`engine/cmd/`)

| Binary | Role |
| --- | --- |
| `engine` | The single-host monolith (detection + choke + embedded console). |
| `agent` | The per-host sensor/enforcer — enrolls to the control plane, streams telemetry, applies signed commands, enforces offline. |
| `controlplane` | The multi-tenant server — mTLS ingest, central store (Postgres RLS), OIDC/BFF login, RBAC, fleet/command dispatch, tenant-scoped console API. |
| `simagent` | **Dev only** — enrolls like a real agent and feeds synthetic telemetry/heartbeats so the console renders without live eBPF (used by the OrbStack mirror). |
| `socbackup` | WAL-safe SQLite snapshot tool for the engine's DB. |

## 3. Repo layout

```
engine/            Go module (the whole backend)
  cmd/             entrypoints (engine, agent, controlplane, simagent, socbackup)
  internal/        the real code — key packages:
    api/           engine HTTP API + embedded web (go:embed)
    choke/         process choke gateway (state ladder, cgroup v2, bpf backend)
    device/        network/device choke (per-MAC, TC clsact)
    score/         chain scorer
    centralstore/  tenant-partitioned store (SQLite + Postgres RLS)  ← isolation Layer 3
    authz/         RBAC + tenant-scope decisions                     ← isolation Layer 4
    bff/           OIDC/PKCE browser-facing login (Keycloak)
    enrollment/    agent mTLS enrollment; mtls/ signing/ crypto
    ingest/        collector: tenant-stamp + fan-out to store(s)     ← isolation Layer 2
    command/       signed command channel (SetMode/Jail/Thaw/…)
    controlplane/  the control-plane HTTP + gRPC server
    cpclient/      the agent-side client loop (enroll/heartbeat/drain)
    heartbeat/ fleet/ policy/ policypull/ enforce/ …
  proto/  gen/     protobuf wire contract + generated Go
web/               Vite multi-entry React console (built to web/dist, embedded)
policies/          Tetragon TracingPolicies + choke DSL policies
attacks/           allowlisted attack scripts (the quick-fire panel / demos)
scripts/  deploy/  provisioning + systemd units + helper scripts
docs/              you are here
```

## 4. Prerequisites

- **Go 1.25+** and **Node 18+** (Node builds the console; Go embeds it).
- **Docker or OrbStack** (for Postgres/Keycloak/NATS when running the control plane).
- **A Linux host with a BTF-enabled kernel ≥ 5.15** for anything touching real
  eBPF (Tetragon). macOS builds fine but can't run the eBPF data plane natively —
  use a Linux VM (Multipass/OrbStack) or `-fake` mode.

## 5. Build

```bash
cd engine
make build                 # engine (native) — rebuilds web/dist + embeds it
make build-linux           # engine for linux/amd64 (the deploy artifact)
make build-agent           # the agent
make build-controlplane    # the control plane
make web                   # just the frontend (npm run build) → web/dist
make proto                 # regenerate protobuf (after editing proto/*.proto)
```

Binaries can also be cross-compiled directly:
`CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/controlplane`.

## 6. Test

```bash
cd engine && make test && make vet     # Go unit + integration tests, go vet
cd web && npm run lint && npm run typecheck && npm run test   # web gates + vitest
cd web && npm run e2e                   # Playwright (needs a running target)
```

CI expects all of the above green. Isolation is enforced by automated
cross-tenant read-denial tests — keep them passing.

## 7. Run it locally — pick a path

| You want… | Use | Real eBPF? |
| --- | --- | --- |
| Hack on the **console / control plane** (multi-tenant, OIDC, RBAC) with realistic data | **OrbStack mirror** → [../deployment/orbstack-local-mirror.md](../deployment/orbstack-local-mirror.md) | No (synthetic via `simagent`) |
| Just render the UI / poke the engine API with no kernel | `engine -fake` (synthesizes events) | No |
| The **engine against real kernel events** (Tetragon) | A Linux host — deploy to a server ([../deployment/ubuntu-server.md](../deployment/ubuntu-server.md)) or an OrbStack Ubuntu machine running Tetragon | Yes |

## 8. Key concepts (read before deep work)

- **Tenant isolation invariant** — the four-layer rule that no tenant ever reads
  another's data. Non-negotiable; constrains the whole control-plane design.
  → [../plan/tenant-isolation-invariant.md](../plan/tenant-isolation-invariant.md)
- **The state ladder** — the per-process five-rung enforcement machine
  (pristine → throttled → tarpit → quarantined → severed).
  → [../architecture/state-ladder.md](../architecture/state-ladder.md)
- **Wire contract** — the agent↔control-plane protobuf/gRPC protocol (enrollment,
  telemetry, commands, heartbeat, policy pull).
  → [../plan/wire-contract.md](../plan/wire-contract.md)
- **Architecture** — components + data flow, current and target.
  → [../architecture/overview.md](../architecture/overview.md) (engine) and
  [../plan/architecture.md](../plan/architecture.md) (multi-tenant target)
- **Threat model** — what we defend against. → [../plan/threat-model.md](../plan/threat-model.md)

## 9. Where the work is going

The roadmap is phased (spine before breadth): [../plan/roadmap.md](../plan/roadmap.md).
The current active thread is **"C" — folding the engine's rich UI into the
multi-tenant console** ([../plan/console-v2-parity.md](../plan/console-v2-parity.md)).

## 10. Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for branch/commit/PR conventions and
the local gates a change must pass.
