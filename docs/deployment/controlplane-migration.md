# Control-plane migration runbook — `soc.adanianlabs.io` → tenant #0

> **What this is:** the operator runbook to bring the live single-host demo
> (`soc.adanianlabs.io`, a bare `cmd/engine` process on an Azure VM) under the new
> multi-tenant control plane **without a flag-day rewrite** — the strangler
> migration of [`plan.md`](../plan/plan.md) §7. Every step is independently
> shippable and reversible.
>
> **Not executed here.** These steps run against the live Azure box and cloud
> infra; this document is the plan, not an applied change.

---

## 0. Prerequisites (built and proven)

- `controlplane` binary (`make build-controlplane`) — the assembled control plane
  (`internal/controlplane`): mTLS gRPC agent services + authz-gated operator API.
- `agent` binary (`make build-agent`) — the sensing/enforcing agent with the
  opt-in `-controlplane` uplink (default OFF; enforcement never depends on it).
- Deploy artifacts: [`deploy/controlplane.service`](../../deploy/controlplane.service)
  (systemd), [`deploy/terraform/`](../../deploy/terraform) (K8s + OSS stack),
  [`deploy/docker-compose.oss.yml`](../../deploy/docker-compose.oss.yml).

---

## 1. Stabilise the live box first (Phase 0 close-out)

Before any architecture change, close the operational holes in
[`live-soc-adanianlabs.md`](live-soc-adanianlabs.md):

1. Put the running engine under **systemd** (`deploy/ebpf-engine.service`) with
   `Restart=always` — no more bare root process.
2. **Rotate the `admin/ebpf-soc-demo` credential.** The binary no longer ships a
   default (a missing password fails fast), so set a strong `pass_hash` in
   `engine.yaml` and restart.
3. Verify TLS renewal + DB/audit-chain backup.

Reversible: these are config/supervision changes only; the engine keeps serving.

## 2. Stand up the control plane beside it (Phase 1)

1. Provision the control-plane environment with `deploy/terraform` (managed K8s
   for SaaS, or on-prem for residency) — the OSS stack: Postgres+RLS, NATS,
   Keycloak.
2. Run `controlplane` with `-state-dir` (persistent CA + fleet key), `-store
   postgres`, and `-oidc-issuer` pointing at the Keycloak realm. It exports the
   CA bundle (`-ca-out`) and fleet public key (`-fleet-pubkey-out`) that agents
   pin.
3. Create tenant **`adanian-internal`** and an operator in Keycloak.

The live engine is untouched and still serving its own console.

## 3. Enrol the live box as agent #0 of tenant `adanian-internal`

1. In the console/API, mint a one-time bootstrap token for `adanian-internal`
   (`POST /api/admin/enroll-token`).
2. On the Azure box, run the **agent** alongside the existing engine (or the
   engine in dual-write mode) with:
   `-controlplane <cp>:9443 -bootstrap-token <token> -ca-bundle ca.pem
    -fleet-pubkey fleet.pub`.
3. The agent enrols (mTLS), streams telemetry to the control plane, and **still
   enforces locally if the control plane is unreachable** (the autonomy moat).

Reversible: drop the `-controlplane` flags and the agent is fully standalone
again; enforcement is unaffected throughout.

## 4. Cut the console over

Once the central multi-tenant console (`console.html` + the BFF OIDC login)
renders `adanian-internal`'s data, point `soc.adanianlabs.io` at the control
plane (or make it a tenant login). The old per-host console becomes a
localhost-only debug surface.

## 5. Retire the monolith path

When agents everywhere report centrally, drop the embedded console from the agent
build and delete the client-driven `api/fleet.go` fan-out.

---

## Rollback

Every step above is reversible in isolation — the runbook's atomic-swap +
backup-artifact pattern from `live-soc-adanianlabs.md` §2 carries over. The
invariant throughout: **kernel enforcement never depends on the control plane**,
so no migration step can take the protected host offline.
