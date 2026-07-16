# Documentation

Project docs, organized by audience.

> **New to the project?** Start with
> **[getting-started/developer-onboarding.md](getting-started/developer-onboarding.md)** —
> what it is, repo layout, build, test, and how to run it locally. Then read the
> [tenant-isolation invariant](plan/tenant-isolation-invariant.md) and the
> [architecture overview](architecture/overview.md).

---

## [Getting started](getting-started/)

- [developer-onboarding.md](getting-started/developer-onboarding.md) — **read
  first**: the whole picture for a new developer (binaries, layout, build/test,
  local-run options, key concepts).
- [multipass-vm-setup.md](getting-started/multipass-vm-setup.md) — bring up a
  local Linux VM on macOS (real kernel events / eBPF) via Multipass.

Also at the repo root: **[CONTRIBUTING.md](../CONTRIBUTING.md)** (branch/commit/PR
conventions + local gates).

## [Architecture](architecture/)

- [overview.md](architecture/overview.md) — system overview, components, data
  flow, scoring, dashboard.
- [state-ladder.md](architecture/state-ladder.md) — the per-process five-rung
  enforcement machine (pristine → throttled → tarpit → quarantined → severed).
- [network-choke-gateway.md](architecture/network-choke-gateway.md) — per-device
  (MAC) enforcement via a TC clsact data plane on an inline Linux bridge.

## [Plan](plan/) — the multi-tenant SOC conversion

The strategy and design for turning the single-host engine into a multi-tenant
SaaS/MSSP platform. Design references (not status reports).

- [plan.md](plan/plan.md) — the enterprise conversion plan (strategy, gap
  analysis, migration, GA criteria).
- [roadmap.md](plan/roadmap.md) — phased execution roadmap with exit gates.
- [architecture.md](plan/architecture.md) — the target multi-tenant architecture.
- [tenant-isolation-invariant.md](plan/tenant-isolation-invariant.md) — **the
  core rule**: four-layer isolation, no cross-tenant reads.
- [threat-model.md](plan/threat-model.md) — what the platform defends against.
- [wire-contract.md](plan/wire-contract.md) — the agent ↔ control-plane protocol.
- [d4c-tech-decisions.md](plan/d4c-tech-decisions.md) — infrastructure ADRs (bus,
  store, RLS).
- [console-v2-parity.md](plan/console-v2-parity.md) — **active work "C"**: folding
  the engine's rich UI into the multi-tenant console (finalized status inside).
- [kickoff-prompt.md](plan/kickoff-prompt.md) — the Phase 0 charter.

## [Deployment](deployment/)

**Which guide?**

| Scenario | Guide |
| --- | --- |
| Local dev of the **multi-tenant console** (durable, systemd, mirrors prod) | [orbstack-local-mirror.md](deployment/orbstack-local-mirror.md) |
| Deploy the **engine** to a fresh Ubuntu server (recommended) | [ubuntu-server.md](deployment/ubuntu-server.md) |
| Fastest engine deploy (build → scp → run) | [tarball-quickstart.md](deployment/tarball-quickstart.md) |
| Deep, manual engine walkthrough (rationale + hardening checklist) | [linux-server.md](deployment/linux-server.md) |
| Azure-specific engine deploy | [azure.md](deployment/azure.md) |
| The **network / device choke** inline-bridge gateway | [network-choke-gateway.md](deployment/network-choke-gateway.md) |
| Stand the **control plane** up beside the live engine (tenant #0) | [controlplane-migration.md](deployment/controlplane-migration.md) |
| Operate the live `soc.adanianlabs.io` host | [live-soc-adanianlabs.md](deployment/live-soc-adanianlabs.md) |

> Credentials for the local stack live in `docs/credentials/` (gitignored — not
> committed). Production secrets stay in the operator's password manager.

## [Production rollout](production-rollout/)

- [README.md](production-rollout/README.md) — mass-deployment + day-2 operating
  model for many inline device-choke gateways (hardware, provisioning, fleet
  enrollment, staged rollout, monitoring, upgrades, rollback, audit, privacy).

## [Operations](operations/)

- [run-on-multipass-vm.md](operations/run-on-multipass-vm.md) — day-to-day runbook
  for the Multipass deployment.
- [reset-engine-and-policies.md](operations/reset-engine-and-policies.md) — reset
  the engine and reload policies (demo-prep / clean slate).

## [Reference](reference/)

- [chokectl.md](reference/chokectl.md) — the `chokectl` fleet CLI.

## [Frontend](frontend-dev/)

The dashboard: a **Vite multi-entry React** app (TypeScript, Tailwind, Zustand,
Radix, D3, Vitest + Playwright), built to a static bundle and embedded into the Go
binary with `go:embed` — no Node runtime in production.

- [README.md](frontend-dev/README.md) — stack, scope, the five console entries
  (SOC, Choke, Devices, Fleet, Login), and the parity gate.
- [recommended-stack.md](frontend-dev/recommended-stack.md) — why this stack.
- [security-console-ui.md](frontend-dev/security-console-ui.md) — SOC briefing,
  Choke table, and drilldown UI contracts.
- [78-panel-redesign-target-vm-e2e-certification-plan.md](frontend-dev/78-panel-redesign-target-vm-e2e-certification-plan.md)
  — the release certification plan.

## [Development](development/) — historical

Preserved *how it was built* records; the code has since shipped past them.

- [build-plan.md](development/build-plan.md) — the original 5-day plan that
  produced the first version of the codebase.
- [network-choke-build-plan.md](development/network-choke-build-plan.md) — the
  staged plan that built per-device (MAC) network enforcement.
