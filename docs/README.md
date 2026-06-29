# Documentation

Project docs are organized by audience and lifecycle. Start at the top
of the relevant section.

## [Architecture](architecture/)

Design, components, and the gateway's runtime model.

- [overview.md](architecture/overview.md) — system overview, components,
  data flow, scoring, dashboard.
- [state-ladder.md](architecture/state-ladder.md) — the per-process
  five-rung state machine (pristine → throttled → tarpit → quarantined
  → severed).
- [network-choke-gateway.md](architecture/network-choke-gateway.md) —
  per-device (MAC) enforcement via a TC clsact data plane on an inline
  Linux bridge. **Built** — the `/devices` console is live and the data
  plane is proven 6/6 in the netns lab (real per-MAC drop + restore).

## [Getting started](getting-started/)

First-run setup for new contributors.

- [multipass-vm-setup.md](getting-started/multipass-vm-setup.md) —
  bring up a local Linux VM on macOS via Multipass.

## [Deployment](deployment/)

Production deployment paths.

- [ubuntu-server.md](deployment/ubuntu-server.md) — **recommended
  step-by-step** for a fresh Ubuntu 22.04/24.04 server: `setup.sh` →
  build → `install.sh` (systemd) → nginx/TLS → verify.
- [tarball-quickstart.md](deployment/tarball-quickstart.md) — fastest
  path: `make tarball`, scp, run, open in browser.
- [linux-server.md](deployment/linux-server.md) — the longer, manual
  walkthrough (per-step rationale, transfer options, hardening checklist).
- [network-choke-gateway.md](deployment/network-choke-gateway.md) —
  inline transparent-bridge gateway for the per-device (MAC) network
  choke (two NICs, TC clsact, no Tetragon).
- [azure.md](deployment/azure.md) — Azure-specific deployment.
- [commands.md](deployment/commands.md) — deployment command reference.
- [live-soc-adanianlabs.md](deployment/live-soc-adanianlabs.md) — operational
  runbook + change log for the live `soc.adanianlabs.io` host (deploy/redeploy,
  the enforcing-mode sudo-lockout trap, Tetragon enforce policies vs apt, and
  the netns device-choke verification proven 6/6).

## [Production Rollout](production-rollout/)

Mass deployment and day-2 operating model for many inline device-choke
gateways.

- [README.md](production-rollout/README.md) — hardware standards, site survey,
  golden image/provisioning, fleet enrollment, secrets, staged rollout,
  monitoring, upgrades, rollback, emergency controls, inventory, audit
  retention, privacy, operator runbook, support workflow, and packaging backlog.

## [Operations](operations/)

Day-2 ops once a deployment is live.

- [run-on-multipass-vm.md](operations/run-on-multipass-vm.md) —
  day-to-day runbook for the Multipass deployment.
- [reset-engine-and-policies.md](operations/reset-engine-and-policies.md)
  — reset the engine and reload policies.

## [Reference](reference/)

CLI / API reference material.

- [chokectl.md](reference/chokectl.md) — the `chokectl` fleet CLI.

## [Frontend](frontend-dev/)

The dashboard frontend: a **Vite multi-entry React** app (TypeScript,
Tailwind, Zustand, Radix, D3, Vitest + Playwright) built to a static
bundle and embedded into the Go binary with `go:embed`. No Node runtime
in production; Go stays the only server.

- [README.md](frontend-dev/README.md) — stack, scope, the five console
  entries (SOC, Choke, Devices, Fleet, Login), and the 78-panel parity gate.
- [recommended-stack.md](frontend-dev/recommended-stack.md) — why this stack.
- [security-console-ui.md](frontend-dev/security-console-ui.md) — current
  SOC briefing, Choke tracked-process table, and drilldown UI contracts.
- [78-panel-redesign-target-vm-e2e-certification-plan.md](frontend-dev/78-panel-redesign-target-vm-e2e-certification-plan.md)
  — the release certification plan.
- [pending-work.md](frontend-dev/pending-work.md) — completion report.

The console now runs the **UI 2.0** redesign: a cool neutral-slate
palette, a unified enterprise header standard across all pages, an
executive summary band on the SOC dashboard, and decluttered toolbars.
Operational deploy history lives in
[deployment/live-soc-adanianlabs.md](deployment/live-soc-adanianlabs.md).

## [Development](development/)

Project history and the original build plan.

- [build-plan.md](development/build-plan.md) — the original 5-day build
  plan that produced this codebase.
- [network-choke-build-plan.md](development/network-choke-build-plan.md)
  — staged plan to add per-device (MAC) network enforcement: netns PoC →
  data plane → control plane → fleet/deploy.
