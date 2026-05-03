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

## [Getting started](getting-started/)

First-run setup for new contributors.

- [multipass-vm-setup.md](getting-started/multipass-vm-setup.md) —
  bring up a local Linux VM on macOS via Multipass.

## [Deployment](deployment/)

Production deployment paths.

- [linux-server.md](deployment/linux-server.md) — fresh Linux server
  (cloud VM, bare metal, hypervisor guest).
- [azure.md](deployment/azure.md) — Azure-specific deployment.
- [commands.md](deployment/commands.md) — deployment command reference.

## [Operations](operations/)

Day-2 ops once a deployment is live.

- [run-on-multipass-vm.md](operations/run-on-multipass-vm.md) —
  day-to-day runbook for the Multipass deployment.
- [reset-engine-and-policies.md](operations/reset-engine-and-policies.md)
  — reset the engine and reload policies.

## [Reference](reference/)

CLI / API reference material.

- [chokectl.md](reference/chokectl.md) — the `chokectl` fleet CLI.

## [Development](development/)

Project history and the original build plan.

- [build-plan.md](development/build-plan.md) — the original 5-day build
  plan that produced this codebase.
