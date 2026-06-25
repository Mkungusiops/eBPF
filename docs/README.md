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
  **design (not yet built):** per-device (MAC) enforcement via a TC
  clsact data plane on an inline Linux bridge.

## [Getting started](getting-started/)

First-run setup for new contributors.

- [multipass-vm-setup.md](getting-started/multipass-vm-setup.md) —
  bring up a local Linux VM on macOS via Multipass.

## [Deployment](deployment/)

Production deployment paths.

- [tarball-quickstart.md](deployment/tarball-quickstart.md) — fastest
  path: `make tarball`, scp, run, open in browser.
- [linux-server.md](deployment/linux-server.md) — fresh Linux server
  (cloud VM, bare metal, hypervisor guest).
- [network-choke-gateway.md](deployment/network-choke-gateway.md) —
  inline transparent-bridge gateway for the per-device (MAC) network
  choke (two NICs, TC clsact, no Tetragon).
- [azure.md](deployment/azure.md) — Azure-specific deployment.
- [commands.md](deployment/commands.md) — deployment command reference.
- [live-soc-adanianlabs.md](deployment/live-soc-adanianlabs.md) — operational
  runbook + change log for the live `soc.adanianlabs.io` host (deploy/redeploy,
  the enforcing-mode sudo-lockout trap, Tetragon enforce policies vs apt, and
  the netns device-choke verification proven 6/6).

## [Operations](operations/)

Day-2 ops once a deployment is live.

- [run-on-multipass-vm.md](operations/run-on-multipass-vm.md) —
  day-to-day runbook for the Multipass deployment.
- [reset-engine-and-policies.md](operations/reset-engine-and-policies.md)
  — reset the engine and reload policies.

## [Reference](reference/)

CLI / API reference material.

- [chokectl.md](reference/chokectl.md) — the `chokectl` fleet CLI.

## [Frontend migration](frontend-migration/)

Plan for converting the five embedded HTML consoles (SOC, Choke,
Devices, Fleet, Login) to a statically-exported Next.js app re-embedded
in the Go binary.

- [README.md](frontend-migration/README.md) — **one combined document:**
  architecture, phased build, timeline, the full 63-route API inventory,
  the 78-panel per-console parity gate, cutover, and risks. (Supersedes
  the former four-file split.)

## [Development](development/)

Project history and the original build plan.

- [build-plan.md](development/build-plan.md) — the original 5-day build
  plan that produced this codebase.
- [network-choke-build-plan.md](development/network-choke-build-plan.md)
  — staged plan to add per-device (MAC) network enforcement: netns PoC →
  data plane → control plane → fleet/deploy.
