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

To run the whole platform locally with real eBPF: **`make deploy-local`** —
[deployment/orbstack-local-mirror.md](deployment/orbstack-local-mirror.md). The
full multi-host platform (control plane + engine + one real agent per tenant +
a device to contain, both gateways enforcing for real) is
[deployment/aws-multi-host.md](deployment/aws-multi-host.md). Also at the repo
root: **[CONTRIBUTING.md](../CONTRIBUTING.md)** (branch/commit/PR conventions +
local gates).

## [API](api/)

The contract between this platform and anything that integrates with it.
Generated from source and **gated in CI**, so a difference between these
documents and the running system is a platform bug, not a stale doc.

- [README.md](api/README.md) — **start here**: what each document is and how to
  read it.
- [integration-guide.md](api/integration-guide.md) — how to authenticate and
  call the platform, with worked examples.
- [openapi.yaml](api/openapi.yaml) — both HTTP surfaces, generated from the
  route registrations. `make api-docs` renders it to a single self-contained
  `docs/api/dist/index.html` that makes no network requests.
- [wire-contract.md](api/wire-contract.md) — the agent ↔ control-plane gRPC
  contract as served, generated from the `.proto` files.

## [Architecture](architecture/)

- [overview.md](architecture/overview.md) — the **single-host engine**:
  components, data flow, scoring, dashboard. Start here; it is the product's
  core.
- [state-ladder.md](architecture/state-ladder.md) — the per-process five-rung
  enforcement machine (pristine → throttled → tarpit → quarantined → severed).
- [network-choke-gateway.md](architecture/network-choke-gateway.md) — per-device
  (MAC) enforcement via a TC clsact data plane on an inline Linux bridge.
- [analyst-assistant.md](architecture/analyst-assistant.md) — the read-only LLM
  analyst, and the three structural layers that keep it read-only next to a
  containment console.
- [behaviour-and-intel.md](architecture/behaviour-and-intel.md) — the two
  detection layers on top of the rule scorer: per-deployment behavioural
  baselines, and local threat-intelligence matching. Includes why an empty
  findings list means three different things and how the API keeps them apart.
- [posture-dial.md](architecture/posture-dial.md) — the one number on the
  executive band, the three ways it has been wrong, and why it is now scored
  against the estate's own baseline with the baseline shown beside it.
- [tech-stack-and-ebpf-programs.md](architecture/tech-stack-and-ebpf-programs.md)
  — reference tables: every technology and why it was chosen, plus every eBPF
  program, its hook, and the function it serves.

The **multi-tenant** topology is in [plan/architecture.md](plan/architecture.md);
`architecture/overview.md` covers the engine that runs on each host.

## [Plan](plan/) — the multi-tenant SOC conversion

The strategy and design for turning the single-host engine into a multi-tenant
SaaS/MSSP platform. Design references, with status headers marking what has
shipped. Phases 0 and 1 are complete; Phase 2 is in progress.

- [plan.md](plan/plan.md) — the enterprise conversion plan (strategy, gap
  analysis, migration, GA criteria).
- [roadmap.md](plan/roadmap.md) — phased execution roadmap with exit gates, and
  **the best single view of what is done**.
- [architecture.md](plan/architecture.md) — the target multi-tenant architecture.
- [tenant-isolation-invariant.md](plan/tenant-isolation-invariant.md) — **the
  core rule**: four-layer isolation, no cross-tenant reads. Built and enforced
  in CI; three GA boxes still open.
- [threat-model.md](plan/threat-model.md) — what the platform defends against.
- [wire-contract.md](plan/wire-contract.md) — the agent ↔ control-plane protocol
  as designed. For the generated contract see [api/wire-contract.md](api/wire-contract.md).
- [d4c-tech-decisions.md](plan/d4c-tech-decisions.md) — infrastructure ADRs (bus,
  store, RLS).
- [console-v2-parity.md](plan/console-v2-parity.md) — folding the engine's rich
  UI into the multi-tenant console. Functionally complete.
- [platform-assistant.md](plan/platform-assistant.md) — the menu-bar chat design.
  Mostly shipped; streaming is not.
- [ai-and-console-reuse.md](plan/ai-and-console-reuse.md) — the work plan behind
  the assistant and the console testability push. Partially delivered.

## [Deployment](deployment/)

**Which guide?**

| Scenario | Guide |
| --- | --- |
| **The reference deployment** — full platform across AWS hosts (`make deploy-estate`) | [aws-multi-host.md](deployment/aws-multi-host.md) |
| **The whole platform locally**, real eBPF, one command (`make deploy-local`) | [orbstack-local-mirror.md](deployment/orbstack-local-mirror.md) |
| Before shipping to a customer — readiness, gaps, known traps | [pre-deployment-checklist.md](deployment/pre-deployment-checklist.md) |
| Deploy the **engine** to a fresh Ubuntu server | [ubuntu-server.md](deployment/ubuntu-server.md) |
| Fastest engine deploy (build → scp → run) | [tarball-quickstart.md](deployment/tarball-quickstart.md) |
| Deep, manual engine walkthrough (rationale + hardening checklist) | [linux-server.md](deployment/linux-server.md) |
| The **network / device choke** inline-bridge gateway | [network-choke-gateway.md](deployment/network-choke-gateway.md) |

Every deploy script and how they compose:
[`scripts/deploy/README.md`](../scripts/deploy/README.md).

> Credentials for the local stack live in `docs/credentials/` (gitignored — not
> committed). Production secrets stay in the operator's password manager.

## [Operations](operations/)

- [enforcement-traps.md](operations/enforcement-traps.md) — **the two ways this
  platform locks you out of your own host**, and how to recover. Read before
  enabling enforcement anywhere.
- [synthetic-telemetry.md](operations/synthetic-telemetry.md) — **where the fake
  data comes from.** `DATA_MODE`, the activity generator that pinned the
  executive posture dial at 97/100 around the clock, and how to tell a real
  estate from a metronome.
- [backup-and-restore.md](operations/backup-and-restore.md) — backup, restore,
  data-plane wipe and full rebuild; every procedure verified live.
- [reset-engine-and-policies.md](operations/reset-engine-and-policies.md) — reset
  the engine and reload policies (demo-prep / clean slate).

## [Production rollout](production-rollout/)

- [README.md](production-rollout/README.md) — mass-deployment + day-2 operating
  model for many inline device-choke gateways (hardware, provisioning, fleet
  enrollment, staged rollout, monitoring, upgrades, rollback, audit, privacy).

## [Reference](reference/)

- [chokectl.md](reference/chokectl.md) — the `chokectl` fleet CLI.

## [Frontend](frontend-dev/)

The dashboard: a **Vite multi-entry React** app (TypeScript, Tailwind, Zustand,
Radix, D3, Vitest + Playwright), built to a static bundle. The single-tenant
engine embeds it with `go:embed`; the control plane serves it from nginx. Either
way there is no Node runtime in production.

- [README.md](frontend-dev/README.md) — stack, scope, the five console entries
  (SOC, Choke, Devices, Fleet, Login), and the parity gate.
- [recommended-stack.md](frontend-dev/recommended-stack.md) — why this stack.
- [security-console-ui.md](frontend-dev/security-console-ui.md) — SOC briefing,
  Choke table, and drilldown UI contracts.
- [78-panel-redesign-target-vm-e2e-certification-plan.md](frontend-dev/78-panel-redesign-target-vm-e2e-certification-plan.md)
  — the release certification plan.

## [Browser tests](browser-test/)

Two Playwright suites over the console, split by what kind of claim they make.

- [README.md](browser-test/README.md) — **start here**: the e2e (mocked) vs
  probe (live deployment) split, how to run each, the mocked-backend API, and
  the conventions. Also records the defects this suite found and how known,
  unfixed ones are kept visible instead of deleted.
- [playwright-browser-testing-guide.md](browser-test/playwright-browser-testing-guide.md)
  — the portable method the suites were built from (Browser → Context → Page,
  the four-layer split, the three multi-page patterns).

## [Technical reference](technical-document/)

A single long-form document covering the whole platform, for readers who want it
in one piece — `eBPF-SOC-Technical-Reference.pdf` and an HTML rendering of the
same content.

## [Development](development/) — historical

Preserved *how it was built* records; the code has since shipped past them.

- [build-plan.md](development/build-plan.md) — the original 5-day plan that
  produced the first version of the codebase.
- [network-choke-build-plan.md](development/network-choke-build-plan.md) — the
  staged plan that built per-device (MAC) network enforcement.
