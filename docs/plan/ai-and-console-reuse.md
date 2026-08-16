# AI Assistant and Console Reuse — Work Plan

What to take from [`DataInVizApp_V2`](../../../DataInVizApp_V2), what to build fresh, and the order
to do it in. Every number here was measured against both trees on 2026-08-16, not estimated.

Companion to [`plan.md`](plan.md) and [`roadmap.md`](roadmap.md). Branch: `feat/soc-assistant`,
currently level with `main` at `v1.3.0-1-g0c04c1f`.

---

## 0. The finding this plan closes

The audit found frontend line coverage at **13.19%** (2,042 / 15,486). That is not spread evenly —
it is concentrated in exactly the routes that cannot be tested:

| File | Uncovered lines | Covered |
|---|---:|---:|
| `soc/panels.tsx` | 1,157 | 13.2% |
| `soc/CorrelationGraph.tsx` | 645 | **0.3%** |
| `soc/SocRoute.tsx` | 565 | 0.4% |
| `choke/ChokeRoute.tsx` | 423 | **0.0%** |
| `choke/utils.ts` | 350 | 0.0% |
| `soc/exportStudio.tsx` | 320 | 0.6% |
| `choke/panels.tsx` | 315 | 0.0% |
| `soc/ExecutiveBand.tsx` | 290 | 1.0% |

Those eight files are 4,065 uncovered lines — **30% of everything uncovered**. `devices` and `fleet`
do not appear. That is the whole thesis: `devices` is the one route with an injected API, and it is
the one route with a route-level unit test. Coverage is low *because* components reach the network
directly, not because nobody wrote tests.

30 test files exist and 156 tests pass. Only **3** render a component. There are **0** stories.

---

## 1. What is actually reusable

Verified by reading both trees. The honest split between *code you can lift* and *designs you must
re-implement*:

| From DataInViz | Reuse as | Why |
|---|---|---|
| `lib/context/ActionsContext.tsx` (57 lines) | **Lift, adapt** | Framework-agnostic React. Drop `"use client"`. |
| `lib/context/AppActionsProvider.tsx` (49 lines) | **Lift, adapt** | Same. |
| `lib/actions/*.ts` (16 interfaces) | **Copy the shape** | Domain-specific; the discipline transfers, not the content. |
| `lib/visualizations/types.ts` (153 lines) | **Copy the shape** | Field-descriptor system is the valuable part. |
| `lib/visualizations/core/registry.ts` (19 lines) | **Re-implement** | Trivial, and it performs *no validation* — see §4. |
| `connection-controller/packages/core/src/registry.ts` | **Copy the idea only** | Duck-typing; Go has a type system. See §5. |
| `.storybook/main.ts` | **Do not copy** | `@storybook/nextjs-vite`. We are plain Vite. |
| `.storybook/vitest.setup.ts` (`setProjectAnnotations`) | **Lift** | The story-as-test bridge is portable. |
| `agents-md/*/instructions.md` (1,344 lines) | **Lift as reference** | They are markdown files. Prose transfers directly. |
| `services/llm_controller` (TypeScript service) | **Copy the design** | See §3 — do not deploy a Node service. |

### The DI mechanism, precisely

DataInViz injects through **context**; `DevicesRoute` injects through **props**. Both are correct,
and the difference matters:

- **Props** — explicit, no magic, perfect for a route boundary. What `DevicesRouteProps` already does.
- **Context** — avoids drilling through seven component layers. What SOC needs.

Use **both**: props at the route boundary (so a test constructs a route with a fake API and no
provider), context beneath it (so `panels.tsx` does not receive an `api` prop through four
ancestors). The route reads its prop and publishes it into context. DataInViz only needed context
because Next.js cannot serialize functions across the server boundary — a constraint we do not have,
so we are free to keep the props seam that is already working.

One detail worth copying verbatim: `actions/types.ts` types results as `unknown`
*"to avoid direct dependency on supabase types"*. The interface layer names no backend type. That is
the rule that makes the fake trivially writable.

---

## 2. Tier 1 — `feat/console-testability`

Corrective. Behaviour-preserving throughout: the Playwright suite (47 passed, 12 skipped) is the
contract. A DOM change that was not intended is a failure, not a diff to accept.

### Ordering is derived from counting, not size

Files importing their feature's `api.ts` directly, measured:

| Route | Hooks | Components | Cost | Why |
|---|---:|---:|---|---|
| `devices` | 2 | 0 | **done** | `DevicesApi` + `createDevicesApi(request)`. The model. |
| `fleet` | 2 | 0 | small | All network already inside `useFleetSnapshot`, `useFleetControls`. |
| `soc` | 1 | 7 | medium | `panels`, `CorrelationGraph`, `DrillPanel`, `SocModals`, `GraphSelectionRail`, `exportStudio`, `analytics`. |
| `choke` | 5 | 5 | largest | Spread across both, and it is the containment path — highest blast radius. |

**Order: fleet → soc → choke.** Fleet proves the pattern on two hooks and zero components. Choke goes
last because a mistake there is a mistake in the path that kills processes.

### 1A — Dependency injection (medium)

- **Fleet.** Define `FleetApi` beside `fleet/api.ts` mirroring `DevicesApi`. Inject into the two
  hooks, defaulting to the real client so no call site changes. Fix two known bugs while the hooks
  are open: `useFleetSnapshot` fetches with no `AbortSignal`, and the toast timer is never cleared.
- **SOC.** Lift the seven components' fetches into `hooks.ts` first, then inject once. Do not inject
  and lift in the same commit — the lift is where behaviour can drift, and it needs its own e2e run.
- **Choke.** Same lift for five components, then inject into five hooks. Verify with e2e between
  each step.
- Give every route a `*RouteProps` with `api`, `pollMs`, `now` — the three seams `DevicesRoute`
  already has. Publish `api` into `ActionsContext` at the route boundary.

**Exit:** every route renders in a test with a fake API and **zero network**. One route-level unit
test per route. Playwright still 47/0.

### 1B — Storybook and component tests (medium)

Configure Storybook for **`@storybook/react-vite`**. The reference config is `@storybook/nextjs-vite`
and will not transfer; only `vitest.setup.ts`'s `setProjectAnnotations` bridge does.

**Prerequisite, and it is a real one:** story-as-test needs Vitest browser mode, which needs
**Vitest 3+**. This repo is on `2.1.8`. Dependabot PR **#11** (`vitest 2.1.9 → 4.1.10`) is therefore
a dependency of this phase, not unrelated noise. Land it first, with `@vitest/browser` and
`@vitest/coverage-v8` moved to matching majors.

Stories for the containment path first — enforcement ladder, confirm modals, choke tables, device
tables — because those are the components where a silent regression has the worst consequence.

**Exit:** stories for every containment-path component. Coverage measured per component and
ratcheting up from 13.19%, the way the Go ratchet already works.

### 1C — Visualization registry (medium)

Current state is bespoke: `renderForceGraph` at 370 lines inside an 840-line `CorrelationGraph.tsx`,
`panels.tsx` at 1,711 lines, plus hand-rolled timeline, MITRE matrix and KPI tiles. Adding a panel
means editing four places.

Measured duplication — and it is worse than duplication, it is **divergence**:

- `formatTime` defined **4×** with **three different signatures**: `(value: string)` in
  `soc/format.ts`, `(iso?: string)` in `soc/panels.tsx`, `(value?: string)` in `choke/utils.ts` and
  `fleet/fleetLogic.ts`.
- `Sparkline` defined **2×** with **different props**: `{ bars: number[] }` in
  `choke/components.tsx`, `{ values: number[] }` in `soc/components.tsx`.

These are not drop-in replacements for each other. Consolidating them is a behaviour change that
needs tests first — which is why this comes after 1A and 1B, not before.

Port the **contract**, not the chart library. We need no geomap or boxplot. We need
`registry + normalize + fieldSpecs` so a SOC panel becomes a module instead of another 300 lines in
a route file.

**Add validation the reference does not have** — see §4.

---

## 3. Tier 2 — `feat/soc-assistant`

Additive. Introduces the first external network dependency and a live API key.

### The hard constraint

The assistant must never hold `sever`, `quarantine`, `bulk-manual`, or the kill-switch. An agent with
those tools is precisely the *one actor contains many hosts* risk that EN-2 dual control exists to
prevent — minus the second pair of eyes. Give it queries; let a human press the button.

Measured surface: **84 endpoints, 63 GET, 26 mutating**, of which **17 are containment actions**:

```
/api/choke/kill-switch      /api/choke/device-kill-switch   /api/fleet/kill-switch
/api/choke/jail             /api/choke/device-jail          /api/fleet/device-jail
/api/choke/bulk-manual      /api/choke/manual               /api/choke/thaw
/api/choke/device-thaw      /api/choke/device-mode          /api/choke/mode
/api/choke/preset           /api/choke/thresholds           /api/choke/forget
/api/choke/annotate         /api/choke/policy/preview
```

Enforce read-only in the **registry**, not in a prompt. A prompt is a request; a registry is a
constraint.

### Where it runs: Go, in-engine — not a Node service

`llm_controller` is mature and tempting to lift wholesale. Do not. This product deploys as **static
Go binaries with `CGO_ENABLED=0`** under systemd; the only container is Tetragon. Adding a Node
service to a host that runs as root with `CAP_BPF` means a new runtime, a new systemd unit, a new
listening port, and an npm dependency tree on a security appliance. That is a material increase in
attack surface to obtain an HTTP client and a prompt loader.

What transfers is the **design**:

- **Provider abstraction.** `providers/openai.ts:72` reads `baseURL` from config with an env
  fallback. That is the entire reason OpenWeights needs no new code path — it is OpenAI-compatible.
  Reproduce that one idea in Go: base URL, model and key all configuration.
- **Agents as markdown.** `agents-md/*/instructions.md` are plain files, reviewable in a PR like any
  other artefact. Lift them as *reference*, and copy one policy verbatim from
  `researcher/instructions.md`: **"No fabricated numbers — do not invent values to fill gaps."** An
  LLM inventing an alert count on a SOC console is not a quality problem, it is a safety problem.
- **Tool map construction.** `buildMemoryToolMap` builds a tool map from injected dependencies rather
  than importing them. Same idea, Go types.

### 2A — Provider and read-only tool surface (small)

`engine/internal/assistant/`:

- `provider.go` — `Provider` interface plus an OpenAI-compatible client. Base URL, model and key from
  config. Key from `OPEN_WEIGHT_API_KEY`, read the way `cmd/controlplane/main.go` already reads
  `CP_ADMIN_TOKEN`. Never in the browser, never in the repo, never in a deploy script.
- `tool.go` — `Tool` carries the HTTP method and path it maps to. `Registry.Register` **rejects
  anything that is not GET**, and rejects any path on the containment denylist.
- Defence in depth: the HTTP doer handed to tools refuses non-GET at the transport, so a tool that
  builds its own request still cannot mutate. Registration validation catches mistakes loudly;
  the transport catches them absolutely.
- Tools: alerts, events, decisions, process tree, MITRE lookup.

**Exit:** a tool that mutates **cannot be registered**, proven by a failing test — the ratchet idea
from `internal/isolationguard`, which is already tests-only with a `doc.go` to stay buildable.

### 2B — Agents and console integration (medium)

Two agents to start, both mapping to work an analyst does by hand today: *explain this process chain*
and *summarise this incident*. The assurance-report generator in `ChokeRoute` is already a blunt
version of the second.

Surface it in the drill panel where the operator already is — not a separate chat page.

**Depends on Tier 1A/SOC.** The drill panel lives in the route with seven components still fetching
directly. Wiring a new surface into the least-testable file in the tree, before it has a seam, is how
`panels.tsx` reached 1,711 lines. Do SOC's DI first.

**Exit:** an analyst asks *"why did this score 117?"* and gets an answer grounded in the actual
chain, with the key held server-side.

---

## 4. Registries: port the contract, add the validation

The reference has **two** registries and they are not equally good:

- `lib/visualizations/core/registry.ts` — 19 lines, a bare `Map.set`. **No validation at all.**
- `connection-controller/packages/core/src/registry.ts` — 150 lines, validates every required method
  at load time and **stores constructors, not instances**, "so that per-request mutable state cannot
  leak between concurrent calls."

Port the visualization *contract* with the plugin registry's *rigour*: a panel module that fails to
satisfy the contract must be rejected when it registers, not when a user opens the dashboard.

---

## 5. Tier 3 — `feat/backend-contracts` (Go)

Independent of the frontend; can run in parallel.

### The `alertstats` 501 is real — and it is two capabilities, not one

`alertstats.go:166` does return `http.StatusNotImplemented`. It is easy to miss with a grep for
`501`, because the code names the constant:

```go
ranger, canRange := s.cfg.Store.(centralstore.RangeQuerier)
if !canRange {
    http.Error(w, "alert stats unsupported by this store backend", http.StatusNotImplemented)
    return
}
```

The endpoint type-asserts **two** optional capabilities with different consequences, and only one of
them is handled well:

| Capability | Missing → | Verdict |
|---|---|---|
| `SeverityCounter` | falls through to a bounded scan, logs a warning | **already right** |
| `RangeQuerier` | **501 to the operator** | the finding |

So the graceful pattern already exists in the same function, twelve lines above the failure. The
`SeverityCounter` path is documented as optional, carries compile-time assertions
(`var _ SeverityCounter = (*Store)(nil)`), and degrades. The `RangeQuerier` path has none of that —
it is discovered by type assertion at request time, and the operator learns about it as a broken
dashboard tile.

This is the argument for capability descriptors in one function: whether a backend can answer
`/api/alert-stats` is knowable at construction, not at request time. A backend that cannot should
fail to register, or declare the gap so the console never offers the tile — not 501 mid-incident.

### What else is missing

1. **No compile-time assertions in `internal/enforce/`.** Zero `var _ Enforcer = (*Multi)(nil)` —
   verified, the count is 0. Trivial to add, and the cheapest guard Go offers. Contrast
   `centralstore/severity.go`, which does carry them: the codebase already knows this pattern, it is
   just not applied where enforcement lives.

2. **The real Liskov failure is semantic, and Go's type system cannot catch it.** `Enforcer`
   documents *"implementations must be idempotent"*. `DryRun.Apply` is a no-op returning `nil` — so a
   caller **cannot distinguish "enforcement applied" from "enforcement pretended."** That is the same
   class as the F4 bug already fixed in `cgroupv2`, where a discarded `cgroup.freeze` error recorded
   `outcome=ok` for a quarantine that never happened.

   The Go analogue of `isValidConnection` is therefore **not** a method-presence check — Go has that
   already. It is a **shared conformance suite**: one table-driven test every backend must pass,
   asserting idempotency and what a `nil` return actually promises.

3. **`NoopDeviceBackend` returns `(nil, nil)`** from `SeenSnapshot` and `FlowsSnapshot` — an
   undeclared third state that is neither data nor error. A capability declaration makes "this
   backend has no kernel side" explicit instead of encoding it as a silent nil.

4. **`Multi.Apply` discovers capability by trying.** `ErrUnsupported` means "next backend please".
   A declared capability set would let `Multi` route rather than probe.

---

## 6. Sequencing

```
Tier 1A fleet ─→ 1A soc ─→ 1A choke ─→ 1C registry
                    │
                    └─────────────────→ Tier 2B console integration
Tier 2A provider + tools ──────────────↗   (independent; start any time)

Tier 3 backend contracts ── parallel, no frontend dependency
```

**Start with 2A and 1A-fleet.** 2A is a new Go package touching nothing, and it carries the security
decision, so it deserves attention while the tree is quiet. 1A-fleet is two hooks and proves the DI
shape on the smallest surface before SOC.

Prerequisite for 1B: land Dependabot **#11** (Vitest 4).

---

## 7. What not to do

- **Do not deploy a Node service** for the assistant (§3).
- **Do not copy `.storybook/main.ts`** — wrong framework.
- **Do not port geomap, boxplot, histogram.** We need the registry contract, not ten chart types.
- **Do not consolidate `formatTime`/`Sparkline` before tests exist.** Three signatures and two prop
  shapes mean consolidation is a behaviour change.
- **Do not give the assistant a write tool**, however narrow, however well-prompted.
- **Do not merge Dependabot #1** (`golang 1.27rc2-bookworm`) — a release candidate in a deploy image
  for a product running as root with `CAP_BPF`.

## 8. Measurement baseline (2026-08-16)

| Metric | Now | Target |
|---|---:|---|
| Frontend line coverage | 13.19% | ratcheting, floor raised per batch |
| Frontend function coverage | 27.12% | — |
| Test files / that render a component | 30 / **3** | every containment component |
| Stories | **0** | containment path complete |
| Routes with injected API | **1 of 4** | 4 of 4 |
| `formatTime` definitions | **4** (3 signatures) | 1 |
| `Sparkline` definitions | **2** (2 prop shapes) | 1 |
| Playwright | 47 passed, 12 skipped | unchanged — it is the contract |
| Assistant write tools | n/a | **0, enforced by a failing test** |
