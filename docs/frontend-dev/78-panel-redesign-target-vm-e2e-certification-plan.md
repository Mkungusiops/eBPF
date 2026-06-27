# 78-Panel Redesign And Target VM E2E Certification Plan

> Status: redesign and certification plan
> Date: 2026-06-25
> Scope: full panel-by-panel redesign of the embedded eBPF web UI
> Constraint: full replacement UI, end-to-end tested on the deployed target VM, no compatibility fallback

## Purpose

This document defines the delivery and certification plan for replacing the embedded eBPF web UI
with a full redesigned 78-panel application. It assumes a large agent team, strict ownership,
frozen scope, continuous verification, and target-VM end-to-end proof before the work is called
complete.

This is not a compatibility cutover. The legacy HTML may be used as a behavior oracle while
building and testing, but the shipped UI is a full replacement.

## Executive Position

A full 78-panel redesign is a high-risk, high-concurrency project because the application has
78 panels, 63 HTTP routes, 21 CSRF-protected writes, one SSE stream, D3, PDF/CSV exports,
localStorage continuity, and Go binary embedding.

The work is viable only if the team does not attempt an unstructured panel-by-panel rewrite. The
team must build a single cohesive application platform, assign every panel to an owner, integrate
continuously, and let automated end-to-end gates determine release readiness.

Expected risk: extreme.

Expected confidence if executed well:

- Visual redesign complete across all panels: medium-high
- Core workflows end-to-end: medium
- All writes, SSE, auth, deploy, flood, and edge states clean: medium-low
- Production polish across every long-tail edge case: low

## Non-Negotiables

- All five routes ship redesigned: `/`, `/choke`, `/devices`, `/fleet`, `/login`.
- All 78 panels are implemented, wired, and testable.
- No route-level runtime fallback to the legacy HTML.
- No "MVP-only" surfaces presented as complete.
- Existing Go auth remains authoritative.
- Existing API contracts are preserved unless a backend bug blocks correctness.
- All 21 unsafe write paths are CSRF-tested.
- The single Go binary deployment model is preserved.
- Runtime CDN dependencies are removed.
- SSE, auth redirects, CSRF, 503 disabled states, localStorage continuity, static embedding,
  and target VM E2E certification must pass.

## Delivery Strategy

The redesign succeeds by changing the shape of the work, not by pretending the work is small.

Core strategy:

1. Build one frontend platform shared by all consoles.
2. Create one design system and forbid local component forks.
3. Keep API contracts stable.
4. Split panel ownership cleanly.
5. Put integration and testing on the same priority as feature work.
6. Treat the legacy UI as the source of behavioral truth.
7. Ship only when the release gates pass.

The design target is behavioral parity with a new visual system. It is not pixel parity.

## Stack Decision

Use the companion recommendation from `recommended-stack.md`:

- Vite multi-entry
- React
- TypeScript strict
- Tailwind via PostCSS
- Zustand
- Radix UI primitives
- cmdk
- TanStack Virtual
- D3 dynamic import for the SOC correlation graph
- jsPDF + jspdf-autotable dynamic import
- Vitest
- Playwright

Do not use Next.js for this plan. The production runtime is static assets embedded into
the Go binary, with Go-owned auth and no SSR. Vite matches the current five-page model and avoids
static-export friction.

## Team Model

Recommended active swarm: 32-40 implementation agents plus a small command cell.

More agents than this will likely reduce throughput because the shared platform, stores, design
system, and test harness become merge bottlenecks.

### Command Cell

| Role | Count | Responsibility |
|---|---:|---|
| Lead integrator | 1 | Own architecture, branch health, merge order, final release decision |
| Design director | 1 | Own visual system, density, responsive rules, tokens, UX consistency |
| API/build integrator | 1 | Own Go embed, auth allowlist, CSRF behavior, asset serving, Makefile |
| QA commander | 1 | Own Playwright gates, fixtures, test data, target VM certification, release report |

### Workstream Ownership

| Workstream | Agents | Write Ownership |
|---|---:|---|
| Platform | 5 | `web/src/lib`, stores, providers, Vite, app bootstraps |
| Design system | 5 | `web/src/components`, tokens, shared CSS, accessibility primitives |
| SOC dashboard | 10 | `web/src/features/soc` |
| Choke console | 8 | `web/src/features/choke` |
| Fleet console | 3 | `web/src/features/fleet` |
| Devices console | 3 | `web/src/features/devices` |
| Login/auth shell | 1 | `web/src/features/login`, auth shell wiring |
| Test automation | 6 | Playwright, Vitest, fixtures, smoke, contract checks |
| Release/deploy | 2 | build packaging, target VM deploy, rollback rehearsal, runbook |

## Repository Architecture

Create `web/` at the repo root as a Vite multi-entry app.

```text
web/
  index.html
  choke.html
  devices.html
  fleet.html
  login.html
  src/
    entries/
      soc.tsx
      choke.tsx
      devices.tsx
      fleet.tsx
      login.tsx
    app/
      Shell.tsx
      providers.tsx
    components/
      badges/
      charts/
      command/
      feedback/
      forms/
      layout/
      overlays/
      tables/
    features/
      soc/
      choke/
      devices/
      fleet/
      login/
    lib/
      api.ts
      stream.ts
      types.ts
      dsl.ts
      classify.ts
      device.ts
      fleet.ts
      storage.ts
      csv.ts
      pdf.ts
    stores/
    test/
```

Build output goes to `web/dist/`, then into `engine/internal/api/web/` for `go:embed`.

## Backend Integration Requirements

These backend changes are mandatory for the redesigned UI to work end-to-end:

- Add directory `embed.FS` for built frontend assets.
- Serve Vite assets with immutable caching.
- Serve HTML with `Cache-Control: no-store`.
- Keep Go auth/session/cookie behavior unchanged.
- Keep `soc_session` and `csrf_token` names unchanged.
- Keep `/api/login` and `/api/run-attack` form-encoded.
- Widen public auth paths for login assets, built static assets, `/favicon.svg`,
  `/favicon.ico`, and `/favicon-light.svg`.
- Add deterministic version hashing over the entire embedded web filesystem.
- Preserve `X-Accel-Buffering: no` and flushing behavior for SSE.
- Fix any fleet CSRF/fan-out mismatch that prevents fleet writes from working.

## Shared Runtime Contracts

### API Client

All feature code must call one shared `api()` helper.

Requirements:

- Read `csrf_token` from `document.cookie`.
- Attach `X-CSRF-Token` to every unsafe same-origin `/api/*` request.
- Preserve form-encoded calls for `/api/login` and `/api/run-attack`.
- Redirect 401s to `/login`.
- Surface 403 as an explicit CSRF/auth failure.
- Surface 503 as disabled-state UI for fleet, devices, and choke-dependent panels.
- Preserve `copyToClipboard` fallback for plain HTTP.

### SSE

All realtime behavior must use one shared stream provider.

Requirements:

- One `EventSource('/api/stream')` per tab.
- No CSRF on SSE.
- No `withCredentials`.
- Heartbeats update connection freshness but do not create visible events.
- Reconnect after transient failure.
- Probe `/api/whoami` after repeated closed/error states to detect expired sessions.
- Refresh REST snapshots after reconnect because there is no replay stream.
- Batch high-volume updates with `requestAnimationFrame`.
- Cap long lists to protect render performance.

### Storage

All localStorage access must go through a typed storage utility.

Requirements:

- Preserve existing `soc.*` keys where operator continuity depends on them.
- Preserve shared theme key `soc.theme`.
- Preserve avatar key shape `soc.avatar.<user>`.
- Preserve Choke keys for tape ack, jail filters, notifications, watchlist, and refresh state.
- Treat storage decode failures as recoverable, not fatal.

## Design System Contract

Every panel must use the shared design system. No feature team should create private versions of
tables, modals, buttons, badges, popovers, or toasts.

### Required Components

- `AppShell`
- `TopNav`
- `SideRail`
- `PageHeader`
- `Panel`
- `SectionHeader`
- `StatCard`
- `KpiTile`
- `DataTable`
- `VirtualList`
- `FilterBar`
- `SearchInput`
- `StateBadge`
- `SeverityBadge`
- `ModeBadge`
- `HealthPill`
- `OriginPill`
- `RiskChip`
- `Toast`
- `Modal`
- `ConfirmModal`
- `SlideOver`
- `Popover`
- `DropdownMenu`
- `ContextMenu`
- `CommandPalette`
- `ThresholdSlider`
- `Sparkline`
- `TimelineBars`
- `FlowList`
- `EmptyState`
- `ErrorState`
- `LoadingState`

### Visual Direction

The redesigned UI should feel like an operational security console:

- Dense, scan-friendly screens.
- Strong hierarchy without decorative clutter.
- Consistent dark and light themes.
- Clear severity, mode, health, and enforcement color semantics.
- Tables optimized for repeated operator use.
- Predictable keyboard and modal behavior.
- Responsive behavior preserved where practical, with desktop operator workflows prioritized.

### Accessibility Baseline

Every shared overlay and command surface must include:

- Escape close.
- Backdrop close where appropriate.
- Focus trap for modal dialogs.
- `role="dialog"` and `aria-modal` for modals.
- `aria-live` for toasts and stale/reconnect banners.
- Visible focus states.
- Keyboard access for menu and command actions.

## Panel Inventory And Ownership

Every row below is part of the release scope.

### Login - 1 Panel

| Panel | Owner | Required Behavior |
|---|---|---|
| Login form | Login/auth shell agent | Native POST to `/api/login`, `?err=1` error, theme toggle, password reveal, unauthenticated assets |

### Devices - 7 Panels

| Panel | Owner | Required Behavior |
|---|---|---|
| Top bar / header | Devices A | SOC/choke links, title, data-plane strip, bridge-master warning |
| Disabled banner | Devices A | 503 gateway-disabled state |
| State counts strip | Devices A | pristine/throttled/tarpit/quarantined/severed counts |
| Enforcement mode bar | Devices B | `device-mode`, `device-kill-switch`, reason-required confirm |
| Bulk action bar | Devices B | select all, action, reason, revert, `device-jail`, `device-thaw` |
| Device table | Devices C | MAC, IP, hostname, state, bucket, protected, source, last seen |
| Per-device flows expander | Devices C | `device-flows?mac=`, destination list sorted by activity |

### Fleet - 13 Panels

| Panel | Owner | Required Behavior |
|---|---|---|
| Top bar / header | Fleet A | identity, nav, theme |
| Disabled banner | Fleet A | 503 fleet-disabled state |
| KPI strip | Fleet A | aggregate from `/api/fleet/state` |
| Targeting selector | Fleet B | all vs selected target set |
| Posture preset chooser | Fleet B | containment/maintenance confirm and fan-out |
| Thresholds editor | Fleet B | ascending validation, dirty state, fan-out write |
| Emergency controls | Fleet B | kill-switch and thaw fan-out |
| Fleet table | Fleet C | drift, unreachable, selection, row identity |
| Cgroup tier inhabitants | Fleet C | shared-scale bars |
| Live decisions feed | Fleet C | `/api/fleet/decisions?limit=80` |
| Alerts feed | Fleet C | `/api/fleet/alerts` |
| Toasts | Design system + Fleet B | per-host fan-out result reporting |
| Confirm modal | Design system + Fleet B | Radix dialog with danger and reason variants |

### Choke - 26 Panels

| Panel | Owner | Required Behavior |
|---|---|---|
| Topbar Row 1 | Choke A | identity, search, status, user, devices link |
| Topbar Row 2 | Choke A | range, KPIs, refresh, scope, action cluster |
| IR Presets trail bar | Choke A | mode and preset status |
| Stale-stream banner | Stream team + Choke A | 30s stale detection and reconnect action |
| Active filter strip | Choke B | DSL chips and clear behavior |
| Threat-Intelligence ribbon | Choke B | derived local threat cards |
| Engine Stack panel | Choke B | `/api/system-health` |
| State Ladder panel | Choke B | `/api/choke/state` |
| Thresholds panel | Choke C | 4-handle pointer slider, blast radius, threshold write |
| Cgroup Tiers panel | Choke C | `/api/choke/cgroups` |
| Choke Map / BPF mirror | Choke C | `/api/choke/buckets` |
| Tracked Processes list | Choke D | virtualized list, actions, alert chips, origin |
| Decision Tape | Choke E | SSE decisions, cap 400, burst banner, auto-scroll |
| Policy Workbench | Choke F | policy preview |
| Process Drill-in slide-over | Choke F | tracked exec and untracked jail PID variants |
| Jail Process picker modal | Choke G | process polling, inspect drawer, reason-required jail |
| Host reachability popover | Choke H | endpoint health and latency |
| Live data stream popover | Choke H | stream state and reconnect controls |
| Audit chain popover | Choke H | `/api/verify-chain` |
| Enforcement mode popover | Choke H | mode, preset, kill-switch |
| Notifications panel | Choke F | operational notices |
| Admin profile dropdown + avatar | Choke F | shared avatar storage |
| Command palette | Design system + Choke F | cmdk commands |
| Confirm modal | Design system | audit reason and auto-revert |
| Help modal | Choke F | redesigned help surface |
| Operations status bar | Choke A | sticky status and 1s clock |

### SOC Dashboard - 31 Panels

| Panel | Owner | Required Behavior |
|---|---|---|
| Left sidebar | SOC A | persisted collapse, nav, live badges |
| Top bar / header | SOC A | DSL search, risk, time range, host/live/theme |
| Stale-data banner | Stream team + SOC A | reconnect control |
| Version-update toast | Platform + SOC A | `/api/version` SHA change |
| KPI row | SOC B | severity counts, deltas, sparklines, drill open |
| Severity timeline | SOC B | stacked bars, anomaly markers, brush, legend toggles |
| Alert triage queue | SOC C | DSL, classification, group, sort, bulk, keyboard |
| Drill-down slide-over | SOC D | lineage, replay, notes, origin, inline choke action |
| MITRE ATT&CK coverage | SOC E | technique and tactic bars |
| Top processes by score | SOC E | lazy origin via `/api/process` |
| IOCs observed | SOC E | file and network indicators |
| Network connections | SOC E | outbound TCP peers |
| Live event stream | SOC F | SSE, cap 200, pause, filter, virtualized |
| Policy viewer modal | SOC G | `/api/policies`, `/api/policy-stats` |
| Quick-fire attacks modal | SOC G | `/api/attacks`, `/api/run-attack` form POST |
| Process correlation graph modal | SOC H | D3 island, zoom, drag, TTL fade |
| Rule simulator modal | SOC I | redesigned simulator |
| MITRE Navigator modal | SOC I | PDF export path |
| Fleet modal | SOC J | peer probes, credentials included, mixed-content limitation surfaced |
| Watchlist modal | SOC J | localStorage-compatible watchlist |
| Honeypots modal | SOC G | `/api/honeypots`, 5s poll |
| Kprobe performance modal | SOC G | `/api/policy-stats`, 5s poll |
| Time Machine modal | SOC I | snapshot/live source switch |
| Command palette | Design system + SOC J | cmdk |
| Notifications center modal | SOC J | read/clear, localStorage |
| Account / profile modal | SOC J | avatar shared with Choke |
| KPI drill modal | SOC B | severity, EPS, and process variants |
| Pill popovers | SOC A | live, host, risk |
| Help modal | SOC J | redesigned help |
| Export confirm modal + PDF/CSV | SOC I | dynamic jsPDF and CSV |
| Alert hover preview + context menu | SOC C | viewport clamping |

## End-To-End Certification

The redesign is releasable only when the certification gates below pass. These are not optional
smoke checks; they are the release definition. Local tests are necessary but insufficient: the
final release claim requires proof from the deployed target VM.

### Repo Gate

- `go test ./...` passes.
- Web typecheck passes.
- Web lint passes.
- Vitest unit tests pass.
- Built HTML contains no runtime CDN dependencies.
- D3 and PDF libraries are dynamically imported where required.

### Auth And API Gate

- `/login` loads unauthenticated with all required assets.
- Bad credentials show the login error.
- Good credentials set cookies and land on the app.
- Logout clears session cookies.
- Unauthenticated API requests return the expected 401 behavior.
- Every unsafe surfaced write sends `X-CSRF-Token`.
- Missing CSRF returns 403.
- `/api/login` and `/api/run-attack` remain form-encoded.
- Fleet, Devices, and Choke disabled states render cleanly on 503.

### Browser Route Gate

| Route | Required Checks |
|---|---|
| `/login` | unauthenticated load, bad creds, good creds, theme, password reveal |
| `/` | all 31 SOC panels render, stream updates, alert drill, modals, attack flow |
| `/choke` | all 26 Choke panels render, state, circuits, decisions, threshold write, manual action, jail picker |
| `/devices` | all 7 panels render, disabled or active state, counts, bulk validation, flows expander |
| `/fleet` | all 13 panels render, disabled or active state, drift, thresholds, preset, kill-switch, thaw |

### Realtime Gate

- One EventSource per tab.
- Heartbeats do not create visible events.
- Stale banner appears after silence.
- Reconnect restores REST snapshots.
- Expired session redirects to `/login`.
- Fake-mode stream updates SOC and Choke surfaces.
- Decision flood does not lock the UI.
- Long lists are capped and/or virtualized.

### Embedded Binary Gate

- One binary serves all five redesigned routes.
- Built assets load after authentication.
- Login assets load before authentication.
- Static asset responses have immutable cache headers.
- HTML responses have `no-store`.
- `/api/version` changes on frontend asset changes.
- No clean route falls through to a 404 unexpectedly.
- No CDN or external asset request is required.

### Target VM Deploy Gate

- Linux build succeeds.
- The redesigned frontend is embedded into the Linux engine binary.
- The binary is deployed to the target VM through the project deploy path.
- The target VM service starts cleanly.
- Target VM login works in a real browser session.
- All five routes load on the target VM.
- Browser console is clean for release-critical flows.
- SSE works through the deployed target VM path.
- A safe attack flow updates SOC.
- A representative Choke write flow succeeds.
- Device and Fleet routes render either enabled state or explicit disabled state, depending on
  host configuration.
- `/api/version` on the target VM reports the newly deployed frontend SHA.
- Release report records known residual risks and links to target VM test artifacts.

### Target VM Evidence Gate

The target VM certification run must produce artifacts that can be reviewed after the fact:

- deployed binary name, build timestamp, and frontend version SHA
- target VM hostname or alias
- target VM service status after deploy
- Playwright HTML report
- Playwright traces for failures
- screenshots for `/login`, `/`, `/choke`, `/devices`, and `/fleet`
- browser console log capture
- network request capture showing no CDN dependency
- `/api/version` response
- safe attack smoke result
- representative Choke write result
- Fleet and Devices enabled/disabled-state result

## Test Implementation Plan

Required Playwright suites:

- `auth.spec.ts`
- `routes.spec.ts`
- `csrf.spec.ts`
- `sse.spec.ts`
- `soc.spec.ts`
- `choke.spec.ts`
- `devices.spec.ts`
- `fleet.spec.ts`
- `embedded.spec.ts`
- `target-vm-smoke.spec.ts`

Required Vitest suites:

- `dsl.test.ts`
- `classify.test.ts`
- `device.test.ts`
- `fleet.test.ts`
- `storage.test.ts`
- `api.test.ts`
- `stream.test.ts`

Required test fixtures:

- fake-mode event stream
- representative alerts
- representative process lineage
- representative decisions
- Choke state snapshot
- Fleet fan-out success
- Fleet partial failure
- Device state active
- Device state disabled
- Device protected MAC failure
- expired session
- missing CSRF

## Acceptance Criteria

The UI is complete only if all of these are true:

- All 78 panels are redesigned.
- All 78 panels are wired to real data or a real disabled/error state.
- All surfaced mutations are CSRF-clean.
- All modals, popovers, drawers, and command surfaces use shared primitives.
- All routes pass browser smoke.
- SOC and Choke realtime behavior works.
- Fleet and Devices poll behavior works.
- LocalStorage continuity is preserved for operator-critical keys.
- The app works without external network assets.
- The deployed target VM passes the full target VM E2E certification gate.

## Target VM Certification Flow

The target VM is the final source of truth for release readiness. A local build can pass every
unit and browser test and still fail because of static embedding, auth allowlists, nginx/proxy
behavior, service startup, target host flags, or missing runtime assets.

The certification flow must exercise the deployed system as an operator would use it:

1. Build the Linux engine binary with the redesigned frontend embedded.
2. Deploy the binary to the target VM.
3. Start or restart the engine on the target VM using the project-approved deploy path.
4. Open the target VM URL in Playwright.
5. Log in through `/login`.
6. Visit `/`, `/choke`, `/devices`, and `/fleet`.
7. Assert that every panel renders a data, empty, disabled, or error state.
8. Verify that no browser console release blocker is emitted.
9. Verify that no CDN or external runtime asset is requested.
10. Verify that `/api/version` reflects the deployed frontend build.
11. Verify SOC realtime behavior through the deployed SSE path.
12. Run a safe attack flow and confirm SOC updates.
13. Run a representative Choke write with CSRF and confirm the UI updates.
14. Verify Devices and Fleet active or disabled states according to target VM configuration.
15. Save screenshots, traces, logs, and the release report.

## Risk Register

| Risk | Severity | Mitigation |
|---|---|---|
| D3 graph consumes multiple agents | High | One owner, imperative island, stable wrapper contract |
| SOC triage slips | High | Treat triage as core product path; assign dedicated owner |
| Choke decision tape janks | High | Store updates outside React, caps, virtual list, rAF batching |
| Threshold slider regressions | High | Dedicated owner, pointer tests, threshold validation unit tests |
| Jail picker/action path fails | High | Explicit Playwright flow with reason-required CSRF write |
| Fleet CSRF/fan-out mismatch blocks writes | High | API/build integrator owns backend correction |
| Static asset auth breaks login | High | Embedded binary gate covers unauthenticated assets |
| Agents fork design primitives | High | Shared component ownership, reject local component forks |
| Merge conflicts slow integration | High | Disjoint feature folders and command-cell ownership of shared files |
| LocalStorage incompatibility | Medium | Typed storage utility and snapshot diff |
| Device choke cannot be fully validated on target host | Medium | Remote disabled-state smoke plus Linux/netns validation |
| Visual completeness hides broken writes | High | CSRF and route-specific Playwright gates block release |
| Browser performance degrades under stream flood | High | Virtualization, list caps, rAF batching, flood test |
| Long-tail modal polish misses | Medium | Shared overlay primitives and panel checklist |

## Things Not To Do

- Do not keep a route-level legacy fallback as part of the release claim.
- Do not introduce a second fetch wrapper.
- Do not introduce private modals, popovers, toasts, badges, or tables.
- Do not rename cookies or auth paths.
- Do not convert `/api/run-attack` to JSON.
- Do not put D3 under React's SVG ownership.
- Do not wait until the end to test deploy embedding.
- Do not use CDN scripts.
- Do not mark a panel complete without loading, empty, error, and data states.

## Final Feasibility Call

This plan accepts the product constraint: full 78-panel redesign, end-to-end testing on the
deployed target VM, and no compatibility fallback.

The risk remains red. The work can be attempted with a large, disciplined agent swarm, but the
release should be judged only by the certification gates above. If the gates do not pass, the
honest result is not "done."
