# Frontend Migration — HTML → Next.js (single source of truth)

### eBPF Runtime-Security Engine — web console conversion

> **Status:** proposed · **Authored:** 2026-06-17 · **Last verified against the codebase:**
> 2026-06-25 · **Author:** generated from a full bottom-up analysis of the embedded consoles.
>
> This is the **one combined document** for the migration — it folds together what used to be
> four files (`work-plan.md`, `api-inventory.md`, `parity-checklist.md`, and this `README.md`).
> Everything is here: the decision, the architecture, the phased build, the full route
> inventory, the per-panel parity gate, the risk register, and the day-1 quick start.

The goal is to convert the **five** server-embedded vanilla-JS consoles into a single Next.js
app (App Router + TypeScript + Tailwind) that is **statically exported** and **re-embedded
into the Go engine binary** via `go:embed`, served by the existing `net/http` mux in
[http.go](../../engine/internal/api/http.go).

| Page | File | Size | Panels | Role |
|---|---|---|--:|---|
| Main SOC dashboard | [index.html](../../engine/internal/api/index.html) | 539 KB / 11,044 lines | 31 | Real-time threat triage |
| Choke Gateway console | [choke.html](../../engine/internal/api/choke.html) | 368 KB / 7,509 lines | 26 | Per-process incident response / enforcement |
| **Devices (network choke) console** | [devices.html](../../engine/internal/api/devices.html) | 20 KB / 359 lines | 7 | **Per-device (MAC) LAN enforcement** |
| Fleet console | [fleet.html](../../engine/internal/api/fleet.html) | 43 KB / 918 lines | 13 | Multi-host control plane |
| Login | [login.html](../../engine/internal/api/login.html) | 11 KB / 292 lines | 1 | Form-post auth page |

---

## Table of contents

1. [Executive summary & scope options](#1-executive-summary--scope-options)
2. [What changed since the first draft](#2-what-changed-since-the-first-draft-2026-06-17--2026-06-25)
3. [Target architecture & tech stack](#3-target-architecture--tech-stack)
4. [Proposed repo layout & route mapping](#4-proposed-repo-layout--route-mapping)
5. [Shared component & infrastructure architecture](#5-shared-component--infrastructure-architecture)
6. [Phase-by-phase plan](#6-phase-by-phase-plan)
7. [Milestone timeline](#7-milestone-timeline)
8. [Complete API inventory (63 routes)](#8-complete-api-inventory-63-routes)
9. [Real-time / SSE strategy](#9-real-time--sse-strategy)
10. [Auth / session strategy](#10-auth--session-strategy)
11. [Theming strategy](#11-theming-strategy)
12. [Testing & parity strategy](#12-testing--parity-strategy)
13. [Build & deployment integration](#13-build--deployment-integration)
14. [Cutover / rollout strategy](#14-cutover--rollout-strategy)
15. [Risks & mitigations](#15-risks--mitigations)
16. [Parity checklist (per-panel acceptance gate)](#16-parity-checklist-per-panel-acceptance-gate)
17. [Day 1 quick start](#17-day-1-quick-start)
18. [Reference files to read first](#18-reference-files-to-read-first)

---

## 1. Executive summary & scope options

**Scope.** Convert the five embedded vanilla-JS consoles into one Next.js app that is
statically exported (`output: 'export'`) and re-embedded into the Go binary via `go:embed`,
served by the existing mux. **Auth stays 100% in Go**; SSE is consumed client-side via
`EventSource`. No SSR, no Node in production — the single-binary SSH deploy is preserved.

**Scale (verified 2026-06-25):** **78 panels** (SOC 31 / Choke 26 / Fleet 13 / **Devices 7** +
login 1), **63 registered HTTP routes**, **21 CSRF-protected writes**, and exactly **one** SSE
stream (`/api/stream`). The Devices console and its 10 device routes are new since the first
draft — see [§2](#2-what-changed-since-the-first-draft-2026-06-17--2026-06-25).

**Effort.** An earlier conversational estimate of ~12–15 dev-days was a *top-down line-count
guess*. This bottom-up, panel-by-panel analysis (78 panels, 63 routes, a D3 force-graph, 14+
modals, a dual-path drill-in, five near-duplicate PDF generators, a pointer-event threshold
slider, rAF flood-batching, and now a fifth console) puts a **faithful 1:1 port at ~59–85
dev-days** for one engineer — see the [timeline](#7-milestone-timeline). That figure supersedes
the earlier one.

**Why static-export-embedded (decided, reaffirmed).** Production stays a **single static Go
binary deployed over SSH** (SCP + atomic `.new`→live rename — see the deploy targets in the
[Makefile](../../Makefile)). No Node on target hosts, no nginx static dir, no container.
Therefore:

- `output: 'export'` → `out/` tree → embedded via `embed.FS` → served by the existing mux.
- **Auth stays 100% in Go** ([auth.go](../../engine/internal/api/auth.go)): cookie session
  `soc_session` (HttpOnly) + `csrf_token` (JS-readable), HMAC-signed, 24 h TTL. No Next SSR,
  no route handlers, no middleware.
- **SSE consumed client-side** via `EventSource('/api/stream')` — same-origin, cookie
  auto-sent, GET so CSRF-exempt.

### 1.1 Scope options

| Option | Effort | What it includes |
|---|--:|---|
| **A — Faithful 1:1** | ~59–85 dev-days | Every one of the 78 panels at parity, both themes, all modals, all exports, all five consoles. |
| **B — MVP, deferred surfaces** | ~47–58 dev-days | Core triage + per-process enforcement + per-device enforcement + fleet. **Defers:** Time Machine, Rule Simulator, MITRE Navigator PDF, Honeypots & Kprobe-Perf modals, the in-dashboard Fleet *modal* (the standalone `/fleet` console already covers it), and command-palette polish. Each deferred item is a registered modal with a clean seam, shippable later. |

This plan is written for **Option A**; the deferred items in Option B are flagged inline as
`[Option B: defer]`. Pick one explicitly before starting — the difference is ~5 calendar weeks.

---

## 2. What changed since the first draft (2026-06-17 → 2026-06-25)

The `feat/network_choke` branch landed a **whole new enforcement surface** — per-device (MAC)
network choke — after the original four-file plan was written. This combined document folds it
in. Concrete deltas:

- **New console:** `/devices` ([devices.html](../../engine/internal/api/devices.html), 359
  lines, 7 panels) — a per-MAC LAN enforcement console linked from **both** the SOC dashboard
  ([index.html:1816](../../engine/internal/api/index.html#L1816)) and the Choke console
  ([choke.html:1847](../../engine/internal/api/choke.html#L1847)). It is **poll-only (4 s)**,
  has **no SSE**, and is **503-aware** (it lights up only when the engine runs with
  `-devchoke-iface`).
- **10 new routes** (54 → **63**): one page (`/devices`), seven `/api/choke/device-*`
  endpoints, and two `/api/fleet/device-*` fan-outs. Handlers in
  [devchoke.go](../../engine/internal/api/devchoke.go) and
  [fleet.go](../../engine/internal/api/fleet.go).
- **5 new CSRF writes** (16/20 → **21**): `device-jail`, `device-thaw`, `device-mode`,
  `device-kill-switch` (choke side) + `fleet/device-jail`. **These are JSON, not
  form-encoded** — only `/api/login` and `/api/run-attack` remain form-encoded.
- **The Devices console already ships an in-app confirm modal** with Esc + backdrop close,
  danger accenting, and a reason-required variant
  ([devices.html:158-217](../../engine/internal/api/devices.html#L158-L217)). **Use it as the
  reference implementation for the shared `Modal`/`ConfirmModal`** — it is ahead of the fleet
  modal (which still lacks Esc/backdrop close).
- **`computeVersionSHA` is now more wrong, not less.** It still hashes only
  `indexHTML + loginHTML + faviconSVG`
  ([http.go:30-36](../../engine/internal/api/http.go#L30-L36)) — so it misses **choke, fleet,
  AND devices** changes. Phase 8 must widen it to hash the whole `embed.FS` deterministically.
- **`isPublicPath` is unchanged** — still only `/login, /api/login, /favicon.svg,
  /favicon.ico` ([auth.go:324-330](../../engine/internal/api/auth.go#L324-L330)). So
  `/favicon-light.svg` remains auth-guarded (latent bug), and `/_next/*` must be added on
  cutover.
- **All four dark consoles still load Tailwind from `cdn.tailwindcss.com`** (index, choke,
  fleet, devices); only `login.html` is self-styled. The migration drops every CDN script.

**Device gateway gating.** The `/api/choke/device-*` routes are *always registered* but the
handlers `503` with `network device choke not enabled (start engine with -devchoke-iface)`
when the gateway is nil ([devchoke.go:22-28](../../engine/internal/api/devchoke.go#L22-L28)).
The gateway is wired from `main()` only when **both** `-devchoke-obj` (compiled `devchoke.o`)
**and** `-devchoke-iface` (comma-separated bridge-slave interfaces) are set; otherwise an
in-memory noop backend is used. Config keys: `devchoke_obj`, `devchoke_ifaces`,
`devchoke_protect` (the MAC allow-list — gateway/uplink/DHCP-DNS/operator — that the engine
refuses to quarantine/sever). See
[network-choke-gateway.md](../architecture/network-choke-gateway.md) for the data-plane design.

---

## 3. Target architecture & tech stack

| Concern | Decision |
|---|---|
| Framework | Next.js **App Router**, `output: 'export'` (static) |
| Language | TypeScript (strict) |
| Styling | **Tailwind compiled via PostCSS** (drop the runtime `cdn.tailwindcss.com` script — used by all four dark consoles); `darkMode: 'class'`; reproduce the `soc-*` palette as CSS-variable tokens |
| State | Zustand stores mirroring the existing mutable `state` / `S` / `JAIL` / `Pills` / `Sess` objects (imperative-mutate-then-render maps cleanly to Zustand) |
| Realtime | One shared `EventSource('/api/stream')` behind a `<StreamProvider>` + `useStream()` hook (SOC + Choke only; **Fleet and Devices are poll-only**) |
| Data fetching | Typed `lib/api.ts` fetch wrapper (CSRF injection, 401→`/login`, 503 handling); polling via a `useInterval` hook |
| Charts | **Hand-built** sparklines/bars (flexbox/grid divs, as today). **D3 7.9** stays for the correlation-graph island only, **dynamically imported** |
| PDF/CSV | **jsPDF 2.5.1 + jspdf-autotable 3.8.2**, bundled via npm (no CDN), **dynamically imported** |
| Auth | Unchanged Go cookie/CSRF model |
| Serving | `embed.FS` over `web/` + `http.FileServerFS` for `/_next/`; explicit page handlers for `/`, `/choke`, `/devices`, `/fleet`, `/login` |

**Hard constraints (do not violate):**

- No SSR, no Next route handlers, no `middleware.ts`. Every page is `'use client'`.
- Cookie names `soc_session` / `csrf_token`, their flags, the HMAC scheme, and the 24 h TTL
  must not change — [fleet.go](../../engine/internal/api/fleet.go) hard-codes `soc_session`
  for cross-host peer auth (and the device fan-outs ride the same peer channel).
- `EventSource` must **not** set `withCredentials` (same-origin; the Lax cookie auto-sends).
- Bundle Tailwind / d3 / jsPDF locally — remove all runtime CDN `<script>` tags so air-gapped
  internal hosts (and the inline-bridge device-choke box, which may have no WAN) work offline.

---

## 4. Proposed repo layout & route mapping

The Next app lives at repo root in `web/`, sibling to `engine/`. Build output is staged into
`engine/internal/api/web/` (a git-ignored build artifact) for `go:embed`.

```
/Users/jeff/Code/eBPF/
├── engine/
│   └── internal/api/
│       ├── http.go              # mux — extend to serve embed.FS
│       ├── auth.go              # UNCHANGED (logic); widen isPublicPath only
│       ├── choke.go fleet.go …  # handlers UNCHANGED (logic)
│       ├── devchoke.go          # device handlers UNCHANGED (logic)
│       ├── index.go             # swap string embeds → embed.FS
│       └── web/                 # << next export output, go:embed target (gitignored)
├── web/                         # << NEW Next.js app
│   ├── next.config.ts           # output:'export', trailingSlash:true, images.unoptimized
│   ├── tailwind.config.ts       # soc-* palette via CSS vars, darkMode:'class', safelist
│   ├── app/
│   │   ├── layout.tsx           # root: theme bootstrap, providers, no-FOUC <script>
│   │   ├── page.tsx             # / → SOC dashboard (index.html)
│   │   ├── choke/page.tsx       # /choke
│   │   ├── devices/page.tsx     # /devices  (NEW — network choke console)
│   │   ├── fleet/page.tsx       # /fleet
│   │   └── login/page.tsx       # /login (?err=1 read client-side)
│   ├── components/              # shared design system (badges, pills, modal, toast…)
│   ├── features/{soc,choke,devices,fleet}/   # console-specific panels
│   ├── lib/
│   │   ├── api.ts               # typed fetch wrapper + CSRF
│   │   ├── stream.tsx           # StreamProvider + useStream
│   │   ├── dsl.ts               # search DSL parser (ported verbatim, unit-tested)
│   │   ├── classify.ts          # classifyAlert/classifyBinary/guessPolicy
│   │   ├── types.ts             # Event/Alert/Decision/Entry/DeviceEntry from Go structs
│   │   └── pdf.ts csv.ts        # export generators
│   └── stores/                  # zustand: socStore, chokeStore, deviceStore, fleetStore, sessionStore
└── Makefile                     # add `web` target before `build`/`build-linux`
```

**Route → page mapping** (matches the four embedded page handlers in
[http.go](../../engine/internal/api/http.go) + login):

| Go route / handler | Next route | Export file |
|---|---|---|
| `/` `handleIndex` | `app/page.tsx` | `web/index.html` |
| `/choke` `handleChokeConsole` | `app/choke/page.tsx` | `web/choke/index.html` |
| `/devices` `handleDevicesConsole` | `app/devices/page.tsx` | `web/devices/index.html` |
| `/fleet` `handleFleetConsole` | `app/fleet/page.tsx` | `web/fleet/index.html` |
| `/login` `HandleLoginPage` | `app/login/page.tsx` | `web/login/index.html` |

`trailingSlash: true` so `/choke` cleanly maps to `choke/index.html`. Note: `handleIndex`
currently 404s **any non-`/` path** ([http.go:264-266](../../engine/internal/api/http.go#L264-L266))
— the mux must be extended (Phase 8 / smoke-tested in Phase 2.5) to serve `/_next/*` and the
per-route HTML.

---

## 5. Shared component & infrastructure architecture

The biggest leverage point: **all five consoles share visual DNA and ~half their primitives.**
But note the corrected sequencing thesis (see [§6](#6-phase-by-phase-plan)): the *hardest*
shared primitives — `SlideOver`, `PillPopover`, `ContextMenu`, virtualized `DataGrid`, and SSE
flood-batching — **do not appear in Fleet or Devices** (both poll-only, no drill, no live
feed). They are built and hardened in **Phase 0**, proven in **Choke**, not "discovered for
free" by doing the small consoles first. Fleet and Devices first only de-risk the
`api()` / poll / 503 / fan-out / bulk-action / confirm-modal path.

### 5.1 Typed API client — `lib/api.ts`
Port the existing `window.fetch` CSRF wrapper ([index.html](../../engine/internal/api/index.html)
lines 8–29; [choke.html](../../engine/internal/api/choke.html) lines 31–52; the device
console's `post()` at [devices.html:330-340](../../engine/internal/api/devices.html#L330-L340))
into one helper:

- Read the non-HttpOnly `csrf_token` cookie via `document.cookie`; attach `X-CSRF-Token` on
  every non-GET/HEAD/OPTIONS `/api/*` request.
- On `401` (`{error:'unauthorized', redirect:'/login'}`) → `window.location.href='/login'`.
- On `503` → surface "gateway/fleet/device choke not enabled" (the choke, fleet, **and device**
  disabled banners — the device console shows
  `device choke disabled (start with -devchoke-iface)`).
- `copyToClipboard` with an `execCommand` fallback — **keep it**; the engine ships over HTTP
  (non-secure context), so the `navigator.clipboard` API is unavailable and copy buttons
  otherwise silently no-op in prod.
- Typed wrappers per endpoint group; types derived from the Go structs (`store.Event`,
  `store.Alert`, `store.Decision`, `choke.Entry`, `choke.DeviceEntry`, `choke.DeviceFlow`).

### 5.2 EventSource hook/provider — `lib/stream.tsx`
One `EventSource('/api/stream')` per tab behind `<StreamProvider>`; `useStream()` exposes:

- Discriminated-union frames decoded from the JSON envelope `{type,payload}` (the server only
  ever fires the default `message` event): `heartbeat` | `event` | `alert` | `process_exit`
  | `decision`. Early-return on heartbeat (every 15 s).
- Connection enum `connecting | live | reconnect | down`; `lastMessageAt` (any frame incl.
  heartbeat) vs `lastEventAt` (real payload) — the staleness-watchdog vs "Xs ago" distinction.
- **Manual** exponential backoff `Math.min(30000, 1000 * 2 ** Math.min(retries, 5))` (ignore
  native retry); 45 s watchdog; `visibilitychange` reconnect; 30 s stale banner. Keep
  `retries` in a `useRef` (not state) so backoff survives re-render.
- **SSE 401 handling (new):** `EventSource.onerror` cannot expose an HTTP status, so an
  expired 24 h session would otherwise loop forever in backoff. After **N consecutive CLOSED
  transitions** (e.g. 3), `fetch('/api/whoami')`; on 401 → `window.location='/login'`.
- `onReconnect` callback so each page re-hydrates from REST snapshots — there is **no**
  `Last-Event-ID` replay. SOC re-fetches `/api/alerts` + `/api/events`; Choke re-fetches
  `state` + `circuits` + `decisions` + `cgroups` (debounced ~750 ms under bursts). **Devices
  and Fleet don't subscribe at all** — their 4 s/5 s polls *are* their refresh.
- Replaces the monkey-patched `_socHookSSE` / `setLiveState` / `onmessage` patching with a
  subscriber pattern. Drop the dormant `_socHookLiveState` no-op.

### 5.3 Design system — `components/` (extract first, in Phase 0)
Shared by **all five** consoles:

- **Badges/pills:** `StateBadge` (pristine/throttled/tarpit/quarantined/severed — the device
  console uses the identical five-rung palette, see
  [devices.html:11-16](../../engine/internal/api/devices.html#L11-L16)), `SeverityTag`/`SevDot`,
  `ClassificationBadge` (attack/threat/baseline), `UidPill`, `ModePill` (now also
  `enforcing/detect-only/dry-run/kill-switched` for the device plane), `HealthPill`,
  `AckBadge`, `WatchTag`, `HoneyBadge`, `ChokeBadge`, `ProtectedBadge` (device allow-list).
- **Overlays:** `Modal`/`ConfirmModal` (Escape + backdrop close — **port the device console's
  `openConfirm()` as the canonical implementation**: it already has danger accenting, a
  reason-required variant, focus management, and Esc/backdrop close that the fleet modal
  lacks); `SlideOver` (drill panel); `PillPopover` (host/live/audit/risk/mode — same
  head/body/actions shell across index + choke). **Bake an a11y baseline in here** (focus
  trap, `role="dialog"`, `aria-modal`, `aria-live` for toasts/stale-banner) — cheapest now.
- **Feedback:** `Toast`/`ToastContainer` (ok/warn/err) + a `reportFanout` helper for fleet
  *and device* partial-failure reporting (both return `{results:[{...,ok,error}]}` /
  `{hosts:[{name,ok,error,status}]}`).
- **Data:** `StatCard`/`StatTile`/`KpiTile` (sparkline + delta, clickable-filter variant) and
  the device console's plain count cards, `Sparkline` (generic bar strip), `DataGridRow` +
  sticky header + filter chips + sortable column headers (tracked-process list, jail picker,
  decision tape, alert triage, **and the device table** all share this), `BulkActionBar` (the
  device console's select-all + action + reason + revert + choke/thaw bar is a textbook
  instance), `ContextMenu`, `FilterChipBar`.
- **Domain:** `OriginPill`/`OriginBlock`, `RiskSignalChip`, `MitreTacticPill`,
  `ProcessTreeNode`, `RefreshControl`, `ThresholdInput` with dirty tracking, `Button`/`Input`,
  and a `FlowList` (device → destination connections: `dest_ip:port proto · pkts/bytes`).

### 5.4 Pure logic utils (port verbatim, unit-test)
- `lib/dsl.ts` — search DSL (`severity/policy/uid/score/process/exec/pid/ack/pinned`, `/regex/`,
  AND/OR/NOT, bare-number→PID broadening) drives **two** panels in both index and choke;
  choke adds `binary:`/`state:`/`action:`/`score:>N`.
- `lib/classify.ts` — `classifyAlert`/`classifyBinary` (BASELINE_ROOT/DESCENDANT/TOOL regex +
  ATTACK_PATTERNS) and `guessPolicy`; correctness-critical for threat-vs-baseline + MITRE.
- `lib/pick.ts` — `pick(o,'snake','Pascal')` accessor; normalize SSE/fetch payloads to
  canonical snake_case at the boundary, then type as canonical.
- `lib/fleet.ts` — `majority()` + `detectDrift()` (reachable + ok rows only).
- `lib/device.ts` — `flagName(flags)` (bitmask `THROTTLE=1/TARPIT=2/QUARANTINE=4/SEVER=8` →
  label, [devices.html:116-122](../../engine/internal/api/devices.html#L116-L122)), `fmtBytes`,
  and the MAC-id slug helper (`mac.replace(/:/g,'-')` for DOM ids).
- Constants: risk = `critical*8 + high*3 + medium*1` capped at 100; sim thresholds
  low≥5/med≥10/high≥20/crit≥40; caps alerts 200 / events 500 / liveEvents 200 / decisions
  400 / circuits 2000; device bucket rates throttle 50/s, tarpit 5/s, quarantine 1/s.

### 5.5 Theme — `components/ThemeProvider`
No-FOUC bootstrap `<script>` reading `soc.theme` (JSON-encoded) **before paint** in the root
layout. Favicon swap on toggle (`/favicon.svg` ↔ `/favicon-light.svg`). The `soc.avatar.<user>`
localStorage namespace is **shared with choke** via a synthetic `StorageEvent`. (CSP
implications of the inline script: see [§11](#11-theming-strategy) and
[§15](#15-risks--mitigations).) The device console is currently themeless (dark-only); on
migration it inherits the shared theme for free.

---

## 6. Phase-by-phase plan

> **Sequencing correction.** Fleet and Devices go early because they are the smallest *full
> vertical slices* and validate the `api()`/poll/503/fan-out/bulk/confirm path end-to-end —
> **not** because they de-risk the hard primitives (neither has a SlideOver, PillPopover,
> ContextMenu, virtualization, or SSE flood-batching). Those are built in Phase 0 and proven
> under load in Choke.

> **Parity is folded into every console phase's exit criteria.** The
> [parity checklist](#16-parity-checklist-per-panel-acceptance-gate) is the per-panel
> acceptance gate — Phase 7 is a final sweep, not where parity is first measured.

### Phase 0 — Scaffold + infra + hard primitives (8–12 days)
**Goal:** Next app boots; design-system primitives **and the hardest shared infra** exist and
are tested in isolation. This phase carries the load-bearing work the per-console estimates
assume is already done.
**Tasks:**
- `create-next-app` in `web/`; configure `next.config.ts` (`output:'export'`,
  `trailingSlash:true`, `images.unoptimized:true`, `rewrites()` proxying `/api/*` to the
  engine for `next dev` only); Tailwind PostCSS with the `soc-*` CSS-variable palette,
  `darkMode:'class'`, and a **safelist** for dynamically-built class strings (`state-${k}`,
  `st-${state}`, `kpi-delta ${cls}`, `act-*`, arbitrary `text-[11px]`, inline `grid-template`).
- Build `lib/api.ts` (CSRF wrapper, 401/503), `lib/stream.tsx` (StreamProvider + backoff +
  watchdog + visibility + **the new whoami-on-CLOSED 401 probe**), `ThemeProvider` + no-FOUC
  bootstrap, `lib/types.ts` from Go structs.
- Build and **harden the hard primitives now:** `SlideOver`, `PillPopover` (viewport
  clamping), `ContextMenu` (viewport clamping), virtualized `DataGrid` (react-window), the rAF
  flood-batching utility for live feeds, and `ConfirmModal` (porting the device console's
  `openConfirm`).
- Port + unit-test `lib/dsl.ts`, `lib/classify.ts`, `lib/pick.ts`, `lib/fleet.ts`,
  `lib/device.ts`.
- Extract core design-system components (§5.3) into a component-sandbox page; add the a11y
  baseline to `Modal`/`SlideOver`/`Toast`.
**Exit:** `next build` produces `out/`; CSRF wrapper attaches the header on a stub POST;
`EventSource` connects to a local engine and logs frames; the whoami-401 probe redirects on an
expired cookie; DSL/classify/device unit tests pass; theme toggle persists + swaps favicon with
no flash; primitives demonstrably behave like their legacy counterparts in the sandbox.

### Phase 1 — Auth/login + app shell (2–3 days)
**Goal:** Login flow + shared topbar/nav shell across all consoles.
**Tasks:**
- `app/login/page.tsx`: a real `<form method=POST action=/api/login>` (preserves 303→`/` and
  Set-Cookie). Read `?err=1` **client-side** to show "Invalid credentials" (the Go `<!--ERR-->`
  string-replace at [login.html:222](../../engine/internal/api/login.html#L222) does not survive
  a React page). Reference `/favicon.svg` (the public one).
- `app/layout.tsx`: providers, theme bootstrap, favicon `<link id=appFavicon>`.
- Topbar/cross-console nav shell (Single Host `/`, Choke `/choke`, **Devices `/devices`**,
  Fleet `/fleet`, Sign out `/api/logout`); user pill from `/api/whoami` (401→login). The SOC
  and Choke navs already cross-link to `/devices` — preserve those.
**Exit:** logging in against a live engine sets cookies and lands on `/`; bad creds show the
inline error via `?err=1`; `/api/logout` clears the session; nav links route across all five
pages; whoami populates the user label.

### Phase 2 — Fleet console (4–6 days)
**Goal:** full `/fleet` parity (13 panels). Smallest *multi-host* console; validates
`api()`/poll/503/fan-out and forces extraction of TopBar/Toast/ConfirmModal/StatCard/Pill/
ThemeToggle.
**Tasks:**
- Polling hook (`useInterval`, 5 s, `Promise.all` over 4 reads); `api()` 503→`#disabledBanner`;
  `hosts.length === 0` boot short-circuit (KPIs 0/—, never poll).
- KPI strip (6 cards) computed in **one** place from `/api/fleet/state` (avoid the `state._kpi`
  desync risk); fleet table with selection/drift/unreachable rows (key rows by `name`);
  `majority()`/`detectDrift()` from `lib/fleet.ts`.
- Cgroup tier bars (shared `maxN` scale); merged decisions feed
  (`/api/fleet/decisions?limit=80`, 60 rendered); merged alerts feed (`/api/fleet/alerts`).
- Targeting toggle (all/sel); posture presets (containment/maintenance → confirm modal);
  thresholds editor (ascending validation, dirty-flag prefill precedence); emergency controls
  (`kill-switch`/`thaw`); `reportFanout` toasts (per-host `{ok,error,status}`; `targets:null`
  = all).
- The "live" pulsing dot is **decorative** — do **not** add SSE (no fleet SSE endpoint exists).
**Exit:** against a `--fleet-hosts` engine, table/KPIs/feeds match `fleet.html`; drift
highlights match; preset/threshold/kill-switch/thaw fan out with correct partial-failure
toasts; without `--fleet-hosts`, the disabled banner shows on 503. Parity Fleet section green.

### Phase 2.5 — Embedded smoke test (1 day)
**Goal:** exercise the *real* `embed.FS` + mux path early, so embedding/routing bugs surface
now instead of at Phase 8. (Everything before this runs via `next dev` + the rewrites proxy.)
**Tasks:** wire a minimal version of the Phase 8 build (`make web && go build`), serve the real
binary, and verify `/fleet` loads, `/_next/*` is served with immutable caching, HTML is
`no-store`, `trailingSlash` routing resolves, and the `handleIndex` non-`/` 404 fallthrough is
fixed for clean routes.
**Exit:** the single binary serves `/fleet` and its `/_next` assets correctly with the right
cache headers; no 404/302 loops on clean routes.

### Phase 2.7 — Devices (network choke) console (2–3 days)
**Goal:** full `/devices` parity (7 panels). Reuses everything Fleet just proved (poll, 503,
bulk bar, confirm modal, toasts) on a single-host endpoint set — the cheapest console after
the shared work, hence early.
**Tasks:**
- Poll loop (`useInterval`, **4 s**) → `GET /api/choke/device-state` + `GET /api/choke/devices`;
  503 → `device choke disabled (start with -devchoke-iface)` banner. **Consolidate the legacy
  double `device-state` fetch** ([devices.html:264-266](../../engine/internal/api/devices.html#L264-L266)
  fetches it twice per tick) into one.
- Data-plane state strip: mode badge (`enforcing`/`detect-only`/`dry-run`/`kill-switched`),
  `plane`/`links`/`frames` — with the **bridge-master amber warning** when `links_attached>0 &&
  frames_seen===0` (attached to the wrong iface)
  ([devices.html:135](../../engine/internal/api/devices.html#L135)).
- State counts strip (5 cards from `device-state.counts`).
- Enforcement mode bar: `POST device-mode` (reason-required confirm; disabled under `dry_run`,
  which is a boot flag), `POST device-kill-switch` (confirm).
- Bulk action bar: select-all + per-row checkbox; action select
  (throttle 50/s · tarpit 5/s · quarantine 1/s DHCP+DNS allowed · sever block); **reason
  required**; optional `revert_after_seconds`; `POST device-jail` / `POST device-thaw` with
  `{results:[{mac,ok,error,state}]}` → `"3/4 choked"` toast.
- Device table: MAC + `device_id`, IP, hostname, `StateBadge` + revert-pending ⟲, bucket
  (`flagName rate/s`), last-seen "ago", source; `protected` allow-list badge; flows-count badge.
- Per-device flows expander (`▸/▾` → `GET /api/choke/device-flows?mac=` → "connecting to"
  destination list, busiest first).
**Exit:** against a `-devchoke-iface` engine, the table/counts/mode/flows match `devices.html`;
choke/thaw/mode/kill-switch carry CSRF + reason and audit correctly; allow-listed MACs refuse
quarantine/sever (`ok=false` surfaced); without `-devchoke-iface`, the disabled banner shows on
503. Parity Devices section green.

### Phase 3 — Choke console (18–24 days)
**Goal:** full `/choke` parity (26 panels).
**Tasks (grouped):**
- **Topbar Row 1/2** (mode pill, global DSL search driving the proc list + tape, host/audit/
  live pills, KPI tiles → exclusive tape filter, RefreshControl, action cluster, **the new
  `/devices` cross-link**). Replace the monkey-patched render pipeline with reactive store
  subscriptions + 120 ms RAF throttle + debounced refresh (circuits 750 ms / cgroups 900 ms;
  poll cadences: buckets 5 s, system-health 5 s, circuits 7 s, alerts 8 s, host-ping 8 s,
  cgroups 9 s, state 10 s).
- **Decision Tape** (SSE `decision`-only, cap 400, density spark, burst banner, hover preview
  via `/api/choke/process/<exec_id>`, ctx menu, bulk bar, auto-scroll).
- **Tracked Processes list** (cap 300 render / 2000 store, sort-by-score, origin pill, alert
  chips from `/api/alerts?limit=200`, per-row actions → `/api/choke/manual`).
- **Jail Process picker modal** (`/api/choke/processes` poll 4 s while open; chips, sort,
  inspect drawer with `/api/choke/proc/<pid>` single-flight, lineage/MITRE/signals,
  `/api/choke/jail` reason-required).
- **Thresholds drag** (4-handle pointer-event slider, live blast-radius, `PUT
  /api/choke/thresholds`), State Ladder (`/api/choke/state`), Cgroup Tiers
  (`/api/choke/cgroups`), Choke Map (`/api/choke/buckets`), Engine Stack (`/api/system-health`).
- **Threat-Intel ribbon** (4 cards, all derived locally); ops status bar (1 s tick).
- **Drill-in slide-over** — TWO variants in one container: tracked `exec_id`
  (`/api/choke/process/<exec_id>`) vs untracked jail PID (`openJailProcessDetail` with live
  `/proc`).
- **4 pill popovers** (host ping 8 s, live, audit `/api/verify-chain`, mode `/api/choke/mode` +
  `preset` + `kill-switch`).
- **Policy Workbench** (`POST /api/choke/policy/preview`, nothing installed), notifications
  panel, profile/avatar, command palette (⌘K), keyboard map (J jail, K kill, c/f/m/d presets,
  Esc unwind), confirm modal with audit-reason + auto-revert.
- Forget `/api/choke/forget`, annotate `/api/choke/annotate`, thaw `/api/choke/thaw`,
  forensic snapshot `/api/choke/forensic-snapshot`, bulk `/api/choke/bulk-manual`.
**Exit:** every panel matches `choke.html` against a live gateway engine; write actions are
audited correctly; decision floods (>5/s, 5000+ circuits) don't jank (debounce + caps verified);
copy works over HTTP. Parity Choke section green.

### Phase 4 — Main SOC dashboard (16–22 days)
**Goal:** full `/` parity (31 panels).
**Tasks (grouped):**
- **Store architecture** (the bulk): SSE-driven alerts/events ring buffers (cap 200/500),
  `epsBuckets[60]` rolling-by-second, derived selectors (filtered/sorted/grouped alerts, KPIs,
  timeline buckets, MITRE counts, IOC/network aggregation), all localStorage-backed slices
  (replicate **every** `soc.*` key exactly).
- **Alert triage queue** + DSL + classification + drill slide-over (lineage, replay player,
  inline Choke box → `/api/choke/jail`, origin, notes); KPI row (5 cards + drill); severity
  timeline (brush + anomaly); right column (MITRE/topProcs/IOC/network); live event stream
  (virtualize; rAF batching to survive bursts).
- **Correlation graph (D3 island)** — keep D3 imperative inside `useRef`/`useEffect`; React
  must **not** own SVG nodes. Preserve in-place node mutation, debounced 600 ms SSE merge,
  1.5 s TTL fade, zoom/pan/drag, Live vs Forensic. **Dynamically `import('d3')`.**
- Tool modals: Policies (`/api/policies` + `/api/policy-stats`), Attacks (`/api/attacks` +
  `/api/run-attack` form-encoded), Rule Simulator `[Option B: defer]`, MITRE Navigator (PDF)
  `[Option B: defer]`, Watchlist, Honeypots (`/api/honeypots`, 5 s) `[Option B: defer]`,
  Kprobe Perf (`/api/policy-stats`, 5 s) `[Option B: defer]`, Time Machine `[Option B: defer]`,
  Command Palette, Notifications Center, Profile, KPI drill, pill popovers
  (`/api/decisions?limit=1` health probe), Help, Export confirm + jsPDF/CSV generators
  (consolidate the five near-duplicate PDF generators; **dynamically `import('jspdf')`**).
- Fleet **modal** `[Option B: defer]` (cross-origin credentialed probes to `{host}/api/whoami`
  + `{host}/api/choke/state` — preserve `credentials:'include'`; **note the mixed-content
  limitation under HTTPS** — see [§15](#15-risks--mitigations)).
- `refreshChokeMap` `/api/choke/circuits` 10 s; version poll `/api/version` 30 s → reload
  toast; deep-link `?exec=` + cross-links to `/choke?exec=&origin=`.
**Exit:** all 31 panels match `index.html`; localStorage keys byte-compatible; graph stable
under attack-script floods; PDFs/CSVs match. Parity SOC section green.

### Phase 5 — SSE/auth hardening (1–2 days)
**Goal:** a single hardened realtime + auth path.
**Tasks:** verify one EventSource per tab (no duplicate snapshot storms); reconnect/watchdog/
visibility/backoff verified on sleep-wake; **whoami-401 probe redirects an expired session**
(not an infinite loop); confirm no `withCredentials`; confirm the CSRF header on **every** write
endpoint (`/api/run-attack`, all `/api/choke/*` writes incl. the 4 `device-*`, all
`/api/fleet/*` writes incl. `device-jail`); 401 redirect; 503 graceful for choke + devices +
fleet.
**Exit:** 403 audit (all 21 mutations carry CSRF); laptop sleep-wake reconnects + re-hydrates;
expired session redirects to login; no duplicate connections.

### Phase 6 — *(folded into per-console exit criteria)*
Parity is validated continuously per phase. Retained as a number-stable slot; no separate work.

### Phase 7 — Parity QA (5–8 days)
**Goal:** final side-by-side sweep against the legacy HTML on a live engine (see
[§12](#12-testing--parity-strategy)). ~65 panels is too many to validate in a 2–3 day window,
and panel parity is also enforced per-phase.
**Exit:** the [parity checklist](#16-parity-checklist-per-panel-acceptance-gate) is green for
all consoles; both themes; flood, drift, disabled, and reconnection states verified.

### Phase 8 — Build & embed integration (1–2 days)
**Goal:** `next build` → embed → single binary. (Mostly proven in Phase 2.5.)
**Tasks:** `embed.FS` over `web/` (`//go:embed all:web`); `http.FileServerFS` for `/_next/`
(immutable cache); page handlers read `web/index.html`, `web/choke/index.html`,
`web/devices/index.html`, `web/fleet/index.html`, `web/login/index.html` (`no-store`); extend
`isPublicPath` to allow `/_next/*` + login assets + `/favicon-light.svg`; fix the `handleIndex`
404 catch-all for clean routes; Makefile `web` target before `build`/`build-linux`; **widen
`computeVersionSHA` ([http.go:30](../../engine/internal/api/http.go#L30)) to hash the whole
`embed.FS` with a deterministic sorted `fs.WalkDir`** — today it hashes only
`index+login+favicon`, so choke/fleet/**devices** changes don't bump the SHA *and* an unsorted
walk would fire false reload toasts.
**Exit:** `make build-linux` yields a single binary serving all five routes; `/_next/`
immutable, HTML `no-store`; the version toast fires on any frontend change but is stable across
identical builds.

### Phase 9 — Cutover / rollout (1–2 days active + soak)
See [§14](#14-cutover--rollout-strategy).

---

## 7. Milestone timeline

Single engineer. Ranges sum independently (low column / high column); the reuse benefit is
already reflected by carrying the heavy shared work in Phase 0 and using post-reuse per-console
numbers — **the discount is applied once, not twice.**

| Phase | Days (low–high) | Cumulative low | Cumulative high |
|---|--:|--:|--:|
| 0 Scaffold + infra + hard primitives | 8–12 | 8 | 12 |
| 1 Auth/login + shell | 2–3 | 10 | 15 |
| 2 Fleet console | 4–6 | 14 | 21 |
| 2.5 Embedded smoke test | 1–1 | 15 | 22 |
| 2.7 Devices console | 2–3 | 17 | 25 |
| 3 Choke console | 18–24 | 35 | 49 |
| 4 SOC dashboard | 16–22 | 51 | 71 |
| 5 SSE/auth hardening | 1–2 | 52 | 73 |
| 7 Parity QA | 5–8 | 57 | 81 |
| 8 Build & embed | 1–2 | 58 | 83 |
| 9 Cutover + soak | 1–2 | 59 | 85 |

**Total ≈ 59–85 dev-days → ~12–17 calendar weeks** for one engineer (realistic center ~72
days). **Option B (deferred surfaces)** removes ~10–15 days from Phase 4, landing at **~47–58
dev-days / ~9–12 weeks.** Parallelizing Choke and SOC across two engineers after Phase 2.7
compresses calendar time to ~7–9 weeks.

---

## 8. Complete API inventory (63 routes)

Complete list of every HTTP route the Next.js client must (or must not) call, derived from
[http.go](../../engine/internal/api/http.go) (`Server.Start`, lines 87–164) and the handler
files. **63 registered routes.**

Legend — **Auth:** does the middleware require a valid session? · **CSRF:** does the client need
to send `X-CSRF-Token`? · **Stream:** SSE (`text/event-stream`)?

### 8.1 Public / page routes

| Path | Methods | Auth | CSRF | Notes |
|---|---|:--:|:--:|---|
| `/login` | GET | no | — | Login page (public). → `app/login/page.tsx` |
| `/api/login` | POST | no | no | **Form-encoded** (`user`,`pass`); bcrypt check; issues `soc_session` + `csrf_token`; 303→`/` or `/login?err=1` |
| `/api/logout` | GET (UI) | passthrough | no | Clears both cookies; stateless |
| `/api/whoami` | GET | yes | no | Username + engine host identity; 401 if no/invalid cookie |
| `/favicon.svg` | GET | no | — | Dark favicon (public) |
| `/favicon.ico` | GET | no | — | Same SVG bytes (public) |
| `/favicon-light.svg` | GET | **yes** | — | Light favicon — **still auth-guarded (latent bug).** Only fetched post-auth, so adding to `isPublicPath` is hardening, not a blocker |
| `/` | GET | yes | — | Main dashboard SPA. **Also the catch-all: non-`/` paths 404 here** — must be fixed for clean Next routes. → `app/page.tsx` |
| `/choke` | GET | yes | — | Choke console page. → `app/choke/page.tsx` |
| `/devices` | GET | yes | — | **Device (network choke) console page** (served even when device choke disabled). → `app/devices/page.tsx` |
| `/fleet` | GET | yes | — | Fleet console page (served even when fleet disabled). → `app/fleet/page.tsx` |

### 8.2 SOC dashboard API

| Path | Methods | Auth | CSRF | Stream | Purpose |
|---|---|:--:|:--:|:--:|---|
| `/api/version` | GET | yes | — | — | Build SHA + start time; polled 30 s; SHA change → reload toast |
| `/api/system-health` | GET | yes | — | — | System Health panel snapshot (~5 s poll) |
| `/api/events` | GET | yes | — | — | 200 most recent security events |
| `/api/alerts` | GET | yes | — | — | 100 most recent alerts |
| `/api/process/{exec_id}` | GET | yes | — | — | Drill-in: ancestry chain + events + origin for one exec_id |
| `/api/stream` | GET | yes | — | **yes** | The single SSE bus (events/alerts/decisions/process_exit + heartbeat) |
| `/api/policies` | GET | yes | — | — | The 3 Tetragon tracing policies + embedded YAML + MITRE |
| `/api/policy-stats` | GET | yes | — | — | `tetra tracingpolicy list` parsed; **503 if tetragon down** |
| `/api/attacks` | GET | yes | — | — | Closed set of demo attack scripts |
| `/api/run-attack` | POST | yes | **yes** | — | **Form-encoded** (`id`); launches an allowlisted attack script |
| `/api/honeypots` | GET | yes | — | — | Honeypot decoy dir prefix + decoy files |
| `/api/decisions` | GET | yes | — | — | Recent enforcement decisions (audit chain) |
| `/api/verify-chain` | GET | yes | — | — | Re-walk the tamper-evident audit hash chain; backs the "audit OK" badge |
| `/api/origin` | GET | yes | — | — | **Debug** pid→remote-client attribution. **Not called by any client — skip.** |

### 8.3 Choke gateway API (per-process)

| Path | Methods | Auth | CSRF | Purpose |
|---|---|:--:|:--:|---|
| `/api/choke/state` | GET | yes | — | Single-call hydrate: mode, thresholds, kill-switch, audit stats |
| `/api/choke/circuits` | GET | yes | — | Full snapshot of every tracked process/circuit |
| `/api/choke/buckets` | GET | yes | — | Kernel-side per-PID throttle token-bucket map |
| `/api/choke/cgroups` | GET | yes | — | Kernel-side view of which PIDs are in each choke cgroup tier |
| `/api/choke/processes` | GET | yes | — | Host process list joined with circuit state (jail picker) |
| `/api/choke/proc/{pid}` | GET | yes | — | Live `/proc` snapshot for one PID (inspect drawer). **One-shot JSON, not a stream** |
| `/api/choke/process/{exec_id}` | GET | yes | — | Choke drill-in: circuit entry + this exec_id's decisions |
| `/api/choke/policies` | GET | yes | — | List loaded ChokePolicies. **Not called by any client — skip.** |
| `/api/choke/forensic-snapshot` | GET | yes | — | Full state dump for IR (download) |
| `/api/choke/thresholds` | PUT, POST | yes | **yes** | Update the 4 escalation score thresholds at runtime |
| `/api/choke/manual` | POST | yes | **yes** | Manual override of a single circuit's state (+ audit reason) |
| `/api/choke/bulk-manual` | POST | yes | **yes** | Same action across many exec_ids; per-target outcomes |
| `/api/choke/kill-switch` | POST | yes | **yes** | Engage/disengage the global enforcement kill switch |
| `/api/choke/policy/preview` | POST | yes | **yes** | Validate candidate policy YAML + preview affected processes |
| `/api/choke/preset` | POST | yes | **yes** | Atomically apply a named operational preset (mode + thresholds) |
| `/api/choke/mode` | POST | yes | **yes** | Runtime swap detect-only ↔ enforcing |
| `/api/choke/forget` | POST | yes | **yes** | Drop circuits from live state (audit history preserved) |
| `/api/choke/thaw` | POST | yes | **yes** | Release the quarantined cgroup; frozen processes resume |
| `/api/choke/annotate` | POST | yes | **yes** | Attach/clear an operator note on a circuit |
| `/api/choke/jail` | POST | yes | **yes** | Pick-a-process-and-act (pid/binary/descendant union); **reason required** |

### 8.4 Network device choke API (per-MAC) — NEW

All endpoints are **503-aware**: registered unconditionally, but they return `503 network
device choke not enabled (start engine with -devchoke-iface)` when the gateway is nil. Handlers
in [devchoke.go](../../engine/internal/api/devchoke.go). The mode can be `enforcing` /
`detect-only` / `dry-run` (boot flag) / `kill-switched`.

| Path | Methods | Auth | CSRF | Purpose & payload |
|---|---|:--:|:--:|---|
| `/api/choke/devices` | GET | yes | — | `DeviceEntry[]`, most-dangerous-first (`Snapshot()`): `{mac, device_id, last_ip, hostname, vendor, state, protected, source, first_seen, last_seen, bucket:{rate_per_sec,burst,tokens,flags}, flows, revert_pending}` |
| `/api/choke/device-state` | GET | yes | — | Data-plane snapshot: `{data_plane, links_attached, frames_seen, devices_seen, mode, enforcing, dry_run, kill_switched, tracked, devices_known, counts:{pristine,throttled,tarpit,quarantined,severed}}` |
| `/api/choke/device-flows` | GET | yes | — | `?mac=<mac>` (**400 if missing**) → `{mac, flows:[{dest_ip,dest_port,proto,packets,bytes}]}` busiest-first; what a device is contacting |
| `/api/choke/device-jail` | POST | yes | **yes** | **JSON** `{macs:[...], action:"throttle"\|"tarpit"\|"quarantine"\|"sever", reason (REQUIRED), revert_after_seconds?}` → `{action, reason, results:[{mac,ok,error,state}]}`; allow-listed MAC → `ok=false` |
| `/api/choke/device-thaw` | POST | yes | **yes** | **JSON** `{macs:[...] \| mac, reason?}` → `{results:[{mac,ok,error}]}`; precise per-device release |
| `/api/choke/device-mode` | POST | yes | **yes** | **JSON** `{enforcing:bool, reason}` → `{mode, previous}`; detect-only audits without touching the data plane |
| `/api/choke/device-kill-switch` | POST | yes | **yes** | **JSON** `{on:bool}` → `{engaged, previous}`; global stop (decisions still audited) |

### 8.5 Fleet API (Tier-1 control plane)

All GETs are **503-aware** (fleet disabled → disabled banner). All writes fan out across peers
and return `{hosts:[{name,ok,error,status}]}`; `targets:null` means all hosts.

| Path | Methods | Auth | CSRF | Purpose |
|---|---|:--:|:--:|---|
| `/api/fleet/hosts` | GET | yes | — | Configured fleet peers (parsed from hosts file) |
| `/api/fleet/state` | GET | yes | — | Fan-out `/api/choke/state` to every peer; aggregate |
| `/api/fleet/cgroups` | GET | yes | — | Fan-out `/api/choke/cgroups` across the fleet |
| `/api/fleet/decisions` | GET | yes | — | Fan-out recent decisions across the fleet |
| `/api/fleet/alerts` | GET | yes | — | Fan-out alerts across the fleet |
| `/api/fleet/devices` | GET | yes | — | **NEW** — fan-out `/api/choke/devices` so one operator sees every choked LAN device fleet-wide |
| `/api/fleet/preset` | POST | yes | **yes** | Apply a preset across the whole fleet |
| `/api/fleet/thresholds` | PUT | yes | **yes** | Set thresholds across the whole fleet |
| `/api/fleet/kill-switch` | POST | yes | **yes** | Toggle kill-switch across the whole fleet |
| `/api/fleet/thaw` | POST | yes | **yes** | Thaw quarantine across the whole fleet |
| `/api/fleet/device-jail` | POST | yes | **yes** | **NEW** — choke a MAC fleet-wide; only the host(s) in the device's path enforce, others report no-op via the per-host envelope |

### 8.6 Notes

- **Form-encoded (not JSON):** `/api/login`, `/api/run-attack`. Everything else is JSON,
  **including all device writes.**
- **CSRF required on every non-GET** — **21 write endpoints**: 1 SOC (`run-attack`) + 11 choke
  (process) + 4 device + 5 fleet (incl. `fleet/device-jail`). Audit them all in Phase 5.
- **SSE:** `/api/stream` is the *only* stream. `/api/choke/proc/{pid}` and
  `/api/choke/device-flows` look live but are one-shot GETs.
- **Skip (verified dead/debug):** `/api/origin`, `/api/choke/policies`.
- **Cross-origin exception:** the SOC dashboard's Fleet *modal* probes peer hosts directly with
  `credentials:'include'` — the only cross-origin fetch in the app (mixed-content limitation
  under HTTPS; see risk #15).

---

## 9. Real-time / SSE strategy

- **One stream:** `GET /api/stream` (`text/event-stream`) is the *only* EventSource
  (`handleSSE`, [http.go:346-395](../../engine/internal/api/http.go#L346-L395)). It fires only
  the default `message` event; the `type` lives inside the JSON envelope `{type,payload}`. The
  heartbeat is a real `data:{"type":"heartbeat"}` frame every 15 s — early-return on it. There
  is **no** per-PID or per-device live stream: `/api/choke/proc/<pid>` and
  `/api/choke/device-flows` are one-shot JSON GETs.
- **One connection per tab** via `<StreamProvider>`; consumers subscribe to the types they need
  (SOC: all four; Choke: `decision` only; **Devices & Fleet: none — poll-only**).
- **Discriminated-union** frames; normalize payloads to canonical snake_case at the hook
  boundary.
- **Manual reconnection** (no native retry): `Math.min(30000, 1000*2**min(retries,5))`, 45 s
  watchdog, `visibilitychange` reconnect, 30 s stale banner. `retries` in a `useRef`.
- **SSE 401:** `onerror` can't expose status — after N CLOSED transitions, probe
  `/api/whoami`; 401 → `/login`.
- **On-reconnect snapshot catch-up** (mandatory — no `Last-Event-ID`): SOC re-fetches
  `/api/alerts` + `/api/events`; Choke re-fetches `state` + `circuits` + `decisions` +
  `cgroups` (debounced ~750 ms under bursts).
- **rAF batching** to survive attack-script floods (hundreds of events/sec); cap lists
  (200/500/200/400/2000); virtualize long lists (react-window for event stream / triage).
- **No CSRF, no `withCredentials`** on the stream — same-origin GET, Lax cookie auto-sends.
- **`X-Accel-Buffering: no`** is set on the SSE response so nginx doesn't buffer it; preserve
  that behavior end-to-end (the embedded build doesn't change it, but verify under the TLS
  proxy in soak).
- **Dev caveat:** `next dev` (:3000) is cross-origin to the engine — use `next.config`
  `rewrites()` to proxy `/api/*` so cookies stay same-origin. Production is single-origin
  embedded.

---

## 10. Auth / session strategy

Auth stays entirely in Go ([auth.go](../../engine/internal/api/auth.go)); the SPA only reacts.

- **Login:** native `<form method=POST action=/api/login>` (form-encoded) → 303 to `/`;
  failure → 303 `/login?err=1`. Show the error from `?err=1` read **client-side** (the server
  `<!--ERR-->` string-replace at [login.html:222](../../engine/internal/api/login.html#L222)
  does not survive a React page).
- **Session cookie `soc_session`** (HttpOnly, SameSite=Lax, 24 h, HMAC-SHA256) — the SPA cannot
  read it; it relies on the automatic same-origin send + `/api/whoami` for identity. **Do not
  rename** (hard-coded in [fleet.go](../../engine/internal/api/fleet.go) for peer auth, which
  the device fan-outs also use).
- **CSRF double-submit:** read the non-HttpOnly `csrf_token` cookie, send `X-CSRF-Token` on
  every non-GET `/api/*`. Required on `/api/run-attack`, all `/api/choke/*` writes (including
  the four `device-*` writes), and all `/api/fleet/*` writes (including `device-jail`).
- **401 →** `window.location.href='/login'`; the whoami fetch tolerates failure asymmetrically
  (fleet's whoami bypasses the wrapper — preserve).
- **Middleware allowlist:** `isPublicPath`
  ([auth.go:324-330](../../engine/internal/api/auth.go#L324-L330)) is currently
  `/login, /api/login, /favicon.svg, /favicon.ico` only. Extend it for `/_next/*`, the exported
  login assets, and `/favicon-light.svg` on cutover.
- **No Secure flag today** (behind nginx→localhost HTTP) — keep as-is; optionally set Secure
  under HTTPS later. Keep SameSite=Lax (the top-level login POST/redirect needs it).

---

## 11. Theming strategy

- **Compile Tailwind via PostCSS** (drop `cdn.tailwindcss.com`, used by index/choke/fleet/
  devices). Reproduce the `soc-*` palette as `rgb(var(--x) / <alpha-value>)` CSS-variable
  tokens; port **every** `.theme-light` override (dozens, incl. modal-specific ones for fleet/
  mitre/palette) and the body radial-gradient. The device console's `st-*` state classes
  ([devices.html:11-16](../../engine/internal/api/devices.html#L11-L16)) collapse into the
  shared `StateBadge` tokens.
- **Safelist** the dynamically-built class strings (`state-${k}`, `st-${state}`,
  `kpi-delta ${cls}`, `act-*`, arbitrary `text-[11px]`, inline `grid-template`) or Tailwind JIT
  purges them.
- **No-FOUC bootstrap:** a synchronous inlined `<script>` in the root layout reads `soc.theme`
  (JSON-encoded) before paint.
- **Favicon swap on toggle** (`/favicon.svg` ↔ `/favicon-light.svg`), both shipped from
  `public/`; keep `/favicon.ico` → SVG alias.
- **Cross-page sync:** `soc.theme` + `soc.avatar.<user>` are shared with the choke page via
  `StorageEvent` — keep the identical JSON encoding or break sync. The device console inherits
  the shared theme on migration (it ships dark-only today).
- **CSP note:** the inline bootstrap script is incompatible with a *strict* CSP, and nonces
  would require the banned SSR/middleware. There is **no CSP today** (verified — zero security
  headers in Go). Decision: **ship at status-quo (no CSP)** and document the risk; a hash-based
  CSP (`script-src 'sha256-…'` emitted by the Go page handler) is achievable later precisely
  because Tailwind/d3/jsPDF are now bundled (no CDN). See risk #5.

---

## 12. Testing & parity strategy

1. **Unit tests** for pure logic: `dsl.ts` (every operator + bare-number→PID broadening),
   `classify.ts` (BASELINE/ATTACK regex + guessPolicy), `fleet.ts` (`majority`/`detectDrift`),
   `device.ts` (`flagName` bitmask + `fmtBytes`), the risk math, and eps bucketing.
2. **Side-by-side parity rig:** run the engine serving legacy HTML on one port and the Next dev
   build (via the `rewrites()` proxy) on another, both pointed at the **same live engine**. Walk
   each panel in the [parity checklist](#16-parity-checklist-per-panel-acceptance-gate) and diff
   behavior:
   - Trigger `/api/run-attack` to flood SSE; verify KPIs/timeline/graph/tape update identically
     and **don't jank** (rAF batching + caps + debounce).
   - Verify localStorage keys are byte-identical (export both snapshots; diff `soc.*` keys) so
     operators keep ack/notes/pins/views/watchlist/avatar.
   - Drift/unreachable/disabled (503) states on fleet **and devices**; partial-failure fan-out
     toasts (`{hosts:[…]}` for fleet, `{results:[…]}` for devices).
   - Reconnection: kill/restart the stream, sleep-wake the laptop; confirm snapshot catch-up and
     the expired-session redirect.
3. **Auth/CSRF audit:** confirm every one of the 21 mutations sends `X-CSRF-Token` (no silent
   403s); 401→login; SSE works without CSRF.
4. **Offline check:** load on an air-gapped host (incl. the inline-bridge device-choke box) —
   confirm no CDN dependency (Tailwind/d3/jsPDF all bundled).
5. **Perf budget:** assert d3 and jsPDF are **dynamically imported** and excluded from the
   shared chunk; set a first-load JS budget for each route (the legacy pages were single large
   files; many small `/_next` chunks over nginx→localhost must not regress cold load).
6. **Responsive parity:** preserve the breakpoints/grid-collapse per console **or** explicitly
   declare desktop-only scope and get sign-off — do not let the Tailwind migration silently drop
   breakpoints.
7. **Visual regression:** screenshot key panels in both themes against the legacy console.

---

## 13. Build & deployment integration

Faithful to the current `go:embed` + mux model.

**Embedding** — replace the per-file string embeds in
[index.go](../../engine/internal/api/index.go) /
[choke.go](../../engine/internal/api/choke.go) /
[fleet.go](../../engine/internal/api/fleet.go) /
[devchoke.go](../../engine/internal/api/devchoke.go) with one dir embed:

```go
//go:embed all:web
var webFS embed.FS   // 'all:' includes _next dotfiles/underscored dirs
```

In `Server.Start`: `sub,_ := fs.Sub(webFS,"web")`;
`mux.Handle("/_next/", http.FileServerFS(sub))` with
`Cache-Control: public, max-age=31536000, immutable`; page handlers read `web/index.html`,
`web/choke/index.html`, `web/devices/index.html`, `web/fleet/index.html`, `web/login/index.html`
served **`no-store`**.

**Mux changes (most important):** widen `isPublicPath` for `/_next/*` + login assets +
`/favicon-light.svg`; fix the `handleIndex` non-`/` 404 so clean routes resolve.

**next.config:** `output:'export'`, `trailingSlash:true`, `images.unoptimized:true`, default
`basePath`/`assetPrefix` (Go owns `/_next` at root).

**Makefile** — add `web` before `build`/`build-linux` (Node only on the build machine):

```make
WEB_DIR   := $(ROOT)/web
EMBED_DIR := $(ENGINE_DIR)/internal/api/web
web:
	cd $(WEB_DIR) && npm ci && npm run build      # next build (output:'export') -> web/out
	rm -rf $(EMBED_DIR) && mkdir -p $(EMBED_DIR)
	cp -R $(WEB_DIR)/out/. $(EMBED_DIR)/
build:       web ; cd $(ENGINE_DIR) && go build -o engine ./cmd/engine
build-linux: web ; cd $(ENGINE_DIR) && GOOS=linux GOARCH=$(LINUX_ARCH) CGO_ENABLED=0 go build ...
```

Add `$(EMBED_DIR)` to `.gitignore` and `clean`. Deploy/redeploy/tarball funnel through
`build-linux`, so they inherit `web` automatically — the SCP + atomic `.new`→live single-binary
SSH deploy in the [Makefile](../../Makefile) is fully preserved.

**Versioning:** widen `computeVersionSHA`
([http.go:30-36](../../engine/internal/api/http.go#L30-L36)) to hash the whole `embed.FS` via a
**deterministic sorted `fs.WalkDir`** (or a sorted name+content manifest) — fixes both the
latent bug (it currently hashes only `index+login+favicon`, so choke/fleet/**devices**-only
changes don't bump the SHA) and unstable SHAs that would fire false reload toasts.
`/_next/static` hashed filenames give HTTP cache-busting; the `/api/version` 30 s poll + reload
toast stays the app-level "redeploy detected" signal.

---

## 14. Cutover / rollout strategy

**Coexistence mechanism.** Do **not** use a mutually-exclusive `-tags legacyui` build flag —
that contradicts per-route shipping. Instead, **compile both the legacy string embeds and the
new `web/` `embed.FS` into the same binary** during migration, and select per route at runtime
via an env flag (e.g. `CHOKE_UI_NEXT=fleet,devices,choke`):

```go
// in each page handler
if uiNextEnabled("devices") { serveNext("web/devices/index.html") } else { serveLegacy(devicesHTML) }
```

This makes the migration **per-route and reversible without a redeploy**: ship Next `/fleet`
and `/devices` first (smallest, lowest risk), then `/choke`, then `/`, while the others keep
serving legacy HTML. Once all are signed off, delete the legacy embeds and the flag.

- **Soak:** run the binary on a staging/VM host (`install-vm`) behind the same nginx TLS reverse
  proxy; verify SSE `X-Accel-Buffering: no` survives, exercise floods, confirm localStorage
  carry-over. For the device console, soak on an actual inline-bridge box with `-devchoke-iface`.
- **Rollback:** retain the previous single binary; `redeploy`'s atomic rename makes reverting one
  `.new`→live swap. Because all assets are in-binary, rollback is instant and total — no asset
  drift. (The per-route env flag is a faster in-place rollback for a single console.)
- **Operator continuity:** because localStorage keys are byte-identical, operators lose no
  ack/notes/pins/views/watchlist/avatar/theme across the cutover.

---

## 15. Risks & mitigations

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| 1 | D3 correlation graph (imperative force sim, in-place node mutation, TTL fade, debounced merge) | High | Keep D3 in a `useRef`/`useEffect` island; React never owns SVG nodes; port logic 1:1; dynamic `import('d3')` |
| 2 | SSE flood jank (attack scripts emit 100s/s; 5000+ circuits) | High | rAF batching, list caps (200/500/400/2000), debounced snapshot refresh (750/900 ms), virtualization — **built in Phase 0** |
| 3 | localStorage incompatibility on cutover (ack/notes/pins/views/watchlist/avatar/fleet) | High | Replicate every `soc.*`/`choke.*` key + JSON encoding + `StorageEvent` sync exactly; diff snapshots in QA |
| 4 | CSRF wrapper missed on a write → silent 403 | High | One `lib/api.ts` wrapper; audit **all 21** write endpoints (incl. the 5 device writes) in Phase 5 |
| 5 | Middleware allowlist misses `/_next/*`/login assets → 302 loop | High | Extend `isPublicPath` (Phase 8); smoke-test login asset loads unauthenticated in Phase 2.5 |
| 6 | Estimate overrun / scope creep | High | Commit to Option A or B up front; parity folded into each phase's exit criteria; ~72-day realistic center, not 12–15 |
| 7 | Monkey-patch render pipeline → naive reactive re-render regresses throttling | Med-High | Zustand store + explicit RAF throttle + subscriber pattern (no `onmessage` patching) |
| 8 | Small consoles (Fleet/Devices) do NOT exercise hard primitives | Med-High | Build + harden those in Phase 0, prove under load in Choke; Fleet/Devices validate only api/poll/503/fan-out/bulk/confirm |
| 9 | Tailwind CDN→build purges dynamic class strings (incl. device `st-*`) | Med | Safelist `state-${k}`/`st-${state}`/`act-*`/`kpi-delta`/arbitrary values; port all `.theme-light` overrides |
| 10 | Embedding/routing bugs (404 catch-all, `/_next`, trailingSlash, headers) surface late | Med | **Phase 2.5 embedded smoke test** exercises the real `embed.FS`+mux path early |
| 11 | SSE 401 silent infinite reconnect on expired session | Med | whoami probe after N CLOSED transitions → redirect to `/login` |
| 12 | Bundle-perf regression (large single files → many `/_next` chunks, cold load over nginx→localhost) | Med | Dynamic-import d3 + jsPDF; assert excluded from shared chunk; first-load JS budget in QA |
| 13 | Threshold drag (document mousemove + live blast recompute) | Med | Careful pointer-event port with touch support + cleanup |
| 14 | Dual-casing payloads (snake vs Pascal) → runtime undefined | Med | `pick()` + normalize at boundary; derive types from Go structs (incl. `DeviceEntry`/`DeviceFlow`) |
| 15 | Cross-origin fleet-MODAL probes (`credentials:'include'`) mixed-content-block under HTTPS/nginx-TLS | Med | Preserve as the only cross-origin fetch; flag as a known limitation (or defer the modal — Option B) |
| 16 | Login `?err=1` server string-replace doesn't survive React | Med | Move the error to a client-side `?err=1` read |
| 17 | Dev cross-origin breaks cookie auth | Med | `next.config` `rewrites()` proxy; never use `withCredentials` as a workaround |
| 18 | No CSP today; inline theme script blocks a strict CSP | Med | Ship status-quo (no CSP), document; hash-based CSP later (bundling makes it achievable) |
| 19 | Responsive/mobile parity silently dropped in Tailwind port | Med | Per-console responsive checklist item, or explicit desktop-only sign-off |
| 20 | Accessibility regressions across 14+ modals | Low-Med | a11y baseline (focus trap, `role=dialog`, `aria-modal`, `aria-live`) on shared overlays in Phase 0; reuse the device console's already-good confirm modal |
| 21 | Dual drill paths in choke (tracked exec_id vs jail PID) | Med | Model both variants explicitly in one slide-over |
| 22 | `copyToClipboard` no-op on HTTP (non-secure context) | Low-Med | Keep the `execCommand` fallback |
| 23 | `computeVersionSHA` omits choke/fleet/**devices** (existing bug) + non-deterministic walk | Low | Hash whole `embed.FS` with a sorted `fs.WalkDir` |
| 24 | Device console 503-vs-data confusion (gateway nil when no `-devchoke-iface`) | Low | 503-aware banner like fleet; bridge-master amber warning (`links>0 && frames==0`) preserved |

---

## 16. Parity checklist (per-panel acceptance gate)

Per-panel acceptance gate for the HTML→Next.js conversion — **78 panels** across the four
consoles plus login. Each console phase's exit criterion is "its section here is green," and
Phase 7 is the final sweep. Verify each item **side-by-side against the legacy HTML on the same
live engine, in both themes.** Complexity tags (`H`/`M`/`L`) indicate relative porting risk.

**How to use.** For each panel: ☐ renders · ☐ data source wired · ☐ refresh model matches (poll
cadence / SSE / on-action) · ☐ all interactions work · ☐ light + dark theme · ☐ empty/loading/
error states · ☐ no console errors under an SSE flood.

### Login (1 panel)

- [ ] **Login form** — `<form method=POST action=/api/login>` (form-encoded); 303→`/` on
  success; `?err=1` inline error read client-side; favicon loads unauthenticated.

### Devices (network choke) console — `/devices` (7 panels)

- [ ] `L` **Top bar / header** — SOC back-link, title, process-console cross-link, data-plane
  state strip (mode badge / `plane` / `links` / `frames`) with the **bridge-master amber
  warning** when `links_attached>0 && frames_seen===0`
- [ ] `L` **Disabled banner** — 503 when started without `-devchoke-iface`
  (`device choke disabled (start with -devchoke-iface)`)
- [ ] `L` **State counts strip** (5 cards) — pristine/throttled/tarpit/quarantined/severed from
  `device-state.counts`
- [ ] `M` **Enforcement mode bar** — mode badge (enforcing/detect-only/dry-run/kill-switched);
  `POST device-mode` (reason-required confirm; disabled under `dry_run`); `POST
  device-kill-switch` (confirm)
- [ ] `M` **Bulk action bar** — select-all + per-row checkbox; action select (throttle/tarpit/
  quarantine/sever); **reason required**; `revert_after_seconds`; `POST device-jail` /
  `device-thaw`; `"N/M choked"` toast from `{results:[…]}`
- [ ] `H` **Device table** — MAC + `device_id`, IP, hostname, `StateBadge` + revert-pending ⟲,
  bucket (`flagName rate/s`), last-seen ago, source; `protected` allow-list badge; flows-count
  badge; keyed by `mac`
- [ ] `M` **Per-device flows expander** — `▸/▾` → `GET device-flows?mac=` → "connecting to"
  destination list (`dest_ip:port proto · pkts/bytes`), busiest first
- [ ] `L` **Confirm modal** (in-app) — reason-required variant, danger accent, Esc + backdrop
  close (already implemented — **promote to the shared `ConfirmModal`**)

> Devices is **poll-only (4 s)** — no SSE. **Consolidate the legacy double `device-state` fetch
> per tick** into one. 503-aware like fleet.

### Fleet console — `/fleet` (13 panels)

- [ ] `L` **Top bar / header** — identity, nav, theme toggle
- [ ] `L` **Disabled banner** (`#disabledBanner`) — shows on 503 when fleet not enabled
- [ ] `L` **KPI strip** (6 stat cards) — computed once from `/api/fleet/state` (no `_kpi`
  desync)
- [ ] `L` **Targeting selector** (left rail) — all/sel, auto-flips on row select
- [ ] `M` **Posture preset chooser** (left rail) — containment/maintenance → confirm modal →
  fan-out
- [ ] `M` **Thresholds editor** (left rail) — ascending validation, dirty-flag prefill
  precedence, `PUT /api/fleet/thresholds`
- [ ] `M` **Emergency controls** (left rail) — `kill-switch` / `thaw` fan-outs
- [ ] `H` **Fleet table** (center) — selection, drift highlight, unreachable rows, keyed by
  `name`; `majority()`/`detectDrift()`
- [ ] `M` **Cgroup tier inhabitants** (center) — shared `maxN` scale bars
- [ ] `M` **Live decisions feed** (right rail) — `/api/fleet/decisions?limit=80`, 60 rendered
- [ ] `L` **Alerts feed** (right rail) — `/api/fleet/alerts`
- [ ] `L` **Toasts** (`#toasts`) — `reportFanout` per-host `{ok,error,status}`
- [ ] `L` **Confirm modal** (`#modalRoot`) — **add Esc/backdrop close (legacy lacks it; reuse
  the device console's)**

> Fleet is **poll-only (5 s).** The pulsing "live" dot is decorative — do not add SSE. *(A
> fleet-wide device view via `/api/fleet/devices` and a `/api/fleet/device-jail` fan-out exist
> in the API but are not yet surfaced in `fleet.html` — optional new panels, not a parity gap.)*

### Choke console — `/choke` (26 panels)

- [ ] `M` **Topbar Row 1** — identity / search / status / user (now also a `/devices` cross-link)
- [ ] `H` **Topbar Row 2** — range / KPIs / refresh / scope / actions; KPI tiles → exclusive
  tape filter
- [ ] `L` **IR Presets trail bar**
- [ ] `L` **Stale-stream banner** (30 s)
- [ ] `L` **Active filter strip**
- [ ] `M` **Threat-Intelligence ribbon** (4 cards, derived locally)
- [ ] `L` **Engine Stack panel** — `/api/system-health`
- [ ] `L` **State Ladder panel** — `/api/choke/state`
- [ ] `H` **Thresholds panel** — 4-handle pointer-event drag slider, live blast-radius,
  `PUT /api/choke/thresholds`
- [ ] `L` **Cgroup Tiers panel** — `/api/choke/cgroups`
- [ ] `L` **Choke Map / BPF mirror** — `/api/choke/buckets`
- [ ] `H` **Tracked Processes list** (center) — cap 300/2000, sort-by-score, origin pill, alert
  chips, per-row → `/api/choke/manual`
- [ ] `H` **Decision Tape** (right, live) — SSE `decision`-only, cap 400, density spark, burst
  banner, hover preview, ctx menu, bulk bar, auto-scroll
- [ ] `M` **Policy Workbench** — `POST /api/choke/policy/preview` (nothing installed)
- [ ] `H` **Process Drill-in slide-over** — dual variant: tracked exec_id vs untracked jail PID
  (`/proc`)
- [ ] `H` **Jail Process picker modal** — `/api/choke/processes` 4 s while open; inspect drawer
  `/api/choke/proc/<pid>`; `/api/choke/jail` reason-required
- [ ] `M` **Pill popover: Host reachability** (8 s ping)
- [ ] `M` **Pill popover: Live data stream**
- [ ] `M` **Pill popover: Audit chain** — `/api/verify-chain`
- [ ] `M` **Pill popover: Enforcement mode** — `/api/choke/mode` + `preset` + `kill-switch`
- [ ] `M` **Notifications panel**
- [ ] `M` **Admin profile dropdown + avatar** — `soc.avatar.<user>` shared with SOC
- [ ] `M` **Command palette** (⌘K)
- [ ] `L` **Confirm modal** (shared) — audit-reason + auto-revert
- [ ] `L` **Help modal** (`?`)
- [ ] `L` **Operations status bar** (sticky bottom, 1 s tick)
- [ ] Also wire: `forget`, `annotate`, `thaw`, `forensic-snapshot`, `bulk-manual`

> Poll cadences: buckets 5 s · system-health 5 s · circuits 7 s · alerts 8 s · host-ping 8 s ·
> cgroups 9 s · state 10 s. Reactive store + 120 ms RAF throttle (no `onmessage` patching).

### Main SOC dashboard — `/` (31 panels)

- [ ] `M` **Left sidebar (rail)** — collapsible, persisted `soc.sidebarOpen`, live badges
- [ ] `H` **Top bar / header** — search (DSL), risk gauge, time-range, host pill, live pill,
  refresh control, theme toggle (now also a `/devices` cross-link)
- [ ] `L` **Stale-data banner** (>30 s silent) + force reconnect
- [ ] `L` **Version-update toast** — `/api/version` SHA change
- [ ] `H` **KPI row** (5 cards) — severity counts + deltas + sparklines; click → drill
- [ ] `H` **Severity timeline** — per-minute stacked bars, anomaly markers, bucket click +
  drag-brush, legend toggles
- [ ] `H` **Alert triage queue** — DSL filter, classification, sort/group, bulk bar, saved
  views, keyboard nav (j/k/a/r/Enter)
- [ ] `H` **Drill-down slide-over** — lineage, replay player, inline Choke box →
  `/api/choke/jail`, origin, notes
- [ ] `L` **MITRE ATT&CK coverage** (right col) — per-policy technique bars
- [ ] `M` **Top processes by score** (right col) — lazy origin via `/api/process`
- [ ] `L` **IOCs observed** (right col) — files + network peers
- [ ] `L` **Network connections** (right col) — outbound TCP peers
- [ ] `M` **Live event stream** — SSE, cap 200, regex filter, pause, hide-self-noise;
  **virtualize**
- [ ] `M` **Policy viewer modal** — `/api/policies` + `/api/policy-stats`
- [ ] `L` **Quick-fire attacks modal** — `/api/attacks` + `/api/run-attack` (form-encoded, 429)
- [ ] `H` **Process correlation graph modal (D3)** — imperative island; dynamic `import('d3')`;
  TTL fade, debounced merge, zoom/pan/drag, Live vs Forensic
- [ ] `M` **Rule simulator modal** — `[Option B: defer]`
- [ ] `H` **MITRE Navigator modal** (PDF) — `[Option B: defer]`
- [ ] `H` **Fleet modal (multi-host)** — cross-origin `credentials:'include'` probes —
  `[Option B: defer]`; mixed-content limitation under HTTPS
- [ ] `M` **Watchlist modal**
- [ ] `H` **Honeypots modal** — `/api/honeypots` (5 s) — `[Option B: defer]`
- [ ] `H` **Kprobe performance modal** — `/api/policy-stats` (5 s) — `[Option B: defer]`
- [ ] `H` **Time Machine modal** — snapshot/live source switch — `[Option B: defer]`
- [ ] `M` **Command palette** (⌘/Ctrl+K)
- [ ] `H` **Notifications center modal**
- [ ] `H` **Account / profile modal** — avatar shared with choke
- [ ] `M` **KPI drill modal** (severity/eps/procs variants)
- [ ] `H` **Pill popovers** (live/host/risk) — `/api/decisions?limit=1` health probe
- [ ] `L` **Help modal**
- [ ] `H` **Export confirm modal + PDF/CSV** — consolidate 5 generators; dynamic `import('jspdf')`
- [ ] `M` **Alert hover preview + right-click context menu** — viewport clamping

> Replicate **every** `soc.*` localStorage key (ack/notes/pins/views/watchlist/avatar/theme/
> sidebar) byte-for-byte so operator state survives cutover.

### Cross-cutting verification (all consoles)

- [ ] **CSRF** header on all 21 write endpoints — no silent 403s
- [ ] **401** anywhere → redirect to `/login`
- [ ] **SSE 401**: expired session → whoami probe → redirect (not an infinite reconnect loop)
- [ ] **SSE reconnect**: kill/restart stream + laptop sleep-wake → snapshot catch-up
- [ ] **SSE flood**: `/api/run-attack` → KPIs/timeline/graph/tape update identically, no jank
- [ ] **503**: choke + **devices** + fleet disabled banners
- [ ] **localStorage** snapshot diff: `soc.*` / `choke.*` keys byte-identical to legacy
- [ ] **Offline/air-gapped**: no CDN dependency (Tailwind/d3/jsPDF bundled)
- [ ] **Perf budget**: d3 + jsPDF dynamically imported, out of the shared chunk; first-load JS
  within budget
- [ ] **Responsive**: breakpoints/grid-collapse preserved per console (or desktop-only signed
  off)
- [ ] **a11y**: focus trap + `role=dialog`/`aria-modal` on modals/slide-overs; `aria-live` on
  toasts/stale-banner
- [ ] **copyToClipboard**: works over plain HTTP (`execCommand` fallback)
- [ ] **Embedded path**: `/_next/*` immutable cache, HTML `no-store`, clean-route 404 fallthrough
  fixed, `computeVersionSHA` stable across identical builds and sensitive to all five pages
- [ ] **Cross-page sync**: `soc.theme` + `soc.avatar.<user>` sync via `StorageEvent`

---

## 17. Day 1 quick start

```bash
# 1. Scaffold the Next app at repo root, sibling to engine/
cd /Users/jeff/Code/eBPF
npx create-next-app@latest web --typescript --tailwind --app --eslint --src-dir=false --import-alias "@/*"

# 2. next.config.ts — static export + embed-friendly
#    output:'export'; trailingSlash:true; images:{unoptimized:true};
#    rewrites() proxying /api/* -> http://localhost:<engine-port> for `next dev` only

# 3. Add deps (bundle, no CDN; d3 + jsPDF will be dynamically imported)
cd /Users/jeff/Code/eBPF/web
npm i d3@7.9.0 jspdf@2.5.1 jspdf-autotable@3.8.2 zustand react-window
npm i -D @types/d3

# 4. First files to create (Phase 0 infra):
#    web/lib/api.ts        (port CSRF wrapper from engine/internal/api/index.html:8-29
#                           and the device console post() at devices.html:330-340)
#    web/lib/stream.tsx    (StreamProvider + useStream; backoff/watchdog/visibility + whoami-401 probe)
#    web/lib/dsl.ts        (+ web/lib/dsl.test.ts)      — port + unit test verbatim
#    web/lib/classify.ts   (+ test)                     — port + unit test verbatim
#    web/lib/pick.ts  web/lib/fleet.ts  web/lib/device.ts (flagName/fmtBytes/mac-slug)
#    web/lib/types.ts      (Event/Alert/Decision/Entry/DeviceEntry/DeviceFlow from Go structs)
#    web/components/ThemeProvider.tsx (no-FOUC soc.theme bootstrap + favicon swap)
#    web/components/{Modal,ConfirmModal,SlideOver,PillPopover,ContextMenu,DataGrid,Toast,StatCard,Pill,StateBadge,Button}.tsx

# 5. Verify export builds and the stream connects to a running engine
npm run build           # produces web/out/
npm run dev             # then visit /, watch EventSource('/api/stream') frames in the console
```

---

## 18. Reference files to read first

- CSRF wrapper + 401 redirects + SSE consumption: [index.html](../../engine/internal/api/index.html)
- Choke store `S`/`JAIL`/`Pills`/`Sess` + decision-only SSE + threshold drag: [choke.html](../../engine/internal/api/choke.html)
- **Device console: poll loop, bulk bar, in-app confirm modal, flows expander, data-plane state:** [devices.html](../../engine/internal/api/devices.html)
- **Device API handlers + payload shapes (503-aware gating):** [devchoke.go](../../engine/internal/api/devchoke.go)
- **Device gateway internals (`Snapshot`/`DataPlaneState`/`DeviceEntry`/`DeviceFlow`):** [devgateway.go](../../engine/internal/choke/devgateway.go)
- Poll-only fan-out + drift + 503 disabled banner: [fleet.html](../../engine/internal/api/fleet.html)
- Fleet fan-out incl. `device-jail`/`devices`: [fleet.go](../../engine/internal/api/fleet.go)
- Form-post login + `<!--ERR-->` marker: [login.html](../../engine/internal/api/login.html)
- Auth/CSRF/cookies/`isPublicPath`: [auth.go](../../engine/internal/api/auth.go)
- Mux, `handleSSE`, `computeVersionSHA`, page handlers, all 63 route registrations: [http.go](../../engine/internal/api/http.go)
- `-devchoke-obj`/`-devchoke-iface`/`-devchoke-protect` wiring: [main.go](../../engine/cmd/engine/main.go), [config.go](../../engine/internal/config/config.go)
- Embeds to replace: [index.go](../../engine/internal/api/index.go), [choke.go](../../engine/internal/api/choke.go), [fleet.go](../../engine/internal/api/fleet.go), [devchoke.go](../../engine/internal/api/devchoke.go)
- Build/deploy targets to extend: [Makefile](../../Makefile)
- Device data-plane design context: [network-choke-gateway.md](../architecture/network-choke-gateway.md), [network-choke-build-plan.md](../development/network-choke-build-plan.md)
