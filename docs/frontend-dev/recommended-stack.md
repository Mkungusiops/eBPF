# Recommended Frontend Stack — HTML → SPA rework

> **Status:** adopted · **Date:** 2026-06-25 · Companion to
> [README.md](README.md) and
> [78-panel-redesign-target-vm-e2e-certification-plan.md](78-panel-redesign-target-vm-e2e-certification-plan.md).
> This is the active stack for the frontend-dev work: **Vite (multi-entry) + React** instead
> of the earlier Next.js App Router proposal, plus headless primitives (Radix, cmdk) that
> retire the riskiest hand-rolled overlay and command-palette work.

## Why this stack (the constraints it's matched to)

The rework is locked to a specific runtime model: **statically built, embedded into the Go
binary via `go:embed`, auth stays in Go, no SSR/no middleware, single-binary SSH deploy,
offline-capable** (the inline-bridge device-choke box may be air-gapped), with **one SSE
stream**, a **D3 force graph**, **PDF/CSV export**, and **five separate consoles** (SOC, Choke,
Devices, Fleet, Login) that are already served as independent pages.

Given those constraints, Next.js would mean disabling everything it exists for. **Vite emits
exactly the static, multi-page bundle this model wants**, with none of the `output: 'export'`
friction (trailingSlash, catch-all 404, basePath/assetPrefix).

## Core stack

| Layer | Pick | Why for *this* codebase |
|---|---|---|
| Build / bundler | **Vite** (multi-page — one HTML entry per console) | Emits a plain static bundle straight into `go:embed`; per-console entries preserve the current "each console is its own page, small bundle" model and map onto the per-route cutover flag |
| Framework | **React 18+** (function components + hooks) | The component model is the whole point of the rework; huge ecosystem for the headless primitives below |
| Language | **TypeScript (strict)** | Types hand-derived from the Go structs (`store.Event`/`Alert`/`Decision`, `choke.Entry`/`DeviceEntry`/`DeviceFlow`) kill the snake/Pascal-casing class of runtime bugs |
| Routing | **None by default (MPA)** | Full-page nav between consoles is fine; modals/slide-overs are state, not routes; `?exec=` is a query param. Add `react-router` *only inside SOC* if deep-linking grows |
| State | **Zustand** | Maps 1:1 onto the existing mutable `state`/`S`/`JAIL`/`Pills` objects; lets you mutate the store *outside* React and batch — essential to survive the SSE flood without re-render storms (Context would melt here) |
| Styling | **Tailwind CSS via PostCSS** | The markup is already Tailwind-shaped; `darkMode:'class'` + CSS-variable tokens reproduce the `soc-*` palette. Lowest-friction path. Drops the four `cdn.tailwindcss.com` script tags |
| Overlays / menus | **Radix UI primitives** (Dialog, Popover, DropdownMenu) | Headless + accessible (focus trap, `aria-modal`, Esc) out of the box — directly retires risk #20 (a11y across 14+ modals) and de-risks the hardest Phase 0 work. Keep your own Tailwind styling on top |
| Command palette | **cmdk** | De-facto headless ⌘K palette; Tailwind-friendly; saves building it twice (SOC + Choke) |
| Force graph | **D3 7.9** (correlation-graph island only, **dynamic import**) | Keep the hard-won imperative force sim; don't replace it. Hand-built divs for sparklines/bars as today |
| Long lists | **TanStack Virtual** | Event stream / triage / decision tape virtualization; better-maintained successor to react-window |
| PDF / CSV | **jsPDF + jspdf-autotable** (dynamic import) | Consolidate the five near-duplicate generators; CSV stays hand-rolled |
| Realtime | **native `EventSource`** behind `StreamProvider` + `useStream` | No library needed; same-origin GET, Lax cookie auto-sends. Don't reach for socket.io |

## Supporting / dev tooling

| Layer | Pick | Why |
|---|---|---|
| Unit tests | **Vitest** | Native Vite integration, Jest-compatible API — for `dsl`/`classify`/`fleet`/`device` logic |
| E2E / parity | **Playwright** | The side-by-side parity rig: both themes, SSE flood, reconnect, drift/503 |
| Component tests | **React Testing Library** | Panel-level behavior |
| Lint + format | **Biome** (or ESLint + Prettier) | Biome is one fast tool replacing both; either is fine |
| Icons | **lucide-react** (optional) | The inline SVGs are already Feather/Lucide-style |
| Package manager | **pnpm** (or npm to match `npm ci` in the Makefile) | Faster/stricter; minor either way |

## The one genuine "maybe": data fetching

The poll-only consoles (Fleet 5 s, Devices 4 s, Choke multi-cadence) are a textbook fit for
**TanStack Query** — polling, dedup, retry, stale-while-revalidate for free. But it doesn't fit
the SSE-driven SOC/Choke live data (that goes into Zustand anyway), so you'd run two paradigms.

**Call:** start without it — a typed `lib/api.ts` fetch wrapper (CSRF, 401→login, 503) + a
`useInterval` hook covers the polls. Add TanStack Query later *only if* the polling boilerplate
becomes painful. Don't adopt it speculatively.

## Deliberately avoid

- **Next.js** — you'd disable everything it's for (SSR, route handlers, middleware, server
  components); you'd then fight static-export friction for no benefit.
- **Component kits (MUI / Chakra / AntD)** — clash with the bespoke dark SOC aesthetic and bloat
  the bundle. Radix gives accessibility *without* imposing visuals.
- **Redux** — too much ceremony; Zustand fits the imperative model.
- **A charting library** — D3 already handles the one hard chart; everything else is flexbox divs.
- **Runtime CSS-in-JS (emotion / styled-components)** — Tailwind covers it and runtime CSS-in-JS
  hurts the first-load JS budget.

## Net

**Vite (multi-entry) + React + TypeScript + Tailwind + Zustand + Radix/cmdk + D3/jsPDF (dynamic)
+ Vitest/Playwright.**

The **Radix + cmdk + Vitest** additions are the biggest improvements over the migration doc's
current Next.js write-up — they remove most of the riskiest hand-rolled Phase 0 work (focus
traps, accessible overlays, the command palette).

> **Note on effort:** the framework choice changes only a few days of the ~59–85 dev-day
> estimate. The cost is porting 78 panels' behavior (the D3 graph, rAF flood batching, the
> threshold slider, the monkey-patched render pipeline). The decisions that actually move the
> number are **scope (Option A vs B)** and **incremental sequencing (Fleet + Devices first,
> then judge)** — see [README.md §1.1](README.md#11-scope-options) and
> [§6](README.md#6-phase-by-phase-plan).

## How this changes the main plan

This stack has been adopted in [README.md](README.md) and in the current `web/` project:

- **Tech stack** - Vite multi-entry replaces the former Next App Router/static-export plan.
  Radix, cmdk, TanStack Virtual, Vitest, and Playwright are part of the active frontend gate.
- **Repo layout** - `web/` is a Vite project with five HTML entries and
  `build.rollupOptions.input` in `vite.config.ts`; output is `web/dist/`.
- **Build and deploy** - the web build produces Vite assets that are staged into
  `engine/internal/api/web/` for `go:embed`; Vite `/assets/*` replaces the earlier static
  export asset path assumptions.
- **Quick start** - use the existing `web/` project and run `npm install`, `npm run lint`,
  `npm run typecheck`, `npm run test`, and `npm run build`.
