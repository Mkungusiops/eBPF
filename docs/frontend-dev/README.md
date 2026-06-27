# Frontend Dev - Vite Multi-Entry React Console

> Status: active implementation and certification plan
> Last updated: 2026-06-25
> Supersedes: the earlier static-export framework proposal

This folder tracks the frontend migration for the eBPF runtime-security console. The adopted
stack is the one in [recommended-stack.md](recommended-stack.md): Vite multi-entry, React,
strict TypeScript, Tailwind via PostCSS, Zustand, Radix primitives, cmdk, TanStack Virtual,
dynamic D3/jsPDF imports, Vitest, and Playwright.

The release gate is the 78-panel target VM certification plan in
[78-panel-redesign-target-vm-e2e-certification-plan.md](78-panel-redesign-target-vm-e2e-certification-plan.md).

## Scope

The redesigned frontend keeps the existing production model:

- One static frontend build is embedded into the Go engine binary with `go:embed`.
- Go remains the only production server. There is no Node runtime in production.
- Auth, session cookies, CSRF, and API handlers stay in Go.
- SOC and Choke share one same-origin `/api/stream` EventSource per tab.
- Devices and Fleet remain poll-driven.
- Runtime CDN dependencies are not allowed.

Panel inventory:

| Route | Console | Panels | Entry |
|---|---|---:|---|
| `/login` | Login | 1 | `web/login.html` |
| `/` | SOC dashboard | 31 | `web/index.html` |
| `/choke` | Choke Gateway | 26 | `web/choke.html` |
| `/devices` | Network Choke Devices | 7 | `web/devices.html` |
| `/fleet` | Choke Fleet Console | 13 | `web/fleet.html` |

## Target Stack

| Concern | Decision |
|---|---|
| Build | Vite multi-page app, one HTML entry per console |
| UI | React 18 function components and hooks |
| Language | TypeScript strict |
| Styling | Tailwind compiled through PostCSS, no runtime Tailwind script |
| State | Zustand stores for shared mutable console state |
| Overlays | Radix primitives where shared accessibility behavior is needed |
| Command palette | cmdk for SOC and Choke command surfaces |
| Long lists | TanStack Virtual for event and decision streams |
| Realtime | Native `EventSource` hidden behind `StreamProvider` and `useStream()` |
| D3 | D3 only in the SOC correlation graph island, loaded with `import("d3")` |
| PDF | jsPDF and jspdf-autotable loaded with dynamic imports |
| Unit tests | Vitest |
| Browser tests | Playwright |

## Repo Layout

```text
web/
  index.html
  choke.html
  devices.html
  fleet.html
  login.html
  vite.config.ts
  src/
    app/
    components/
    entries/
      soc.tsx
      choke.tsx
      devices.tsx
      fleet.tsx
      login.tsx
    features/
      soc/
      choke/
      devices/
      fleet/
      login/
    lib/
    stores/
    test/
  e2e/

engine/internal/api/
  web/             # staged Vite build output for go:embed
  web_embed.go
  web_assets.go
```

Vite emits `web/dist/`. The Go build stages that output into `engine/internal/api/web/` and
serves route HTML plus immutable `/assets/*` files from the embedded filesystem.

## Route Mapping

| Go route | Vite HTML | React entry |
|---|---|---|
| `/` | `web/index.html` | `src/entries/soc.tsx` |
| `/choke` | `web/choke.html` | `src/entries/choke.tsx` |
| `/devices` | `web/devices.html` | `src/entries/devices.tsx` |
| `/fleet` | `web/fleet.html` | `src/entries/fleet.tsx` |
| `/login` | `web/login.html` | `src/entries/login.tsx` |

## Backend Integration

Required serving behavior:

- HTML responses for the five routes use `Cache-Control: no-store`.
- Built `/assets/*` responses use immutable cache headers.
- Login assets load before authentication.
- Protected route HTML and APIs keep the existing Go auth gate.
- Unsafe writes keep `X-CSRF-Token` injection from the shared API wrapper.
- `/api/login` and `/api/run-attack` remain form-encoded.
- Frontend version hashing covers the full embedded web filesystem.
- Runtime browser requests must not depend on external CDNs.

## Required Local Gates

Run from `web/` unless noted:

```bash
npm run lint
npm run typecheck
npm run test
npm run build
```

Run from `engine/`:

```bash
go test ./...
```

Route and browser certification uses Playwright:

```bash
PLAYWRIGHT_START_WEB_SERVER=1 npm run e2e -- --project=chromium
```

Target VM certification uses the deployed URL and credentials documented by the release
operator:

```bash
EBPF_TARGET_VM_URL=https://soc.adanianlabs.io \
EBPF_WEB_BASE_URL=https://soc.adanianlabs.io \
EBPF_E2E_USER=admin \
EBPF_E2E_PASSWORD=... \
npm run e2e -- --project=chromium target-vm-smoke.spec.ts
```

Only run write-enabled target VM checks with an explicit release decision because those flows
mutate the target engine.

## Certification Checklist

The frontend-dev folder is complete only when these items are true:

- The active docs describe the Vite stack and no longer require the older static-export framework.
- `web/package.json` has lint, typecheck, unit, build, and e2e gates.
- Required Vitest and Playwright suites exist and pass locally.
- Browser tests prove all five routes render their expected panels or explicit disabled states.
- Browser/network tests prove no CDN dependency at runtime.
- Static lint proves D3/jsPDF stay out of initial route code except where dynamically imported.
- Embedded binary tests prove route fallback, asset caching, login asset access, and version hashing.
- Target VM Playwright evidence exists for login, SOC, Choke, Devices, Fleet, SSE, safe attack,
  and representative Choke write behavior.
- `pending-work.md` records any remaining release blockers with evidence status.

## Reference Docs

- [recommended-stack.md](recommended-stack.md)
- [78-panel-redesign-target-vm-e2e-certification-plan.md](78-panel-redesign-target-vm-e2e-certification-plan.md)
- [pending-work.md](pending-work.md)
