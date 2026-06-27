# Frontend Dev Completion Report

> Status: implementation gates complete; target VM certification smoke complete
> Date: 2026-06-25
> Source folder: `docs/frontend-dev/`

This file replaces the earlier pending-work index. The Vite multi-entry React stack from
`recommended-stack.md` is now reflected in `README.md`, the missing local gates and route-specific
test suites have been added, and the release-critical local and deployed checks listed below have
passed.

## Completed

### Documentation

- Rewrote `README.md` around Vite multi-entry React instead of the older static-export
  framework plan.
- Updated `recommended-stack.md` from recommendation language to adopted-stack language.
- Reconciled the docs around:
  - `web/*.html` entries
  - `web/vite.config.ts`
  - `web/src/entries/*`
  - `web/dist/`
  - `engine/internal/api/web/`
  - Vite `/assets/*` embedding
  - no runtime CDN dependency

### Web Stack Gate

- Added `npm run lint`.
- Added `web/scripts/lint.mjs` to statically enforce:
  - no runtime CDN references in web source, HTML entries, package metadata, or Vite config
  - no stale Next/static-export references in active web source/config
  - exactly one `new EventSource(...)`, located in `src/lib/stream.tsx`
  - no non-type static D3 import
  - required dynamic imports for `d3`, `jspdf`, and `jspdf-autotable`
  - required runtime and dev dependencies are present

### Required Playwright Suites

All required suite files now exist:

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

Added route-specific suites:

- `soc.spec.ts`
- `choke.spec.ts`
- `devices.spec.ts`
- `fleet.spec.ts`

Added `e2e/support/mock-api.ts` so local route tests can verify the UI panels and workflows
without requiring a live engine.

Refactored `csrf.spec.ts` to authenticate once and verify all 21 unsafe write endpoints in one
pass. The previous per-endpoint parallel login pattern rate-limited the target VM.

### Required Vitest Suites

Added the exact-name unit suites that were missing from the pending checklist:

- `dsl.test.ts`
- `classify.test.ts`
- `storage.test.ts`

Existing suites continue to cover API, CSRF contracts, fixtures, routes, stream behavior, device
logic, and fleet logic.

### Fixtures

The required fixtures are present in `web/e2e/support/fixtures.ts`:

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

## Verification Evidence

### Local Gates

Passed from `web/`:

```bash
npm run lint
npm run typecheck
npm run test
npm run build
```

`npm run test` result: 10 files passed, 41 tests passed.

Passed from `engine/`:

```bash
go test ./...
```

Passed from repo root:

```bash
make build-linux
```

`make build-linux` rebuilt the Vite frontend, staged `web/dist` into
`engine/internal/api/web/`, and produced `engine/engine-linux-amd64`.

### Local Browser Gates

Passed against the local Vite server:

```bash
PLAYWRIGHT_START_WEB_SERVER=1 npm run e2e -- --project=chromium soc.spec.ts choke.spec.ts devices.spec.ts fleet.spec.ts
```

Result: 4 passed.

Passed local embedded/login browser checks:

```bash
PLAYWRIGHT_START_WEB_SERVER=1 npm run e2e -- --project=chromium embedded.spec.ts
```

Result: 2 passed, 3 skipped because `EBPF_EXPECT_EMBEDDED=1` was not set for the local Vite
server.

### Target VM Gates

Passed against `https://soc.adanianlabs.io`:

```bash
EBPF_WEB_BASE_URL=https://soc.adanianlabs.io \
EBPF_E2E_USER=admin \
EBPF_E2E_PASSWORD=... \
EBPF_EXPECT_EMBEDDED=1 \
npm run e2e -- --project=chromium embedded.spec.ts
```

Result: 5 passed.

Passed against `https://soc.adanianlabs.io`:

```bash
EBPF_WEB_BASE_URL=https://soc.adanianlabs.io \
EBPF_E2E_USER=admin \
EBPF_E2E_PASSWORD=... \
npm run e2e -- --project=chromium --workers=1 auth.spec.ts csrf.spec.ts sse.spec.ts
```

Result: 11 passed.

Passed against `https://soc.adanianlabs.io` with both opt-in smoke flags:

```bash
EBPF_TARGET_VM_URL=https://soc.adanianlabs.io \
EBPF_WEB_BASE_URL=https://soc.adanianlabs.io \
EBPF_E2E_USER=admin \
EBPF_E2E_PASSWORD=... \
EBPF_E2E_RUN_SAFE_ATTACK=1 \
EBPF_E2E_RUN_WRITES=1 \
npm run e2e -- --project=chromium target-vm-smoke.spec.ts
```

Result: 3 passed.

The final target VM run captured screenshots under:

```text
web/test-results/target-vm-smoke-target-VM--fc204-rk-evidence-and-version-SHA-chromium/
```

Files:

- `target-vm-login.png`
- `target-vm-soc.png`
- `target-vm-choke.png`
- `target-vm-devices.png`
- `target-vm-fleet.png`

The latest Playwright HTML report is:

```text
web/playwright-report/index.html
```

## Current Pending Items

No blocking implementation work remains from the frontend-dev pending checklist.

Remaining non-blocking certification caveat:

- The automated checks now cover the route shells, core controls, local API contracts, embedded
  asset behavior, target VM route load, target VM auth/CSRF/SSE, safe attack smoke, and
  representative Choke write smoke. They do not replace a human visual review of every hidden
  modal, hover popover, disabled state, empty state, and error state across all 78 panels.

Recommended final release signoff:

- Open `web/playwright-report/index.html`.
- Inspect the five target VM screenshots listed above.
- Spot-check hidden/modal-heavy surfaces manually if release policy requires visual signoff
  beyond automated route and workflow certification.
