# Browser tests for the eBPF SOC console

Two Playwright suites, two different kinds of claim. Read
[`playwright-browser-testing-guide.md`](./playwright-browser-testing-guide.md)
for the general method; this file is what that method turned into for **this**
codebase.

---

## 1. The two suites, and why they are separate

| | **e2e** (`web/e2e/*.spec.ts`) | **probe** (`web/e2e/probe/*.probe.spec.ts`) |
|---|---|---|
| Config | `web/playwright.config.ts` | `web/playwright.probe.config.ts` |
| Command | `npm run e2e` | `npm run test:probe` |
| Size | 180 tests (~5.5 min) | 40 tests (~14 min) |
| Backend | mocked in the browser (`e2e/support/mock-api.ts`) | **a running deployment** |
| Needs credentials | no | yes (`PROBE_USER` / `PROBE_PASSWORD`) |
| Parallel | yes | no — serial, one worker |
| Answers | *does the console behave?* | *does **this deployment** behave?* |

They are not redundant. Neither can see what the other sees:

- **The mock can produce what a live rig cannot.** A 200 whose body omits a
  field the console dereferences; a `text/html` body where JSON was promised; a
  stream that connects and then goes silent; a server with no
  `/api/decision-stats`. Every one of those is a real failure mode and none of
  them can be arranged on a healthy estate.
- **The live rig can produce what the mock cannot.** An nginx that buffers the
  SSE stream; a service worker serving last month's shell; a `go:embed` that
  shipped a stale console; a tenant boundary that only exists once four server
  layers agree. `page.route()` removes the entire network from the picture, so a
  mocked run cannot see any of it.

The e2e config carries `testIgnore: ["probe/**"]` so `npm run e2e` never
reaches for a live estate.

---

## 2. Running them

### e2e (no backend needed)

```bash
cd web
npm run dev &                      # or point at any running console
EBPF_WEB_BASE_URL=http://127.0.0.1:5173 npm run e2e
npm run e2e -- --headed --debug    # watch it
npm run e2e -- surfaces            # one file, by name fragment
```

> **Check which server is on :5173 first, every time.** The default base URL is
> `http://127.0.0.1:5173`. Vite does not own that port — it takes it if it is
> free and silently moves to :5174 if it is not, while the suite keeps pointing
> at :5173. Whatever answers there gets tested.
>
> Two ways this has actually bitten, both of which produce failures that look
> like product bugs:
>
> - the local OrbStack mirror holds :5173, so the suite tests the *mirror*;
> - **an unrelated Docker container holds :5173** — a different product's login
>   page answered 200, the SPA never loaded, and a whole file failed with
>   "element not found" on the nav and the alert list. The tell is that
>   *everything* fails at the first locator, including tests nobody touched.
>   `curl -s http://127.0.0.1:5173/api/whoami` returning a stranger's error
>   envelope confirms it in one line.
>
> `lsof -nP -iTCP:5173 -sTCP:LISTEN` settles who is there. To be safe, start
> Vite on a port you chose and point the suite at it — nothing infers it:
>
> ```bash
> npx vite --host 127.0.0.1 --port 5199 --strictPort &
> EBPF_WEB_BASE_URL=http://127.0.0.1:5199 npm run e2e
> ```
>
> `--strictPort` is the point: without it Vite drifts and you are back to
> testing whatever was already listening. Note `PLAYWRIGHT_START_WEB_SERVER=1`
> does **not** help here — it runs `npm run dev`, which ignores
> `EBPF_WEB_BASE_URL` and still binds :5173, so Playwright waits out its full
> 120s timeout on a URL that will never come up.

> **`getByLabel` is not `getByRole` — for a `<label>`-wrapped `<select>` they
> disagree.** The drill's Choke response grid renders
> `<label><span>Action</span><select><option>throttle</option>…</select></label>`.
> Playwright's `getByLabel` computes the label's *text content*, which slurps the
> option text, so the string it matches against is
> `"Actionthrottletarpitquarantinesever"`:
>
> | locator | count |
> |---|---|
> | `getByLabel("Action", { exact: true })` | **0** |
> | `getByLabel("Action")` (substring) | 1 |
> | `getByRole("combobox", { name: "Action", exact: true })` | **1** |
> | `getByLabel("Audit reason", { exact: true })` | 1 (wraps an `<input>`, no options) |
>
> The accessible name is fine — `ariaSnapshot()` reports `combobox "Action"`, so a
> screen reader announces it correctly and this is **not** a product defect. It is a
> `getByLabel` quirk, and the same trap applies to "Revert after". Reach for
> `getByRole` with `exact: true` on any control whose label wraps a `<select>`.
> Measured 2026-08-27; a review caught this in a draft that had `getByLabel` and a
> paragraph explaining why it resolved to one element.

Two specs are load-sensitive under the default `fullyParallel` fan-out and have
each failed once in a run where the other passed — `soc.spec.ts`'s drill
narrative (the process chain collapses to one entry) and `export.spec.ts`'s
clipboard pair (focus and permissions under four workers). Neither reproduces in
isolation. A single red test in an otherwise green run is worth re-running
alone before it is believed; a defect this suite is pinning fails *both* ways.

A handful of e2e specs assert the **engine's** contract rather than the
console's (the 303 on bad credentials, the JSON 401 envelope, CSRF rejection).
Those probe for a backend and skip when there is none, so a run with no engine
reports *skipped*, not *failed*.

| Variable | Effect |
|---|---|
| `EBPF_WEB_BASE_URL` | where the console is served |
| `EBPF_E2E_USER` / `EBPF_E2E_PASSWORD` | unlocks the CSRF + session specs |
| `EBPF_EXPECT_EMBEDDED=1` | asserts the engine's `go:embed` cache headers |
| `EBPF_TARGET_VM_URL` | runs `enforcement.spec.ts` against a real deployment |
| `PLAYWRIGHT_START_WEB_SERVER=1` | let Playwright boot `npm run dev` itself |

### probe (needs a running deployment)

```bash
cd web

# single-tenant engine
PROBE_URL=https://engine.adanianlabs.io PROBE_KIND=engine \
PROBE_USER=admin PROBE_PASSWORD=… \
  npm run test:probe

# multi-tenant control plane
PROBE_URL=https://console.adanianlabs.io PROBE_KIND=controlplane \
PROBE_USER=op-adanian PROBE_PASSWORD=… \
PROBE_OTHER_USER=op-acme PROBE_OTHER_PASSWORD=… PROBE_OTHER_TENANT=acme-corp \
  npm run test:probe
```

`PROBE_KIND` selects which deployment-specific file runs; it is inferred from
the hostname when omitted, but say it explicitly — the two sign-in flows differ
and getting it wrong fails for the wrong reason.

Everything the probe suite does is a **read**. Nothing arms, contains, pushes a
policy or changes estate state. `PROBE_ALLOW_WRITES=1` exists in the env
contract for future write probes and is not yet consumed by any spec.

**One sign-in per run.** `e2e/probe/support/global-setup.ts` logs in once
through the real form / real OIDC flow and saves the session to
`web/.auth/probe-auth.json` (gitignored). Without this the engine's own
brute-force guard (5 logins/min/IP) trips part-way through a run and every
remaining test fails with HTTP 429 — a healthy deployment reported as broken.

---

## 3. Layout

```
web/
├── playwright.config.ts              # e2e — mocked, parallel
├── playwright.probe.config.ts        # probe — live, serial, globalSetup
└── e2e/
    ├── support/
    │   ├── test.ts                   # fixtures, diagnostics, sidebar locators
    │   ├── contracts.ts              # routes, surfaces, unsafe writes, served API paths
    │   ├── mock-api.ts               # the mocked backend + RequestLog
    │   └── fixtures.ts               # stream frames and canned payloads
    ├── a11y.spec.ts                  # accessible names, keyboard, theme
    ├── approvals.spec.ts             # dual control
    ├── assistant.spec.ts             # analyst assistant + chat sidebar
    ├── auth.spec.ts                  # login page, PWA install paths
    ├── choke.spec.ts                 # Choke Gateway, Command ⇄ Assurance
    ├── csrf.spec.ts                  # 21 unsafe writes reject a missing token
    ├── detections.spec.ts            # policy authoring + push gating
    ├── devices.spec.ts               # device plane
    ├── embedded.spec.ts              # asset/cache contract
    ├── enforcement.spec.ts           # live ladder (opt-in, needs a deployment)
    ├── eventstream.spec.ts           # pause, regex filter, list cap, panel wiring
    ├── export.spec.ts                # export studio, real CSV + PDF downloads
    ├── fleet.spec.ts                 # fleet view renders
    ├── fleet-actions.spec.ts         # fleet WRITES: targets, thresholds, fan-out
    ├── graph.spec.ts                 # graph selection -> rail -> action modal
    ├── honesty.spec.ts               # totals vs floors, unknown vs zero
    ├── investigate.spec.ts           # Time Machine, Watchlist, KPI drill
    ├── mobile.spec.ts                # phone viewports
    ├── resilience.spec.ts            # degraded backends, 401, stream health
    ├── routes.spec.ts                # the five HTML entries
    ├── settings.spec.ts              # six settings sections
    ├── soc.spec.ts                   # dashboard, graph, drill
    ├── sse.spec.ts                   # stream contract
    ├── surfaces.spec.ts              # fan-out over every advertised tool
    ├── target-vm-smoke.spec.ts       # screenshot/evidence capture (opt-in)
    ├── triage.spec.ts                # the alert queue: search, sort, group, ack
    └── probe/
        ├── support/live.ts           # probe env, sign-in for both deployments
        ├── support/global-setup.ts   # one sign-in per run, cached PER TARGET
        ├── auth.probe.spec.ts        # the real login form, cookies, sign-out
        ├── deployment.probe.spec.ts  # true of BOTH deployments
        ├── console.probe.spec.ts     # control-plane only
        ├── engine.probe.spec.ts      # single-tenant engine only
        ├── isolation.probe.spec.ts   # two tenants, two contexts
        └── pwa.probe.spec.ts         # service worker + manifest
```

**Artifact directories must not nest.** The e2e config writes to
`test-results/` and the probe config to `test-results-probe/` — deliberately a
sibling, not a child. Playwright *removes* `outputDir` at the start of every
run, so a probe whose artifacts lived under `test-results/probe` had its traces
deleted mid-flight by any concurrent `npm run e2e`, and failed with an ENOENT on
artifact I/O inside whichever test happened to be running. That reads as a
product failure and is a directory collision.

Naming: **Playwright owns `*.spec.ts`, Vitest owns `*.test.ts(x)`.** The Vitest
config only includes `src/**/*.test.ts(x)`, so neither runner steals the
other's files.

`web/tsconfig.json` includes `e2e`, so `npm run typecheck` covers the test code
too. It did not, and four specs held real type errors — including helpers typed
against the test *title* rather than its fixtures.

---

## 4. The mocked backend

`installMockApi(page, options?)` intercepts `**/api/**` and replaces
`EventSource`. Every default body was derived from a response captured off the
live estate rather than invented, because a mock that lies about a field's
presence produces green tests over a broken console.

```ts
// defaults
await installMockApi(page);

// override one route
await installMockApi(page, {
  routes: { "/api/assistant": { enabled: true, agents: AGENTS } }
});

// a non-200
await installMockApi(page, {
  routes: { "/api/choke/device-state": { status: 503, body: { error: "not enabled" } } }
});

// answer the QUERY, not just the path (server-side search, pagination)
await installMockApi(page, {
  routes: {
    "/api/assistant/chats": (req) => ({ chats: search(new URLSearchParams(req.search).get("q")) })
  }
});

// SSE bodies for the assistant's streaming endpoint
await installMockApi(page, {
  routes: { "/api/assistant/stream": assistantStreamBody({ content: "…", steps: [] }) }
});

// what the stream does: "open" (default) | "silent" | "error"
await installMockApi(page, { stream: "silent" });

// record what the page asked for
const recorder = new RequestLog();
await installMockApi(page, { recorder });
expect(recorder.paths().filter((p) => !isServedApiPath(p))).toEqual([]);
```

`RequestLog` exists for one assertion the DOM cannot make: **that the console
only asks for endpoints its servers actually serve.** A panel calling an
unimplemented route renders quiet, not broken — this codebase has shipped that
class three times.

---

## 5. Conventions

Every browser spec opens with a docblock answering three questions: what bug it
pins, why it is a browser test rather than a unit test, and what fixture it
needs. That docblock is the only thing that stops the test being deleted as
"redundant with the unit test" six months later.

- **Selectors**, in order of preference: role/label (`getByRole`, `getByLabel`)
  → `data-panel` → CSS. This app has no `data-testid`; `data-panel` is its
  equivalent and is stable across restyling.
- Two sidebar helpers exist because "Settings" is both a nav item and a
  collapsible section header: `socNavItem(page, label)` for tool buttons,
  `socNavLink(page, label)` for route links.
- **Waiting**: wait for the thing itself, or for `rendered OR error-boundary` —
  never a bare `waitForTimeout`. Where time itself is the subject (the 30s
  stale-stream banner) drive `page.clock` rather than sleeping.
- **`toBeVisible()` is not "the panel opened" in this app.** `SocModals`
  mounts every modal body permanently and hides it with a missing `is-open`
  class, and `SlideOver` renders its `<aside>` unconditionally and hides it with
  `transform: translateX(102%)` — which does not affect Playwright's visibility
  computation at all. Assert `toHaveClass(/is-open/)` (or `aria-hidden`)
  instead; a `toBeVisible()` on either container can pass without anything
  having been opened.
- **`test.fail(true, …)` belongs INSIDE the test body**, as its first
  statement. Written above a test inside a `describe`, it applies to every test
  in that block, and the others then fail with "Expected to fail, but passed".
- **Assert the precondition.** Before the interesting assertion, prove the
  subject exists. Several tests here carry an explicit anti-vacuity floor for
  exactly this reason, and it earned its keep immediately: the tenant-isolation
  probe's "these really are two different tenants" check caught a helper that
  was handing back the *same* signed-in session twice, which would otherwise
  have reported a passing isolation proof over one operator tested twice.
- **`browser.newContext()` inherits the config's `use`.** A probe that needs an
  anonymous or second identity must pass
  `storageState: { cookies: [], origins: [] }` explicitly — `undefined` reads
  as "not specified" and hands back the run's shared session. Likewise, a test
  that *destroys* a session (sign-out) has to own the one it destroys.
- **Never assert on source strings.** Test what the code does.

### Known defects are recorded in code, not deleted

Where this suite found a real defect that is not yet fixed, the assertion stays
and is marked `test.fail(...)` with the cause and the fix written above it. The
suite stays green, the defect stays visible, and `test.fail` turns into a hard
error the moment someone fixes it — so the marker cannot outlive the bug.

The a11y suite uses the same idea in list form: `KNOWN_UNNAMED_CONTROLS` records
the controls that have no accessible name today. A **new** unnamed control fails
the test, and an entry that has been fixed also fails it until it is struck from
the list, so the allowlist can only ever shrink.

---

## 6. What it found

Standing this up surfaced **sixteen product defects** and three stale tests.
None of the product defects is fixed — every one is an assertion that is in the
tree, correct, and marked, so it turns into a hard error the moment someone
fixes the code under it.

### Pinned with `test.fail` (14)

Ranked by consequence.

| # | Defect | Where it is pinned | Source |
|---|---|---|---|
| 1 | **Every multi-tenant fleet write reports "0/0 hosts succeeded" — as success.** The CP answers `{ok, preset, applied, total, detail}` with no `hosts` key; the console reads `result.hosts ?? []`. A write that reached two agents renders as reaching none, in a green toast. | `fleet-actions.spec.ts` | `controlplane/choke.go:1008`, `fleetLogic.ts` |
| 2 | **`summarizeFanout` treats 0/0 hosts as success** — `failed === 0` is satisfied by an empty list, so a fan-out that reached nobody is indistinguishable from one that reached everybody. | `fleet-actions.spec.ts` | `fleetLogic.ts` |
| 3 | **The fleet kill-switch sends no audit reason** though the engine decodes and audits one. Thaw — a recovery action — requires one; bypassing enforcement estate-wide does not. | `fleet-actions.spec.ts` | `useFleetControls.ts`, `api.ts`, `api/choke.go:764` |
| 4 | **Event-stream Pause only dims the list** (`opacity: .62`). `paused` is not in the `visibleEvents` memo; rows keep arriving and scrolling underneath. | `eventstream.spec.ts` | `useSocWindowModel.ts:255` |
| 5 | **A stream frame arriving during the first snapshot poll is discarded** — `setSnapshot(read.snapshot)` replaces the buffer it was written into. The pill still counts it. | `eventstream.spec.ts` | `soc/hooks.ts:38` |
| 6 | **Acking a ×2 grouped alert acks only `members[0]`** — the row claims to stand for two and reaches one. | `triage.spec.ts` | `analytics.ts:91` |
| 7 | **"Top 10 by score" never sorts by score** — `scopedAlerts.slice(0, 10)`. With >10 in a bucket it silently drops the highest. | `investigate.spec.ts` | `KpiDrillBody.tsx:116` |
| 8 | **An empty alert queue blames filters that are not set** — one hard-coded empty state for "you filtered everything out" and "the estate is quiet". | `triage.spec.ts` | `AlertQueue.tsx` |
| 9 | **A grouped export writes one row per group and counts groups as alerts.** | `export.spec.ts` | `exportStudio.tsx` |
| 10 | **`useAssistant` takes the whole SOC route down** when `/api/assistant` 200s without an `agents` array — in the path whose own comment promises it never will. | `resilience.spec.ts` | `useAssistant.ts:162` |
| 11 | **Ctrl+K opens the command palette without focusing it** — modal bodies mount at route load, so cmdk's `autoFocus` fires on a hidden input. | `a11y.spec.ts` | `SocModals.tsx` |
| 12 | **`.choke-topbar-primary` does not wrap on phones** — a 1140px document in a 390px viewport, on the platform's headline surface. | `mobile.spec.ts` | `ChokeRoute.css` |
| 13 | **`soc.savedViews` is advertised in the panel inventory and never written**; no saved-view control exists, and it inflates the account page's key count. | `triage.spec.ts` | `panelInventory.ts` |
| 14 | **GraphBrief counts loopback peers the graph refuses to draw** — the number disagrees with the picture. | `graph.spec.ts` | `GraphBrief.tsx` |

### Recorded but structurally un-failable through a mock (1)

**The fleet console's host selection is inert.** Tick one host, the rail says
"Writes target 1 selected host", and `targets` is read by *neither* server:
`(*Fleet).fanout` calls `f.Peers()` and forwards the body verbatim to every
peer, and the control plane's `handleChokePreset` decodes only `{name, reason}`
before `dispatchAll` to every agent in the tenant. **Selecting one host and
applying containment contains the whole fleet.**

A browser suite cannot fail on this — the mock answers whatever the console
sends — so `fleet-actions.spec.ts` keeps the client-side assertions, states in
its docblock that a green run means only "the console computed the target set
the rail is showing", and carries a `SERVER-SIDE GAPS THIS SUITE STRUCTURALLY
CANNOT FAIL ON` section naming the two handlers and the fix. Writing it down is
the only thing a browser test can do about it.

### Recorded as a shrinking allowlist (1)

Six text inputs have no accessible name — placeholder only, which a screen
reader announces as "edit text, blank" and which vanishes on first keystroke.
`KNOWN_UNNAMED_CONTROLS` in `a11y.spec.ts` records them; a **new** unnamed
control fails the test, and an entry that gets fixed also fails it until it is
struck from the list, so the allowlist can only shrink.

### Fixed, and the pins removed (1)

**Every upstream assistant failure collapsed into one sentence.** A rate limit,
a timeout and an unreachable provider are three different operator actions —
retry now, ask something smaller, escalate — and all three read as the third.
`assistant.spec.ts` pinned two of them with `test.fail`.

Root cause was two faults, both in `internal/assistant`:

- **`Timeout` was doing two jobs.** One 60s value bounded a single completion
  *and* the whole run context, so `Runner.Run` — which issues up to
  `MaxToolCalls` completions plus a closing one — had to finish seven provider
  calls inside the time allotted to one. Invisible while upstream answered in
  ~1s; every-multi-step-answer-fails the day it slowed down. Split into
  `Timeout` (45s, per completion) and `RunBudget` (150s, per answer), both now
  flags: `-assistant-timeout`, `-assistant-run-budget`,
  `-assistant-max-tool-calls`, on both binaries, printed at startup.
- **The 429 body was decoded before the status was read.** `error` is typed as
  an object; the provider returns a bare **string** on 429, so the decode failed
  on the whole body and a rate limit reached the operator as *"provider returned
  unreadable JSON"* — the one status where knowing the reason changes what you
  do. Status is now classified first, and `providerError` accepts either shape.

`assistant.OperatorMessage` maps `ErrRateLimited` / `ErrOverloaded` /
`DeadlineExceeded` / everything-else onto four fixed sentences, never
interpolated from upstream — the constraint that made the message generic in the
first place survives, and `assistant.spec.ts` asserts both halves (it says which
condition; it echoes no provider string, URL or key). Client hang-ups are now
`ClientAbandoned` and log at `Info`: five identical `context canceled` lines had
read like five upstream failures during triage.

Covered by `internal/assistant/operatorerror_test.go` (four real `httptest`
servers, including one that proves a `http.Client` timeout still satisfies
`errors.Is(err, context.DeadlineExceeded)` through `url.Error` and the
provider's own wrap) and by the four `UPSTREAM_CONDITIONS` cases in
`assistant.spec.ts`. Deployed to both boxes 2026-08-27; the question that was
failing now answers in 4.0s, grounded.

### Stale tests repaired (3)

- `choke.spec.ts` was still driving a **Policy Workbench** the dual-mode
  redesign removed, so the Choke route's headline feature — the Command ⇄
  Assurance lens — had no browser coverage at all.
- `devices.spec.ts` mocked only `/api/choke/**`, so the assistant panel the
  Devices route grew escaped to the Vite proxy and 500'd twelve times per run.
- `csrf.spec.ts` asserted a 22-route inventory including
  `/api/choke/policy/preview`, which **both** servers deliberately removed. The
  middleware rejects an unsafe method before routing, so that entry could only
  ever pass. Inventory is now 21.

The e2e directory was also brought into `tsc`, surfacing four real type errors
in the pre-existing specs — including three helpers typed against the test
*title* rather than its fixtures.

## 7. What is deliberately not covered

- **Cross-browser.** Chromium only. The console is an internal operator tool
  with a stated browser baseline; adding WebKit and Firefox projects would
  triple the runtime for a risk nobody has reported.
- **Visual snapshots.** Font rendering is OS-specific, so snapshots would have
  to be generated in a container to be stable. The layout claims that matter
  here (no horizontal overflow, a painted background, a header aligned with its
  column) are asserted as measurements instead, which fail with a number
  attached rather than a diff image.
- **Write probes against the live estate.** Every probe reads. Containment,
  arming and policy pushes are exercised by `enforcement.spec.ts` (opt-in, via
  `EBPF_TARGET_VM_URL`) and by the shell suites under `scripts/e2e/`, which can
  also assert what happened *on the host* — something a browser cannot.
