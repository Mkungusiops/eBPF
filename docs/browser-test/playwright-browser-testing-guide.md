# Browser Testing with Playwright: A Portable Guide

> **Purpose.** This document supports the set up, write, and run
> browser tests that can open **many pages/tabs at once** — for parallel fan-out, for A/B
> comparison of two renders, and for context-level powers like going offline.
>
> It is distilled from a working Next.js + Supabase codebase, but the architecture is
> framework-agnostic. Drop this file into a project (e.g. `docs/testing/browser-testing.md`
> or next to `AGENTS.md` / `CLAUDE.md`) and point the model at it.

---

## 1. The mental model: Browser → Context → Page

Everything about "opening multiple pages" follows from Playwright's three-level hierarchy.
There is no custom machinery involved — a test just asks for a lower-level fixture than usual.

```
Browser                     one launched Chromium process (shared across a worker's tests)
└── BrowserContext          an isolated profile: own cookies, localStorage, permissions,
    │                       viewport defaults, offline flag, geolocation, colorScheme
    ├── Page                one tab
    ├── Page                another tab (shares the context's cookies/storage)
    └── Page
```

Playwright's default test fixtures hand you the **bottom** of this tree:

```ts
test('the usual shape', async ({ page }) => { ... });   // one context, one page, auto-closed
```

To open more than one page, take a **higher** fixture instead:

| You take | You can do | Isolation |
|---|---|---|
| `{ page }` | one tab | fresh context per test (Playwright's default) |
| `{ context, page }` | `context.newPage()` for a 2nd tab | **shared** cookies/storage with `page` |
| `{ browser }` | `browser.newContext()` → `context.newPage()`, N times | each context fully isolated |
| `{ request }` / `request.newContext()` | HTTP-only context, no browser at all | for API seeding/teardown |

**Rule of thumb**
- Need a second *logged-in tab* of the same session → `context.newPage()`.
- Need N *independent* browsers-worth of state, or different viewports/locales/offline → `browser.newContext()`.
- Need to create/delete data, not click on it → `request.newContext()`.

**You must close what you open.** Playwright auto-closes the *fixture* context, not yours:

```ts
const context = await browser.newContext();
try { /* ... */ } finally { await context.close(); }   // closes every page inside it
```

---

## 2. The four-layer test architecture

Do not put every test in one runner. Split by *what kind of claim* the test makes. Each layer
gets its own config file so it can be run and ignored independently.

| Layer | Runner | Dir | Server it needs | Answers |
|---|---|---|---|---|
| **Unit / component** | Vitest + jsdom | `src/**/__tests__`, `tests/*.test.ts(x)` | none | Does this function/component behave? |
| **E2E journeys** | Playwright | `tests/e2e/` | starts its own dev server | Can a user complete this flow end to end? |
| **Probes** | Playwright | `tests/probe/` | **an already-running full stack** | Does the *whole stack* do X? (measured in a real browser) |
| **Storybook / visual** | Playwright | `tests/storybook/` | starts Storybook | Does every component mount? Does it look right? |

### Which layer does a claim belong in?

Ask: **can jsdom observe this?**

- Computed values, store state, callbacks fired, rendered text → **unit**. Cheapest, run always.
- Layout geometry, `getBoundingClientRect`, background images, CSS that must actually paint,
  scroll overflow, real fonts, animation timing, WebSockets, `visibilitychange`, focus order,
  touch-target sizes → **browser** (probe or storybook). jsdom neither paints nor measures.
- A multi-step user flow across routes with real auth and a real database → **e2e**.

Write the reason into the test's docblock (see §7). "This is here rather than in unit tests
because jsdom does not paint background images" is the single most useful line in the file.

---

## 3. Install and layout

```bash
npm i -D @playwright/test
npx playwright install --with-deps chromium
```

```
<app>/
├── playwright.config.ts            # e2e — starts the app
├── playwright.probe.config.ts      # probes — assumes the stack is up
├── playwright.storybook.config.ts  # storybook/visual
├── vitest.config.ts                # unit (jsdom) — excludes **/e2e/**, **/*.spec.ts
└── tests/
    ├── e2e/
    │   ├── _helpers/auth.ts        # log in through the real form
    │   ├── _helpers/fixtures.ts    # create/tear down data over the API
    │   └── *.spec.ts
    ├── probe/*.probe.spec.ts
    ├── storybook/*.spec.ts
    └── *.test.ts(x)                # unit, picked up by Vitest not Playwright
```

**Naming convention that makes the split work:** Playwright owns `*.spec.ts`, Vitest owns
`*.test.ts(x)`. Then each runner's `include`/`exclude` is a one-liner and neither steals the
other's files.

---

## 4. Config templates

### 4a. E2E — starts the app itself

```ts
// playwright.config.ts
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  testMatch: '**/*.spec.ts',
  // Probes are pinned to a running stack and to seeded ids; storybook needs a
  // different server. Picking either up here means CI runs them against the
  // wrong world and they fail for reasons that are not bugs.
  testIgnore: ['tests/storybook/**', 'tests/probe/**'],
  fullyParallel: true,
  retries: 0,
  use: {
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
    headless: true,
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'npm run dev',
    port: 3000,
    reuseExistingServer: !process.env.CI,   // locally, attach to the server you already have
    timeout: 120 * 1000,
  },
});
```

`fullyParallel: true` runs tests in parallel **worker processes**, each with its own browser.
That is a different axis from opening multiple pages inside one test — both can be used at once.

### 4b. Probe — deliberately starts nothing

```ts
// playwright.probe.config.ts
import { defineConfig, devices } from '@playwright/test';

/**
 * Manual/CI verification against a stack that is ALREADY up (app + database +
 * any backing services), because what these verify is the behaviour of the
 * whole stack rather than of the frontend alone. Point it with PROBE_URL.
 */
export default defineConfig({
  testDir: './tests/probe',
  outputDir: 'test-results/probe',
  fullyParallel: false,          // they touch shared, seeded data
  workers: 1,
  timeout: 120_000,              // real networks, cold route compiles
  expect: { timeout: 20_000 },
  reporter: [['line']],
  use: {
    ...devices['Desktop Chrome'],
    baseURL: process.env.PROBE_URL ?? 'http://localhost:3000',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
});
```

### 4c. Storybook / visual

```ts
// playwright.storybook.config.ts
import { defineConfig, devices } from '@playwright/test';

const external = process.env.STORYBOOK_URL;
const url = external ?? 'http://localhost:6006';

export default defineConfig({
  testDir: './tests/storybook',
  outputDir: 'test-results/storybook',
  preserveOutput: 'failures-only',
  fullyParallel: false,
  timeout: 60_000,
  expect: { timeout: 20_000 },
  reporter: [['line']],
  use: { ...devices['Desktop Chrome'], baseURL: url, trace: 'retain-on-failure' },
  // Attach to an external Storybook when given one; otherwise boot our own.
  ...(external ? {} : {
    webServer: {
      command: 'npm run storybook -- --ci --no-open',
      url,
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
    },
  }),
});
```

### 4d. Scripts

```jsonc
{
  "scripts": {
    "test:unit":      "vitest -c vitest.config.unit.ts",
    "test:e2e":       "playwright test",
    "test:probe":     "playwright test -c playwright.probe.config.ts",
    "test:storybook": "playwright test -c playwright.storybook.config.ts"
  }
}
```

---

## 5. The three multi-page patterns

### Pattern A — Parallel fan-out over a work queue

**Use when:** you have N independent URLs to visit and want them checked concurrently inside a
*single* test (so you get one aggregated failure message, not N flaky tests).

Canonical example: mount **every** Storybook story and fail if any throws.

```ts
import { expect, test, type ConsoleMessage, type Page } from '@playwright/test';

const CONCURRENCY = 4;
const IGNORED_CONSOLE = /Failed to load resource/;   // known-harmless noise, not a failure

async function failureFor(page: Page, origin: string, storyId: string) {
  const errors: string[] = [];
  const onPageError = (e: Error) => errors.push(String(e.message));
  const onConsole = (m: ConsoleMessage) => {
    if (m.type() === 'error' && !IGNORED_CONSOLE.test(m.text())) errors.push(m.text());
  };
  page.on('pageerror', onPageError);
  page.on('console', onConsole);
  try {
    await page.goto(`${origin}/iframe.html?id=${encodeURIComponent(storyId)}&viewMode=story`,
      { waitUntil: 'domcontentloaded' });

    // Either it rendered, or the framework swapped in its error display.
    // Waiting on "root has children" ALONE would hang forever on a throw.
    await page.waitForFunction(() => {
      if (document.body.classList.contains('sb-show-errordisplay')) return true;
      const root = document.getElementById('storybook-root');
      return !!root && root.innerHTML.trim().length > 0;
    });

    const display = await page.evaluate(() => {
      if (!document.body.classList.contains('sb-show-errordisplay')) return '';
      return (document.getElementById('error-message')?.textContent ?? 'error').slice(0, 300);
    });
    if (display) return `${storyId}: ${display.replace(/\s+/g, ' ')}`;
    if (errors.length) return `${storyId}: ${errors[0].slice(0, 300)}`;
    return null;
  } catch (error) {
    return `${storyId}: ${String((error as Error).message).split('\n')[0]}`;
  } finally {
    page.off('pageerror', onPageError);   // listeners leak across the loop otherwise
    page.off('console', onConsole);
  }
}

test('every story in the index mounts without throwing', async ({ browser, baseURL }) => {
  test.setTimeout(15 * 60_000);                       // a fan-out is one long test

  const origin = baseURL ?? 'http://localhost:6006';
  const index = await (await fetch(`${origin}/index.json`)).json();
  const storyIds = Object.values(index.entries)
    .filter((e: any) => e.type === 'story').map((e: any) => e.id);

  expect(storyIds.length, 'story index should not be empty').toBeGreaterThan(100);

  const failures: string[] = [];
  const queue = [...storyIds];

  await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
    // One context per LANE, reused across its items: a fresh context per item
    // costs more than rendering the item does.
    const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
    const page = await context.newPage();
    try {
      for (let id = queue.pop(); id; id = queue.pop()) {
        const failure = await failureFor(page, origin, id);
        if (failure) failures.push(failure);
      }
    } finally {
      await context.close();
    }
  }));

  expect(failures, `${failures.length} of ${storyIds.length} items failed`).toEqual([]);
});
```

Why this shape:
- **Lanes, not one-context-per-item.** Context creation dominates the cost of a cheap page.
- **Shared mutable queue + `pop()`** gives natural load-balancing; slow items don't stall a lane.
- **Collect failures, assert once at the end** — you learn about all 31 broken stories in one run,
  not the first one.
- **Sanity-check the input** (`toBeGreaterThan(100)`) so an empty index can't pass vacuously.

### Pattern B — A second page in the *same* context (A/B comparison)

**Use when:** you need to compare two renders of the same thing under the same session, e.g.
"the placeholder reserves exactly the height the real component will take".

```ts
test('deferred and mounted charts reserve the same height',
  async ({ context, page }) => {                       // note: BOTH fixtures
    await openStory(page, storyId, { freezeDeferredCharts: true });
    const deferred = await measureGeometry(page);

    const mountedPage = await context.newPage();       // same cookies, same storage
    await mountedPage.setViewportSize(viewport);
    await openStory(mountedPage, storyId);
    await mountAllCharts(mountedPage);
    const mounted = await measureGeometry(mountedPage);

    expect.soft(
      Math.abs((deferred.chart?.height ?? 0) - (mounted.chart?.height ?? 0)),
      `deferred (${deferred.chart?.height}px) and mounted (${mounted.chart?.height}px) must match`,
    ).toBeLessThanOrEqual(1);

    await mountedPage.close();                          // your page, your job
  });
```

### Pattern C — Your own context, for context-level powers

**Use when:** the thing under test is a *context* option, not a page action. The `page` fixture
cannot give you these.

```ts
test('the offline banner appears when the socket dies and clears on reconnect',
  async ({ browser }) => {
    test.setTimeout(8 * 60_000);
    const context = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
    const page = await context.newPage();

    page.on('websocket', ws => {
      sockets.push(ws.url());
      ws.on('close', () => console.log('[ws closed]', ws.url().slice(0, 80)));
    });

    await login(page);
    await openFeature(page);

    // Prove the thing under test actually exists, or the rest is vacuous.
    expect(sockets.some(u => /realtime\/v1\/websocket/.test(u)),
      'no realtime socket opened, so channel health is not under test').toBe(true);

    await context.setOffline(true);        // <-- CONTEXT-level. This is the whole point.
    await expect.poll(bannerVisible, { timeout: 90_000,
      message: 'the warning never appeared after the socket dropped' }).toBe(true);

    await context.setOffline(false);
    await expect.poll(bannerVisible, { timeout: 120_000,
      message: 'the warning never cleared after the socket came back' }).toBe(false);

    await context.close();
  });
```

**Critical detail worth memorising:** `page.route()` **cannot** intercept a WebSocket *upgrade* —
only HTTP. To kill a live socket for real, use `context.setOffline(true)`.

Other context-only options: `colorScheme`, `reducedMotion`, `locale`, `timezoneId`,
`geolocation`, `permissions`, `storageState`, `viewport` defaults, `recordVideo`.

### Setting context options declaratively

```ts
test.describe('visual contract', () => {
  test.use({
    colorScheme: 'light',
    locale: 'en-US',
    timezoneId: 'UTC',
    contextOptions: { reducedMotion: 'reduce' },   // <-- NOT a sibling of colorScheme
  });
  ...
});
```

⚠️ **Known footgun:** `reducedMotion` is a *browser-context* option. Written as a top-level
sibling of `colorScheme` in `test.use()` it is **silently ignored** and the suite screenshots
mid-animation. Anything not in Playwright's top-level `TestOptions` must go inside
`contextOptions`. Silent, not an error — verify by asserting an animation-dependent value.

---

## 6. Auth and self-seeding fixtures

Two separate sessions, on purpose.

### 6a. The browser session — log in through the real form

```ts
// tests/e2e/_helpers/auth.ts
import { type Page } from '@playwright/test';

/**
 * Prerequisite: a seeded, onboarded user that already belongs to a workspace.
 * Selectors verified <DATE> against <path/to/LoginForm.tsx>.
 */
export const TEST_EMAIL = process.env.E2E_EMAIL ?? 'test@example.com';
export const TEST_PASSWORD = process.env.E2E_PASSWORD ?? 'Password123';

export async function login(page: Page): Promise<void> {
  await page.goto('/home');
  const email = page.locator('input[type="email"], input[name="email"]').first();
  await email.waitFor({ timeout: 10_000 });
  await email.fill(TEST_EMAIL);
  await page.locator('input[type="password"]').first().fill(TEST_PASSWORD);
  await page.locator('button:has-text("Sign in"), button[type="submit"]').first().click();
  await page.waitForURL('**/workspace/**', { timeout: 20_000 });
}
```

Speed-up when you have many authenticated tests: log in once in a `globalSetup`, save
`await context.storageState({ path: 'auth.json' })`, and set `use: { storageState: 'auth.json' }`.
Keep at least one test that drives the real form, or the login page goes untested.

### 6b. The fixture session — create data over the API, not the UI

```ts
// tests/e2e/_helpers/fixtures.ts
import { request, type APIRequestContext } from '@playwright/test';

/**
 * Every id here is created at runtime and torn down afterwards. Nothing is
 * hardcoded: a DB reset re-provisions the test user into a NEW random
 * workspace, so a spec pinned to a seeded id is broken by design the first
 * time anyone resets.
 *
 * Credentials are read from the RUNNING APP's own /api/config rather than from
 * ambient env vars, so the specs are hermetic against whatever stack the dev
 * server points at and CI needs no extra configuration.
 */
async function readRuntimeConfig(baseURL: string) {
  const probe = await request.newContext({ baseURL, timeout: 120_000 });
  try {
    let lastError = '';
    // Retried: this is the very first request, and a dev server that just said
    // "ready" still compiles each route on first hit. In CI that first compile
    // is reliably slower than a default request timeout, and the failure looks
    // like a misconfiguration rather than a cold start.
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try {
        const res = await probe.get('/api/config');
        if (res.ok()) return await res.json();
        lastError = `status ${res.status()}`;
      } catch (e) { lastError = String(e); }
      await new Promise(r => setTimeout(r, 3_000));
    }
    throw new Error(`GET ${baseURL}/api/config never succeeded: ${lastError}`);
  } finally {
    await probe.dispose();     // request contexts dispose(), browser contexts close()
  }
}
```

Two rules that matter:

1. **Seed as the *same user* the browser logs in as, with the *same* privileges** — not with an
   admin/service-role key. A fixture created by an admin proves nothing about whether the user is
   *allowed* to create it, and silently defeats row-level security testing.
2. **Create at runtime, tear down after.** Hardcoded fixture ids rot the first time someone
   resets the database. If you must pin ids (probes often do), say so loudly in the docblock and
   keep those specs out of the CI config (`testIgnore`).

---

## 7. Writing conventions

### Every browser test opens with a docblock that answers three questions

```ts
/**
 * The colour swatch's three states, measured in a real browser.
 *
 * WHAT BUG THIS PINS: an unset colour row painted a hollow ring beside grey
 * `token:accent` text. Neither half was true — the text was a hardcoded
 * fallback naming a default no chart uses, and the ring was empty because
 * there was no colour behind the invented name.
 *
 * WHY IT IS HERE AND NOT IN UNIT TESTS:
 *   - The unset swatch's slash is a background image, which jsdom neither
 *     paints nor measures.
 *   - Explicit vs inherited must stay visually distinguishable — held to a
 *     pixel comparison rather than a computed CSS string, which would pass
 *     whether or not the stylesheet ever loaded.
 *
 * FIXTURE: the seeded v2 line panel. A legacy panel renders a different
 * component and this fails at the first wait rather than passing on an
 * empty page.
 */
```

This is not ceremony. Six months later it is the only thing that stops someone deleting the test
as "redundant with the unit test", or moving it back to jsdom where it silently passes.

### Assertion style

```ts
// expect.poll for anything that settles asynchronously — never a bare waitForTimeout
await expect.poll(() => page.evaluate(() => document.documentElement.dataset.theme),
  { timeout: 15_000 }).toBe('dark');

// expect.soft for geometry: report ALL the layout failures in one run
expect.soft(geometry.documentOverflow, 'page must not scroll horizontally').toBeLessThanOrEqual(0);
expect.soft(geometry.lead.width).toBeGreaterThan(geometry.support.width);

// Always attach a message naming the claim, with the actual numbers in it
expect.soft(Math.abs(a - b), `deferred (${a}px) and mounted (${b}px) must match`)
  .toBeLessThanOrEqual(1);
```

### Selectors

Prefer, in order: role/label (`getByRole`, `getByLabel`) → `data-testid` → CSS. Never a class
name generated by a CSS framework. Probes lean on `data-testid` and `aria-label` because they
survive restyling:

```ts
await page.locator('[data-testid="viz-inspector"]').waitFor({ timeout: 60_000 });
await page.locator('button[aria-label="Open chat history"]').click();
```

### Waiting

```ts
// GOOD — wait for the thing itself. Dev-mode route compiles are slow and variable.
await page.locator('[data-testid="composer"]').waitFor({ timeout: 180_000 });

// GOOD — a compound condition the app actually reaches
await page.waitForFunction(() => document.getElementById('root')?.innerHTML.trim().length > 0);

// AVOID — a fixed sleep. If you truly cannot express the condition, comment WHY.
await page.waitForTimeout(3000);
```

### Assert the precondition, or the test can pass vacuously

Three separate real bugs in the source project came from tests that passed while testing nothing.
Before the interesting assertion, prove the subject exists:

```ts
expect(storyIds.length, 'index should not be empty').toBeGreaterThan(100);
expect(sockets.some(u => /websocket/.test(u)), 'no socket opened; nothing under test').toBe(true);
```

### 🚫 Hard rule: tests assert behaviour, never source strings

A test that reads a source file and asserts on its text — `readFileSync` plus
`expect(source).toMatch(...)` / `.not.toMatch(...)` / `.toContain(...)` — is **invalid**.

It passes for the wrong reasons and fails for the wrong reasons: it cannot tell working code from
code that merely *looks* right, it breaks on formatting and renames, and it silently stops testing
anything once its regex drifts.

- Test what the code **does**: render it, call it, drive it; assert on returned values, rendered
  output, store state, or calls made to injected dependencies.
- If a behaviour is hard to observe, **fix the seam** — extract the unit, inject the dependency,
  mock at the boundary.
- **Structural constraints belong in eslint, not tests.** "Must not import X", "no `useRef` in
  this file" are `no-restricted-imports` / `no-restricted-syntax` rules, matched against the AST.
- If neither a behavioural test nor a lint rule can express it, say so and leave it **untested**
  rather than shipping an assertion that cannot fail.

**The narrow exception**, judged by *what the assertion protects*, not by what file it reads:
a genuine ongoing system invariant — "these two copies must stay in sync" (a function mirrored
into a deployment dir, a config value shared across services, a generated file vs its source), or
a negative security fact ("a service-role key must never appear in the frontend bundle") that no
unit test can observe. Even then prefer exact equality (`toBe` on the whole file) over
`toContain`/regex, which can drift into passing vacuously.

**Delete** the other kind: "this component no longer imports that hook", written to confirm a
refactor landed. That asserts a fact about *work history*, not about the system. Git already
records it.

---

## 8. Running

```bash
npm run test:unit                      # fast, always
npm run test:e2e                       # boots the app itself
npm run test:e2e -- --headed --debug   # watch it / step through
npm run test:e2e -- tests/e2e/foo.spec.ts -g 'partial name'

# Probes need the stack up FIRST (app + database + services), then:
PROBE_URL=http://localhost:3000 npm run test:probe -- tests/probe/foo.probe.spec.ts

STORYBOOK_URL=http://localhost:6006 npm run test:storybook

npx playwright show-trace test-results/**/trace.zip   # post-mortem on a failure
npx playwright codegen http://localhost:3000          # record selectors
```

### Debugging checklist

| Symptom | Likely cause |
|---|---|
| Passes locally, times out in CI | Cold route compile. Raise timeouts; retry the *first* request. |
| Hangs forever waiting for content | Your wait condition can't be satisfied on the error path. Wait for `rendered OR error-shown`. |
| Screenshot differs run to run | Animation. Set `contextOptions: { reducedMotion: 'reduce' }`, pin `locale`/`timezoneId`, freeze the clock. |
| `page.route()` doesn't intercept | It's a WebSocket. Use `context.setOffline(true)`. |
| Passes but proves nothing | Missing precondition assertion. See §7. |
| Second tab isn't logged in | You used `browser.newContext()` where you wanted `context.newPage()`. |
| Test leaks / browser won't exit | An opened context/page never closed. Wrap in `try/finally`. |
| Snapshots differ on CI vs laptop | Font rendering is OS-specific — snapshots are per-platform (`-linux.png`). Generate them in a container. |

---

## 9. Porting checklist

1. `npm i -D @playwright/test && npx playwright install --with-deps chromium`.
2. Decide the file-name split: Playwright owns `*.spec.ts`, unit runner owns `*.test.ts(x)`.
   Add the matching `exclude` to the unit config (`**/e2e/**`, `**/*.spec.ts`).
3. Copy the three configs from §4; fix ports, `webServer.command`, and `testIgnore`.
4. Add the four scripts from §4d.
5. Write `_helpers/auth.ts` against the *real* login form. Note the date and the component path
   you verified the selectors against.
6. Write `_helpers/fixtures.ts` that reads config from the running app and seeds as the test user.
7. Start with two tests: an unauthenticated smoke spec (routes resolve, 404 renders, health
   endpoint answers, `<html lang>` is set) and Pattern A over whatever your project has many of.
8. Only then add probes — and keep them out of the CI config via `testIgnore`.
9. Add the §7 conventions to `AGENTS.md` / `CLAUDE.md` so they survive.

---

## 10. Quick reference

```ts
// --- fixtures ---------------------------------------------------------
test('…', async ({ page }) => {})                      // 1 tab
test('…', async ({ context, page }) => {})             // + context.newPage() shares session
test('…', async ({ browser }) => {})                   // + browser.newContext() isolates
test('…', async ({ request }) => {})                   // HTTP only, no browser

// --- multiple pages ---------------------------------------------------
const ctx  = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
const page = await ctx.newPage();
const two  = await ctx.newPage();                      // same cookies/storage as `page`
await ctx.close();                                     // closes every page in it

// --- context-only powers ----------------------------------------------
await ctx.setOffline(true);
await ctx.grantPermissions(['clipboard-read']);
await ctx.addCookies([...]);
const state = await ctx.storageState({ path: 'auth.json' });

// --- events -----------------------------------------------------------
page.on('pageerror', e => …);                          // uncaught exception in the page
page.on('console',   m => m.type() === 'error' && …);
page.on('websocket', ws => ws.on('close', () => …));
page.off('console', handler);                          // ALWAYS, in a reuse loop

// --- measuring in the real browser ------------------------------------
const box = await page.locator('#el').evaluate(el => el.getBoundingClientRect());
const theme = await page.evaluate(() => document.documentElement.dataset.theme);
await page.evaluate(v => localStorage.setItem('theme', v), 'dark');
await page.reload({ waitUntil: 'domcontentloaded' });  // mount effects re-read storage

// --- timeouts ---------------------------------------------------------
test.setTimeout(15 * 60_000);                          // per test, for fan-outs
await expect.poll(fn, { timeout: 90_000, message: 'what should have happened' }).toBe(true);
```
