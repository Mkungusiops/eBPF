import { chromium, type FullConfig } from "@playwright/test";

import { readProbeEnv, signIn } from "./live";

/**
 * One sign-in for the whole probe run.
 *
 * WHY THIS EXISTS RATHER THAN A LOGIN PER TEST: the engine rate-limits
 * /api/login as brute-force defence (5/min/IP by default). A suite that signs
 * in per test trips that guard part-way through and then fails with HTTP 429
 * on every remaining test — which reads as a broken deployment and is a
 * broken harness. The control plane has the same problem in a different shape:
 * each OIDC round trip is a full redirect chain through Keycloak.
 *
 * The saved state is a real browser session obtained through the real login
 * form / real OIDC flow, so nothing is faked. `auth.probe.spec.ts` still drives
 * the form itself, so the login page does not go untested.
 *
 * A failure here is NOT fatal: the specs each skip on missing credentials, and
 * a run with no PROBE_URL should report "skipped", not "setup failed".
 */
/**
 * Where the run's session is cached — PER TARGET, and not under `outputDir`.
 *
 * TWO SEPARATE TRAPS ARE ENCODED IN THIS ONE PATH.
 *
 * It is not under `outputDir` because Playwright CLEARS that directory at the
 * start of a run — after globalSetup has already written into it — so a state
 * file kept there is deleted before the first test reads it, and every test
 * fails with "Error reading storage state".
 *
 * It is keyed by TARGET because it used to be a single `.auth/probe-auth.json`
 * shared by both deployments. An engine run and a control-plane run overlapping
 * (or an engine run simply finishing last) left the console specs restoring
 * `soc_session` cookies scoped to engine.adanianlabs.io and NO `soc_cp_session`
 * at all. The console then boots unauthenticated, fires exactly fourteen 401s
 * before the OIDC chain silently re-authenticates it, and the run fails on
 * browser-console noise that says nothing about the deployment. Measured, not
 * theorised: a dead-session load of "/" produces 14 401s; a live one produces 0.
 */
export function storageStatePath(baseURL: string, kind: string): string {
  // The host, not just the kind: two engines, or a staging control plane, must
  // not share a cache either.
  const host = (() => {
    try {
      return new URL(baseURL).host.replace(/[^a-zA-Z0-9.-]/g, "_");
    } catch {
      return "unknown";
    }
  })();
  return `.auth/probe-auth-${kind}-${host}.json`;
}

export default async function globalSetup(_config: FullConfig): Promise<void> {
  const env = readProbeEnv();
  if (!env.baseURL || !env.user || !env.password) return;

  const browser = await chromium.launch();
  try {
    const context = await browser.newContext({
      baseURL: env.baseURL,
      ignoreHTTPSErrors: true,
      serviceWorkers: "block"
    });
    const page = await context.newPage();
    await signIn(page, env, "/");

    const path = storageStatePath(env.baseURL, env.kind);
    const state = await context.storageState({ path });

    // Fail LOUDLY here rather than four minutes later as browser-console noise.
    // A globalSetup that saved the wrong deployment's session — or no session
    // at all — must not hand every spec a state file that quietly does nothing.
    const host = new URL(env.baseURL).host;
    const sessionCookie = env.kind === "controlplane" ? "soc_cp_session" : "soc_session";
    const saved = state.cookies.filter((cookie) => cookie.domain.replace(/^\./, "") === host);
    if (!saved.some((cookie) => cookie.name === sessionCookie)) {
      throw new Error(
        `sign-in saved no ${sessionCookie} for ${host}. Cookies saved: ` +
          (saved.map((cookie) => `${cookie.name}@${cookie.domain}`).join(", ") || "none") +
          `. Check PROBE_KIND (${env.kind}) matches PROBE_URL.`
      );
    }

    await context.close();
  } catch (error) {
    // Leave no half-written state behind: a stale auth.json would make every
    // spec look authenticated and fail on the first assertion instead of
    // skipping honestly.
    console.error(`[probe] sign-in failed for ${env.baseURL}: ${String(error)}`);
    throw error;
  } finally {
    await browser.close();
  }
}
