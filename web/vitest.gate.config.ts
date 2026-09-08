import { defineConfig } from "vitest/config";

import base from "./vitest.config";

/**
 * The gate's own gate.
 *
 * outcomeTypecheckGate.test.ts proves that the command a human or an agent
 * actually types — `npm test` — fails when a type error exists. It proves it
 * the only way that is not a claim about a string: by running that command as a
 * child process and comparing exit statuses. That costs minutes and one whole
 * worker, so it cannot live in the default suite it invokes — measured once at
 * 355s of a 368s run, starving the pool and timing out six unrelated files.
 *
 * Kept as a separate config rather than a bare path argument so CI, a local
 * run and a future third caller cannot drift about which file this is.
 */
export default defineConfig({
  ...base,
  test: {
    ...base.test,
    include: ["src/test/outcomeTypecheckGate.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
    // One file, one child process, no pool contention — and a budget that fits
    // two full `npm test` children rather than the 10s the ordinary suite uses.
    testTimeout: 600_000,
    hookTimeout: 600_000,
    fileParallelism: false
  }
});
