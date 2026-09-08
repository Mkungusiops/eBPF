import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    clearMocks: true,
    environment: "jsdom",
    environmentOptions: {
      jsdom: {
        url: "http://127.0.0.1/"
      }
    },
    globals: true,
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    // outcomeTypecheckGate proves that `npm test` fails on a type error — by
    // SPAWNING `npm test` as a child. Inside the default run that is both
    // recursive-shaped and ruinous: measured at 355s of a 368s run, it starved
    // the worker pool and timed out six unrelated files, so the test written to
    // keep the gate honest was the thing breaking it. It runs as its own gate
    // (`npm run test:gate`, which CI invokes) where it has the machine to
    // itself and nothing else is waiting on the pool.
    exclude: ["**/node_modules/**", "**/dist/**", "src/test/outcomeTypecheckGate.test.ts"],
    setupFiles: ["src/test-setup.ts"],
    testTimeout: 10_000,
    // Frontend coverage was previously unmeasurable: @vitest/coverage-v8 was
    // not installed, so `vitest run --coverage` failed outright and 152 green
    // tests carried no indication that 35 of 54 source files were untouched.
    coverage: {
      provider: "v8",
      reporter: ["text-summary", "lcov"],
      include: ["src/**/*.{ts,tsx}"],
      exclude: [
        "src/**/*.test.{ts,tsx}",
        "src/test/**",
        "src/entries/**",
        "src/**/*.d.ts"
      ]
    }
  }
});
