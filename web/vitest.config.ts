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
