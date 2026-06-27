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
    include: ["src/**/*.test.ts"],
    testTimeout: 10_000
  }
});
