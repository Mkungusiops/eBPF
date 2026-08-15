// ESLint for the console.
//
// This did not exist before: `npm run lint` ran scripts/lint.mjs, a bespoke
// checker for four architectural invariants (no CDN refs, no Next.js strings,
// one EventSource, declared dependencies). That script is good and still runs —
// it catches things ESLint cannot. But because ESLint itself was never
// installed, no hooks rule, exhaustive-deps rule or a11y rule had ever
// executed, every `// eslint-disable-next-line` in the tree was inert, and a
// document-level keydown listener bound to the fleet kill-switch shipped with
// no dependency array, re-registering on every render.
//
// Rule severity is chosen so this lands green on the existing tree and then
// ratchets: the two rules that catch real defects are errors, the stylistic
// ones start as warnings.

import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import jsxA11y from "eslint-plugin-jsx-a11y";

export default tseslint.config(
  {
    ignores: [
      "dist/**",
      "node_modules/**",
      "playwright-report/**",
      "test-results/**",
      "coverage/**",
      "scripts/**",
      // Shipped as-is to the browser rather than bundled, so it is not part of
      // the typed source tree.
      "public/**",
      "*.config.js",
      "*.config.cjs",
      "*.config.ts",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: { ...globals.browser, ...globals.es2021 },
    },
    plugins: {
      "react-hooks": reactHooks,
      "jsx-a11y": jsxA11y,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,

      // The two that matter here. rules-of-hooks is non-negotiable — a
      // conditional hook corrupts React's state ordering. exhaustive-deps is an
      // error because a missing dependency array is what shipped the
      // re-registering kill-switch listener.
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "error",

      // The console is operated under time pressure, sometimes by keyboard
      // only. Warnings for now; the SOC shell has 16 always-mounted dialogs to
      // work through before these can be errors.
      "jsx-a11y/alt-text": "warn",
      "jsx-a11y/anchor-is-valid": "warn",
      "jsx-a11y/aria-props": "error",
      "jsx-a11y/aria-role": "error",
      "jsx-a11y/role-has-required-aria-props": "error",

      // TypeScript is strict and the tree has zero `any` — keep it that way.
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/no-non-null-assertion": "warn",
    },
  },
  {
    // Tests may reach past the type system to build fixtures.
    files: ["**/*.test.{ts,tsx}", "e2e/**/*.ts", "src/test/**/*.{ts,tsx}"],
    languageOptions: { globals: { ...globals.node } },
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-non-null-assertion": "off",
    },
  },
  {
    // Playwright's fixture API is `async ({ page }, use) => {}` — an empty
    // destructure is how a fixture declares it needs nothing, and `use` is
    // Playwright's callback, not a React hook.
    files: ["e2e/**/*.ts"],
    rules: {
      "no-empty-pattern": "off",
      "react-hooks/rules-of-hooks": "off",
    },
  },
);
