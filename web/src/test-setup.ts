/**
 * Vitest setup, loaded before every test file.
 *
 * `@testing-library/jest-dom` was already a dependency but was never wired in,
 * so its matchers (toBeInTheDocument, toBeEnabled, toHaveTextContent) were
 * unavailable and any test reaching for one failed with "Invalid Chai
 * property" — which reads as a broken test rather than missing setup. Wiring it
 * here is a prerequisite for the component-test work in
 * docs/plan/ai-and-console-reuse.md §2B.
 */
import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Unmount between tests. Without this, components from a previous test stay in
// the document and getByRole starts matching the wrong one — a failure mode
// that shows up as an unrelated test breaking when a new one is added.
afterEach(cleanup);
