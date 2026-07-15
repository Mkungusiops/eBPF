// Package isolationguard holds the CI-enforced guards for the tenant isolation
// invariant (docs/plan/tenant-isolation-invariant.md §8):
//
//   - a BYPASS-LINT that fails if any package outside internal/centralstore runs
//     a raw query against the tenant-partitioned telemetry table (Layer 3: all
//     storage access must go through the single tenant-scoped data-access layer);
//   - a cross-tenant RPC COVERAGE RATCHET that fails when a new wire RPC is added
//     without a declared isolation posture (Layer 1-2: forces every new endpoint
//     to consciously classify its tenant handling);
//   - a SIDE-CHANNEL check that a denial carries no tenant-existence information.
//
// These are tests, not runtime code; this file keeps the package buildable.
package isolationguard
