// Package e2e holds cross-package, in-process end-to-end tests of the agent ↔
// control-plane wire contract over real gRPC + mTLS: enrollment, tenant-stamped
// telemetry ingest with resume/dedup and cross-tenant isolation, signed
// commands with local guardrails, and heartbeat. It is test-only; this file
// keeps the package buildable by `go build ./...`.
package e2e
