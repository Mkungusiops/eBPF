# Phase 0 Charter — Foundations & Don't-Break-the-Demo

> **What this is:** the execution contract for **Phase 0** of the enterprise conversion. It
> was drafted as a kickoff prompt and is preserved here verbatim-in-intent as a charter so the
> scope, invariants, and definition of done are reviewable and diff-able — not chat-only.
>
> **Read alongside:** [`plan.md`](plan.md) (strategy), [`architecture.md`](architecture.md)
> (target split + §5 isolation), [`roadmap.md`](roadmap.md) (phase board). This charter is the
> **code-and-docs slice** of roadmap.md's Phase 0 section — it deliberately excludes the
> live-box ops (systemd supervision on the running Azure host) and the Terraform/IaC baseline,
> which stay in roadmap Phase 0 but are **out of scope for this execution pass**.
>
> **Status:** not started. The next prompt after this closes is Phase 1's first artifact —
> the agent↔control-plane wire contract.

---

## 1. Objective

Lay the engineering groundwork for the eventual **agent / control-plane split** described in
[`architecture.md`](architecture.md) — **without changing any runtime behaviour** and **without
breaking the live path**. This is a strangler-pattern foundation: new entrypoints compile over
today's `internal/` packages, but no package moves and today's engine binary stays behaviourally
identical.

---

## 2. Definition of Done

Phase 0 is complete when **all** of the following hold:

- [ ] All **three** binaries build from the shared `internal/` packages: `cmd/engine` (unchanged),
      `cmd/agent`, `cmd/controlplane`.
- [ ] `make build`, `make build-linux`, and `make deploy` still work; `cmd/engine` behaviour is
      **unchanged**.
- [ ] Tests pass: `go test ./...`, `go vet ./...`, and the web suite
      (`npm ci && npm run lint && npm run typecheck && npm test`).
- [ ] **CI is green** on every PR and produces **signed** artifacts + a **container image** +
      **SBOM**.
- [ ] **No plaintext credential default remains** on the flag/config surface — a missing password
      fails fast with a clear error.
- [ ] Both new planning docs exist and are reviewed:
      [`tenant-isolation-invariant.md`](tenant-isolation-invariant.md) and
      [`threat-model.md`](threat-model.md).

---

## 3. Hard invariants (do not violate)

These constrain every change in Phase 0 **and** everything downstream:

- **Agent autonomy is the moat.** Never make in-kernel enforcement depend on a network service.
  The agent must enforce while disconnected.
- **The hash-chained audit is sacred.** Leave `internal/store/decisions.go` untouched.
- **The agent is a single static binary.** Keep it `CGO_ENABLED=0`; confine any new heaviness
  (extra deps, a DB driver, an HTTP server) to `cmd/controlplane`.
- **Do not touch the crypto** in `internal/api/auth.go`.
- **Do not move `internal/` packages** in this phase (strangler pattern — new entrypoints only).
- **Do not touch the live Azure box.**
- **Match the codebase's existing comment style** — it is heavy and intentional. Read neighbouring
  files before writing.

---

## 4. Deliverables (in order)

1. **Build-target split scaffolding.** Introduce `engine/cmd/agent/` and `engine/cmd/controlplane/`
   as thin new entrypoints compiling over the existing `internal/` packages. `cmd/agent` wires the
   same sensing + enforcing path as `cmd/engine` does today; `cmd/controlplane` is a minimal HTTP
   stub reusing `internal/api` + a store. Add `make build-agent` and `make build-controlplane`.
   Keep `cmd/engine` building and unchanged.

2. **CI.** On every PR: run `go test ./...`, `go vet ./...`, the web suite
   (`npm ci && npm run lint && npm run typecheck && npm test`), build all three binaries, and
   produce a **signed container image + SBOM**.

3. **Remove plaintext credential defaults.** Strip the `-pass "ebpf-soc-demo"` default from
   `cmd/engine/main.go` and the corresponding default in `internal/config/config.go` so a missing
   password **fails fast** with a clear error instead of shipping a known default. Update
   `deploy/engine.yaml.example` and docs to match. **Do not touch** the crypto in
   `internal/api/auth.go`.

4. **`tenant-isolation-invariant.md`.** Specify exactly what *"one tenant can never read another's
   data"* means across the **four enforcement layers** in `architecture.md` §5 —
   **mTLS identity → ingest stamp → storage filter → API scope** — plus the test strategy that
   proves it.

5. **`threat-model.md`.** Cover the control plane, the agent↔cloud channel, enforcement blast
   radius (reference the **sudo-lockout trap** in
   [`docs/deployment/live-soc-adanianlabs.md`](../deployment/live-soc-adanianlabs.md) §3), and
   supply-chain / bundle signing.

---

## 5. Explicitly out of scope (this is Phase 1)

Do **not** build in Phase 0:

- The real wire protocol, mTLS enrollment, ingest collector, message bus, ClickHouse.
- Identity / RBAC / SSO, the multi-tenant console.
- Any move of `internal/` packages.
- Any change to the live Azure box.

---

## 6. Working discipline

- Small, reviewable commits. **Do not commit or push unless asked.** If branching, branch from
  `feat/enterprise-gradeI`.
- Run the test suites **after each change** and report results **honestly** — failures reported as
  failures, skips reported as skips.
- Finish with a **green/red build summary** across all three binaries + the web suite.
