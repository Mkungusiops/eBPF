# Contributing

New here? Start with
[docs/getting-started/developer-onboarding.md](docs/getting-started/developer-onboarding.md)
— it covers what the project is, the repo layout, prerequisites, and how to build
and run it locally.

## Local gates (must pass before a PR)

```bash
# backend
cd engine && make test && make vet && make build-linux

# frontend
cd web && npm run lint && npm run typecheck && npm run test && npm run build
```

CI runs the same. **Do not** weaken or skip the tenant-isolation
(cross-tenant read-denial) tests — that invariant is the product's core promise.

## Conventions

- **Branches**: feature branches off `main` (e.g. `feat/…`, `fix/…`). Don't commit
  to `main` directly.
- **Commits**: imperative subject, explain the *why* in the body. Keep changes
  focused; match the style/idioms of the surrounding code.
- **Protobuf**: edit `engine/proto/**/*.proto`, then `make proto` to regenerate —
  never hand-edit generated `gen/` files. Wire changes must keep the agent↔CP
  contract compatible (see [docs/plan/wire-contract.md](docs/plan/wire-contract.md)).
- **Frontend**: the console is a Vite multi-entry React app embedded into the Go
  binary via `go:embed` (no Node runtime in production). Keep `web/scripts/lint.mjs`
  green — it forbids runtime CDN references and stale framework imports.
- **Secrets**: never commit credentials. `docs/credentials/` is gitignored;
  production secrets live in the operator's password manager only.

## Security & isolation

Any change to the control plane, ingest, store, or authz must preserve the
**four-layer tenant isolation invariant**
([docs/plan/tenant-isolation-invariant.md](docs/plan/tenant-isolation-invariant.md)):
mTLS identity → ingest stamp → RLS store → RBAC. When in doubt, fail closed.

## Docs

Keep docs current with the code. Deployment/runbook changes belong in
[docs/deployment/](docs/deployment/); design decisions in
[docs/plan/](docs/plan/). Avoid point-in-time "status/completion report" docs —
prefer living reference docs.
