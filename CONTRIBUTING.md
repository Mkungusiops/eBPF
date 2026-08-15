# Contributing

New here? Start with
[docs/getting-started/developer-onboarding.md](docs/getting-started/developer-onboarding.md)
— it covers what the project is, the repo layout, prerequisites, and how to build
and run it locally.

## Local gates (must pass before a PR)

```bash
# backend — run from the REPO ROOT (there is no engine/Makefile)
make vet && make test && make build-linux

# backend, with the gates CI applies
cd engine && go test -race ./... && golangci-lint run ./...

# REQUIRED on macOS: ~10 files are behind `//go:build linux`, and neither the
# compiler nor golangci-lint looks at them when you build on darwin. A change
# can pass every gate above and still fail to compile for the target that ships.
cd engine && CGO_ENABLED=0 GOOS=linux go build ./...

# frontend
cd web && npm run lint && npm run typecheck && npm run test && npm run build
```

`npm run lint` runs ESLint *and* the architectural checker in
`web/scripts/lint.mjs`; both must pass. `make vet` and `make test` are
repo-root targets — `cd engine && make test` fails with "No rule to make target",
which is what this file used to instruct.

CI runs the same, plus `-race`, a coverage ratchet, and `scripts/scan.sh --ci`
(govulncheck, staticcheck, npm audit, gitleaks, trivy). **Do not** weaken or
skip the tenant-isolation (cross-tenant read-denial) tests — that invariant is
the product's core promise.

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
