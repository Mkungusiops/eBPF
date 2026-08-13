#!/usr/bin/env bash
#
# scripts/isolation-test.sh — the Phase-1 exit gate: "two tenants' data provably
# isolated (leakage tests green)".
#
# Tenant isolation is not one check, it is four independent layers, and the gate
# is that EVERY layer denies on its own — because any single one of them is one
# refactor away from being bypassed:
#
#   Layer 1  identity   tenant_id comes from the agent's client cert, never from
#                       anything the agent can assert about itself
#   Layer 2  ingest     every record is stamped with that tenant_id
#   Layer 3  storage    Postgres RLS / ClickHouse partitioning scopes the rows,
#                       even if the app forgets a WHERE clause
#   Layer 4  authz      the read is an authorization decision, and a denial is a
#                       404 (a 403 would confirm the tenant exists)
#
#   ./scripts/isolation-test.sh                # the Go layer suites (needs a DB)
#   ./scripts/isolation-test.sh --ssh <alias>  # + live checks against a deployment
#
# Run it in CI. This is the test that stops the platform from becoming a breach.

LOG_TAG="isolation"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

SSH_TO=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh) SSH_TO="${2:?}"; shift 2 ;;
    -h|--help) sed -n '3,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done

FAILED=0

# ── The Go suites that own each layer ──────────────────────────────────────
printf '\n%s── layer suites (Go) ──%s\n\n' "$C_BOLD" "$C_RESET"

# internal/mtls        Layer 1 — tenant derived from the certificate Subject
# internal/ingest      Layer 2 — stamping
# internal/centralstore Layer 3 — RLS / partitioning, incl. the cross-tenant read test
# internal/authz       Layer 4 — the decision layer
# internal/isolationguard — the invariant itself
PKGS=(
  ./internal/mtls
  ./internal/ingest
  ./internal/centralstore
  ./internal/authz
  ./internal/isolationguard
)

# The Postgres/ClickHouse isolation tests SKIP silently without a DSN — which
# would turn this gate green while proving nothing. Refuse that.
if [[ -z "${EBPF_TEST_PG_DSN:-}" ]]; then
  if [[ -f "$REPO_ROOT/deploy/.env" ]]; then
    # shellcheck disable=SC1091
    source "$REPO_ROOT/deploy/.env"
    export EBPF_TEST_PG_DSN="postgres://soc:${POSTGRES_PASSWORD}@127.0.0.1:5432/ebpf_soc?sslmode=disable"
    export EBPF_TEST_CH_DSN="clickhouse://soc:${CLICKHOUSE_PASSWORD}@127.0.0.1:9000/ebpf_soc"
    dim "using the local devstack DSNs from deploy/.env"
  else
    err "EBPF_TEST_PG_DSN is not set, so the Layer-3 RLS tests would SKIP."
    err "A skipped isolation test is not a passing isolation test."
    dim "start a database first:  ./scripts/devstack.sh up"
    exit 1
  fi
fi

log "go test ${PKGS[*]}"
if (cd "$REPO_ROOT/engine" && go test -count=1 "${PKGS[@]}"); then
  ok "all four isolation layers pass their unit + integration suites"
else
  err "an isolation layer FAILED — do not ship this"
  FAILED=$((FAILED + 1))
fi

# ── Live checks against a real deployment ──────────────────────────────────
if [[ -n "$SSH_TO" ]]; then
  printf '\n%s── live deployment (%s) ──%s\n\n' "$C_BOLD" "$SSH_TO" "$C_RESET"
  SSH_ALIAS="$SSH_TO"; export SSH_ALIAS

  # RLS is only enforced for a NOSUPERUSER role. If the control plane ever
  # connects as the table owner or a superuser, the policy silently stops
  # applying and every read returns every tenant. Assert the role exists and is
  # not a superuser — this is the single most dangerous misconfiguration.
  printf '  %-46s' "app role exists and is NOSUPERUSER"
  role="$(rsudo "cd /etc/ebpf-soc/stack && docker compose exec -T postgres psql -U soc -d ebpf_soc -tAq -c \
    \"SELECT rolsuper FROM pg_roles WHERE rolname = 'ebpf_app';\"" 2>/dev/null | tr -d '[:space:]')"
  case "$role" in
    f) printf '%s✓%s\n' "$C_GRN" "$C_RESET" ;;
    t) printf '%s✗ ebpf_app IS A SUPERUSER — RLS is bypassed, tenants are NOT isolated%s\n' "$C_RED" "$C_RESET"; FAILED=$((FAILED + 1)) ;;
    *) printf '%s✗ role ebpf_app not found — has the control plane started?%s\n' "$C_RED" "$C_RESET"; FAILED=$((FAILED + 1)) ;;
  esac

  printf '  %-46s' "RLS is FORCED on telemetry"
  rls="$(rsudo "cd /etc/ebpf-soc/stack && docker compose exec -T postgres psql -U soc -d ebpf_soc -tAq -c \
    \"SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE relname = 'telemetry';\"" 2>/dev/null | tr -d '[:space:]')"
  if [[ "$rls" == "t" ]]; then
    printf '%s✓%s\n' "$C_GRN" "$C_RESET"
  else
    printf '%s✗ RLS not forced — the table owner bypasses the tenant policy%s\n' "$C_RED" "$C_RESET"
    FAILED=$((FAILED + 1))
  fi

  printf '  %-46s' "tenant_isolation policy present"
  pol="$(rsudo "cd /etc/ebpf-soc/stack && docker compose exec -T postgres psql -U soc -d ebpf_soc -tAq -c \
    \"SELECT count(*) FROM pg_policies WHERE tablename = 'telemetry' AND policyname = 'tenant_isolation';\"" 2>/dev/null | tr -d '[:space:]')"
  if [[ "$pol" == "1" ]]; then
    printf '%s✓%s\n' "$C_GRN" "$C_RESET"
  else
    printf '%s✗ the tenant_isolation policy is missing%s\n' "$C_RED" "$C_RESET"
    FAILED=$((FAILED + 1))
  fi
fi

printf '\n'
if (( FAILED > 0 )); then
  err "TENANT ISOLATION IS NOT PROVEN — $FAILED check(s) failed"
  exit 1
fi
ok "tenant isolation holds at every layer"
