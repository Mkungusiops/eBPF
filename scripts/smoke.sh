#!/usr/bin/env bash
#
# scripts/smoke.sh — is the deployed platform actually correct, not just up?
#
# "Up" is a process listening on a port. "Correct" means the control plane
# answers, the store round-trips, an enrollment token can be minted, and — the
# one that matters — a caller cannot read a tenant it has no grant for. A green
# /healthz with broken tenant isolation is the worst possible outcome, so that
# check is here rather than only in the Go test suite.
#
#   ./scripts/smoke.sh --ssh <alias> --tenant acme
#   ./scripts/smoke.sh --url http://127.0.0.1:9090 --tenant acme   # local/tunnel
#
# Env: CP_ADMIN_TOKEN (required).
# Exit: 0 all checks passed, 1 one or more failed.

LOG_TAG="smoke"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

SSH_TO=""; TENANT="acme"; URL=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh)    SSH_TO="${2:?}"; shift 2 ;;
    --tenant) TENANT="${2:?}"; shift 2 ;;
    --url)    URL="${2:?}"; shift 2 ;;
    -h|--help) sed -n '3,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done

CP_URL="${URL:-${CP_URL:-http://127.0.0.1:9090}}"
[[ -n "${CP_ADMIN_TOKEN:-}" ]] || die "CP_ADMIN_TOKEN is not set (see .deploy/<name>/secrets.env)"
if [[ -n "$SSH_TO" ]]; then SSH_ALIAS="$SSH_TO"; export SSH_ALIAS; fi

# There is nothing to smoke-test in a dry run: no deployment was made. Saying
# "checks passed" here would be a lie in exactly the place a lie is worst.
if [[ "${DRY_RUN:-0}" == "1" ]]; then
  dim "dry-run: skipping the smoke test (nothing was deployed to check)"
  exit 0
fi

PASSED=0; FAILED=0
check()  { printf '  %-46s' "$1"; }
passed() { printf '%s✓%s %s\n' "$C_GRN" "$C_RESET" "${1:-}"; PASSED=$((PASSED + 1)); }
failed() { printf '%s✗ %s%s\n' "$C_RED" "${1:-}" "$C_RESET"; FAILED=$((FAILED + 1)); }

# http <method> <path> [body] → "<body>\n<status>", executed on the server when
# --ssh is set (the operator API is loopback-only there, by design).
http() {
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "$SSH_TO" ]]; then
    local remote="curl -sS -m 10 -X $method -H 'Content-Type: application/json'"
    remote+=" -H \"Authorization: Bearer \$CP_ADMIN_TOKEN\""
    if [[ -n "$body" ]]; then remote+=" -d $(printf '%q' "$body")"; fi
    remote+=" -w '\\n%{http_code}' '$CP_URL$path'"
    ssh "${SSH_BASE_OPTS[@]}" "$SSH_TO" \
      "CP_ADMIN_TOKEN=$(printf '%q' "$CP_ADMIN_TOKEN") sh -c $(printf '%q' "$remote")" 2>/dev/null || true
  else
    local args=(-sS -m 10 -X "$method" -H 'Content-Type: application/json'
                -H "Authorization: Bearer $CP_ADMIN_TOKEN" -w '\n%{http_code}')
    if [[ -n "$body" ]]; then args+=(-d "$body"); fi
    curl "${args[@]}" "$CP_URL$path" 2>/dev/null || true
  fi
}
status_of() { printf '%s' "$1" | tail -n1 | tr -d '[:space:]'; }
body_of()   { printf '%s' "$1" | sed '$d'; }

printf '\n%s── smoke: %s ──%s\n\n' "$C_BOLD" "${SSH_TO:-$CP_URL}" "$C_RESET"

# 1. The service is alive.
check "control plane /healthz"
r="$(http GET /healthz)"
if [[ "$(status_of "$r")" == "200" ]]; then passed; else failed "HTTP $(status_of "$r")"; fi

check "control plane /readyz"
r="$(http GET /readyz)"
if [[ "$(status_of "$r")" == "200" ]]; then passed; else failed "HTTP $(status_of "$r")"; fi

# 2. The admin token maps to a principal with cross-tenant scope.
check "admin token authenticates (/api/whoami)"
r="$(http GET /api/whoami)"
if [[ "$(status_of "$r")" == "200" ]]; then
  passed "$(body_of "$r" | tr -d '\n' | cut -c1-60)"
else
  failed "HTTP $(status_of "$r") — the admin bearer is not accepted"
fi

# 3. An unauthenticated caller is refused. If this passes, the whole API is open.
check "unauthenticated request is rejected"
if [[ -n "$SSH_TO" ]]; then
  r="$(ssh "${SSH_BASE_OPTS[@]}" "$SSH_TO" "curl -sS -m 10 -o /dev/null -w '%{http_code}' '$CP_URL/api/whoami'" 2>/dev/null || true)"
else
  r="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' "$CP_URL/api/whoami" 2>/dev/null || true)"
fi
if [[ "$r" == "401" ]]; then passed "401"; else failed "expected 401, got ${r:-no response}"; fi

# 4. Enrollment works — without this no agent can ever join.
check "enrollment token mints for '$TENANT'"
r="$(http POST /api/admin/enroll-token "{\"tenant\":\"$TENANT\"}")"
if [[ "$(status_of "$r")" == "200" ]] && printf '%s' "$(body_of "$r")" | grep -q '"token"'; then
  passed
else
  failed "HTTP $(status_of "$r"): $(body_of "$r" | head -c 80)"
fi

check "the minted token carries the CA bundle agents pin"
if printf '%s' "$(body_of "$r")" | grep -q 'BEGIN CERTIFICATE'; then
  passed
else
  failed "no ca_bundle_pem in the response — agents would have nothing to pin"
fi

# 5. The store answers a tenant-scoped read.
check "tenant-scoped telemetry read"
r="$(http GET "/api/telemetry?tenant=$TENANT&limit=1")"
if [[ "$(status_of "$r")" == "200" ]]; then
  passed "$(body_of "$r" | grep -o '"count":[0-9]*' || printf 'count:0')"
else
  failed "HTTP $(status_of "$r") — the central store is not readable"
fi

# 6. THE isolation check. A tenant nobody granted must be unreadable — and the
# denial must be a 404, not a 403: a 403 would confirm the tenant exists, which
# is itself a cross-tenant leak (threat model §6, side channels).
check "cross-tenant read is denied"
ghost="smoke-not-a-real-tenant-$RANDOM"
if [[ -n "$SSH_TO" ]]; then
  r="$(ssh "${SSH_BASE_OPTS[@]}" "$SSH_TO" \
       "curl -sS -m 10 -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer bogus-token' '$CP_URL/api/telemetry?tenant=$ghost'" 2>/dev/null || true)"
else
  r="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer bogus-token' \
       "$CP_URL/api/telemetry?tenant=$ghost" 2>/dev/null || true)"
fi
case "$r" in
  401) passed "401 (bad credential rejected before any lookup)" ;;
  404) passed "404 (denied without confirming existence)" ;;
  403) failed "403 — a denial must not confirm the tenant exists; expected 404" ;;
  200) failed "200 — AN UNAUTHENTICATED CALLER READ TENANT DATA. Stop and fix this." ;;
  *)   failed "unexpected HTTP ${r:-none}" ;;
esac

# 7. The data tier the control plane depends on.
if [[ -n "$SSH_TO" ]]; then
  check "postgres accepting connections"
  if rsudo_quiet "cd /etc/ebpf-soc/stack && docker compose exec -T postgres pg_isready -U soc -d ebpf_soc"; then
    passed
  else
    failed "pg_isready says no"
  fi

  check "control-plane unit is enabled (survives reboot)"
  if rssh_quiet "systemctl is-enabled --quiet ebpf-soc-controlplane"; then
    passed
  else
    failed "not enabled — the platform will not come back after a reboot"
  fi

  check "trust material persisted (CA survives restart)"
  if rsudo_quiet "test -s /var/lib/ebpf-soc-controlplane/ca.key"; then
    passed
  else
    failed "no persisted CA key — a restart would issue a NEW CA and orphan every agent"
  fi
fi

printf '\n'
if (( FAILED > 0 )); then
  err "$FAILED failed, $PASSED passed"
  exit 1
fi
ok "$PASSED checks passed"
exit 0
