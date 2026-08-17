#!/usr/bin/env bash
#
# scripts/ci/verify-deploy.sh — assert the estate is actually serving after a
# deploy, and that every host runs the SAME build.
#
# A deploy that reports success while half the fleet still runs the previous
# binary is the failure mode this catches. It has already happened here: an
# agent was left on a three-day-old build in a multi-agent tenant, which is
# exactly the configuration where containment-routing bugs surface.
#
# Reads the same environment the deploy workflow uses, so it can be run by hand:
#   CP_HOST=control-plane ENGINE_HOST=single_tenant_engine \
#   AGENT_HOSTS="adanian-internal=Tenant_A_agent acme-corp=Tenant_B_agent" \
#   ./scripts/ci/verify-deploy.sh
LOG_TAG="verify-deploy"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

FAIL=0
check() { # check <label> <condition-output> <expected>
  if [[ "$2" == "$3" ]]; then ok "$1"; else err "$1 — got '$2', want '$3'"; FAIL=$((FAIL + 1)); fi
}

remote() { ssh -o BatchMode=yes -o ConnectTimeout=10 "$1" "${@:2}"; }

# ── control plane ────────────────────────────────────────────────────────────
if [[ -n "${CP_HOST:-}" ]]; then
  step_header "control plane ($CP_HOST)"
  check "ebpf-soc-controlplane active" \
    "$(remote "$CP_HOST" 'systemctl is-active ebpf-soc-controlplane' || true)" "active"
  check "nginx active" "$(remote "$CP_HOST" 'systemctl is-active nginx' || true)" "active"
  check "keycloak active" "$(remote "$CP_HOST" 'systemctl is-active ebpf-keycloak' || true)" "active"
  # :80 answers 200 when plaintext, 301 when TLS is on. Both are healthy; a
  # connection failure is not.
  code80=$(remote "$CP_HOST" 'curl -s -o /dev/null -w "%{http_code}" --max-time 15 http://127.0.0.1/ || true')
  case "$code80" in
    200|301|302) ok "console :80 serving ($code80)" ;;
    *) err "console :80 — got '$code80'"; FAIL=$((FAIL + 1)) ;;
  esac

  # TLS REGRESSION GUARD. A deploy run with the wrong TARGET_HOST, or without
  # TLS=1, rewrites the nginx site to a plaintext block bound to the IP and
  # silently drops the :443 server — the console then refuses connections on its
  # real hostname while every service still reports healthy. That has happened.
  # If a certificate exists on the box, HTTPS must be served.
  domain=$(remote "$CP_HOST" 'sudo ls /etc/letsencrypt/live 2>/dev/null | grep -v README | head -1' || true)
  if [[ -n "$domain" ]]; then
    log "  certificate present for $domain — TLS is expected"
    listening443=$(remote "$CP_HOST" 'sudo ss -lnt 2>/dev/null | grep -c ":443 " || true')
    check "nginx listening on :443" "$([[ "${listening443:-0}" -gt 0 ]] && echo yes || echo no)" "yes"
    https=$(curl -s -o /dev/null -w "%{http_code}" --max-time 20 "https://$domain/" || true)
    case "$https" in
      200|302) ok "https://$domain/ serving ($https)" ;;
      *) err "https://$domain/ — got '$https'; the TLS server block is missing or the host is unreachable"
         FAIL=$((FAIL + 1)) ;;
    esac

    # The HTML shell MUST tell the browser to revalidate.
    #
    # With no Cache-Control, browsers apply heuristic freshness and reuse the
    # shell for days. After a deploy that shell names asset hashes which no
    # longer exist, the SPA catch-all answers those requests with index.html,
    # and the browser refuses to parse text/html as an ES module. The console
    # comes up BLANK — no error boundary, because React never ran. It is
    # invisible to every other check here, since the server is serving 200 and
    # the current build is perfectly fine.
    cc=$(curl -s -o /dev/null -D - --max-time 20 "https://$domain/" 2>/dev/null | tr -d '\r' | grep -i '^cache-control:' | head -1 || true)
    if [[ "$cc" == *no-cache* || "$cc" == *no-store* ]]; then
      ok "console HTML revalidates (${cc#*: })"
    else
      err "console HTML sends no revalidation directive (got '${cc:-none}'); a cached shell will point at deleted bundles and the console will load blank after the next deploy"
      FAIL=$((FAIL + 1))
    fi

    # A missing hashed asset must 404, not fall through to the SPA catch-all.
    # Answering index.html for a .js request is what turns a stale cache into
    # an unparseable module instead of a clean, visible failure.
    # Assert on the STATUS, not the content type: nginx serves its own 404 page
    # as HTML, which is correct and would make a content-type check fail on a
    # perfectly fixed deployment. What matters is that the browser is told the
    # module is absent rather than handed a 200 it will try to parse.
    miss=$(curl -s -o /dev/null -w "%{http_code}" --max-time 20 "https://$domain/assets/does-not-exist-$$.js" || true)
    if [[ "$miss" == "404" ]]; then
      ok "missing assets 404 instead of falling through to the SPA shell"
    else
      err "a missing /assets/*.js returned $miss, not 404; a stale shell will receive HTML where it expects a module and the console will load blank"
      FAIL=$((FAIL + 1))
    fi
  fi

  # No sim-agents. A sim beside a real agent acks containment it never applied.
  sims=$(remote "$CP_HOST" 'systemctl list-units --type=service --state=running 2>/dev/null | grep -ci "ebpf-sim" || true')
  check "no sim-agents running (DATA_MODE=none)" "${sims:-0}" "0"
fi

# ── single-tenant engine ─────────────────────────────────────────────────────
if [[ -n "${ENGINE_HOST:-}" ]]; then
  step_header "engine ($ENGINE_HOST)"
  check "ebpf-engine active" "$(remote "$ENGINE_HOST" 'systemctl is-active ebpf-engine' || true)" "active"
  # 302 = redirect to login, i.e. serving and gated. 200 would mean UNGATED.
  check "engine redirects to login" \
    "$(remote "$ENGINE_HOST" 'curl -s -o /dev/null -w "%{http_code}" --max-time 15 http://127.0.0.1:8090/ || true')" "302"
fi

# ── agents: all present, and all on the SAME build ───────────────────────────
if [[ -n "${AGENT_HOSTS:-}" ]]; then
  step_header "agents"
  declare -a SUMS=()
  for pair in $AGENT_HOSTS; do
    host="${pair#*=}"; tenant="${pair%%=*}"
    check "$host ebpf-agent active" "$(remote "$host" 'systemctl is-active ebpf-agent' || true)" "active"
    sum=$(remote "$host" 'sudo sha256sum /opt/ebpf-soc/agent 2>/dev/null | cut -d" " -f1' || true)
    SUMS+=("$sum")
    log "  $host (tenant $tenant) agent sha256 ${sum:0:16}"
  done
  uniq_count=$(printf '%s\n' "${SUMS[@]}" | sort -u | grep -c . || true)
  check "every agent runs the same build" "$uniq_count" "1"
fi

printf '\n'
if (( FAIL > 0 )); then
  err "$FAIL post-deploy check(s) failed"
  exit 1
fi
ok "estate verified"
