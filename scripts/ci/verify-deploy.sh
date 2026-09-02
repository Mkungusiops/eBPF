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

    # No synthetic activity generator. This is the agent-side half of
    # DATA_MODE=none and it is the one that was missing.
    #
    # `ebpf-activity.service` runs a scripted attack loop — the attack
    # catalogue, /etc/shadow reads and connections to hardcoded "threat actor"
    # IPs, every 20-45s, forever. It was installed unconditionally, so an
    # estate deployed with DATA_MODE=none still fabricated ~2,000 alerts/hour
    # and the console's executive posture dial sat at 93-97 "critical" around
    # the clock on hosts where nothing was happening.
    #
    # The check above it — "no sim-agents running (DATA_MODE=none)" — passed
    # throughout, which is precisely why this one is needed: the estate's
    # no-fake-data assertion did not cover the estate's largest fake-data
    # source.
    # `systemctl is-active` PRINTS its answer and also EXITS non-zero for any
    # non-active state, so `cmd || echo absent` fires on top of "inactive" and
    # the check reported the two-line value "inactive\nabsent". Take the first
    # line, and only fall back when nothing was printed at all.
    act=$(remote "$host" 'systemctl is-active ebpf-activity 2>/dev/null | head -1' || true)
    act="${act:-absent}"
    if [[ "$act" == "active" ]]; then
      err "$host runs ebpf-activity — a synthetic attack loop. Every alert count and the executive posture dial on this estate are fabricated. Redeploy the agent with DATA_MODE=none."
      FAIL=$((FAIL + 1))
    else
      ok "$host has no synthetic activity generator (ebpf-activity: $act)"
    fi

    sum=$(remote "$host" 'sudo sha256sum /opt/ebpf-soc/agent 2>/dev/null | cut -d" " -f1' || true)
    SUMS+=("$sum")
    log "  $host (tenant $tenant) agent sha256 ${sum:0:16}"
  done
  uniq_count=$(printf '%s\n' "${SUMS[@]}" | sort -u | grep -c . || true)
  check "every agent runs the same build" "$uniq_count" "1"
fi

# ── loaded policies that never fire ─────────────────────────────────────────
#
# `tetra tracingpolicy list` reports NPOST per policy: how many events its
# probe has posted since it was loaded. The deploy already verifies a policy is
# LOADED, which is a different claim — outbound-connections sat "enabled" with
# NPOST 0 while sensitive-file-access had 654, and nothing anywhere surfaced
# that. It took a manual test connection to establish the probe worked at all.
#
# Reported, NOT failed, and that distinction is the whole design:
#
#   - Policies reload on every deploy, so a zero counter minutes later is
#     normal and failing on it would cry wolf on every run.
#   - A genuinely quiet host has every policy at zero, which is also fine.
#
# So the signal is RELATIVE: a policy at zero while its siblings are posting is
# the one worth looking at. That comparison is the only one this can make
# honestly from a single reading, and it is the one an operator cannot make at
# all today.
step_header "policy activity"
for pair in ${AGENT_HOSTS:-}; do
  host="${pair#*=}"
  raw=$(remote "$host" 'sudo docker exec tetragon tetra tracingpolicy list 2>/dev/null | awk "NR>1 && \$2 != \"\" {print \$2\" \"\$(NF-2)}"' || true)
  [[ -n "$raw" ]] || { log "  $host: policy counters unavailable (tetra not reachable)"; continue; }
  total=0; quiet=""
  while read -r name npost; do
    [[ -n "$name" ]] || continue
    npost="${npost//[^0-9]/}"; npost="${npost:-0}"
    total=$((total + npost))
    [[ "$npost" == "0" ]] && quiet="$quiet $name"
  done <<< "$raw"
  if [[ -n "$quiet" && "$total" -gt 0 ]]; then
    log "  $host: posting $total event(s); SILENT probes:$quiet"
    log "     a probe at zero while its siblings post is either a policy that"
    log "     matches nothing here, or one hooked to a symbol this kernel lacks."
  elif [[ "$total" -gt 0 ]]; then
    ok "$host: every loaded policy is posting ($total events)"
  else
    ok "$host: no policy has posted yet (quiet host, or freshly reloaded)"
  fi
done

# ── nothing overrides the unit this deploy just wrote ────────────────────────
#
# A systemd drop-in that sets ExecStart= WINS over the unit file, silently and
# permanently. Two of these existed on this estate — hand-written on 2026-08-16
# to wire the assistant, never removed once the deploy learned to write those
# flags itself. From then on the deploy wrote a correct unit on every run and
# systemd ran an eight-day-old command line instead.
#
# It is invisible from every angle an operator would normally look: the unit
# file is right, `systemctl cat` shows the deploy's ExecStart first, the
# service is active, and the feature is simply absent with no error anywhere.
# The only honest source is /proc/<pid>/cmdline, which is what this reads.
#
# Checked here rather than fixed here: a deploy that silently deletes operator
# configuration is its own hazard. This says exactly what to look at.
step_header "unit overrides"
for spec in "${CP_HOST:+$CP_HOST=ebpf-soc-controlplane}" "${ENGINE_HOST:+$ENGINE_HOST=ebpf-engine}"; do
  [[ -n "$spec" ]] || continue
  h="${spec%%=*}"; unit="${spec#*=}"
  overrides=$(remote "$h" "ls /etc/systemd/system/$unit.service.d/*.conf 2>/dev/null | wc -l" || echo 0)
  overrides="${overrides//[^0-9]/}"
  if [[ "${overrides:-0}" -gt 0 ]]; then
    shadowed=$(remote "$h" "grep -l '^ExecStart=' /etc/systemd/system/$unit.service.d/*.conf 2>/dev/null | tr '\n' ' '" || true)
    if [[ -n "$shadowed" ]]; then
      err "$h: $unit has a drop-in that overrides ExecStart ($shadowed). systemd is running THAT command line, not the one this deploy wrote. Compare: sudo tr '\\0' '\\n' < /proc/\$(systemctl show $unit -p MainPID --value)/cmdline"
      FAIL=$((FAIL + 1))
    else
      ok "$h: $unit drop-ins present but none override ExecStart"
    fi
  else
    ok "$h: no systemd drop-in shadowing $unit"
  fi
done

printf '\n'
if (( FAIL > 0 )); then
  err "$FAIL post-deploy check(s) failed"
  exit 1
fi
ok "estate verified"
