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

# ── the assistant is actually on the RUNNING command line ────────────────────
#
# 2026-09-02: a deploy shipped both servers with the analyst assistant off.
# Every unit was active, every health check answered, and this script reported
# the estate verified — because nothing here had ever looked at the capability
# itself. It was gone for 45 minutes, until a browser probe noticed.
#
# The check above ("unit overrides") is the near miss: it knows an ExecStart
# drop-in can shadow the deploy's unit, and it says so, but it only asks whether
# a shadowing file EXISTS. Every other way of losing the flags — a deploy run
# without ASSISTANT_URL, a recovery that guessed wrong, a unit rewritten by hand
# — leaves no drop-in behind and passes it untouched.
#
# WHERE THE ANSWER COMES FROM. Not `systemctl cat`: this script's own comment
# above spells out why that text is not evidence of what is running, and taking
# an ExecStart= line out of it gets the answer wrong in both directions. The
# flags are read from /proc/<MainPID>/cmdline — the command line the service is
# executing right now, drop-ins and all — with `systemctl show -p ExecStart`
# (systemd's merged unit+drop-in view, not the raw file) as the fallback for a
# unit that is loaded with nothing running. Which of the two answered is
# reported, because "what it runs now" and "what it would run next start" are
# different claims and only the first one was asked for.
#
# A box that answers NEITHER is a failure here, not a shrug. "Could not tell"
# read as "fine" is precisely how the outage passed.
#
# _assistant_running_script — the probe that runs ON the target, on its stdin.
# In a function of its own because bash 3.2 (macOS, where this is often run by
# hand) mis-parses an apostrophe in a here-document nested inside a command
# substitution; piping a function's output keeps the substitution clean.
_assistant_running_script() {
  cat <<'REMOTE'
unit="$1"
state=unreadable; src=none; args=; reason=

pid="$(systemctl show "$unit" -p MainPID --value 2>/dev/null)"
pid="${pid#MainPID=}"   # systemd before v230 has no --value; keep the number
case "$pid" in ''|*[!0-9]*) pid=0 ;; esac
if [ "$pid" -gt 0 ]; then
  # NUL-separated, one argument per line: an exact split, where the unit
  # fallback below can only split on spaces.
  if raw="$(tr '\000' '\n' <"/proc/$pid/cmdline" 2>/dev/null)" && [ -n "$raw" ]; then
    args="$raw"; src=process
  elif raw="$(sudo -n cat "/proc/$pid/cmdline" 2>/dev/null | tr '\000' '\n')" && [ -n "$raw" ]; then
    args="$raw"; src=process
  else
    reason="/proc/$pid/cmdline could not be read"
  fi
else
  reason="the unit is loaded but nothing is running (MainPID 0)"
fi
if [ -z "$args" ]; then
  raw="$(systemctl show "$unit" -p ExecStart --value 2>/dev/null |
         sed -n 's/.*argv\[\]=//p' | sed 's/ ; .*//' | head -n1)"
  if [ -n "$raw" ]; then args="$(printf '%s\n' "$raw" | tr ' ' '\n')"; src=unit; fi
fi
# An empty argument list finds no flags, and "no flags" would be reported as
# "no assistant here" — the exact silent omission this check exists to stop. So
# it stays unreadable instead.
if [ -n "$args" ]; then
  state=read
else
  reason="${reason:+$reason; }no command line came back from the process or from systemctl show"
fi

# One flag's value = the argument that follows the flag. An argument list with
# no -assistant-url on it is a real answer: "running, deliberately without one".
flag() { printf '%s\n' "$args" | grep -A1 -x -e "$1" | sed -n 2p; }

# The record is pipe-delimited and the reason is a systemd message or a path
# this script does not control the shape of, so it carries neither.
reason="$(printf '%s' "$reason" | tr '|\n\r\t' '    ' | cut -c1-120)"

# Printed last and unconditionally: reaching this line is the proof that the
# reads above actually happened on the target.
printf 'EBPF-ASSISTANT-RUNNING|%s|%s|%s|%s|%s|%s\n' "$state" "$src" \
  "$(flag -assistant-url)" "$(flag -assistant-model)" "$(flag -assistant-deep-model)" \
  "$reason"
REMOTE
}

step_header "analyst assistant (running command line)"

# The expectation comes from the SAME environment the deploy ran with, which is
# what the header of this file says to pass. Three cases, and the third is a
# real deployment shape, not an oversight:
#   ASSISTANT_URL set   → the estate is meant to be running that assistant
#   ASSISTANT_OFF=1     → it is meant to be running none
#   neither             → nobody stated one; report what is there and fail only
#                         on what can be judged without an expectation
ASST_WANT=none
[[ -n "${ASSISTANT_URL:-}" ]] && ASST_WANT=on
if [[ "${ASSISTANT_OFF:-0}" == "1" ]]; then
  if [[ "$ASST_WANT" == on ]]; then
    err "ASSISTANT_OFF=1 and ASSISTANT_URL are both set — say one thing or the other; nothing here can be checked against a contradiction"
    FAIL=$((FAIL + 1))
  fi
  ASST_WANT=off
fi

# Newline-joined strings, not arrays: this runs under `set -u` on bash 3.2,
# where expanding an EMPTY array is an unbound variable and aborts the script.
ASST_SEEN=""
for spec in "${CP_HOST:+$CP_HOST=ebpf-soc-controlplane}" "${ENGINE_HOST:+$ENGINE_HOST=ebpf-engine}"; do
  [[ -n "$spec" ]] || continue
  h="${spec%%=*}"; unit="${spec#*=}"
  script="$(_assistant_running_script)"
  # Match the marker rather than the whole reply: a login banner ahead of it is
  # noise, not a failed probe. No marker at all = the box never answered, which
  # is reported as unreadable rather than as "no assistant".
  line=$(remote "$h" bash -s -- "$unit" <<<"$script" 2>/dev/null | grep -m1 '^EBPF-ASSISTANT-RUNNING|' || true)
  if [[ -z "$line" ]]; then
    line="EBPF-ASSISTANT-RUNNING|unreadable|none||||the probe returned nothing (ssh failed, or no login shell)"
  fi
  IFS='|' read -r _marker astate asrc aurl amodel adeep areason <<<"$line"

  if [[ "$astate" != read ]]; then
    err "$h: cannot tell whether $unit is running the assistant — $areason. A verification that cannot see the capability it just deployed is how the 2026-09-02 outage passed. Check by hand: sudo tr '\\0' '\\n' < /proc/\$(systemctl show $unit -p MainPID --value)/cmdline"
    FAIL=$((FAIL + 1))
    continue
  fi

  # Which record answered. `unit` means nothing was running to read, so every
  # line below is about what the box WOULD start — a weaker claim than the one
  # this section is here to make, and it has to be worded as the weaker one
  # rather than reported as fact about a running process.
  case "$asrc" in
    process) awhere="on the running command line"; averb="is running" ;;
    *)       awhere="in the unit it would start (nothing is running)"; averb="would start"
             warn "$h: read from the UNIT, not from a running process ($areason) — this is what $unit would start, not what it is running" ;;
  esac

  if [[ -n "$aurl" ]]; then
    ASST_SEEN="${ASST_SEEN:+$ASST_SEEN
}$h $aurl"
    case "$ASST_WANT" in
      on)
        if [[ "$aurl" == "${ASSISTANT_URL}" ]]; then
          ok "$h: assistant LIVE $awhere — ${amodel:-<no model flag>} via $aurl${adeep:+ (sidebar: $adeep)}"
          if [[ -n "${ASSISTANT_MODEL:-}" && -n "$amodel" && "$amodel" != "$ASSISTANT_MODEL" ]]; then
            warn "$h: the model there is $amodel, but this deploy named $ASSISTANT_MODEL — the capability is up, on a different model than was asked for"
          fi
        else
          err "$h: $unit $averb the assistant against $aurl, but this deploy named $ASSISTANT_URL — the console will answer from an endpoint nobody deployed"
          FAIL=$((FAIL + 1))
        fi
        ;;
      off)
        err "$h: ASSISTANT_OFF=1 was requested but $unit STILL has -assistant-url $aurl $awhere — the removal did not take"
        FAIL=$((FAIL + 1))
        ;;
      *)
        ok "$h: assistant present $awhere — ${amodel:-<no model flag>} via $aurl${adeep:+ (sidebar: $adeep)} (nothing was asked for on this run, so this is a report)"
        ;;
    esac
  else
    ASST_SEEN="${ASST_SEEN:+$ASST_SEEN
}$h <none>"
    case "$ASST_WANT" in
      on)
        err "$h: $unit has NO assistant flags $awhere, but this deploy named ASSISTANT_URL=$ASSISTANT_URL. Every unit is active and every health check passes; the capability is simply gone. This is the 2026-09-02 failure exactly."
        FAIL=$((FAIL + 1))
        ;;
      off)
        ok "$h: no assistant $awhere (ASSISTANT_OFF=1, as requested)"
        ;;
      *)
        ok "$h: no assistant $awhere — this run named neither ASSISTANT_URL nor ASSISTANT_OFF=1, so this is a report, not an assertion"
        ;;
    esac
  fi
done

# With no expectation to check against, the one judgement still available is
# that the two surfaces are meant to carry the SAME assistant (lib.sh writes the
# flags from one set of variables for both). One surface with it and one without
# is a half-applied deploy, and nothing else on this run would say so.
if [[ "$ASST_WANT" == none && -n "$ASST_SEEN" ]]; then
  asst_uniq=$(printf '%s\n' "$ASST_SEEN" | awk '{print $2}' | sort -u | grep -c . || true)
  if [[ "${asst_uniq:-0}" -gt 1 ]]; then
    err "the probed surfaces are NOT running the same assistant, and this run named neither ASSISTANT_URL nor ASSISTANT_OFF=1, so nothing here can say which is right:"
    printf '%s\n' "$ASST_SEEN" | while read -r ah au; do err "    $ah: $au"; done
    FAIL=$((FAIL + 1))
  fi
fi

printf '\n'
if (( FAIL > 0 )); then
  err "$FAIL post-deploy check(s) failed"
  exit 1
fi
ok "estate verified"
