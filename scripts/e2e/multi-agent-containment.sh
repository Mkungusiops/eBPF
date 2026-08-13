#!/usr/bin/env bash
#
# scripts/e2e/multi-agent-containment.sh — containment must be ROUTED, not broadcast.
#
# multi-tenant.sh proves a sever works when the operator targets a process that
# really is on the agent it drives. It cannot catch the multi-agent failure,
# because it only ever looks at the one host it spawned the victim on — so the
# suite passed while a sever was also killing processes on OTHER hosts in the
# tenant. This suite watches the bystander.
#
# The bug (found 2026-08-03, fixed by the target_match/NOT_TARGET contract):
# the control plane fanned a Jail/Thaw out to every agent in the tenant, and
# each one applied it locally. A sever is syscall.Kill(pid, SIGKILL) and PID
# numbers are per-host, so a non-owning agent killed whatever local process
# happened to hold that number — and acked STATUS_APPLIED for it. The operator
# was told a threat was contained; a different, unrelated process had died on a
# machine they never named.
#
# Requires a tenant with TWO agents and shell on both:
#
#   CONSOLE_URL=https://console.example  MT_USER=… MT_PASS=… MT_TENANT=acme-corp \
#   AGENT_RSH="ssh agent-a" AGENT_OTHER_RSH="ssh agent-b" \
#     ./scripts/e2e/multi-agent-containment.sh
#
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${E2E_ENV:-$ROOT/.deploy-build/e2e.env}"
[[ -f "$ENV_FILE" && -z "${CONSOLE_URL:-}" ]] && { set -a; . "$ENV_FILE"; set +a; }

CONSOLE_URL="${CONSOLE_URL:?CONSOLE_URL required}"
USER_="${MT_USER:?MT_USER required}"
PASS="${MT_PASS:?MT_PASS required}"
TENANT="${MT_TENANT:?MT_TENANT required}"
AGENT_RSH="${AGENT_RSH:?AGENT_RSH required (the agent we target)}"
OTHER_RSH="${AGENT_OTHER_RSH:?AGENT_OTHER_RSH required (the bystander agent)}"

PASSN=0; FAILN=0; FAILED=()
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASSN=$((PASSN+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; [[ -n "${2:-}" ]] && printf '        %s\n' "$2"; FAILN=$((FAILN+1)); FAILED+=("$1"); }
aeq()  { [[ "$2" == "$3" ]] && ok "$1" || bad "$1" "want=$2 got=$3"; }
head_(){ printf '\n=== %s ===\n' "$1"; }

JAR="$(mktemp)"; TMP="$(mktemp)"
trap 'rm -f "$JAR" "$TMP"' EXIT
CURL=(curl -sk --max-time 30)

GET()  { "${CURL[@]}" -b "$JAR" "$CONSOLE_URL$1"; }
POST() { "${CURL[@]}" -b "$JAR" -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" -X POST "$CONSOLE_URL$1" -d "$2"; }
CODE() { "${CURL[@]}" -b "$JAR" -o /dev/null -w '%{http_code}' -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" -X POST "$CONSOLE_URL$1" -d "$2"; }
jqr()  { printf '%s' "$1" | python3 -c "import sys,json;d=json.load(sys.stdin);print($2)" 2>/dev/null; }

# ── Log in ────────────────────────────────────────────────────────────────
"${CURL[@]}" -c "$JAR" -L "$CONSOLE_URL/login" -o "$TMP" || { echo "cannot reach $CONSOLE_URL"; exit 1; }
ACT=$(grep -o 'action="[^"]*"' "$TMP" | head -1 | sed 's/action="//;s/"$//' \
      | python3 -c "import sys,html;print(html.unescape(sys.stdin.read().strip()))")
[[ -n "$ACT" ]] || { echo "no Keycloak form on $CONSOLE_URL/login"; exit 1; }
"${CURL[@]}" -b "$JAR" -c "$JAR" -L -X POST "$ACT" \
  --data-urlencode "username=$USER_" --data-urlencode "password=$PASS" -o /dev/null
CSRF=$(grep csrf_token "$JAR" | awk '{print $7}')
WHO=$(GET /api/whoami)
printf '%s' "$WHO" | grep -q '"user"' || { echo "login failed: $WHO"; exit 1; }

head_ "Fleet shape"
NH=$(jqr "$(GET /api/fleet/hosts)" "len(d['hosts'])")
if [[ "${NH:-0}" -ge 2 ]]; then ok "tenant $TENANT has $NH agents (the config that exposes the bug)"
else bad "tenant needs 2+ agents" "found ${NH:-0} — a single-agent tenant cannot show misrouting"; fi

rx()      { $AGENT_RSH "$1" 2>/dev/null | tr -d '\r'; }
rxo()     { $OTHER_RSH "$1" 2>/dev/null | tr -d '\r'; }
alive_o() { rxo "kill -0 $1 2>/dev/null && echo yes || echo no"; }
alive_t() { rx  "kill -0 $1 2>/dev/null && echo yes || echo no"; }

# ── 1. A sever must never reach a bystander ───────────────────────────────
#
# The sharpest form of the bug: name a target that exists on NO host, with a
# pid that is live only on the BYSTANDER. Nothing about this request points at
# the bystander, so nothing of the bystander's may die.
head_ "A sever must not reach a host the operator never named"
rxo 'setsid sleep 3600 </dev/null >/dev/null 2>&1 & echo ok' >/dev/null
sleep 1
BPID=$(rxo 'pgrep -f "^sleep 3600" | tail -1')
if [[ -n "$BPID" ]]; then ok "spawned a bystander process on the other agent (pid=$BPID)"
else bad "spawn bystander process" "no pid"; fi
aeq "bystander alive before the sever" "yes" "$(alive_o "$BPID")"

R=$(POST /api/choke/manual \
  "{\"exec_id\":\"phantom-not-on-any-host\",\"pid\":$BPID,\"action\":\"sever\",\"reason\":\"e2e: misroute probe\"}")
sleep 2

# THE assertion. Before the fix this printed "no": the fan-out SIGKILLed the
# bystander's process and the console reported STATUS_APPLIED for it.
aeq "BYSTANDER PROCESS SURVIVES A SEVER IT WAS NEVER THE TARGET OF" "yes" "$(alive_o "$BPID")"

# And the operator must not be told it worked. Either the control plane refuses
# to route an irreversible action it cannot pin to one host (409
# AMBIGUOUS_TARGET), or every agent disowns the target — never ok.
OKV=$(jqr "$R" "d.get('ok')")
if [[ "$OKV" == "True" ]]; then
  bad "an unroutable sever must not report success" "got ok=true: $R"
else
  ok "unroutable sever reported honestly ($(jqr "$R" "d.get('status','?')"))"
fi
rxo "kill -9 $BPID 2>/dev/null; true" >/dev/null

# ── 2. The real target still dies ─────────────────────────────────────────
#
# The refusal above must not have been bought by breaking containment. A sever
# aimed at a host the operator names has to still be a SIGKILL.
head_ "Containment still works when the target IS routable"
rx 'setsid sleep 3600 </dev/null >/dev/null 2>&1 & echo ok' >/dev/null
sleep 1
VPID=$(rx 'pgrep -f "^sleep 3600" | tail -1')
if [[ -n "$VPID" ]]; then ok "spawned the real victim on the targeted agent (pid=$VPID)"
else bad "spawn victim" "no pid"; fi

# Name the host explicitly, the way the console does from the choke row's agent
# field. Find which agent owns VPID by asking each for a REVERSIBLE rung: the
# owner applies, the others report NOT_TARGET. That asymmetry is itself the fix
# working — before it, every agent answered APPLIED.
OWNER=""
for AID in $(jqr "$(GET /api/fleet/hosts)" "' '.join(h['name'] for h in d['hosts'])"); do
  RR=$(POST /api/choke/manual \
    "{\"exec_id\":\"e2e-owner-probe-$VPID\",\"pid\":$VPID,\"agent_id\":\"$AID\",\"action\":\"throttle\",\"reason\":\"e2e: owner probe\"}")
  [[ "$(jqr "$RR" "d.get('ok')")" == "True" ]] && { OWNER="$AID"; break; }
done
if [[ -n "$OWNER" ]]; then ok "control plane identified the owning agent ($OWNER)"
else bad "identify the owning agent" "no agent claimed pid $VPID"; fi
aeq "victim survives the reversible rung" "yes" "$(alive_t "$VPID")"

R=$(POST /api/choke/manual \
  "{\"exec_id\":\"e2e-owner-probe-$VPID\",\"pid\":$VPID,\"agent_id\":\"$OWNER\",\"action\":\"sever\",\"reason\":\"e2e: routed sever\"}")
aeq "routed sever APPLIED" "STATUS_APPLIED" "$(jqr "$R" "d.get('status')")"
sleep 2
aeq "ROUTED SEVER ACTUALLY KILLED THE TARGET" "no" "$(alive_t "$VPID")"

# ── 3. Cleanup ────────────────────────────────────────────────────────────
rx  "pkill -f '^sleep 3600' 2>/dev/null; true" >/dev/null
rxo "pkill -f '^sleep 3600' 2>/dev/null; true" >/dev/null

printf '\n=====================================\n'
printf 'PASS: %d   FAIL: %d\n' "$PASSN" "$FAILN"
if ((FAILN)); then printf '\nFailures:\n'; for f in "${FAILED[@]}"; do printf '  - %s\n' "$f"; done; exit 1; fi
exit 0
