#!/usr/bin/env bash
#
# End-to-end test of BOTH choke gateways against a live MULTI-TENANT console.
#
# Exercises the whole chain the product actually sells:
#   browser -> Keycloak OIDC -> control-plane BFF (tenant authz)
#           -> signed command -> real agent -> kernel
#
# Authentication goes through the real OIDC code flow rather than an admin
# bearer token, so tenant scoping and the RBAC denial paths are covered too.
#
# Usage:
#   CONSOLE_URL=http://127.0.0.1:18080 \
#   MT_USER=op-adanian MT_PASS=... MT_TENANT=adanian-internal \
#   AGENT_RSH="ssh Tenant_A_agent" ./scripts/e2e/multi-tenant.sh
#
#   AGENT_RSH runs a shell command on the agent host that owns the tenant —
#   needed because a process `sever` is a real SIGKILL, so the target must be a
#   disposable victim we spawn ourselves, never part of the agent's workload.
set -uo pipefail

BASE="${CONSOLE_URL:?set CONSOLE_URL}"
MT_USER="${MT_USER:?set MT_USER}"
MT_PASS="${MT_PASS:?set MT_PASS}"
TENANT="${MT_TENANT:?set MT_TENANT (the tenant MT_USER belongs to)}"
OTHER_TENANT="${MT_OTHER_TENANT:-acme-corp}"
AGENT_RSH="${AGENT_RSH:-}"
# Device state and mode reach the console ONLY on the agent heartbeat
# (cpclient.HeartbeatInterval, 30s). Anything asserting them must clear a full
# interval or a real change reads as a miss.
HB_WAIT="${HB_WAIT:-45}"

# CURL_RESOLVE pins a hostname to an IP for the duration of the run, the way
# curl --resolve does. Needed whenever the console has just been pointed at a new
# domain: the records are live at the authoritative nameservers but the local
# resolver (or an upstream router) still serves a cached answer, and the OIDC
# flow follows ABSOLUTE redirects to the new hostname — so the suite cannot just
# be aimed at the IP. Example:
#   CURL_RESOLVE=console.example.com:80:203.0.113.10
CURL=(curl)
for _r in ${CURL_RESOLVE:-}; do CURL+=(--resolve "$_r"); done

JAR="$(mktemp -d)/cp.jar"
PASS=0; FAIL=0
declare -a FAILURES=()
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); FAILURES+=("$1"); printf '  FAIL  %s\n     -> %s\n' "$1" "${2:-}"; }
note() { printf '  NOTE  %s\n' "$1"; }
head_(){ printf '\n=== %s ===\n' "$1"; }
aeq()  { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "expected '$2', got '$3'"; fi; }
amatch(){ if [[ "$3" =~ $2 ]]; then ok "$1"; else bad "$1" "expected /$2/, got '$3'"; fi; }

GET()  { "${CURL[@]}" -s -b "$JAR" --max-time 25 "$BASE$1"; }
CODE() { "${CURL[@]}" -s -b "$JAR" -o /dev/null -w '%{http_code}' --max-time 25 "$BASE$1"; }
POST() { "${CURL[@]}" -s -b "$JAR" --max-time 30 -X POST "$BASE$1" -H 'content-type: application/json' -d "$2"; }
POSTC(){ "${CURL[@]}" -s -b "$JAR" -o /dev/null -w '%{http_code}' --max-time 30 -X POST "$BASE$1" -H 'content-type: application/json' -d "$2"; }
jqr()  { printf '%s' "$1" | python3 -c "import sys,json;d=json.load(sys.stdin);print(eval(sys.argv[1]))" "$2" 2>/dev/null; }

# ── Keycloak OIDC code flow, driven with curl ──────────────────────────────
head_ "Session + tenant scoping"
TMP="$(mktemp)"
"${CURL[@]}" -s -c "$JAR" -L --max-time 25 "$BASE/login" -o "$TMP" || { echo "cannot reach $BASE"; exit 1; }
ACT=$(grep -o 'action="[^"]*"' "$TMP" | head -1 | sed 's/action="//;s/"$//' \
      | python3 -c "import sys,html;print(html.unescape(sys.stdin.read().strip()))")
[[ -n "$ACT" ]] || { echo "no Keycloak form on $BASE/login"; exit 1; }
"${CURL[@]}" -s -b "$JAR" -c "$JAR" -L --max-time 25 -X POST "$ACT" \
  --data-urlencode "username=$MT_USER" --data-urlencode "password=$MT_PASS" -o "$TMP" >/dev/null
WHO=$(GET /api/whoami)
printf '%s' "$WHO" | grep -q '"user"' || { echo "login failed: $WHO"; exit 1; }
aeq "authenticated via Keycloak OIDC" "$TENANT" "$(jqr "$WHO" "d['tenants'][0]")"
aeq "principal may respond (enforce)" "True" "$(jqr "$WHO" "d['can_respond']")"

# Tenant isolation, both directions. A denial is a 404 by design (no side channel).
amatch "cross-tenant READ of $OTHER_TENANT denied"  "40[34]" "$(CODE "/api/choke/circuits?tenant=$OTHER_TENANT")"
amatch "cross-tenant WRITE to $OTHER_TENANT denied" "40[34]" \
  "$(POSTC "/api/choke/manual?tenant=$OTHER_TENANT" '{"exec_id":"x","action":"throttle","reason":"iso probe"}')"

head_ "Fleet"
HOSTS=$(GET /api/fleet/hosts)
NH=$(jqr "$HOSTS" "len(d['hosts'])")
if [[ "${NH:-0}" -ge 1 ]]; then ok "tenant has $NH agent(s) registered"
else bad "tenant has a live agent registered" "no agents — is the agent enrolled and can it reach CP:9443?"; fi
AGENT=$(jqr "$HOSTS" "d['hosts'][0]['name']")

# ── Process plane: console -> CP -> signed command -> agent -> kernel ──────
if [[ -n "$AGENT_RSH" && "${NH:-0}" -ge 1 ]]; then
  head_ "PROCESS CHOKE GATEWAY — console -> CP -> agent -> kernel"
  rx() { $AGENT_RSH "$1" 2>/dev/null | tr -d '\r'; }
  rx 'setsid sleep 3600 </dev/null >/dev/null 2>&1 & echo ok' >/dev/null
  sleep 1
  VPID=$(rx 'pgrep -f "^sleep 3600" | tail -1')
  if [[ -n "$VPID" ]]; then ok "spawned disposable victim on the agent (pid=$VPID)"
  else bad "spawn victim on the agent" "no pid"; fi
  alive() { rx "kill -0 $1 2>/dev/null && echo yes || echo no"; }
  aeq "victim alive before enforcement" "yes" "$(alive "$VPID")"

  EXECID="e2e-mt-victim-$VPID"
  for step in throttle tarpit quarantine; do
    R=$(POST /api/choke/manual "{\"exec_id\":\"$EXECID\",\"pid\":$VPID,\"action\":\"$step\",\"reason\":\"e2e ladder: $step\"}")
    aeq "$step APPLIED on the real agent (signed command)" "STATUS_APPLIED" "$(jqr "$R" "d['status']")"
    aeq "victim survives $step (non-terminal rung)" "yes" "$(alive "$VPID")"
  done
  R=$(POST /api/choke/thaw "{\"exec_id\":\"$EXECID\",\"pid\":$VPID,\"reason\":\"e2e: release\"}")
  aeq "thaw APPLIED on the agent" "STATUS_APPLIED" "$(jqr "$R" "d['status']")"
  aeq "victim alive after the full reversible ladder" "yes" "$(alive "$VPID")"
  R=$(POST /api/choke/manual "{\"exec_id\":\"$EXECID\",\"pid\":$VPID,\"action\":\"sever\",\"reason\":\"e2e: terminal rung\"}")
  aeq "sever APPLIED on the agent" "STATUS_APPLIED" "$(jqr "$R" "d['status']")"
  sleep 2
  aeq "SEVER ACTUALLY KILLED THE PROCESS ON THE AGENT" "no" "$(alive "$VPID")"
else
  note "no agent (or no AGENT_RSH) — process-plane enforcement skipped"
fi

# ── Device plane ───────────────────────────────────────────────────────────
head_ "DEVICE CHOKE GATEWAY — data plane, plane isolation, inventory"
DS=$(GET /api/choke/device-state)
DPLANE=$(jqr "$DS" "d['data_plane']"); DLINKS=$(jqr "$DS" "d['links_attached']")
printf '  data_plane=%s links_attached=%s devices_known=%s\n' \
  "$DPLANE" "$DLINKS" "$(jqr "$DS" "d['devices_known']")"
# "unknown" = no agent reporting; "noop" = agent has no tc plane attached. The
# CP must report what the AGENTS say, never assume a registered agent enforces.
if [[ "${NH:-0}" -ge 1 ]]; then
  amatch "CP reports an agent-sourced device plane" "tc|noop|partial" "$DPLANE"
  [[ "$DPLANE" == "tc" ]] && ok "agents have a real tc data plane (links=$DLINKS)" \
                          || note "agents run the noop device backend — enforcement is audit-only"
fi

DEVS=$(GET /api/choke/devices)
NIP=$(printf '%s' "$DEVS" | python3 -c "
import sys,json; print(sum(1 for x in (json.load(sys.stdin) or []) if x.get('last_ip')))")
NPROT=$(printf '%s' "$DEVS" | python3 -c "
import sys,json; print(sum(1 for x in (json.load(sys.stdin) or []) if x.get('protected')))")
[[ "${NIP:-0}"   -gt 0 ]] && ok "device rows carry last_ip (n=$NIP)"        || note "no device IPs yet (agents may not have discovered neighbours)"
[[ "${NPROT:-0}" -gt 0 ]] && ok "protected devices are flagged (n=$NPROT)"  || note "no protected devices flagged yet"

# Plane isolation: arming the DEVICE plane must never arm the PROCESS plane —
# a sever there is a SIGKILL rather than a reversible drop rule.
if [[ "${NH:-0}" -ge 1 ]]; then
  PROC_BEFORE=$(jqr "$(GET /api/choke/state)" "d['mode']")
  wait_devmode() { local i; for ((i=0;i<HB_WAIT;i++)); do
    [[ "$(jqr "$(GET /api/choke/device-state)" "d['mode']")" == "$1" ]] && return 0; sleep 1; done; return 1; }
  R=$(POST /api/choke/device-mode '{"enforcing":true,"reason":"e2e: arm device plane"}')
  aeq "device-mode arm accepted" "True" "$(jqr "$R" "d['ok']")"
  if wait_devmode enforcing; then ok "device plane enforcing (confirmed by heartbeat)"
  else bad "device plane enforcing" "still '$(jqr "$(GET /api/choke/device-state)" "d['mode']")' after ${HB_WAIT}s"; fi
  aeq "arming DEVICE plane left the PROCESS plane untouched" "$PROC_BEFORE" "$(jqr "$(GET /api/choke/state)" "d['mode']")"
  POST /api/choke/device-mode '{"enforcing":false,"reason":"e2e: restore detect-only"}' >/dev/null
  if wait_devmode detect-only; then ok "device plane restored to detect-only"; else bad "device plane restored" "still enforcing"; fi
fi

printf '\n=====================================\n'
printf 'PASS: %d   FAIL: %d\n' "$PASS" "$FAIL"
if ((FAIL)); then printf '\nFailures:\n'; for f in "${FAILURES[@]}"; do printf '  - %s\n' "$f"; done; fi
exit $((FAIL>0))
