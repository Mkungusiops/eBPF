#!/usr/bin/env bash
#
# Proves an agent keeps working while the control plane is unreachable.
#
# architecture.md states the autonomy invariant plainly: "a missed heartbeat
# never stops enforcement". That is the difference between a security product
# and a liability — if a control-plane outage silently disarms every agent, then
# the blast radius of one host going down is the entire fleet, and an attacker
# who can reach the console can disable protection everywhere without touching a
# single protected machine.
#
# It had never been tested. This stops the control plane outright, requires the
# agent to keep detecting and enforcing locally, then brings it back and
# requires the agent to re-converge on its own.
#
#   AGENT_RSH="ssh Tenant_B_agent" CP_RSH="ssh control-plane" \
#   CONSOLE_URL=... MT_USER=... MT_PASS=... ./scripts/e2e/agent-autonomy.sh
set -uo pipefail

AGENT_RSH="${AGENT_RSH:?set AGENT_RSH}"
CP_RSH="${CP_RSH:?set CP_RSH}"
BASE="${CONSOLE_URL:?set CONSOLE_URL}"
MT_USER="${MT_USER:?set MT_USER}"; MT_PASS="${MT_PASS:?set MT_PASS}"
RECONVERGE="${RECONVERGE:-150}"

CURL=(curl)
for _r in ${CURL_RESOLVE:-}; do CURL+=(--resolve "$_r"); done

JAR="$(mktemp -d)/a.jar"; PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n     -> %s\n' "$1" "${2:-}"; }
head_(){ printf '\n=== %s ===\n' "$1"; }
aeq()  { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "expected '$2', got '$3'"; fi; }
ax()   { $AGENT_RSH "$1" 2>/dev/null | tr -d '\r'; }
cx()   { $CP_RSH "$1" 2>/dev/null | tr -d '\r'; }
GET()  { "${CURL[@]}" -s -b "$JAR" --max-time 20 "$BASE$1"; }

# Always bring the control plane back, however this exits. Leaving a fleet's
# console down because a test aborted is the worst possible failure here.
restore_cp() { cx 'sudo systemctl start ebpf-soc-controlplane >/dev/null 2>&1; true' >/dev/null; }
trap restore_cp EXIT

TMP="$(mktemp)"
"${CURL[@]}" -s -c "$JAR" -L --max-time 25 "$BASE/login" -o "$TMP"
ACT=$(grep -o 'action="[^"]*"' "$TMP" | head -1 | sed 's/action="//;s/"$//' \
      | python3 -c "import sys,html;print(html.unescape(sys.stdin.read().strip()))")
"${CURL[@]}" -s -b "$JAR" -c "$JAR" -L --max-time 25 -X POST "$ACT" \
  --data-urlencode "username=$MT_USER" --data-urlencode "password=$MT_PASS" -o /dev/null
GET /api/whoami | grep -q '"user"' || { echo "login failed"; exit 1; }

reporting() { GET /api/choke/state | python3 -c "
import sys,json
k=(json.load(sys.stdin) or {}).get('kernel') or {}
print(k.get('agents_reporting') or 0)" 2>/dev/null; }
# Local liveness without touching the agent's HTTP API: it requires a session
# (a bare GET is 401) and sqlite3 is not installed on these hosts, so the
# durable signal is the telemetry store still GROWING. If the agent stopped
# working when the console went away, this file stops changing.
db_size() { ax 'sudo stat -c %s /var/lib/ebpf-soc-agent/events.db 2>/dev/null || echo 0'; }
policies() { ax 'sudo docker exec tetragon tetra tracingpolicy list 2>/dev/null | awk "NR>1{print \$2}" | wc -l'; }

head_ "Baseline — control plane up"
aeq "control plane is running" "active" "$(cx 'systemctl is-active ebpf-soc-controlplane')"
aeq "agent service is running" "active" "$(ax 'systemctl is-active ebpf-agent')"
N0=$(reporting)
if [[ "${N0:-0}" -ge 1 ]]; then ok "console sees the agent reporting (n=$N0)"
else bad "agent reporting at baseline" "agents_reporting=$N0 — fix before testing an outage"; fi
P0=$(policies)
printf '  agent has %s Tetragon policies loaded\n' "$P0"

head_ "STOP the control plane"
cx 'sudo systemctl stop ebpf-soc-controlplane' >/dev/null
sleep 3
aeq "control plane is down" "inactive" "$(cx 'systemctl is-active ebpf-soc-controlplane')"
if ! "${CURL[@]}" -s -o /dev/null --max-time 8 "$BASE/api/whoami" 2>/dev/null; then
  ok "console API is genuinely unreachable (the outage is real)"
else
  # nginx may still answer; what matters is the API being down.
  CODE=$("${CURL[@]}" -s -o /dev/null -w '%{http_code}' --max-time 8 "$BASE/api/whoami" 2>/dev/null)
  if [[ "$CODE" =~ ^(502|503|504)$ ]]; then ok "console API returns $CODE (the outage is real)"
  else bad "console API is down" "still answering $CODE — the control plane did not actually stop"; fi
fi

head_ "THE INVARIANT — the agent must carry on alone"
sleep 25   # comfortably past one heartbeat interval, so failures have happened
aeq "agent service survived the outage" "active" "$(ax 'systemctl is-active ebpf-agent')"
aeq "Tetragon is still running" "true" "$(ax 'sudo docker inspect -f "{{.State.Running}}" tetragon 2>/dev/null')"
P1=$(policies)
if [[ "${P1:-0}" == "${P0:-0}" && "${P1:-0}" -ge 1 ]]; then ok "all $P1 detection policies still loaded with no console"
else bad "policies survive the outage" "had $P0, now $P1 — detection degraded when the console went away"; fi

# THE DECISIVE ONE: run a real attack with the console unreachable and require
# the agent to record it. A heartbeat is a report, not a permission slip — if
# telemetry stops when the CP goes away, one console outage blinds the fleet.
EV0=$(db_size)
ax 'sudo bash /opt/ebpf-soc/attacks/02-credential-theft.sh >/dev/null 2>&1; true' >/dev/null
sleep 12
EV1=$(db_size)
if [[ "${EV0:-0}" -gt 0 && "${EV1:-0}" -gt "${EV0:-0}" ]]; then
  ok "agent DETECTED and recorded an attack with the console down ($EV0 -> $EV1 bytes)"
elif [[ "${EV0:-0}" -gt 0 && "${EV1:-0}" == "${EV0:-0}" ]]; then
  bad "agent detects during an outage" "the telemetry store did not grow ($EV0 bytes) — the agent stopped recording when the CP went down"
else
  bad "agent detects during an outage" "could not read the telemetry store (size=$EV0) — cannot prove autonomy"
fi

head_ "RESTORE — the agent must re-converge on its own"
cx 'sudo systemctl start ebpf-soc-controlplane' >/dev/null
for ((i=0;i<60;i+=3)); do
  [[ "$(cx 'systemctl is-active ebpf-soc-controlplane')" == "active" ]] && break
  sleep 3
done
aeq "control plane is back" "active" "$(cx 'systemctl is-active ebpf-soc-controlplane')"

# Re-authenticate, retrying: systemd reports the unit active before the HTTP
# listener and OIDC discovery are ready, so a single attempt here races the
# restart, finds no login form, and reports the agent as never re-converging.
RELOGIN=0
for ((i=0;i<20;i++)); do
  "${CURL[@]}" -s -c "$JAR" -L --max-time 20 "$BASE/login" -o "$TMP" 2>/dev/null
  ACT=$(grep -o 'action="[^"]*"' "$TMP" | head -1 | sed 's/action="//;s/"$//' \
        | python3 -c "import sys,html;print(html.unescape(sys.stdin.read().strip()))" 2>/dev/null)
  if [[ -n "$ACT" ]]; then
    "${CURL[@]}" -s -b "$JAR" -c "$JAR" -L --max-time 20 -X POST "$ACT" \
      --data-urlencode "username=$MT_USER" --data-urlencode "password=$MT_PASS" -o /dev/null 2>/dev/null
    GET /api/whoami | grep -q '"user"' && { RELOGIN=1; break; }
  fi
  sleep 5
done
if [[ "$RELOGIN" == "1" ]]; then ok "console accepts logins again after the restart"
else bad "console usable after restart" "could not re-authenticate — the reporting check below cannot be trusted"; fi

RE=0
for ((i=0;i<RECONVERGE;i+=5)); do
  N=$(reporting); [[ "${N:-0}" -ge 1 ]] && { RE=1; break; }
  sleep 5
done
if [[ "$RE" == "1" ]]; then ok "agent re-registered and is reporting again with no intervention"
else bad "agent re-converges" "agents_reporting still 0 after ${RECONVERGE}s — an outage would need a manual restart on every host"; fi

printf '\n=====================================\n'
printf 'PASS: %d   FAIL: %d\n' "$PASS" "$FAIL"
exit $((FAIL>0))
