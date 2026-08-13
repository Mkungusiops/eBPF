#!/usr/bin/env bash
#
# Proves the DEVICE choke gateway actually drops packets in the kernel.
#
# Every other test asserts state machines and audit rows — this one asserts the
# only thing a customer cares about: after an operator severs a device from the
# console, that device's traffic STOPS, and after they release it, it RESUMES.
#
# Topology: the agent runs the tc data plane on its own NIC; the victim is a
# real neighbour on the same L2 segment serving HTTP. Severing the victim's MAC
# installs a drop rule for frames to/from it, so a request from the agent that
# worked a second ago now fails — with nothing else changed.
#
#   CONSOLE_URL=http://... MT_USER=... MT_PASS=... MT_TENANT=... \
#   AGENT_RSH="ssh Tenant_A_agent" VICTIM_IP=172.31.42.88 VICTIM_MAC=... \
#     ./scripts/e2e/device-drop-proof.sh
set -uo pipefail

BASE="${CONSOLE_URL:?set CONSOLE_URL}"
MT_USER="${MT_USER:?set MT_USER}"; MT_PASS="${MT_PASS:?set MT_PASS}"
AGENT_RSH="${AGENT_RSH:?set AGENT_RSH}"
VICTIM_IP="${VICTIM_IP:?set VICTIM_IP}"
VICTIM_PORT="${VICTIM_PORT:-8000}"
VICTIM_MAC="${VICTIM_MAC:-}"
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

JAR="$(mktemp -d)/cp.jar"; PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n     -> %s\n' "$1" "${2:-}"; }
head_(){ printf '\n=== %s ===\n' "$1"; }
GET()  { "${CURL[@]}" -s -b "$JAR" --max-time 25 "$BASE$1"; }
POST() { "${CURL[@]}" -s -b "$JAR" --max-time 30 -X POST "$BASE$1" -H 'content-type: application/json' -d "$2"; }
jqr()  { printf '%s' "$1" | python3 -c "import sys,json;d=json.load(sys.stdin);print(eval(sys.argv[1]))" "$2" 2>/dev/null; }

# Can the agent reach the victim's service right now? This curl runs ON THE
# AGENT — it is the traffic under test, so it must never inherit CURL_RESOLVE
# (which exists only to work around the LOCAL resolver being stale).
reach() { $AGENT_RSH "curl -s -o /dev/null --max-time 4 http://$VICTIM_IP:$VICTIM_PORT/ && echo yes || echo no" 2>/dev/null | tr -d '\r'; }

# ── sign in ────────────────────────────────────────────────────────────────
TMP="$(mktemp)"
"${CURL[@]}" -s -c "$JAR" -L --max-time 25 "$BASE/login" -o "$TMP"
ACT=$(grep -o 'action="[^"]*"' "$TMP" | head -1 | sed 's/action="//;s/"$//' \
      | python3 -c "import sys,html;print(html.unescape(sys.stdin.read().strip()))")
"${CURL[@]}" -s -b "$JAR" -c "$JAR" -L --max-time 25 -X POST "$ACT" \
  --data-urlencode "username=$MT_USER" --data-urlencode "password=$MT_PASS" -o /dev/null
GET /api/whoami | grep -q '"user"' || { echo "login failed"; exit 1; }

# Resolve the victim's MAC from the agent's own neighbour table if not given —
# the console keys devices by MAC, the operator thinks in IPs.
if [[ -z "$VICTIM_MAC" ]]; then
  VICTIM_MAC=$($AGENT_RSH "ip -4 neigh show | awk '\$1==\"$VICTIM_IP\" {for(i=1;i<=NF;i++) if(\$i==\"lladdr\") print \$(i+1)}' | head -1" 2>/dev/null | tr -d '\r')
fi
[[ -n "$VICTIM_MAC" ]] || { echo "could not resolve the victim MAC for $VICTIM_IP"; exit 1; }

head_ "Setup"
printf '  victim %s -> %s:%s\n' "$VICTIM_MAC" "$VICTIM_IP" "$VICTIM_PORT"
DS=$(GET /api/choke/device-state)
printf '  data_plane=%s links_attached=%s\n' "$(jqr "$DS" "d['data_plane']")" "$(jqr "$DS" "d['links_attached']")"

devstate() { GET /api/choke/devices | python3 -c "
import sys,json
print(next((x['state'] for x in (json.load(sys.stdin) or []) if x['mac']=='$VICTIM_MAC'), 'MISSING'))"; }
protected() { GET /api/choke/devices | python3 -c "
import sys,json
print(next((str(x['protected']) for x in (json.load(sys.stdin) or []) if x['mac']=='$VICTIM_MAC'), 'MISSING'))"; }
wait_state() { local i; for ((i=0;i<HB_WAIT;i++)); do [[ "$(devstate)" == "$1" ]] && return 0; sleep 1; done; return 1; }
wait_devmode() { local i; for ((i=0;i<HB_WAIT;i++)); do
  [[ "$(jqr "$(GET /api/choke/device-state)" "d['mode']")" == "$1" ]] && return 0; sleep 1; done; return 1; }

[[ "$(protected)" == "False" ]] && ok "victim is not on the protect list (a legitimate target)" \
                                || bad "victim is a legitimate target" "protected=$(protected) — the guardrail would refuse"

head_ "Baseline — before any enforcement"
[[ "$(reach)" == "yes" ]] && ok "agent can reach the victim's service" \
                          || bad "agent can reach the victim's service" "unreachable before we did anything"

head_ "Arm the network plane"
POST /api/choke/device-mode '{"enforcing":true,"reason":"drop proof: arm"}' >/dev/null
if wait_devmode enforcing; then ok "device plane enforcing (confirmed by agent heartbeat)"
else bad "device plane enforcing" "still detect-only after ${HB_WAIT}s"; fi
# Detect-only would audit the decision and touch nothing, so the drop below
# would never happen and the proof would be vacuous.

head_ "Sever the device from the console"
R=$(POST /api/choke/device-jail "{\"macs\":[\"$VICTIM_MAC\"],\"action\":\"sever\",\"reason\":\"drop proof: contain the device\"}")
[[ "$(jqr "$R" "d['results'][0]['ok']")" == "True" ]] && ok "sever dispatched to the agent" \
                                                      || bad "sever dispatched" "$R"
if wait_state severed; then ok "console confirms device state=severed"; else bad "console confirms severed" "still '$(devstate)'"; fi

# THE ASSERTION. Nothing about the victim changed — its service is still
# running and its firewall still permits us. The only difference is a drop rule
# in the agent's kernel.
sleep 2
if [[ "$(reach)" == "no" ]]; then ok "TRAFFIC IS ACTUALLY BLOCKED IN THE KERNEL (was reachable a moment ago)"
else bad "traffic is actually blocked" "still reachable — the tc data plane did not drop"; fi

head_ "Release"
POST /api/choke/device-thaw "{\"macs\":[\"$VICTIM_MAC\"],\"reason\":\"drop proof: release\"}" >/dev/null
if wait_state pristine; then ok "console confirms device released -> pristine"; else bad "console confirms released" "still '$(devstate)'"; fi
sleep 2
if [[ "$(reach)" == "yes" ]]; then ok "TRAFFIC RESUMES AFTER RELEASE (a device sever is reversible)"
else bad "traffic resumes after release" "still blocked — the drop rule was not cleared"; fi

# Leave the plane as we found it.
POST /api/choke/device-mode '{"enforcing":false,"reason":"drop proof: restore detect-only"}' >/dev/null
wait_devmode detect-only >/dev/null

printf '\n=====================================\n'
printf 'PASS: %d   FAIL: %d\n' "$PASS" "$FAIL"
exit $((FAIL>0))
