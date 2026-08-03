#!/usr/bin/env bash
#
# Reboots an agent host and requires the whole stack to come back by itself.
#
# Enterprise hosts reboot — for kernel updates, for maintenance windows, because
# someone in a datacentre pressed something. If an agent does not fully return
# on its own, the fleet degrades silently: the console still lists the host, the
# operator still believes it is covered, and nothing is watching it.
#
# "Comes back" is deliberately strict here, because several of these have failed
# independently on this project:
#   * the SERVICE restarts, but Tetragon loses policies that were only ever
#     loaded imperatively (`tetra tracingpolicy add` does not persist);
#   * policies return but an ENFORCING one is resurrected from a stale file on
#     disk, silently re-arming a second authority nobody asked for;
#   * the agent runs but never re-registers, so the console shows a stale
#     heartbeat and the host is invisible to commands;
#   * the tc device plane does not re-attach, so device containment is accepted
#     by the console and silently does nothing.
#
#   AGENT_RSH="ssh Tenant_B_agent" CONSOLE_URL=... MT_USER=... MT_PASS=... \
#     ./scripts/e2e/reboot-resilience.sh
set -uo pipefail

AGENT_RSH="${AGENT_RSH:?set AGENT_RSH}"
BASE="${CONSOLE_URL:?set CONSOLE_URL}"
MT_USER="${MT_USER:?set MT_USER}"; MT_PASS="${MT_PASS:?set MT_PASS}"
BOOT_WAIT="${BOOT_WAIT:-300}"   # ssh back up
SETTLE="${SETTLE:-180}"         # services + tetragon + re-registration

CURL=(curl)
for _r in ${CURL_RESOLVE:-}; do CURL+=(--resolve "$_r"); done

JAR="$(mktemp -d)/r.jar"; PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n     -> %s\n' "$1" "${2:-}"; }
head_(){ printf '\n=== %s ===\n' "$1"; }
GET()  { "${CURL[@]}" -s -b "$JAR" --max-time 25 "$BASE$1"; }
ax()   { $AGENT_RSH "$1" 2>/dev/null | tr -d '\r'; }

TMP="$(mktemp)"
"${CURL[@]}" -s -c "$JAR" -L --max-time 25 "$BASE/login" -o "$TMP"
ACT=$(grep -o 'action="[^"]*"' "$TMP" | head -1 | sed 's/action="//;s/"$//' \
      | python3 -c "import sys,html;print(html.unescape(sys.stdin.read().strip()))")
"${CURL[@]}" -s -b "$JAR" -c "$JAR" -L --max-time 25 -X POST "$ACT" \
  --data-urlencode "username=$MT_USER" --data-urlencode "password=$MT_PASS" -o /dev/null
GET /api/whoami | grep -q '"user"' || { echo "login failed"; exit 1; }

policies()  { ax 'sudo docker exec tetragon tetra tracingpolicy list 2>/dev/null | awk "NR>1{print \$2}" | sort | tr "\n" " "'; }
enforcing() { ax 'sudo docker exec tetragon tetra tracingpolicy list 2>/dev/null | awk "NR>1 && \$(NF-3)==\"enforce\"{printf \"%s \", \$2}"'; }
devlinks()  { GET /api/choke/device-state | python3 -c "import sys,json;print((json.load(sys.stdin) or {}).get('links_attached',0))" 2>/dev/null; }
# Registration alone is not liveness — a host that enrolled once keeps its row
# forever, so counting rows would call a dead agent healthy. agents_reporting
# counts only agents that answered in the current heartbeat window, so it is the
# signal that actually distinguishes "came back" from "still listed".
host_rows()   { GET /api/fleet/hosts | python3 -c "
import sys,json
d=json.load(sys.stdin); d=d if isinstance(d,list) else (d.get('hosts') or d.get('agents') or [])
print(len(d))" 2>/dev/null; }
agent_seen(){ GET /api/choke/state | python3 -c "
import sys,json
k=(json.load(sys.stdin) or {}).get('kernel') or {}
print(k.get('agents_reporting') or 0)" 2>/dev/null; }

head_ "Before the reboot"
BEFORE_POL=$(policies)
BEFORE_LINKS=$(devlinks)
printf '  policies: %s\n  device links attached: %s\n' "$BEFORE_POL" "$BEFORE_LINKS"
if [[ -n "${BEFORE_POL// }" ]]; then ok "agent has Tetragon policies loaded before we start"
else bad "baseline policies" "none loaded — fix the host before testing its reboot behaviour"; fi

head_ "Reboot"
UP_BEFORE=$(ax 'cut -d. -f1 /proc/uptime')
ax 'sudo systemctl reboot >/dev/null 2>&1 &' >/dev/null
printf '  rebooting (uptime was %ss) — waiting for ssh\n' "${UP_BEFORE:-?}"
sleep 20

BOOTED=0
for ((i=0;i<BOOT_WAIT;i+=5)); do
  UP=$(ax 'cut -d. -f1 /proc/uptime')
  # A LOWER uptime than before is the proof it actually rebooted rather than
  # ssh simply never dropping.
  if [[ -n "$UP" && "${UP:-999999}" -lt "${UP_BEFORE:-0}" ]]; then BOOTED=1; break; fi
  sleep 5
done
if [[ "$BOOTED" == "1" ]]; then ok "host rebooted and ssh is back (uptime reset)"
else bad "host came back" "no ssh, or uptime never reset, after ${BOOT_WAIT}s"; fi

head_ "Does everything return on its own?"
# Poll rather than sleeping a fixed guess: Tetragon re-attaches BPF and reloads
# tp.d at its own pace, and reading the list mid-load looks like lost policies.
for ((i=0;i<SETTLE;i+=5)); do
  NOW_POL=$(policies)
  [[ "$(tr -d ' ' <<<"$NOW_POL")" == "$(tr -d ' ' <<<"$BEFORE_POL")" ]] && break
  sleep 5
done

SVC=$(ax 'systemctl is-active ebpf-agent 2>/dev/null')
if [[ "$SVC" == "active" ]]; then ok "ebpf-agent service is active again (enabled at boot)"
else bad "agent service returns" "systemctl is-active = '$SVC' — the agent will not come back unattended"; fi

TET=$(ax 'sudo docker inspect -f "{{.State.Running}}" tetragon 2>/dev/null')
if [[ "$TET" == "true" ]]; then ok "Tetragon container is running again"
else bad "Tetragon returns" "container running = '$TET' — no telemetry on this host"; fi

NOW_POL=$(policies)
if [[ "$(tr -d ' ' <<<"$NOW_POL")" == "$(tr -d ' ' <<<"$BEFORE_POL")" ]]; then
  ok "all policies returned identically: $NOW_POL"
else
  bad "policies survive the reboot" "before='$BEFORE_POL' after='$NOW_POL' — detection silently degraded"
fi

# The reboot must not resurrect an enforcing policy from a file left on disk.
ENF=$(enforcing)
if [[ -z "${ENF// }" ]]; then ok "no policy came back in enforce mode (posture survived the reboot)"
else bad "posture survives the reboot" "ENFORCING after boot: $ENF — a second authority re-armed itself"; fi

head_ "Does the console see it again?"
RE=0
for ((i=0;i<SETTLE;i+=5)); do
  L=$(devlinks); [[ "${L:-0}" -ge 1 ]] && { RE=1; break; }
  sleep 5
done
if [[ "$RE" == "1" ]]; then ok "tc device plane re-attached ($(devlinks) links) — device containment still works"
else bad "device plane re-attaches" "links_attached=$(devlinks) after ${SETTLE}s — the console would accept a device sever that does nothing"; fi

R=$(host_rows)
if [[ "${R:-0}" -ge 1 ]]; then ok "agent still has its fleet registration ($R host row(s))"
else bad "agent keeps its registration" "no host row — the enrolment did not survive the reboot"; fi

N=0
for ((i=0;i<SETTLE;i+=5)); do
  N=$(agent_seen); [[ "${N:-0}" -ge 1 ]] && break
  sleep 5
done
if [[ "${N:-0}" -ge 1 ]]; then ok "agent is heartbeating to the console again (agents_reporting=$N)"
else bad "agent resumes heartbeating" "agents_reporting=0 after ${SETTLE}s — the row is stale and the host is invisible to commands"; fi

printf '\n=====================================\n'
printf 'PASS: %d   FAIL: %d\n' "$PASS" "$FAIL"
exit $((FAIL>0))
