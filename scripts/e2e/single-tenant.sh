#!/usr/bin/env bash
#
# End-to-end test of BOTH choke gateways against a live single-tenant engine.
#
# Proves the things unit tests cannot: that an operator can actually contain
# something on a real kernel, that it is audited, and that it is reversible.
# A process `sever` is a real SIGKILL, so every process action targets a
# disposable victim this script spawns itself — never a real system process.
#
# Manual overrides deliberately bypass detect-only (internal/choke/gateway.go
# act(): manual -> realEnforcer), which is what lets this run enforcement
# assertions against a box that is, correctly, still in detect-only.
#
# Usage:
#   ENGINE_URL=http://127.0.0.1:18090 ENGINE_PASS=... \
#   RSH="ssh single_tenant_engine" ./scripts/e2e/single-tenant.sh
#
#   RSH is how we run a shell command ON the engine host — "ssh <alias>" for a
#   server, "orb -m <machine>" for a local OrbStack VM.
set -uo pipefail

ENGINE="${ENGINE_URL:-http://127.0.0.1:18090}"
USER_="${ENGINE_USER:-admin}"
PASS_="${ENGINE_PASS:?set ENGINE_PASS}"
RSH="${RSH:?set RSH, e.g. \"ssh single_tenant_engine\"}"
# CURL_RESOLVE pins hostname->IP for this run, like curl --resolve. Needed while
# a local or upstream resolver still caches an old answer after a cutover: the
# flows here follow ABSOLUTE redirects to the hostname, so the suite cannot just
# be aimed at the IP. Accepts several space-separated triples:
#   CURL_RESOLVE="console.example.com:443:203.0.113.10 engine.example.com:443:203.0.113.11"
CURL=(curl)
for _r in ${CURL_RESOLVE:-}; do CURL+=(--resolve "$_r"); done

JAR="$(mktemp -d)/eng.jar"
PASS=0; FAIL=0
declare -a FAILURES=()

ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); FAILURES+=("$1"); printf '  FAIL  %s\n     -> %s\n' "$1" "${2:-}"; }
head_(){ printf '\n=== %s ===\n' "$1"; }
aeq()  { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "expected '$2', got '$3'"; fi; }
amatch(){ if [[ "$3" =~ $2 ]]; then ok "$1"; else bad "$1" "expected /$2/, got '$3'"; fi; }
rx()   { $RSH "$1" 2>/dev/null | tr -d '\r'; }

# The engine rate-limits /api/login (default 5/min/IP) as brute-force defence.
# Running this suite repeatedly trips it, and a bare "login failed: HTTP 429"
# reads like a bad password when it is really the protection doing its job.
# Back off and retry rather than disabling the limit on the deployment.
login() { "${CURL[@]}" -s -c "$JAR" -o /dev/null -w '%{http_code}' --max-time 15 \
    -X POST "$ENGINE/api/login" --data-urlencode "user=$USER_" --data-urlencode "pass=$PASS_"; }
code=$(login)
for _ in 1 2 3; do
  [[ "$code" == "429" ]] || break
  echo "  (login rate-limited — the engine's brute-force guard; waiting 30s)"
  sleep 30
  code=$(login)
done
[[ "$code" == "303" ]] || {
  case "$code" in
    429) echo "login still rate-limited (HTTP 429) — wait a minute, or redeploy with LOGIN_RATE=0 for a dedicated test host";;
    000) echo "login unreachable (HTTP 000) — DNS, TLS or the host is down: $ENGINE";;
    *)   echo "login failed: HTTP $code";;
  esac
  exit 1
}
CSRF=$(awk '/csrf_token/{print $7}' "$JAR")

GET()  { "${CURL[@]}" -s -b "$JAR" --max-time 20 "$ENGINE$1"; }
CODE() { "${CURL[@]}" -s -b "$JAR" -o /dev/null -w '%{http_code}' --max-time 20 "$ENGINE$1"; }
POST() { "${CURL[@]}" -s -b "$JAR" --max-time 25 -X POST "$ENGINE$1" -H 'content-type: application/json' -H "X-CSRF-Token: $CSRF" -d "$2"; }
POSTC(){ "${CURL[@]}" -s -b "$JAR" -o /dev/null -w '%{http_code}' --max-time 25 -X POST "$ENGINE$1" -H 'content-type: application/json' -H "X-CSRF-Token: $CSRF" -d "$2"; }
jqr()  { printf '%s' "$1" | python3 -c "import sys,json;d=json.load(sys.stdin);print(eval(sys.argv[1]))" "$2" 2>/dev/null; }

head_ "Baseline"
STATE=$(GET /api/choke/state)
MODE=$(jqr "$STATE" "d['mode']"); AUDIT_N=$(jqr "$STATE" "d['audit']['total']")
printf '  mode=%s audit_rows=%s tracked=%s\n' "$MODE" "$AUDIT_N" "$(jqr "$STATE" "d['tracked']")"
aeq "audit chain intact at start" "True" "$(jqr "$STATE" "d['audit']['ok']")"
aeq "kill-switch disengaged"      "False" "$(jqr "$STATE" "d['kill_switched']")"

head_ "Telemetry is real (Tetragon attached)"
# Assert the policies BY NAME, not by count. A threshold passes just as happily
# when a detection has silently disappeared and an unrelated policy has been
# added in its place — and it has to be edited every time the set legitimately
# changes, which invites bumping the number rather than asking why it moved.
# Names are the thing we actually care about. (`enforce/sever-pipe-to-shell` is
# absent by design: it never fired, and the engine scores curl|sh from the exec
# chain instead — see docs/plan/threat-model.md EN-1d.)
POLS=$(rx 'sudo docker exec tetragon tetra tracingpolicy list 2>/dev/null | awk "NR>1{print \$2}"')
MISSING=""
for want in outbound-connections privilege-escalation sensitive-file-access override-credential-read; do
  grep -qx "$want" <<<"$POLS" || MISSING="$MISSING $want"
done
if [[ -z "$MISSING" ]]; then ok "Tetragon has all 4 detection policies loaded"
else bad "Tetragon TracingPolicies loaded" "missing:$MISSING (loaded: $(tr '\n' ' ' <<<"$POLS"))"; fi
EV=$(jqr "$(GET /api/choke/state)" "d['tracked']")
if [[ "${EV:-0}" -ge 1 ]]; then ok "engine is tracking real processes (n=$EV)"
else bad "engine is tracking real processes" "tracked=$EV"; fi

head_ "PROCESS CHOKE GATEWAY — real enforcement on a disposable victim"
rx 'setsid sleep 3600 </dev/null >/dev/null 2>&1 & echo ok' >/dev/null
sleep 1
VPID=$(rx 'pgrep -f "^sleep 3600" | tail -1')
if [[ -n "$VPID" ]]; then ok "spawned disposable victim (pid=$VPID)"; else bad "spawn victim" "no pid"; fi
alive() { rx "kill -0 $1 2>/dev/null && echo yes || echo no"; }
aeq "victim alive before enforcement" "yes" "$(alive "$VPID")"

# Guardrails — these must refuse, server-side, before anything is applied.
aeq "jail without reason rejected (400)"    "400" "$(POSTC /api/choke/jail "{\"pids\":[$VPID],\"action\":\"quarantine\"}")"
aeq "jail with invalid action rejected (400)" "400" "$(POSTC /api/choke/jail "{\"pids\":[$VPID],\"action\":\"nope\",\"reason\":\"x\"}")"
aeq "manual without exec_id rejected (400)" "400" "$(POSTC /api/choke/manual '{"action":"throttle","reason":"no id"}')"
amatch "POST without CSRF token blocked" "40[13]" \
  "$("${CURL[@]}" -s -b "$JAR" -o /dev/null -w '%{http_code}' --max-time 15 -X POST "$ENGINE/api/choke/jail" \
      -H 'content-type: application/json' -d "{\"pids\":[$VPID],\"action\":\"throttle\",\"reason\":\"csrf\"}")"

EXECID=""
for step in throttle:throttled tarpit:tarpit quarantine:quarantined; do
  act="${step%%:*}"; want="${step##*:}"
  R=$(POST /api/choke/jail "{\"pids\":[$VPID],\"action\":\"$act\",\"reason\":\"e2e ladder: $act\"}")
  [[ -z "$EXECID" ]] && EXECID=$(jqr "$R" "d['results'][0]['exec_id']")
  aeq "ladder $act -> $want" "$want" "$(jqr "$R" "d['results'][0]['state']")"
  # Confirm from RE-READ state, not from the accepted response.
  aeq "re-read confirms state=$want" "$want" "$(jqr "$(GET "/api/choke/process/$EXECID")" "d['entry']['state']")"
  aeq "victim still alive after $act (non-terminal rung)" "yes" "$(alive "$VPID")"
done

POST /api/choke/thaw "{\"exec_id\":\"$EXECID\",\"pid\":$VPID,\"reason\":\"e2e: release\"}" >/dev/null
sleep 1
aeq "thaw releases quarantine -> pristine" "pristine" "$(jqr "$(GET "/api/choke/process/$EXECID")" "d['entry']['state']")"
aeq "victim survives the full reversible ladder" "yes" "$(alive "$VPID")"

R=$(POST /api/choke/jail "{\"pids\":[$VPID],\"action\":\"sever\",\"reason\":\"e2e: terminal rung\"}")
aeq "sever reports state=severed" "severed" "$(jqr "$R" "d['results'][0]['state']")"
sleep 2
aeq "SEVER ACTUALLY KILLED THE PROCESS (kernel effect)" "no" "$(alive "$VPID")"

DEC=$(GET "/api/choke/process/$EXECID")
NDEC=$(jqr "$DEC" "len(d.get('decisions') or [])")
if [[ "${NDEC:-0}" -ge 5 ]]; then ok "audit tape recorded the ladder (n=$NDEC)"; else bad "audit tape" "n=${NDEC:-0}"; fi
printf '%s' "$DEC" | grep -q "by $USER_" && ok "decisions attribute the actor" || bad "decisions attribute the actor" "no actor"
printf '%s' "$DEC" | grep -q "\[manual\]" && ok "decisions marked [manual]" || bad "decisions marked [manual]" "no marker"
aeq "audit hash-chain still verifies" "True" "$(jqr "$(GET /api/verify-chain)" "d['ok']")"

head_ "DEVICE CHOKE GATEWAY — network plane"
DSTATE=$(GET /api/choke/device-state)
printf '  data_plane=%s links=%s devices_known=%s\n' \
  "$(jqr "$DSTATE" "d['data_plane']")" "$(jqr "$DSTATE" "d['links_attached']")" "$(jqr "$DSTATE" "d['devices_known']")"
DEVS=$(GET /api/choke/devices)
TMAC=$(printf '%s' "$DEVS" | python3 -c "
import sys,json
print(next((x['mac'] for x in (json.load(sys.stdin) or []) if not x.get('protected')), ''))")
PMAC=$(printf '%s' "$DEVS" | python3 -c "
import sys,json
print(next((x['mac'] for x in (json.load(sys.stdin) or []) if x.get('protected')), ''))")

# On a flat cloud subnet the only neighbour a host sees is often its own default
# gateway — correctly protected, leaving nothing to contain. That is the
# guardrail working, not a failure, so it is a note. What MUST hold is the
# refusal below.
if [[ -n "$TMAC" ]]; then ok "selected a non-protected device to contain ($TMAC)"
else printf '  NOTE  no non-protected device on this segment — ladder skipped, refusal still asserted\n'; fi

# The protect list is the anti-self-lockout control. Arm the plane and confirm a
# protected MAC is refused AND reported as refused: a device the data plane
# declined to touch must never read back as contained.
if [[ -n "$PMAC" ]]; then
  POST /api/choke/device-mode '{"enforcing":true,"reason":"e2e: arm to test the guardrail"}' >/dev/null
  R=$(POST /api/choke/device-jail "{\"macs\":[\"$PMAC\"],\"action\":\"sever\",\"reason\":\"e2e: protected refusal\"}")
  aeq "sever on a PROTECTED mac is refused" "False" "$(jqr "$R" "d['results'][0]['ok']")"
  aeq "refused device does NOT read back as contained" "pristine" \
    "$(GET /api/choke/devices | python3 -c "
import sys,json
print(next((x['state'] for x in (json.load(sys.stdin) or []) if x['mac']=='$PMAC'), 'MISSING'))")"
  # Throttle IS allowed on a protected device — recoverable, not a lockout.
  R=$(POST /api/choke/device-jail "{\"macs\":[\"$PMAC\"],\"action\":\"throttle\",\"reason\":\"e2e: recoverable rung\"}")
  aeq "throttle on a PROTECTED mac is allowed (recoverable)" "True" "$(jqr "$R" "d['results'][0]['ok']")"
  POST /api/choke/device-thaw "{\"macs\":[\"$PMAC\"],\"reason\":\"e2e: restore\"}" >/dev/null
  POST /api/choke/device-mode '{"enforcing":false,"reason":"e2e: restore detect-only"}' >/dev/null
fi

aeq "device-jail without reason rejected (400)" "400" "$(POSTC /api/choke/device-jail "{\"macs\":[\"$TMAC\"],\"action\":\"quarantine\"}")"
aeq "device-jail invalid action rejected (400)" "400" "$(POSTC /api/choke/device-jail "{\"macs\":[\"$TMAC\"],\"action\":\"x\",\"reason\":\"r\"}")"
aeq "device-jail with no MACs rejected (400)"   "400" "$(POSTC /api/choke/device-jail '{"macs":[],"action":"throttle","reason":"r"}')"

devstate_of() { GET /api/choke/devices | python3 -c "
import sys,json
print(next((x['state'] for x in (json.load(sys.stdin) or []) if x['mac']=='$1'), 'MISSING'))"; }

if [[ -n "$TMAC" ]]; then
  for step in throttle:throttled tarpit:tarpit quarantine:quarantined sever:severed; do
    act="${step%%:*}"; want="${step##*:}"
    R=$(POST /api/choke/device-jail "{\"macs\":[\"$TMAC\"],\"action\":\"$act\",\"reason\":\"e2e device: $act\"}")
    aeq "device $act -> $want" "$want" "$(jqr "$R" "d['results'][0]['state']")"
    aeq "re-read device table confirms $want" "$want" "$(devstate_of "$TMAC")"
  done
  POST /api/choke/device-thaw "{\"macs\":[\"$TMAC\"],\"reason\":\"e2e: release\"}" >/dev/null
  # A device sever is a reversible drop rule, unlike a process SIGKILL.
  aeq "SEVERED DEVICE IS REVERSIBLE -> pristine" "pristine" "$(devstate_of "$TMAC")"
  aeq "device-flows 200 for a known MAC" "200" "$(CODE "/api/choke/device-flows?mac=$TMAC")"
fi
aeq "device-flows without mac rejected (400)" "400" "$(CODE "/api/choke/device-flows")"
amatch "device-mode flips to enforcing" "enforc" "$(jqr "$(POST /api/choke/device-mode '{"enforcing":true,"reason":"e2e"}')" "d['mode']")"
aeq "device-mode restored to detect-only" "detect-only" "$(jqr "$(POST /api/choke/device-mode '{"enforcing":false,"reason":"e2e"}')" "d['mode']")"

head_ "Posture / integrity after the run"
STATE2=$(GET /api/choke/state)
aeq "audit chain intact at end" "True" "$(jqr "$STATE2" "d['audit']['ok']")"
aeq "engine still in its original mode" "$MODE" "$(jqr "$STATE2" "d['mode']")"
N2=$(jqr "$STATE2" "d['audit']['total']")
if [[ "${N2:-0}" -gt "${AUDIT_N:-0}" ]]; then ok "audit chain grew ($AUDIT_N -> $N2)"; else bad "audit chain grew" "$AUDIT_N -> $N2"; fi

# SSH must survive the enforcement policies. This is a REGRESSION GUARD: the
# shipped override-credential-read policy once SIGKILLed the login path on
# OpenSSH >= 9.8 (sshd re-execs sshd-session/sshd-auth, which were not in the
# allowlist), locking every operator out of the host it was protecting.
head_ "Lockout guard"
LOGINS=0
for _ in 1 2 3; do [[ "$(rx 'echo ok')" == "ok" ]] && LOGINS=$((LOGINS+1)); done
aeq "login path survives the enforce policies (3 fresh logins)" "3" "$LOGINS"

printf '\n=====================================\n'
printf 'PASS: %d   FAIL: %d\n' "$PASS" "$FAIL"
if ((FAIL)); then printf '\nFailures:\n'; for f in "${FAILURES[@]}"; do printf '  - %s\n' "$f"; done; fi
exit $((FAIL>0))
