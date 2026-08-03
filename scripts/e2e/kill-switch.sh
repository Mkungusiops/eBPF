#!/usr/bin/env bash
#
# Proves the EMERGENCY STOP actually stops enforcement.
#
# The kill-switch is the control an operator reaches for when enforcement is
# misbehaving in production — the one that has to work on the worst day. Until
# now the suite only ever asserted it was DISENGAGED at startup, which tests
# nothing: a kill-switch wired to a field that no code path reads would pass
# that assertion forever while being decorative.
#
# So this drives the real thing on a disposable victim: enforcement kills ->
# engage -> enforcement must NOT kill -> disengage -> enforcement kills again.
# The middle step is the whole test, and it is the one that cannot be faked by
# reporting state back to itself.
#
# It also pins the subtler half of the contract: with the switch engaged the
# decision is still AUDITED. An emergency stop that silently discards the
# record of what would have happened destroys the forensic trail exactly when
# an incident is in progress.
#
#   ENGINE_URL=https://engine... ENGINE_PASS=... RSH="ssh engine" \
#     ./scripts/e2e/kill-switch.sh
set -uo pipefail

ENGINE="${ENGINE_URL:?set ENGINE_URL}"
PASS_="${ENGINE_PASS:?set ENGINE_PASS}"
USER_="${ENGINE_USER:-admin}"
RSH="${RSH:?set RSH}"

CURL=(curl)
for _r in ${CURL_RESOLVE:-}; do CURL+=(--resolve "$_r"); done

JAR="$(mktemp -d)/k.jar"; PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n     -> %s\n' "$1" "${2:-}"; }
head_(){ printf '\n=== %s ===\n' "$1"; }
aeq()  { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "expected '$2', got '$3'"; fi; }
rx()   { $RSH "$1" 2>/dev/null | tr -d '\r'; }
jqr()  { printf '%s' "$1" | python3 -c "import sys,json;d=json.load(sys.stdin);print(eval(sys.argv[1]))" "$2" 2>/dev/null; }
GET()  { "${CURL[@]}" -s -b "$JAR" --max-time 25 "$ENGINE$1"; }

CSRF=""
POST() { "${CURL[@]}" -s -b "$JAR" --max-time 30 -X POST "$ENGINE$1" \
           -H 'content-type: application/json' -H "X-CSRF-Token: $CSRF" -d "$2"; }

login() { "${CURL[@]}" -s -c "$JAR" -o /dev/null -w '%{http_code}' --max-time 15 \
    -X POST "$ENGINE/api/login" --data-urlencode "user=$USER_" --data-urlencode "pass=$PASS_"; }
code=$(login)
for _ in 1 2 3; do
  [[ "$code" == "429" ]] || break
  echo "  (login rate-limited — the engine's brute-force guard; waiting 30s)"
  sleep 30; code=$(login)
done
[[ "$code" =~ ^(200|303|302)$ ]] || { echo "login failed: HTTP $code"; exit 1; }
# The token is set as a cookie at login, not returned by an endpoint. Reading it
# from the wrong place yields an empty header, every write 403s, and the suite
# then measures a box where nothing was ever armed — see the precondition gate
# below, which exists because that is precisely what happened here once.
CSRF=$(awk '/csrf_token/{print $7}' "$JAR")
[[ -n "$CSRF" ]] || { echo "could not read csrf_token from the cookie jar — writes would all be rejected"; exit 1; }

state()   { GET /api/choke/state; }
ks()      { jqr "$(state)" "d['kill_switched']"; }
mode()    { jqr "$(state)" "d['mode']"; }
audit_n() { jqr "$(state)" "d['audit']['total']"; }
alive()   { rx "kill -0 $1 2>/dev/null && echo yes || echo no"; }

spawn() {
  rx 'setsid sleep 3600 </dev/null >/dev/null 2>&1 & echo ok' >/dev/null
  sleep 1
  rx 'pgrep -f "^sleep 3600" | tail -1'
}

# Restore the box no matter how this exits — a suite that leaves a live host
# armed, or its emergency stop engaged, is worse than no suite.
ORIG_MODE=""
cleanup() {
  POST /api/choke/kill-switch '{"on":false}' >/dev/null 2>&1
  [[ "$ORIG_MODE" == "enforcing" ]] || POST /api/choke/mode '{"enforcing":false,"reason":"kill-switch suite: restore"}' >/dev/null 2>&1
  rx 'pkill -f "^sleep 3600" 2>/dev/null; true' >/dev/null 2>&1
}
trap cleanup EXIT

head_ "Baseline"
ORIG_MODE=$(mode)
printf '  mode=%s kill_switched=%s\n' "$ORIG_MODE" "$(ks)"
aeq "kill-switch starts disengaged" "False" "$(ks)"

# ── 1. enforcement genuinely works, so step 2 means something ───────────────
head_ "1. Enforcement works with the switch DISENGAGED"
POST /api/choke/mode '{"enforcing":true,"reason":"kill-switch suite: arm"}' >/dev/null
sleep 1
aeq "engine armed to enforcing" "enforcing" "$(mode)"

V1=$(spawn)
if [[ -n "$V1" ]]; then ok "spawned disposable victim (pid=$V1)"; else bad "spawn victim" "no pid"; fi
aeq "victim alive before enforcement" "yes" "$(alive "$V1")"
POST /api/choke/jail "{\"pids\":[$V1],\"action\":\"sever\",\"reason\":\"kill-switch suite: control\"}" >/dev/null
sleep 3
CONTROL_KILLED="$(alive "$V1")"
aeq "sever KILLS the process (control — enforcement is real)" "no" "$CONTROL_KILLED"

# PRECONDITION GATE. Step 2 asserts a process SURVIVES a sever. That assertion
# is only meaningful if a sever would otherwise have killed it — on a box where
# enforcement was never armed it passes for the wrong reason and reports a
# working emergency stop that has never been exercised. Refuse to continue
# rather than emit a green result nobody can trust.
if [[ "$CONTROL_KILLED" != "no" ]]; then
  printf '\n  ABORT: enforcement is not actually killing, so the kill-switch test below\n'
  printf '         would pass vacuously. Fix the control before trusting step 2.\n'
  printf '         (mode=%s kill_switched=%s — check that writes are authorised.)\n' "$(mode)" "$(ks)"
  printf '\n=====================================\nPASS: %d   FAIL: %d\n' "$PASS" "$((FAIL+1))"
  exit 1
fi

# ── 2. THE TEST: with the switch engaged, the same call must not kill ───────
head_ "2. THE EMERGENCY STOP — same command, switch ENGAGED"
A_BEFORE=$(audit_n)
POST /api/choke/kill-switch '{"on":true}' >/dev/null
sleep 1
aeq "kill-switch reports engaged" "True" "$(ks)"

V2=$(spawn)
if [[ -n "$V2" ]]; then ok "spawned second victim (pid=$V2)"; else bad "spawn victim" "no pid"; fi
aeq "victim alive before the severed call" "yes" "$(alive "$V2")"

POST /api/choke/jail "{\"pids\":[$V2],\"action\":\"sever\",\"reason\":\"kill-switch suite: must be halted\"}" >/dev/null
sleep 4
# This is the assertion the whole suite exists for.
if [[ "$(alive "$V2")" == "yes" ]]; then
  ok "SEVER DID NOT KILL — the emergency stop actually halts enforcement"
else
  bad "emergency stop halts enforcement" "the process was killed anyway — the kill-switch is decorative"
fi

# The decision must still be on the tape. Losing the record of what WOULD have
# happened is the thing that makes an incident unreconstructable afterwards.
A_AFTER=$(audit_n)
if [[ "${A_AFTER:-0}" -gt "${A_BEFORE:-0}" ]]; then
  ok "the halted decision was still audited ($A_BEFORE -> $A_AFTER)"
else
  bad "halted decisions are audited" "audit total did not grow ($A_BEFORE -> $A_AFTER) — no forensic record of the suppressed action"
fi
aeq "audit chain still verifies under kill-switch" "True" "$(jqr "$(state)" "d['audit']['ok']")"

# ── 3. it is reversible — an emergency stop you cannot lift is an outage ────
head_ "3. Disengaging restores enforcement"
POST /api/choke/kill-switch '{"on":false}' >/dev/null
sleep 1
aeq "kill-switch reports disengaged" "False" "$(ks)"
aeq "victim from step 2 is still alive" "yes" "$(alive "$V2")"

POST /api/choke/jail "{\"pids\":[$V2],\"action\":\"sever\",\"reason\":\"kill-switch suite: enforcement resumed\"}" >/dev/null
sleep 3
aeq "sever KILLS again once disengaged (reversible, not a one-way latch)" "no" "$(alive "$V2")"

head_ "Restore"
[[ "$ORIG_MODE" == "enforcing" ]] || POST /api/choke/mode '{"enforcing":false,"reason":"kill-switch suite: restore detect-only"}' >/dev/null
sleep 1
aeq "engine restored to its original mode" "$ORIG_MODE" "$(mode)"
aeq "kill-switch left disengaged" "False" "$(ks)"

printf '\n=====================================\n'
printf 'PASS: %d   FAIL: %d\n' "$PASS" "$FAIL"
exit $((FAIL>0))
