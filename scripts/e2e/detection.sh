#!/usr/bin/env bash
#
# Proves the DETECTION pipeline works end to end: a real attack runs on the
# host, Tetragon's kprobes fire, the engine scores the chain, and an operator
# sees a severity-rated alert naming what happened.
#
# Everything else in this repo tests RESPONSE — the choke ladder, the device
# drop, the audit chain. All of it is worthless if nothing is detected in the
# first place, and until now no suite ran a single attack. Six simulations
# shipped in attacks/ and were never exercised by CI or by a release check.
#
# The simulations are reconnaissance only — they read credential files, make
# outbound connections, and exec shells. Nothing is destroyed, so this is safe
# to run against a live host.
#
#   ENGINE_URL=https://engine... ENGINE_PASS=... RSH="ssh engine" \
#     ./scripts/e2e/detection.sh
set -uo pipefail

ENGINE="${ENGINE_URL:?set ENGINE_URL}"
PASS_="${ENGINE_PASS:?set ENGINE_PASS}"
USER_="${ENGINE_USER:-admin}"
RSH="${RSH:?set RSH (e.g. \"ssh single_tenant_engine\")}"
ATTACK_DIR="${ATTACK_DIR:-/var/lib/ebpf-engine/attacks}"
# Detection is not synchronous: Tetragon streams to the engine, the engine
# scores the chain, then persists. Poll rather than sleeping a guessed constant.
SETTLE="${SETTLE:-45}"

CURL=(curl)
for _r in ${CURL_RESOLVE:-}; do CURL+=(--resolve "$_r"); done

JAR="$(mktemp -d)/e.jar"; PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n     -> %s\n' "$1" "${2:-}"; }
head_(){ printf '\n=== %s ===\n' "$1"; }
GET()  { "${CURL[@]}" -s -b "$JAR" --max-time 25 "$ENGINE$1"; }
rx()   { $RSH "$1" 2>/dev/null | tr -d '\r'; }

# ── sign in (the engine rate-limits /api/login as brute-force defence) ──────
login() { "${CURL[@]}" -s -c "$JAR" -o /dev/null -w '%{http_code}' --max-time 15 \
    -X POST "$ENGINE/api/login" --data-urlencode "user=$USER_" --data-urlencode "pass=$PASS_"; }
code=$(login)
for _ in 1 2 3; do
  [[ "$code" == "429" ]] || break
  echo "  (login rate-limited — the engine's brute-force guard; waiting 30s)"
  sleep 30; code=$(login)
done
[[ "$code" =~ ^(200|303|302)$ ]] || { echo "login failed: HTTP $code"; exit 1; }

# Highest alert id we have already seen. Everything asserted below must be
# NEWER than this, so a stale alert from an earlier run cannot make a broken
# detector look healthy.
alerts_json() { GET /api/alerts; }
max_id() {
  alerts_json | python3 -c "
import sys,json
d=json.load(sys.stdin); d=d if isinstance(d,list) else d.get('alerts',[])
print(max([a.get('id',0) for a in d], default=0))"
}
# Alerts newer than \$1, as 'severity|score|description' lines.
new_alerts() {
  alerts_json | python3 -c "
import sys,json
base=int(sys.argv[1])
d=json.load(sys.stdin); d=d if isinstance(d,list) else d.get('alerts',[])
for a in d:
    if a.get('id',0) > base:
        print('%s|%s|%s' % (a.get('severity'), a.get('score'), a.get('description') or a.get('title')))" "$1"
}
# Poll until an alert newer than \$1 matches the regex \$2, or SETTLE expires.
wait_alert() {
  local base="$1" re="$2" i
  for ((i=0;i<SETTLE;i++)); do
    new_alerts "$base" | grep -qiE "$re" && return 0
    sleep 1
  done
  return 1
}

BASE=$(max_id)
head_ "Baseline"
printf '  highest alert id before any attack: %s\n' "$BASE"
TRACKED=$(GET /api/choke/state | python3 -c "import sys,json;print(json.load(sys.stdin).get('tracked',0))" 2>/dev/null)
printf '  engine currently tracking %s processes\n' "${TRACKED:-?}"

# ── each simulation, with the signal it is SUPPOSED to raise ────────────────
# Asserting the specific description matters: "some alert fired" would pass
# even if every attack produced the same generic row, which is the failure mode
# that makes a detector useless in triage.
run_attack() {
  local script="$1" label="$2" re="$3"
  local before; before=$(max_id)
  head_ "$label"
  rx "sudo bash $ATTACK_DIR/$script >/dev/null 2>&1; echo done" >/dev/null
  if wait_alert "$before" "$re"; then
    local hit; hit=$(new_alerts "$before" | grep -iE "$re" | head -1)
    ok "$label detected — $(cut -d'|' -f3 <<<"$hit")"
    local sev score; sev=$(cut -d'|' -f1 <<<"$hit"); score=$(cut -d'|' -f2 <<<"$hit")
    # Severity is derived from score (>=40 critical, >=20 high, >=10 medium,
    # >=5 low). A mismatch means triage priority is wrong even though the
    # detection fired, which is subtler and worse than a miss.
    local want="info"
    (( score >= 5  )) && want="low"
    (( score >= 10 )) && want="medium"
    (( score >= 20 )) && want="high"
    (( score >= 40 )) && want="critical"
    if [[ "$sev" == "$want" ]]; then ok "  severity '$sev' matches score $score"
    else bad "severity for score $score" "got '$sev', the score band says '$want'"; fi
  else
    bad "$label detected" "no alert matching /$re/ within ${SETTLE}s"
  fi
}

run_attack 02-credential-theft.sh    "Credential theft (T1552 — reads /etc/shadow, ssh keys)" "credential file|sensitive file"
run_attack 04-privilege-escalation.sh "Privilege escalation (T1548 — setuid to root)"          "privilege escalation|setuid"
run_attack 03-reverse-shell.sh        "Reverse shell (T1059 — nc/socat with a shell argument)"  "reverse shell|network tool|outbound"
run_attack 05-living-off-the-land.sh  "Living off the land (T1218 — trusted binaries abused)"   "downloader|base64|shell|outbound|executable"
run_attack 01-webshell.sh             "Webshell (T1505 — shell spawned from a web path)"        "shell|downloader|outbound|executable"
run_attack 06-persistence.sh          "Persistence (T1053/T1543 — cron, systemd, rc files)"     "sensitive file|executable|shell|persistence"

# ── the pipeline as a whole ────────────────────────────────────────────────
head_ "Pipeline integrity"
TOTAL_NEW=$(new_alerts "$BASE" | wc -l | tr -d ' ')
if [[ "${TOTAL_NEW:-0}" -ge 4 ]]; then ok "attack run produced $TOTAL_NEW new alerts"
else bad "attack run produced alerts" "only ${TOTAL_NEW:-0} new alerts across 6 simulations"; fi

# A chain the engine can attribute is what makes an alert actionable — an
# alert with no exec_id cannot be pivoted to a process tree or choked.
NO_EXEC=$(alerts_json | python3 -c "
import sys,json
base=int(sys.argv[1])
d=json.load(sys.stdin); d=d if isinstance(d,list) else d.get('alerts',[])
print(sum(1 for a in d if a.get('id',0)>base and not a.get('exec_id')))" "$BASE")
if [[ "${NO_EXEC:-1}" == "0" ]]; then ok "every new alert carries an exec_id (pivotable to a process tree)"
else bad "alerts carry exec_id" "$NO_EXEC new alert(s) have no exec_id — not actionable in triage"; fi

# Detection must not have quietly armed enforcement: this rig is detect-only,
# and an attack simulation is exactly when an accidental kill would surface.
MODE=$(GET /api/choke/state | python3 -c "import sys,json;print(json.load(sys.stdin).get('mode',''))" 2>/dev/null)
if [[ "$MODE" == "detect-only" ]]; then ok "engine still detect-only after 6 attacks (detection did not self-arm)"
else bad "engine still detect-only" "mode is now '$MODE'"; fi

printf '\n=====================================\n'
printf 'PASS: %d   FAIL: %d\n' "$PASS" "$FAIL"
exit $((FAIL>0))
