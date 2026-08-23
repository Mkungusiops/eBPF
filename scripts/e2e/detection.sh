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
# -n and a hard timeout, both learned the same way.
#
# Without -n, ssh inherits the suite's stdin and a remote command that reads it
# blocks forever. Without the timeout, ANY remote stall — a throttled sshd, a
# loaded box, a command that never returns — wedges the whole run with no error
# and no output, which is exactly how a 28-minute hang in this suite was
# mistaken for a product failure. A remote call that cannot answer in 30s has
# failed; saying so lets the assertion fail loudly instead of the suite hanging
# silently.
rx()   { timeout 30 $RSH "$1" 2>/dev/null | tr -d '\r'; }
# The same host, deliberately WITHOUT connection multiplexing, so a command run
# through it lands on its own sshd session and therefore its own process chain.
# See run_attack for why that matters.
RSH_FRESH="timeout 60 ${RSH/ssh /ssh -o ControlPath=none }"

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
# limit=2000, not the default 200. Measured on the live engine 2026-08-22: the
# newest 2000 alerts spanned 11.5 hours, so ~3 a minute of ordinary background
# noise with nobody attacking anything. The default page covers a little over
# an hour of that, which is enough for one run and not enough for a run that
# stalls, and a page that no longer reaches BASE makes every count taken
# against it silently undercount. Cheap insurance.
alerts_json() { GET '/api/alerts?limit=2000'; }
max_id() {
  alerts_json | python3 -c "
import sys,json
d=json.load(sys.stdin); d=d if isinstance(d,list) else d.get('alerts',[])
print(max([a.get('id',0) for a in d], default=0))"
}
# Alerts newer than \$1, as 'severity|score|description|exec_id' lines.
new_alerts() {
  alerts_json | python3 -c "
import sys,json
base=int(sys.argv[1])
d=json.load(sys.stdin); d=d if isinstance(d,list) else d.get('alerts',[])
for a in d:
    if a.get('id',0) > base:
        print('%s|%s|%s|%s' % (a.get('severity'), a.get('score'),
              (a.get('description') or a.get('title') or '').replace('|','/'),
              a.get('exec_id') or ''))" "$1"
}

# ── attribution: is this alert the ATTACK's, or the harness's own footprint? ─
#
# Every assertion below used to be a description regex and nothing else, and
# that is why this suite passed on work it never did. Measured on the live
# engine 2026-08-22: a single
#     ssh single_tenant_engine "sudo bash -c 'sleep 1; true'"
# with NO attack at all produced six alerts, among them
#     "Privilege escalation: setuid to root"   (score 20, high)
#     "Sensitive file accessed: /etc/passwd"
#     "Shell -c invocation — ..."
# Five of the six regexes used below match that set. The suite was asserting
# its own ssh login six times over, and would have kept passing with every
# attack script deleted.
#
# So an alert now has to be traced to the attack's own process subtree. Each
# run is launched as
#     sudo bash -c 'bash <script>' <marker>
# which puts <marker> in the argv of the sudo node AND the bash node that every
# process the attack spawns descends from. /api/process/<exec_id> returns that
# chain (tree.Ancestors, capped at 10 levels; nodes live 10 minutes, well past
# SETTLE), so the alert is this attack's only if <marker> appears in one of its
# ancestors.
#
# What this deliberately does NOT do is exclude chains rooted at the harness's
# sshd session. It cannot: the attack runs over that session, so a real attack
# alert and the login noise share a chain ROOT. Verified on the run above — the
# setuid alert's chain carried the marker, while the MOTD-recon alert from the
# SAME ssh connection did not. Attribution has to happen below the root.
#
# rc 0 = this attack's, 1 = someone else's, 2 = chain unreadable,
# 3 = no chain (node gone or never in the tree), 10 = ancestor cap hit, so a
# marker further up could not be seen. Only 0 passes; the rest are reported.
attributed() {   # $1 = exec_id, $2 = marker
  local eid="$1" mark="$2"
  [[ -n "$eid" ]] || return 3
  GET "/api/process/$eid" | python3 -c "
import sys,json
mark=sys.argv[1]
try:
    d=json.load(sys.stdin)
except Exception:
    sys.exit(2)
chain=d.get('chain') or []
if not chain:
    sys.exit(3)
for n in chain:
    if mark in ((n.get('args') or '') + ' ' + (n.get('binary') or '')):
        sys.exit(0)
sys.exit(10 if len(chain) >= 10 else 1)" "$2"
}

# Poll until an alert newer than \$1 matches the regex \$2 AND descends from the
# marker \$3, or SETTLE expires. On success HIT holds the winning alert line.
HIT=""; ATTR_RC=""
wait_alert() {
  local base="$1" re="$2" mark="$3" i line eid rc seen=","
  HIT=""; ATTR_RC=""
  for ((i=0;i<SETTLE;i++)); do
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      eid=$(cut -d'|' -f4 <<<"$line")
      # One chain lookup per exec_id per attack; a verdict of "not ours" is
      # final, an unreadable chain may become readable on the next tick.
      [[ "$seen" == *",$eid,"* ]] && continue
      attributed "$eid" "$mark"; rc=$?
      if (( rc == 0 )); then HIT="$line"; return 0; fi
      ATTR_RC=$rc
      (( rc == 1 )) && seen="$seen$eid,"
    done < <(new_alerts "$base" | grep -iE "$re")
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
# How many of the six raised an alert on their OWN chain. Counted here rather
# than derived from the alert total, which is dominated by background noise.
ATTRIBUTED_N=0

run_attack() {
  local script="$1" label="$2" re="$3"
  local before; before=$(max_id)
  head_ "$label"
  # EACH ATTACK GETS ITS OWN SSH SESSION, and that is a correctness requirement
  # rather than a preference.
  #
  # The engine deduplicates alerts per PROCESS CHAIN: once a chain has reported
  # a finding, later events carrying the same finding are suppressed unless the
  # severity band climbs (see tree.EscalateAlert — it is what stopped 91 of 100
  # alerts being critical). Every attack here runs as `sudo bash <script>` over
  # ssh, so its chain root is the sshd session it arrived on.
  #
  # Share one multiplexed connection across all six attacks and they share one
  # chain root — so attack #2's setuid is deduplicated against attack #1's, and
  # the suite reports "no privilege-escalation alert" about an engine that
  # detected it perfectly. Measured: on a fresh chain the same script produces
  # "Privilege escalation: setuid to root", score 35, every time.
  #
  # Multiplexing is kept for every OTHER call in this suite — the polling is
  # what caused the connection storm — and disabled for exactly this one, which
  # restores an independent chain per attack.
  # The marker: unique to this run, planted in the attack's own argv so the
  # engine's process tree can tell this attack's alerts from the ssh login that
  # launched it. The extra `bash -c` adds one level to the chain (measured
  # depth 5-8, against an API cap of 10) and leaves the script's own argv
  # untouched — the marker lands in $0 of the wrapper, which nothing reads.
  local mark="e2emark-${script%%-*}-$$-${RANDOM}${RANDOM}"
  $RSH_FRESH "sudo bash -c 'bash $ATTACK_DIR/$script >/dev/null 2>&1' $mark; echo done" >/dev/null 2>&1
  if wait_alert "$before" "$re" "$mark"; then
    local hit="$HIT"
    ATTRIBUTED_N=$((ATTRIBUTED_N+1))
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
    # Separate the two failures. "Nothing matched" is a detection regression.
    # "Something matched but none of it was ours" is the harness's own noise
    # answering for the attack — the exact bug this attribution exists to
    # catch — and calling it a miss would send the reader hunting the scorer.
    local candidates; candidates=$(new_alerts "$before" | grep -icE "$re")
    if [[ "${candidates:-0}" -gt 0 ]]; then
      bad "$label detected" "${candidates} alert(s) matched /$re/ within ${SETTLE}s but NONE descended from this run (marker $mark; last chain verdict rc=${ATTR_RC:-none} — 1=another chain, 2=chain unreadable, 3=node not in the tree, 10=hit the 10-ancestor cap). Either the attack raised nothing and the harness's own login matched, or the chain broke."
    else
      bad "$label detected" "no alert matching /$re/ within ${SETTLE}s"
    fi
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
# Counting NEW alerts proves nothing on a live box: this estate raises ~3 a
# minute with nobody logged in, and each of the six ssh logins this suite makes
# raises about six more on its own. The number that means something is how many
# simulations produced an alert the engine could trace back to the simulation.
printf '  %s new alerts in total (most of them background noise and this suite'"'"'s own logins)\n' "$TOTAL_NEW"
if [[ "$ATTRIBUTED_N" -ge 4 ]]; then ok "$ATTRIBUTED_N of 6 simulations alerted on their OWN process chain"
else bad "simulations alert on their own process chain" "only $ATTRIBUTED_N of 6 — the rest were either not detected or not attributable"; fi

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
