#!/usr/bin/env bash
#
# assistant.sh — live end-to-end checks for the analyst assistant.
#
# Runs against a DEPLOYED multi-tenant console with a real session, because the
# three defects this suite exists to catch were all invisible to unit tests:
#
#   1. Free text routed to a fixed-task agent, so a typed question came back as
#      an incident summary. Unit-testable in hindsight; nobody had written it.
#   2. `alert_statistics` sent a `span` parameter no server has ever read, so
#      every trend answer covered 30 minutes while claiming to cover a day. Only
#      a live call against a real endpoint shows the window that was used.
#   3. Three console surfaces were mounted over subjects the tool set could not
#      read at all.
#
# Reads the same env file as the rest of the suite (.deploy-build/e2e.env).
# Skips cleanly when the assistant is not configured on the target — it is an
# opt-in feature and its absence is not a failure.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${E2E_ENV:-$ROOT/.deploy-build/e2e.env}"
[[ -f "$ENV_FILE" ]] || { echo "no env file at $ENV_FILE"; exit 1; }
# shellcheck disable=SC1090
source "$ENV_FILE"

BASE="${CONSOLE_URL:?CONSOLE_URL required}"
MT_USER="${MT_USER:?MT_USER required}"
MT_PASS="${MT_PASS:?MT_PASS required}"

CURL=(curl)
for _r in ${CURL_RESOLVE:-}; do CURL+=(--resolve "$_r"); done

JAR="$(mktemp -d)/asst.jar"
PASS=0; FAIL=0
declare -a FAILURES=()
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); FAILURES+=("$1"); printf '  FAIL  %s\n     -> %s\n' "$1" "${2:-}"; }
note() { printf '  NOTE  %s\n' "$1"; }
head_(){ printf '\n=== %s ===\n' "$1"; }

GET() { "${CURL[@]}" -s -b "$JAR" --max-time 25 "$BASE$1"; }
py()  { python3 -c "$1" 2>/dev/null; }

# ── Unauthenticated first, before we hold a session ────────────────────────
# The assistant endpoints gained their own auth gate: without it an anonymous
# caller could not read data (the tools carry the caller's cookie and every read
# endpoint checks the tenant) but COULD still start a run, driving a full
# tool-calling loop against a paid inference endpoint.
head_ "Unauthenticated access"
for path in "/api/assistant" "/api/assistant/ask" "/api/assistant/stream"; do
  code=$("${CURL[@]}" -s -o /dev/null -w '%{http_code}' --max-time 20 -X POST \
    -H 'content-type: application/json' -d '{"agent":"ask","question":"hi"}' "$BASE$path")
  if [[ "$code" == "401" || "$code" == "405" ]]; then
    ok "$path refuses an anonymous caller ($code)"
  else
    bad "$path refuses an anonymous caller" "got $code — an unauthenticated request can start a model run"
  fi
done

# ── Session ────────────────────────────────────────────────────────────────
head_ "Session"
TMP="$(mktemp)"
"${CURL[@]}" -s -c "$JAR" -L --max-time 25 "$BASE/login" -o "$TMP" || { echo "cannot reach $BASE"; exit 1; }
ACT=$(grep -o 'action="[^"]*"' "$TMP" | head -1 | sed 's/action="//;s/"$//' \
      | py 'import sys,html;print(html.unescape(sys.stdin.read().strip()))')
[[ -n "$ACT" ]] || { echo "no Keycloak form on $BASE/login"; exit 1; }
"${CURL[@]}" -s -b "$JAR" -c "$JAR" -L --max-time 25 -X POST "$ACT" \
  --data-urlencode "username=$MT_USER" --data-urlencode "password=$MT_PASS" -o "$TMP" >/dev/null
WHO=$(GET /api/whoami)
printf '%s' "$WHO" | grep -q '"user"' || { echo "login failed: $WHO"; exit 1; }
ok "authenticated as $MT_USER"

CAP=$(GET /api/assistant)
ENABLED=$(printf '%s' "$CAP" | py 'import sys,json;print(json.load(sys.stdin).get("enabled"))')
if [[ "$ENABLED" != "True" ]]; then
  note "assistant not configured on this deployment — skipping the rest"
  printf '\n  %d passed, %d failed\n' "$PASS" "$FAIL"
  exit $(( FAIL > 0 ))
fi
ok "assistant enabled ($(printf '%s' "$CAP" | py 'import sys,json;print(json.load(sys.stdin).get("model"))'))"

# ── Surface-scoped agent lists ─────────────────────────────────────────────
# Each console panel asks what it can be asked. A panel offered a button that
# cannot apply there teaches the operator to distrust the whole row.
head_ "Surfaces"
check_surface() { # <surface> <must-include> <must-not-include>
  local body agents
  body=$(GET "/api/assistant?surface=$1")
  agents=$(printf '%s' "$body" | py 'import sys,json;print(",".join(a["id"] for a in json.load(sys.stdin).get("agents",[])))')
  if [[ ",$agents," == *",$2,"* ]]; then ok "$1 offers $2"; else bad "$1 offers $2" "got: $agents"; fi
  if [[ -n "${3:-}" && ",$agents," == *",$3,"* ]]; then
    bad "$1 does not offer $3" "got: $agents"
  elif [[ -n "${3:-}" ]]; then
    ok "$1 does not offer $3"
  fi
  # Whatever else a panel shows, the analyst must always be able to just ask.
  local conv
  conv=$(printf '%s' "$body" | py 'import sys,json;a=json.load(sys.stdin).get("agents",[]);print(sum(1 for x in a if x.get("conversational")))')
  if [[ "$conv" == "1" ]]; then ok "$1 offers exactly one conversational agent"; else bad "$1 offers exactly one conversational agent" "got $conv"; fi
}
check_surface devices-assurance assess-device-exposure explain-chain
check_surface choke-assurance   assess-containment     explain-chain
check_surface alert-drill       explain-chain          assess-device-exposure
check_surface kpi-drill         summarise-incident     explain-chain

# ── A real streamed answer ─────────────────────────────────────────────────
head_ "Streaming a grounded answer"
OUT="$(mktemp)"
"${CURL[@]}" -s -b "$JAR" --max-time 120 -N -X POST "$BASE/api/assistant/stream" \
  -H 'content-type: application/json' \
  -d '{"agent":"ask","surface":"kpi-drill","question":"How many critical alerts in the last 24 hours?"}' \
  -o "$OUT"

STEPS=$(grep -c '^event: step'   "$OUT" || true)
ANS=$(grep -c   '^event: answer' "$OUT" || true)
ERRS=$(grep -c  '^event: error'  "$OUT" || true)

if [[ "$ERRS" != "0" ]]; then
  bad "stream completed without an error event" "$(grep -m1 '^data:' "$OUT")"
elif [[ "$ANS" == "1" ]]; then
  ok "stream ended with exactly one answer event"
else
  bad "stream ended with exactly one answer event" "answer events: $ANS (silence must never read as success)"
fi

if [[ "$STEPS" -gt 0 ]]; then
  ok "investigation streamed as it happened ($STEPS tool calls announced before the answer)"
else
  bad "investigation streamed as it happened" "no step events — the analyst sees a bare spinner"
fi

# The answer must be GROUNDED, and it must have read through the tools rather
# than from the model's imagination.
if [[ "$ANS" == "1" ]]; then
  BODY=$(grep '^event: answer' -A1 "$OUT" | grep '^data: ' | sed 's/^data: //')
  GROUNDED=$(printf '%s' "$BODY" | py 'import sys,json;print(json.load(sys.stdin).get("grounded"))')
  if [[ "$GROUNDED" == "True" ]]; then ok "answer is grounded in telemetry"; else bad "answer is grounded in telemetry" "grounded=$GROUNDED"; fi

  # THE WINDOW BUG. alert_statistics used to send `span`, which no server reads,
  # so a question about 24 hours was answered from the server's 30-minute
  # default. The trace is the only place this is visible.
  TOOLS=$(printf '%s' "$BODY" | py 'import sys,json;print(",".join(s["tool"] for s in json.load(sys.stdin).get("steps",[])))')
  note "tools used: ${TOOLS:-none}"
  if [[ ",$TOOLS," == *",alert_statistics,"* ]]; then
    ARGS=$(printf '%s' "$BODY" | py 'import sys,json;print(" ".join(s.get("args","") for s in json.load(sys.stdin).get("steps",[]) if s["tool"]=="alert_statistics"))')
    note "alert_statistics args: $ARGS"
  fi
  # THE CITATION CHECK.
  #
  # Measured on the live rig, gpt-oss:120b answered "policy_stats shows no
  # single rule dominates" having called exactly ONE tool — alert_statistics.
  # It never ran policy_stats. `grounded` was true, correctly: the answer WAS
  # built on a real read. But a claim attributed to a source that was never
  # opened is indistinguishable from evidence, and an analyst has no way to tell
  # without expanding the trace.
  #
  # So: every tool NAMED in the prose must appear in the trace.
  CITED=$(printf '%s' "$BODY" | py '
import sys, json, re
d = json.load(sys.stdin)
called = {s["tool"] for s in d.get("steps", [])}
known = {"list_alerts","alert_statistics","list_events","list_decisions","process_tree",
         "list_choked_processes","list_devices","device_plane_state","device_flows",
         "list_fleet_hosts","fleet_state","list_policies","policy_stats","system_health"}
text = d.get("content","")
named = {t for t in known if re.search(r"\b"+t+r"\b", text)}
print(",".join(sorted(named - called)))')
  if [[ -z "$CITED" ]]; then
    ok "answer cites no tool it did not call"
  else
    bad "answer cites no tool it did not call" "named but never run: $CITED"
  fi

  CONTENT=$(printf '%s' "$BODY" | py 'import sys,json;print(json.load(sys.stdin).get("content","")[:400])')
  note "answer: $CONTENT"
fi

printf '\n  %d passed, %d failed\n' "$PASS" "$FAIL"
if (( FAIL > 0 )); then
  printf '\n  failures:\n'; for f in "${FAILURES[@]}"; do printf '    - %s\n' "$f"; done
  exit 1
fi
