#!/usr/bin/env bash
#
# enrichment.sh — live end-to-end checks for the two detection layers added on
# top of the static chain scorer: the behavioural baseline and threat-intel
# matching.
#
# Runs against a DEPLOYED console with a real session. What it is actually
# guarding is not "does the endpoint return 200" — it is the family of failures
# where the feature is SILENTLY OFF and looks identical to a clean estate:
#
#   1. A feed directory that shipped empty, or whose files failed to parse.
#      Zero indicators match nothing, and "no matches" then reads as "no
#      threats". The only way to tell is to check how many indicators loaded.
#   2. A baseline that never becomes ready, so it never scores. An empty anomaly
#      list means "still learning", which is not "nothing unusual".
#   3. A feed that matches the estate's OWN infrastructure — private ranges, or
#      the inference endpoint — which turns every uplink into a C2 alert. That
#      one is loud rather than silent, but it discredits the whole feature on
#      first contact, so it is asserted here rather than hoped for.
#
# Reads the same env file as the rest of the suite (.deploy-build/e2e.env).
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

JAR="$(mktemp -d)/enrich.jar"
PASS=0; FAIL=0
declare -a FAILURES=()
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); FAILURES+=("$1"); printf '  FAIL  %s\n     -> %s\n' "$1" "${2:-}"; }
note() { printf '  NOTE  %s\n' "$1"; }
head_(){ printf '\n=== %s ===\n' "$1"; }

GET() { "${CURL[@]}" -s -b "$JAR" --max-time 25 "$BASE$1"; }
py()  { python3 -c "$1" 2>/dev/null; }

# ── Anonymous callers first, before we hold a session ──────────────────────
# These endpoints describe how detection behaves on this deployment. An
# anonymous reader must not learn which indicators are loaded (that is a map of
# what this estate can and cannot see) nor what its hosts consider normal.
head_ "Unauthenticated access"
for path in "/api/baseline" "/api/intel" "/api/intel/matches" "/api/baseline/anomalies"; do
  code=$("${CURL[@]}" -s -o /dev/null -w '%{http_code}' --max-time 20 "$BASE$path")
  if [[ "$code" == "401" || "$code" == "403" ]]; then
    ok "$path refuses an anonymous caller ($code)"
  else
    bad "$path refuses an anonymous caller" "got $code"
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

# ── Threat intelligence ────────────────────────────────────────────────────
head_ "Threat-intelligence feeds"
INTEL=$(GET /api/intel)
LOADED=$(printf '%s' "$INTEL" | py 'import sys,json;print(json.load(sys.stdin)["status"].get("loaded"))')
COUNT=$(printf '%s' "$INTEL"  | py 'import sys,json;print(json.load(sys.stdin)["status"].get("indicators",0))')
ERRS=$(printf '%s' "$INTEL"   | py 'import sys,json;print(len(json.load(sys.stdin)["status"].get("errors") or []))')

if [[ "$LOADED" == "True" ]]; then
  ok "a feed directory is loaded"
else
  bad "a feed directory is loaded" "status.loaded=$LOADED — nothing can match, so an empty match list means nothing"
fi

# The assertion that matters most. A deployment reporting zero indicators is
# indistinguishable, on every other panel, from a deployment with nothing to find.
if [[ "${COUNT:-0}" -gt 0 ]]; then
  ok "$COUNT indicators loaded"
else
  bad "indicators are loaded" "0 indicators — 'no matches' on this estate is not evidence of anything"
fi

if [[ "${ERRS:-0}" -eq 0 ]]; then
  ok "no feed failed to parse"
else
  bad "no feed failed to parse" "$ERRS feed problem(s); a partially-parsed feed silently narrows coverage"
fi

SOURCES=$(printf '%s' "$INTEL" | py 'import sys,json;print(", ".join(s["source"]+"="+str(s["indicators"]) for s in json.load(sys.stdin)["status"].get("sources") or []))')
note "sources: ${SOURCES:-none}"

# ── The estate must not match its own infrastructure ───────────────────────
head_ "False-positive guards"
# Private space, the control plane's own private IP, and the metadata service.
# A feed listing any of these would mark every agent uplink as C2 traffic.
for ip in 10.0.0.5 172.31.45.193 192.168.1.1 127.0.0.1 169.254.169.254; do
  M=$(GET "/api/intel/lookup?q=$ip" | py 'import sys,json;print(json.load(sys.stdin).get("matched"))')
  if [[ "$M" == "False" ]]; then
    ok "$ip does not match (unroutable addresses are excluded)"
  else
    bad "$ip does not match" "matched=$M — internal traffic would alert as C2"
  fi
done

# The inference endpoint the assistant itself calls.
M=$(GET "/api/intel/lookup?q=openweights.adanianlabs.io" | py 'import sys,json;print(json.load(sys.stdin).get("matched"))')
if [[ "$M" == "False" ]]; then
  ok "the platform's own inference endpoint is allowlisted"
else
  bad "the platform's own inference endpoint is allowlisted" "matched=$M"
fi

# And the positive control: the shipped starter feed must actually match, or the
# lookup path is broken and every negative above is meaningless.
M=$(GET "/api/intel/lookup?q=198.51.100.7" | py 'import sys,json;print(json.load(sys.stdin).get("matched"))')
if [[ "$M" == "True" ]]; then
  ok "the starter feed's smoke-test address matches (lookup path works)"
else
  note "198.51.100.7 does not match — starter feed replaced by real intel? (every negative above is then unproven)"
fi

# ── Behavioural baseline ───────────────────────────────────────────────────
head_ "Behavioural baseline"
BL=$(GET "/api/baseline?top=5")
BENABLED=$(printf '%s' "$BL" | py 'import sys,json;print(json.load(sys.stdin).get("enabled"))')
READY=$(printf '%s' "$BL"    | py 'import sys,json;print(json.load(sys.stdin)["status"].get("ready"))')
OBS=$(printf '%s' "$BL"      | py 'import sys,json;print(json.load(sys.stdin)["status"].get("observations",0))')
NEED=$(printf '%s' "$BL"     | py 'import sys,json;print(json.load(sys.stdin)["status"].get("need_observations",0))')

if [[ "$BENABLED" == "True" ]]; then
  ok "the baseline is enabled"
else
  bad "the baseline is enabled" "enabled=$BENABLED"
fi

# Readiness is REPORTED, not required: a freshly deployed host is legitimately
# still learning. What must never happen is readiness being unreportable, which
# is what makes "no anomalies" ambiguous.
if [[ -n "$OBS" && -n "$NEED" && "${NEED:-0}" -gt 0 ]]; then
  ok "warm-up progress is reportable ($OBS/$NEED observations, ready=$READY)"
else
  bad "warm-up progress is reportable" "cannot distinguish 'still learning' from 'nothing unusual'"
fi
[[ "$READY" == "True" ]] || note "baseline still warming — anomaly scoring is not active yet on this deployment"

FACETS=$(printf '%s' "$BL" | py 'import sys,json;print(", ".join(f["facet"]+"="+str(f["keys"]) for f in json.load(sys.stdin)["status"].get("facets") or []))')
note "facets: ${FACETS:-none}"

# ── The assistant can actually read both layers ────────────────────────────
head_ "Assistant tool wiring"
CAP=$(GET /api/assistant)
if printf '%s' "$CAP" | grep -q '"enabled":true'; then
  CSRF=$(grep -oE 'csrf_token[[:space:]]+[^[:space:]]+$' "$JAR" | awk '{print $NF}' | tail -1)
  ANS=$("${CURL[@]}" -s -b "$JAR" --max-time 90 -X POST "$BASE/api/assistant/ask" \
        -H 'content-type: application/json' ${CSRF:+-H "X-CSRF-Token: $CSRF"} \
        -d '{"agent":"ask","question":"How many threat intelligence indicators are loaded, and is the behavioural baseline ready yet?","surface":"kpi-drill"}')
  TOOLS=$(printf '%s' "$ANS" | py 'import sys,json;print(",".join(s["tool"] for s in json.load(sys.stdin).get("steps") or []))')
  # The point of the question is that it cannot be answered from alerts. If the
  # model reached for the enrichment tools, they are registered and reachable.
  if printf '%s' "$TOOLS" | grep -qE 'threat_intel_status|baseline_profile'; then
    ok "the assistant reached the enrichment tools ($TOOLS)"
  else
    bad "the assistant reached the enrichment tools" "called: ${TOOLS:-none}"
  fi
  GROUNDED=$(printf '%s' "$ANS" | py 'import sys,json;print(json.load(sys.stdin).get("grounded"))')
  if [[ "$GROUNDED" == "True" ]]; then
    ok "the answer is grounded in tool output"
  else
    bad "the answer is grounded in tool output" "grounded=$GROUNDED"
  fi
  note "answer: $(printf '%s' "$ANS" | py 'import sys,json;print(json.load(sys.stdin).get("content","")[:300])')"
else
  note "assistant not configured on this deployment — tool wiring not checked"
fi

# ── Platform glossary ──────────────────────────────────────────────────────
head_ "Platform glossary"
DOC=$(GET "/api/platform-doc?topic=behavioural-baseline")
if printf '%s' "$DOC" | grep -q '"matched":true'; then
  ok "the glossary answers a known topic"
else
  bad "the glossary answers a known topic" "$(printf '%s' "$DOC" | head -c 200)"
fi
# An unknown topic returns the list rather than a 404: the caller is usually a
# model, and a 404 teaches it the endpoint is broken.
DOC=$(GET "/api/platform-doc?topic=does-not-exist")
if printf '%s' "$DOC" | grep -q '"matched":false' && printf '%s' "$DOC" | grep -q '"topics"'; then
  ok "an unknown topic returns the available topics, not a 404"
else
  bad "an unknown topic returns the available topics" "$(printf '%s' "$DOC" | head -c 200)"
fi

printf '\n  %d passed, %d failed\n' "$PASS" "$FAIL"
if (( FAIL > 0 )); then
  printf '\n  failures:\n'; for f in "${FAILURES[@]}"; do printf '    - %s\n' "$f"; done
  exit 1
fi
