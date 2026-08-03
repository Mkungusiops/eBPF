#!/usr/bin/env bash
#
# Proves the console NOTICES when a second enforcement authority appears.
#
# host-posture.sh asserts the fleet is currently clean. That is a different
# claim from "we would find out if it stopped being clean" — a divergence
# detector wired to a field nobody computes would pass the clean-state check
# forever. This arms a real enforcing Tetragon policy on one agent and requires
# the control plane to say so, then removes it and requires the console to go
# quiet again.
#
# SAFETY: the probe policy is a genuine `Sigkill` with NO monitor-mode guard —
# it has to be, or Tetragon would report it as monitor and there would be
# nothing to detect. It is scoped to a path that exists nowhere on the host
# (/var/tmp/.posture-probe-does-not-exist), so it can match no real process.
# It is removed from BOTH the runtime and every on-disk source, and the suite
# fails loudly if cleanup does not verify.
#
#   CONSOLE_URL=... MT_USER=... MT_PASS=... AGENT_RSH="ssh Tenant_A_agent" \
#     ./scripts/e2e/posture-divergence.sh
set -uo pipefail

BASE="${CONSOLE_URL:?set CONSOLE_URL}"
MT_USER="${MT_USER:?set MT_USER}"; MT_PASS="${MT_PASS:?set MT_PASS}"
AGENT_RSH="${AGENT_RSH:?set AGENT_RSH}"
# Posture reaches the console on the agent heartbeat (~30s), so both the arm
# and the disarm need a full interval before the absence of a change is real.
HB_WAIT="${HB_WAIT:-90}"
PROBE="probe-posture-divergence"

CURL=(curl)
for _r in ${CURL_RESOLVE:-}; do CURL+=(--resolve "$_r"); done

JAR="$(mktemp -d)/p.jar"; PASS=0; FAIL=0
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

kernel() { GET /api/choke/state | python3 -c "
import sys,json
k=(json.load(sys.stdin) or {}).get('kernel') or {}
print('%s|%s|%s|%s' % (k.get('diverged'), ','.join(k.get('diverged_agents') or []),
                       k.get('agents_reporting'), k.get('enforce_actions')))" 2>/dev/null; }
diverged() { cut -d'|' -f1 <<<"$(kernel)"; }
wait_div() { local want="$1" i; for ((i=0;i<HB_WAIT;i++)); do [[ "$(diverged)" == "$want" ]] && return 0; sleep 1; done; return 1; }

remove_probe() {
  ax "sudo docker exec tetragon tetra tracingpolicy delete $PROBE >/dev/null 2>&1
      sudo docker exec tetragon rm -f /etc/tetragon/tetragon.tp.d/$PROBE.yaml /tmp/$PROBE.yaml 2>/dev/null
      sudo rm -f /opt/ebpf-soc/policies/$PROBE.yaml /var/tmp/$PROBE.yaml 2>/dev/null; true" >/dev/null
}
trap remove_probe EXIT

head_ "Baseline — the fleet should be clean before we arm anything"
K=$(kernel)
printf '  diverged=%s agents_reporting=%s enforce_actions=%s\n' \
  "$(cut -d'|' -f1 <<<"$K")" "$(cut -d'|' -f3 <<<"$K")" "$(cut -d'|' -f4 <<<"$K")"
if [[ "$(diverged)" == "False" ]]; then ok "console reports no divergence to start"
else bad "no divergence at baseline" "already diverged (${K}) — clean up before running this"; fi

head_ "Arm a real enforcing policy on the agent"
ax "cat > /var/tmp/$PROBE.yaml <<'YAML'
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: \"$PROBE\"
spec:
  kprobes:
    - call: \"security_file_permission\"
      syscall: false
      return: true
      args:
        - index: 0
          type: \"file\"
        - index: 1
          type: \"int\"
      returnArg:
        index: 0
        type: \"int\"
      selectors:
        - matchArgs:
            - index: 0
              operator: \"Prefix\"
              values: [\"/var/tmp/.posture-probe-does-not-exist\"]
            - index: 1
              operator: \"Mask\"
              values: [\"4\"]
          matchActions:
            - action: Sigkill
YAML
sudo docker cp /var/tmp/$PROBE.yaml tetragon:/tmp/$PROBE.yaml >/dev/null 2>&1
sudo docker exec tetragon tetra tracingpolicy add /tmp/$PROBE.yaml 2>&1 | head -1" >/dev/null
sleep 2
MODE=$(ax "sudo docker exec tetragon tetra tracingpolicy list 2>/dev/null | awk '\$2==\"$PROBE\"{print \$(NF-3)}'")
if [[ "$MODE" == "enforce" ]]; then ok "probe policy is loaded in Tetragon's enforce mode (a real second authority)"
else bad "probe policy armed" "Tetragon reports mode='$MODE' — nothing for the console to detect"; fi

head_ "The console must notice"
if wait_div True; then
  K=$(kernel)
  ok "console reports diverged=true within ${HB_WAIT}s"
  AG=$(cut -d'|' -f2 <<<"$K")
  if [[ -n "$AG" ]]; then ok "it names the offending agent(s): $AG"
  else bad "divergence names the agent" "diverged_agents is empty — an operator cannot act on this"; fi
else
  bad "console reports the divergence" "still diverged=$(diverged) after ${HB_WAIT}s — an armed kernel authority is INVISIBLE to the operator"
fi

head_ "Remove it — the signal must clear, not latch"
remove_probe
LEFT=$(ax "sudo docker exec tetragon tetra tracingpolicy list 2>/dev/null | grep -c $PROBE")
if [[ "${LEFT:-1}" == "0" ]]; then ok "probe policy removed from the agent"
else bad "probe removed" "still loaded — CLEAN THIS UP BY HAND before deploying"; fi

if wait_div False; then ok "console returns to no-divergence (the flag clears, it does not stick)"
else bad "divergence clears" "still reporting diverged after removal — a stuck alarm is as bad as a missing one"; fi

printf '\n=====================================\n'
printf 'PASS: %d   FAIL: %d\n' "$PASS" "$FAIL"
exit $((FAIL>0))
