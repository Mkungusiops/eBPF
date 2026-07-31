#!/usr/bin/env bash
#
# Asserts the DECLARED enforcement posture matches the kernel's actual one.
#
# The platform has two enforcement authorities: the engine's choke gateway
# (governed — honours the operator's mode, writes an audit row, reversible,
# covered by the kill-switch) and Tetragon TracingPolicies (ungoverned — a
# `Sigkill` fires regardless of what mode the console says it is in).
#
# When the second one is armed, "detect-only" in the UI is a lie, and the
# divergence is invisible until something dies. That is threat-model EN-3.
# Two real incidents on this rig came from exactly that gap:
#
#   * an enforcing credential-read policy SIGKILLed the OpenSSH login path
#     and locked the operator out of the host;
#   * the same policy killed `debconf` mid-configure on three hosts, leaving
#     packages in `iF`/`iU` and blocking all further apt.
#
# So the posture is asserted, not assumed — and asserted against TETRAGON, not
# against the YAML on disk. The two disagree in both directions: a file edited
# but never reloaded still runs its old version, and a policy deleted at runtime
# returns on the next restart if its file remains. Only the daemon knows what is
# actually loaded, and it classifies each policy itself.
#
#   ENGINE_RSH="ssh engine" AGENT_RSH="ssh a" AGENT_B_RSH="ssh b" \
#     ./scripts/e2e/host-posture.sh
set -uo pipefail

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n     -> %s\n' "$1" "${2:-}"; }
head_(){ printf '\n=== %s ===\n' "$1"; }

# Actions that kill or divert a syscall with no engine involvement. `Post` is
# reporting and is deliberately absent. Anchored to a real YAML list item, NOT a
# bare substring: these policies carry long comments explaining which actions
# were rejected and why, so an unanchored match reports every well-documented
# detect-only policy as armed.
ENFORCING_RE='^[[:space:]]*-?[[:space:]]*action:[[:space:]]*(Sigkill|Override|NotifyEnforcer)'

# Source directories, in load precedence. A file here outlives a runtime delete.
HOST_DIRS='/opt/ebpf-soc/policies /var/lib/ebpf-engine/policies'
AUTOLOAD='/etc/tetragon/tetragon.tp.d'

# `tetra tracingpolicy list` columns:
#   ID NAME STATE FILTERID NAMESPACE SENSORS KERNELMEMORY MODE NPOST NENFORCE NMONITOR
# KERNELMEMORY prints as two fields ("4.27 MB"), so index from the RIGHT.
TETRA_ROWS='sudo docker exec tetragon tetra tracingpolicy list 2>/dev/null | awk "NR>1{n=NF; print \$2, \$(n-3), \$(n-1)}"'

check_host() {
  local label="$1" rsh="$2"
  head_ "$label"

  # name / mode / nenforce, one policy per line.
  local rows
  rows=$($rsh "$TETRA_ROWS" 2>/dev/null | tr -d '\r' | sed '/^[[:space:]]*$/d')
  if [[ -z "$rows" ]]; then
    bad "$label: Tetragon is reachable and has policies loaded" \
        "no policies listed — Tetragon down, or observability is silently absent"
    return
  fi
  ok "$label: Tetragon loaded $(wc -l <<<"$rows" | tr -d ' ') policies"

  # (1) THE assertion, straight from the daemon. Everything this repo ships
  # declares `policy-mode: monitor`, under which Tetragon suppresses enforcing
  # actions in-kernel (verified on v1.6.1: a Sigkill policy returned exit 0 with
  # the option and 137 without, while Post delivery was identical). So a policy
  # reporting `enforce` is either hand-loaded or deliberately armed.
  local armed
  armed=$(awk '$2!="monitor"{printf "%s(mode=%s) ", $1, $2}' <<<"$rows")
  if [[ -z "$armed" ]]; then
    ok "$label: every loaded policy is in monitor mode (detect-only is honest)"
  else
    bad "$label: every loaded policy is in monitor mode" \
        "ARMED: ${armed% } — the console will report detect-only while the kernel can kill"
  fi

  # (2) Evidence beats prediction. A non-zero enforce counter means this host has
  # already killed something with no engine decision behind it — so there is no
  # audit row for it, and nothing to reverse.
  local fired
  fired=$(awk '$3!="0" && $3!=""{printf "%s(%s) ", $1, $3}' <<<"$rows")
  if [[ -z "$fired" ]]; then
    ok "$label: no kernel enforcement action has ever fired"
  else
    bad "$label: no kernel enforcement action has ever fired" \
        "FIRED: ${fired% } — killed outside the engine, unaudited and irreversible"
  fi

  # (3) What would arm itself on the next restart. A policy carrying an enforcing
  # action is only safe because of its monitor declaration, so the pair must
  # travel together — a file with the action but not the declaration loads in
  # enforce mode by default.
  local staged
  staged=$($rsh "sudo grep -rlE \"$ENFORCING_RE\" $HOST_DIRS $AUTOLOAD 2>/dev/null | while read -r f; do sudo grep -q 'policy-mode' \"\$f\" || echo \"\$f\"; done" 2>/dev/null | tr -d '\r' | tr '\n' ' ')
  if [[ -z "${staged// }" ]]; then
    ok "$label: no unguarded enforcing policy staged on disk (posture survives a restart)"
  else
    bad "$label: no unguarded enforcing policy staged on disk" "would load armed on restart: ${staged% }"
  fi

  # (4) EN-1: the login path must never be killable. The failure mode is losing
  # the host, recoverable only by racing the kprobe attach at boot.
  local sshd_risk
  sshd_risk=$($rsh "sudo docker exec tetragon sh -c 'grep -lE \"$ENFORCING_RE\" $AUTOLOAD/*.yaml 2>/dev/null | xargs -r grep -L sshd-session' 2>/dev/null" 2>/dev/null | tr -d '\r' | tr '\n' ' ')
  if [[ -z "${sshd_risk// }" ]]; then
    ok "$label: no enforcing policy that omits the OpenSSH split-process path"
  else
    bad "$label: SSH lockout risk" "enforcing without allowlisting sshd-session: ${sshd_risk% }"
  fi
}

[[ -n "${ENGINE_RSH:-}"  ]] && check_host "single-tenant engine" "$ENGINE_RSH"
[[ -n "${AGENT_RSH:-}"   ]] && check_host "tenant A agent"       "$AGENT_RSH"
[[ -n "${AGENT_B_RSH:-}" ]] && check_host "tenant B agent"       "$AGENT_B_RSH"

if (( PASS + FAIL == 0 )); then
  echo "no hosts given — set ENGINE_RSH / AGENT_RSH / AGENT_B_RSH" >&2
  exit 2
fi

printf '\n=====================================\n'
printf 'PASS: %d   FAIL: %d\n' "$PASS" "$FAIL"
exit $((FAIL>0))
