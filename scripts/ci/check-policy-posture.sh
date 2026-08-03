#!/usr/bin/env bash
#
# CI gate: every shipped TracingPolicy must be disarmed by declaration.
#
# The platform has two enforcement authorities. The engine's choke gateway is
# governed — it honours the operator's mode, writes an audit row, is reversible,
# and the kill-switch reaches it. A Tetragon policy is not: a `Sigkill` fires
# regardless of what the console says the mode is, with no audit row and no way
# to undo it. So every policy here declares `policy-mode: monitor`, which makes
# Tetragon suppress enforcing actions in-kernel whatever the selectors say.
#
# Until now that invariant held only because it was set by hand.
# scripts/e2e/host-posture.sh catches a violation on the live fleet, but it
# needs the AWS rig and it only runs when someone remembers. A policy added
# months from now with the option missing would ship silently — the same shape
# as sever-pipe-to-shell, which shipped `Sigkill`, was loaded on every host, and
# never fired once: a control that looks like coverage.
#
# Static. No rig, no cluster, no credentials. Runs on every push.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FAIL=0

# Anchored to a real YAML list item. These files discuss the actions they
# REJECTED in prose comments, so an unanchored grep reports every
# well-documented detect-only policy as armed.
ENFORCING='^[[:space:]]*-?[[:space:]]*action:[[:space:]]*(Sigkill|Override|NotifyEnforcer)'

shopt -s nullglob
POLICIES=("$ROOT"/policies/*.yaml)

# A check that passes when there is nothing to check is not a check. If the
# glob ever stops matching — a directory rename, a move — this must fail loudly
# rather than report success over an empty set.
if (( ${#POLICIES[@]} == 0 )); then
  echo "FAIL: no policies matched $ROOT/policies/*.yaml — this check would pass vacuously"
  exit 1
fi

for f in "${POLICIES[@]}"; do
  name="${f#"$ROOT"/}"

  # Checked as a name/value PAIR: the word "monitor" appearing anywhere in the
  # file — including in a comment explaining monitor mode — must not satisfy it.
  if grep -qE '^[[:space:]]*-?[[:space:]]*name:[[:space:]]*"?policy-mode"?' "$f" \
     && grep -qE '^[[:space:]]*value:[[:space:]]*"?monitor"?' "$f"; then
    mode_ok=1
  else
    mode_ok=0
  fi

  armed=$(grep -cE "$ENFORCING" "$f")

  if (( mode_ok == 0 )); then
    echo "FAIL: $name does not declare policy-mode: monitor"
    echo "      Add under spec:"
    echo "        options:"
    echo "          - name: \"policy-mode\""
    echo "            value: \"monitor\""
    FAIL=1
    if (( armed > 0 )); then
      echo "      ...and it carries an enforcing action with no guard:"
      grep -nE "$ENFORCING" "$f" | sed 's/^/        /'
    fi
  fi
done

if (( FAIL == 0 )); then
  printf 'OK: %d policies, all declaring policy-mode: monitor\n' "${#POLICIES[@]}"
fi
exit $FAIL
