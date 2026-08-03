#!/usr/bin/env bash
#
# Run every live end-to-end suite against the deployed rig, in one command.
#
# Reads its target + credentials from an env file kept OUT of git (it holds
# console passwords), defaulting to .deploy-build/e2e.env. Write one per
# environment and point E2E_ENV at it to switch between rigs.
#
#   ./scripts/e2e/all.sh                      # uses .deploy-build/e2e.env
#   E2E_ENV=~/rigs/staging.env ./scripts/e2e/all.sh
#
# Exits non-zero if any suite fails, so it drops straight into CI or a
# pre-merge hook.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${E2E_ENV:-$ROOT/.deploy-build/e2e.env}"

[[ -f "$ENV_FILE" ]] || {
  cat >&2 <<EOF
no env file at $ENV_FILE

Create one (it is gitignored — it holds passwords):

  ENGINE_URL=http://127.0.0.1:18090      # tunnel: ssh -f -N -L 18090:127.0.0.1:8090 <engine-host>
  ENGINE_PASS=...
  ENGINE_RSH="ssh single_tenant_engine"

  CONSOLE_URL=http://<cp-ip>
  MT_USER=op-adanian
  MT_PASS=...
  MT_TENANT=adanian-internal
  AGENT_RSH="ssh Tenant_A_agent"

  # tenant B (optional — proves isolation from the other side)
  MT_B_USER=op-acme
  MT_B_PASS=...
  MT_B_TENANT=acme-corp
  AGENT_B_RSH="ssh Tenant_B_agent"

  # device drop proof (optional)
  VICTIM_IP=172.31.42.88
EOF
  exit 2
}
set -a; . "$ENV_FILE"; set +a

RC=0
declare -a RESULTS=()

section() { printf '\n\033[1m══════ %s ══════\033[0m\n' "$1"; }

# The engine UI is often only reachable through an SSH tunnel (its port is not
# exposed publicly). A tunnel from a previous run dies silently — with the whole
# suite then failing on "login failed: HTTP 000", which looks like a product
# fault rather than a dead forward. So verify it and re-establish if needed.
if [[ -n "${ENGINE_TUNNEL:-}" ]]; then
  if ! curl -s -o /dev/null --max-time 5 "$ENGINE_URL" 2>/dev/null; then
    printf '  (engine unreachable — re-establishing tunnel: %s)\n' "$ENGINE_TUNNEL"
    pkill -f "$ENGINE_TUNNEL" 2>/dev/null
    # shellcheck disable=SC2086
    ssh -f -N -o ExitOnForwardFailure=yes -L $ENGINE_TUNNEL "$ENGINE_TUNNEL_HOST" \
      || { echo "  could not open the tunnel"; }
    sleep 2
  fi
fi

# Runs FIRST, deliberately. Every suite below asserts that enforcement happens
# when the operator asks for it — but none of them would notice a Tetragon
# policy killing processes with no operator involvement at all. If the fleet's
# declared posture is a lie, the rest of the results are measuring the wrong
# system, so establish it before anything else.
section "host enforcement posture"
if ENGINE_RSH="$ENGINE_RSH" AGENT_RSH="${AGENT_RSH:-}" AGENT_B_RSH="${AGENT_B_RSH:-}" \
   bash "$ROOT/scripts/e2e/host-posture.sh"; then RESULTS+=("PASS host-posture"); else RESULTS+=("FAIL host-posture"); RC=1; fi

section "single-tenant engine"
if ENGINE_URL="$ENGINE_URL" ENGINE_PASS="$ENGINE_PASS" RSH="$ENGINE_RSH" \
   bash "$ROOT/scripts/e2e/single-tenant.sh"; then RESULTS+=("PASS single-tenant"); else RESULTS+=("FAIL single-tenant"); RC=1; fi

# Detection before response. Every other suite tests what happens AFTER a threat
# is identified; if nothing is identified, none of it matters. Six attack
# simulations shipped in attacks/ for months without a single suite running one.
section "detection pipeline (attack -> alert)"
if ENGINE_URL="$ENGINE_URL" ENGINE_PASS="$ENGINE_PASS" RSH="$ENGINE_RSH" \
   bash "$ROOT/scripts/e2e/detection.sh"; then RESULTS+=("PASS detection"); else RESULTS+=("FAIL detection"); RC=1; fi

# The emergency stop. Previously only ever asserted to be DISENGAGED, which a
# kill-switch wired to nothing would also satisfy.
section "kill-switch (emergency stop)"
if ENGINE_URL="$ENGINE_URL" ENGINE_PASS="$ENGINE_PASS" RSH="$ENGINE_RSH" \
   bash "$ROOT/scripts/e2e/kill-switch.sh"; then RESULTS+=("PASS kill-switch"); else RESULTS+=("FAIL kill-switch"); RC=1; fi

section "multi-tenant — $MT_TENANT"
if CONSOLE_URL="$CONSOLE_URL" MT_USER="$MT_USER" MT_PASS="$MT_PASS" MT_TENANT="$MT_TENANT" \
   AGENT_RSH="${AGENT_RSH:-}" bash "$ROOT/scripts/e2e/multi-tenant.sh"; then RESULTS+=("PASS multi-tenant/$MT_TENANT"); else RESULTS+=("FAIL multi-tenant/$MT_TENANT"); RC=1; fi

if [[ -n "${MT_B_USER:-}" ]]; then
  section "multi-tenant — ${MT_B_TENANT} (isolation from the other side)"
  # Capture A's tenant FIRST. Bash applies command-prefix assignments left to
  # right, so writing MT_OTHER_TENANT="$MT_TENANT" inline would read the
  # MT_TENANT assigned earlier in the same prefix (B's tenant) and assert that
  # B is denied access to its own data.
  A_TENANT="$MT_TENANT"
  if CONSOLE_URL="$CONSOLE_URL" MT_USER="$MT_B_USER" MT_PASS="$MT_B_PASS" MT_TENANT="$MT_B_TENANT" \
     MT_OTHER_TENANT="$A_TENANT" AGENT_RSH="${AGENT_B_RSH:-}" \
     bash "$ROOT/scripts/e2e/multi-tenant.sh"; then RESULTS+=("PASS multi-tenant/$MT_B_TENANT"); else RESULTS+=("FAIL multi-tenant/$MT_B_TENANT"); RC=1; fi
fi

if [[ -n "${VICTIM_IP:-}" && -n "${AGENT_RSH:-}" ]]; then
  section "device drop proof (kernel)"
  if CONSOLE_URL="$CONSOLE_URL" MT_USER="$MT_USER" MT_PASS="$MT_PASS" \
     AGENT_RSH="$AGENT_RSH" VICTIM_IP="$VICTIM_IP" \
     bash "$ROOT/scripts/e2e/device-drop-proof.sh"; then RESULTS+=("PASS device-drop"); else RESULTS+=("FAIL device-drop"); RC=1; fi
fi

# host-posture asserts the fleet is clean NOW. This asserts we would FIND OUT if
# it stopped being clean — a detector wired to a field nobody computes passes the
# clean-state check forever. Arms a real enforcing policy scoped to a path that
# exists nowhere, then requires the console to name the agent and to clear again.
if [[ -n "${AGENT_RSH:-}" ]]; then
  section "posture divergence detection"
  if CONSOLE_URL="$CONSOLE_URL" MT_USER="$MT_USER" MT_PASS="$MT_PASS" AGENT_RSH="$AGENT_RSH" \
     bash "$ROOT/scripts/e2e/posture-divergence.sh"; then RESULTS+=("PASS posture-divergence"); else RESULTS+=("FAIL posture-divergence"); RC=1; fi
fi

# OPT-IN: this reboots a real host, so it is not part of the default loop —
# five minutes and an outage is the wrong price for an ordinary pre-commit run.
# Run it before a release or a customer deployment, where "does the agent come
# back by itself" is exactly the question that matters:
#   REBOOT_TEST=1 ./scripts/e2e/all.sh
if [[ "${REBOOT_TEST:-0}" == "1" && -n "${AGENT_B_RSH:-}" ]]; then
  section "reboot resilience (reboots ${AGENT_B_RSH##* })"
  if AGENT_RSH="$AGENT_B_RSH" CONSOLE_URL="$CONSOLE_URL" MT_USER="$MT_B_USER" MT_PASS="$MT_B_PASS" \
     bash "$ROOT/scripts/e2e/reboot-resilience.sh"; then RESULTS+=("PASS reboot-resilience"); else RESULTS+=("FAIL reboot-resilience"); RC=1; fi
fi

printf '\n\033[1m══════ summary ══════\033[0m\n'
for r in "${RESULTS[@]}"; do
  case "$r" in PASS*) printf '  \033[32m%s\033[0m\n' "$r";; *) printf '  \033[31m%s\033[0m\n' "$r";; esac
done
exit $RC
