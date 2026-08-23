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

# ── SSH connection multiplexing ────────────────────────────────────────────
#
# Every remote assertion in every suite is its own `ssh host '...'`, and there
# are hundreds of them. Each one is a full TCP connect, key exchange and auth,
# which is slow — and, past a certain rate, is refused: sshd's MaxStartups
# throttles concurrent unauthenticated connections, so the suite eventually
# meets a connection that simply never completes.
#
# That is not hypothetical. A full run wedged for 28 minutes on a single
# `ssh engine 'setsid sleep 3600 &'` inside kill-switch.sh, with no error and
# no timeout, while the same command run by hand returned instantly. The engine
# was healthy throughout — /healthz answered 200 the whole time — so the
# failure looked like a product hang and was a harness one.
#
# Multiplexing makes every suite reuse ONE connection per host. It removes the
# connection storm entirely, and it is why this belongs here rather than in
# each suite: the suites are invoked as separate processes and share nothing
# except what this file hands them.
# A SHORT directory, deliberately not mktemp -d.
#
# ControlPath is a unix socket path and sun_path caps it at 104 bytes. macOS
# mktemp -d returns something like
# /var/folders/h1/qbb8c_fj3f3b7d58jvn4794w0000gn/T/tmp.up70voA3Y4 — 62 bytes
# before the %C token adds 64 more. ssh then refuses every connection with
# "ControlPath too long", which it reports on stderr; the helpers send stderr to
# /dev/null, so every remote call returned EMPTY and the suite reported a
# healthy estate as comprehensively broken.
MUXDIR="/tmp/.e2e-mux-$$"
mkdir -p "$MUXDIR"
# ControlPath must stay short: it is a unix socket path, and the 104-byte
# sun_path limit is reached alarmingly easily under a long TMPDIR.
#
# -n belongs HERE, in the OPTIONS, not appended by the callers.
#
# ssh parses options only up to the hostname; everything after it is the remote
# command. So `$RSH -n "$cmd"` — with RSH already ending in the host — sends the
# remote shell the literal command `-n <cmd>`, which fails and returns nothing.
# Every assertion then compares against an empty string and reports the product
# broken: "no policies listed", "no pid", "expected throttled, got ''". That is
# what one run of this suite reported, in full, about a healthy estate.
MUX="-n -o ControlMaster=auto -o ControlPath=$MUXDIR/%C -o ControlPersist=120 -o BatchMode=yes"

# with_mux rewrites "ssh [opts] host" into "ssh <mux> [opts] host". Empty in,
# empty out — an unset optional host must stay unset, not become a bare "ssh".
with_mux() {
  local rsh="${1:-}"
  [[ -z "$rsh" ]] && return 0
  printf 'ssh %s %s' "$MUX" "${rsh#ssh }"
}

ENGINE_RSH="$(with_mux "${ENGINE_RSH:-}")"
AGENT_RSH="$(with_mux "${AGENT_RSH:-}")"
AGENT_B_RSH="$(with_mux "${AGENT_B_RSH:-}")"
AGENT_C_RSH="$(with_mux "${AGENT_C_RSH:-}")"
CP_RSH="$(with_mux "${CP_RSH:-}")"

# Tear the shared connections down on the way out. Left running they would hold
# a socket and a remote sshd process for ControlPersist after the suite ends,
# which is untidy on a workstation and confusing on a shared runner.
_mux_cleanup() {
  local rsh
  for rsh in "$ENGINE_RSH" "$AGENT_RSH" "$AGENT_B_RSH" "$AGENT_C_RSH" "$CP_RSH"; do
    [[ -n "$rsh" ]] && $rsh -O exit >/dev/null 2>&1 || true
  done
  rm -rf "$MUXDIR"
}
trap _mux_cleanup EXIT

# PREFLIGHT: prove the transport works before trusting a single assertion.
#
# Every remote helper in every suite ends in `2>/dev/null`, so a FATAL ssh error
# is indistinguishable from a command that legitimately returned nothing. When
# ControlPath exceeded the 104-byte socket limit, ssh refused every connection
# on stderr, all of it was discarded, and the suite confidently reported "no
# policies listed", "no pid", "expected throttled, got ''" — a full page of
# product failures against an estate that was completely healthy.
#
# A test harness that cannot tell "the answer is no" from "I could not ask" is
# worse than no harness, because it manufactures incidents. This checks that a
# known-good remote command returns its known-good answer, and refuses to run
# otherwise.
preflight_rsh() {
  local name="$1" rsh="$2" got
  [[ -z "$rsh" ]] && return 0
  got="$(timeout 30 $rsh 'echo __E2E_OK__' 2>/dev/null | tr -d '\r')"
  if [[ "$got" != "__E2E_OK__" ]]; then
    printf '\033[31mpreflight FAILED for %s\033[0m\n' "$name" >&2
    printf '  %s\n' "$rsh" >&2
    printf '  expected __E2E_OK__, got %q\n' "$got" >&2
    printf '  ssh says:\n' >&2
    timeout 30 $rsh 'echo __E2E_OK__' 2>&1 >/dev/null | sed 's/^/    /' >&2
    return 1
  fi
  return 0
}

PREFLIGHT_RC=0
preflight_rsh "engine"   "$ENGINE_RSH"  || PREFLIGHT_RC=1
preflight_rsh "agent A"  "$AGENT_RSH"   || PREFLIGHT_RC=1
preflight_rsh "agent B"  "$AGENT_B_RSH" || PREFLIGHT_RC=1
preflight_rsh "agent C"  "$AGENT_C_RSH" || PREFLIGHT_RC=1
preflight_rsh "cp"       "$CP_RSH"      || PREFLIGHT_RC=1
if (( PREFLIGHT_RC )); then
  printf '\nRefusing to run: remote execution is broken, so every assertion below\n' >&2
  printf 'would report the ESTATE as broken instead of this harness.\n' >&2
  exit 2
fi

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

# The analyst assistant. Read-only by construction, but "read-only" is the
# security property, not the correctness one: an assistant that answers the
# wrong question, over the wrong window, about a subject it cannot see is still
# wrong on an incident console. All three of those shipped, and none of them was
# visible without a live session.
section "analyst assistant (surfaces, streaming, grounding)"
if CONSOLE_URL="$CONSOLE_URL" MT_USER="$MT_USER" MT_PASS="$MT_PASS" \
   bash "$ROOT/scripts/e2e/assistant.sh"; then RESULTS+=("PASS assistant"); else RESULTS+=("FAIL assistant"); RC=1; fi

# Enrichment: the behavioural baseline and threat-intel matching. Runs after the
# assistant suite because one of its checks asks the assistant a question only
# the enrichment tools can answer, which needs a working model endpoint.
section "enrichment (behavioural baseline, threat intel)"
if CONSOLE_URL="$CONSOLE_URL" MT_USER="$MT_USER" MT_PASS="$MT_PASS" \
   bash "$ROOT/scripts/e2e/enrichment.sh"; then RESULTS+=("PASS enrichment"); else RESULTS+=("FAIL enrichment"); RC=1; fi

# Containment must be ROUTED, not broadcast. Every suite above targets a process
# on the one host it drives, so none of them would notice a sever ALSO landing on
# other agents in the tenant — which is exactly what happened: the fan-out
# SIGKILLed whatever local process shared that PID number on every other host and
# acked APPLIED for it. This suite watches the BYSTANDER, so it needs a second
# agent in the SAME tenant (AGENT_C_RSH, enrolled into MT_B_TENANT).
if [[ -n "${AGENT_B_RSH:-}" && -n "${AGENT_C_RSH:-}" && -n "${MT_B_USER:-}" ]]; then
  section "multi-agent containment routing (bystander safety)"
  if CONSOLE_URL="$CONSOLE_URL" MT_USER="$MT_B_USER" MT_PASS="$MT_B_PASS" \
     MT_TENANT="$MT_B_TENANT" AGENT_RSH="$AGENT_B_RSH" AGENT_OTHER_RSH="$AGENT_C_RSH" \
     bash "$ROOT/scripts/e2e/multi-agent-containment.sh"; then RESULTS+=("PASS multi-agent-containment"); else RESULTS+=("FAIL multi-agent-containment"); RC=1; fi
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

# The autonomy invariant: "a missed heartbeat never stops enforcement". If a
# control-plane outage silently disarms every agent, one host going down takes
# the fleet with it, and anyone who can reach the console can disable protection
# everywhere without touching a protected machine. Stops the control plane for
# real, so it is opt-in alongside the reboot suite.
if [[ "${REBOOT_TEST:-0}" == "1" && -n "${AGENT_B_RSH:-}" && -n "${CP_RSH:-}" ]]; then
  section "agent autonomy (control-plane outage)"
  if AGENT_RSH="$AGENT_B_RSH" CP_RSH="$CP_RSH" CONSOLE_URL="$CONSOLE_URL" \
     MT_USER="$MT_B_USER" MT_PASS="$MT_B_PASS" \
     bash "$ROOT/scripts/e2e/agent-autonomy.sh"; then RESULTS+=("PASS agent-autonomy"); else RESULTS+=("FAIL agent-autonomy"); RC=1; fi
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
