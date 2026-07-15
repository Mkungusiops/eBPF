#!/usr/bin/env bash
#
# scripts/fleet-upgrade.sh — upgrade agents in canary rings, with rollback.
#
# The agent runs as root with CAP_BPF on every protected host. A bad agent
# rollout is not a degraded feature — it is a fleet-wide outage of the thing that
# was supposed to contain the breach. So the upgrade is staged:
#
#   ring 1 (canary)   one host. Upgrade, watch, decide.
#   ring 2 (early)    ~25% of the fleet.
#   ring 3 (rest)     everything else.
#
# Between rings the operator must confirm. Each host keeps its previous binary,
# so a failed health check rolls that host back immediately and stops the wave.
#
# The autonomy contract matters here: an agent being upgraded stops reporting for
# a few seconds, but the last-applied policy stays loaded in the kernel. A host
# is never unprotected mid-upgrade — except in the window where the process is
# down, which is why we restart rather than stop-then-start.
#
#   ./scripts/fleet-upgrade.sh --hosts chokectl.hosts --binary dist/v0.4.0/agent-linux-amd64
#   ./scripts/fleet-upgrade.sh --hosts … --rollback
#
# Hosts file: one "name user@host" pair per line, '#' comments (chokectl.hosts).

LOG_TAG="fleet"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

HOSTS_FILE="$REPO_ROOT/chokectl.hosts"; BINARY=""; ROLLBACK=0; CANARY_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --hosts)   HOSTS_FILE="${2:?}"; shift 2 ;;
    --binary)  BINARY="${2:?}"; shift 2 ;;
    --rollback) ROLLBACK=1; shift ;;
    --canary)  CANARY_ONLY=1; shift ;;
    -h|--help) sed -n '3,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done

[[ -f "$HOSTS_FILE" ]] || die "no hosts file: $HOSTS_FILE"

# Parse "name user@host" lines; a bare "user@host" works too.
HOSTS=()
while read -r name target _; do
  if [[ -z "$name" || "$name" == \#* ]]; then continue; fi
  if [[ -z "$target" ]]; then target="$name"; fi
  # chokectl.hosts stores URLs; take the host part if we were handed one.
  target="${target#http://}"; target="${target#https://}"; target="${target%%:*}"
  HOSTS+=("$target")
done <"$HOSTS_FILE"
(( ${#HOSTS[@]} > 0 )) || die "no hosts in $HOSTS_FILE"

# ── Per-host operations ────────────────────────────────────────────────────
upgrade_host() { # <host>
  local h="$1"
  SSH_TARGET="$h"; SSH_ALIAS=""; export SSH_TARGET

  # Keep the outgoing binary. Rollback has to be local to the host and instant —
  # re-fetching an old artifact during an incident is not a rollback plan.
  rsudo "cp -f /opt/ebpf-soc/agent /opt/ebpf-soc/agent.prev 2>/dev/null || true"

  # Stage, then rename over the running binary. Linux refuses to overwrite a
  # running executable (ETXTBSY) but rename(2) is fine: the old inode stays
  # alive for the running process while the path points at the new one.
  rput_root "$BINARY" /opt/ebpf-soc/agent.new 0755
  rsudo "mv -f /opt/ebpf-soc/agent.new /opt/ebpf-soc/agent && systemctl restart ebpf-soc-agent"

  sleep 5
  if rssh_quiet "systemctl is-active --quiet ebpf-soc-agent"; then
    ok "$h — healthy"
    return 0
  fi
  err "$h — the agent did not come back"
  return 1
}

rollback_host() { # <host>
  local h="$1"
  SSH_TARGET="$h"; SSH_ALIAS=""; export SSH_TARGET
  if ! rssh_quiet "sudo test -f /opt/ebpf-soc/agent.prev"; then
    err "$h — no previous binary to roll back to"
    return 1
  fi
  rsudo "cp -f /opt/ebpf-soc/agent.prev /opt/ebpf-soc/agent && systemctl restart ebpf-soc-agent"
  sleep 5
  if rssh_quiet "systemctl is-active --quiet ebpf-soc-agent"; then
    ok "$h — rolled back"
    return 0
  fi
  err "$h — STILL DOWN after rollback. This host is unprotected; intervene now."
  return 1
}

# ── Rollback mode ──────────────────────────────────────────────────────────
if (( ROLLBACK )); then
  step_header "Rolling back ${#HOSTS[@]} host(s)"
  fails=0
  for h in "${HOSTS[@]}"; do
    rollback_host "$h" || fails=$((fails + 1))
  done
  (( fails == 0 )) || die "$fails host(s) failed to roll back"
  ok "fleet rolled back"
  exit 0
fi

# ── Upgrade ────────────────────────────────────────────────────────────────
[[ -n "$BINARY" && -f "$BINARY" ]] || die "--binary <agent-linux-amd64> is required"
file "$BINARY" | grep -q 'statically linked' || die "$BINARY is not a static linux binary"

# Rings. Ring 1 is always exactly one host: a canary that shares its blast radius
# with 24 others is not a canary.
RING1=("${HOSTS[0]}")
RING2=(); RING3=()
total=${#HOSTS[@]}
early=$(( (total - 1) / 4 ))
for ((i = 1; i < total; i++)); do
  if (( i <= early )); then RING2+=("${HOSTS[$i]}"); else RING3+=("${HOSTS[$i]}"); fi
done

printf '\n%sFleet upgrade%s  ·  %d hosts  ·  %s\n' "$C_BOLD" "$C_RESET" "$total" "$(basename "$BINARY")"
printf '  ring 1 (canary)  %d\n  ring 2 (early)   %d\n  ring 3 (rest)    %d\n' \
  "${#RING1[@]}" "${#RING2[@]}" "${#RING3[@]}"

run_ring() { # <label> <host…>
  local label="$1"; shift
  local ring=("$@") h failed=0
  (( ${#ring[@]} > 0 )) || return 0
  step_header "$label — ${#ring[@]} host(s)"
  for h in "${ring[@]}"; do
    log "upgrading $h"
    if ! upgrade_host "$h"; then
      failed=1
      warn "rolling $h back"
      rollback_host "$h" || true
      break
    fi
  done
  if (( failed )); then
    err "$label failed — the wave is stopped. Hosts already upgraded were left running the new binary."
    dim "roll the whole fleet back with: $0 --hosts $HOSTS_FILE --rollback"
    exit 1
  fi
  ok "$label complete"
}

run_ring "Ring 1 (canary)" "${RING1[@]}"
if (( CANARY_ONLY )); then
  ok "canary only — stopping here"
  dim "watch it, then continue: $0 --hosts $HOSTS_FILE --binary $BINARY"
  exit 0
fi

printf '\n'
confirm "Canary is healthy. Proceed to ring 2 (${#RING2[@]} hosts)?" n || { log "stopped after the canary"; exit 0; }
run_ring "Ring 2 (early)" "${RING2[@]}"

printf '\n'
confirm "Proceed to ring 3 (${#RING3[@]} hosts)?" n || { log "stopped after ring 2"; exit 0; }
run_ring "Ring 3 (rest)" "${RING3[@]}"

printf '\n'
ok "fleet upgraded — $total host(s) on $(basename "$BINARY")"
dim "the previous binary is kept at /opt/ebpf-soc/agent.prev on every host"
