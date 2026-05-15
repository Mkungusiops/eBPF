#!/usr/bin/env bash
# scripts/multipass-doctor.sh — make `make deploy` self-heal the VM.
#
# Multipass on macOS (1.16.x) has two recurring failure modes:
#
#   1. State "Unknown"   — daemon and qemu disagree. Recovery: force-stop, start.
#   2. State "Starting"  — VM boots, gets a DHCP lease, sshd opens, but the
#                          daemon's internal SSH probe wedges and never marks
#                          the VM Running. Recovery: stop ALL VMs cleanly,
#                          kickstart multipassd, restart the target VM. The
#                          "stop cleanly first" step is the trick — kickstart
#                          alone leaves orphan qemus holding the qcow2 image
#                          lock, which deadlocks the new daemon at 100% CPU.
#
# Usage:  scripts/multipass-doctor.sh <vm-name>
#
# Exit 0 = VM is Running. Exit non-zero = manual intervention needed
# (script prints the exact command to run).

set -euo pipefail

VM="${1:-ebpf}"
SOCKET=/var/run/multipass_socket
LEASES=/var/db/dhcpd_leases

log()   { printf '\033[1;34m[doctor]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[doctor]\033[0m %s\n' "$*" >&2; }
fatal() { printf '\033[1;31m[doctor]\033[0m %s\n' "$*" >&2; exit 1; }

state_of() {
  multipass list 2>/dev/null | awk -v vm="$VM" '$1 == vm { print $2 }'
}

ip_of() {
  multipass list 2>/dev/null | awk -v vm="$VM" '$1 == vm { print $3 }'
}

# Look up a DHCP lease by VM name (multipass writes the name= hint).
# Returns the most-recently-issued IP (last entry wins).
leased_ip() {
  [[ -r "$LEASES" ]] || return 1
  awk -v vm="$VM" '
    /^{/   { ip="" }
    /name=/ {
      n=$0; sub(/^[[:space:]]*name=/, "", n)
      if (n == vm) want=1
    }
    /ip_address=/ {
      i=$0; sub(/^[[:space:]]*ip_address=/, "", i)
      ip=i
    }
    /^}/ { if (want && ip) last=ip; want=0; ip="" }
    END  { if (last) print last }
  ' "$LEASES"
}

ssh_open() {
  local ip="$1"
  nc -z -G 3 "$ip" 22 >/dev/null 2>&1
}

require_socket() {
  if multipass list >/dev/null 2>&1; then return 0; fi
  warn "multipass socket unreachable — daemon is down or wedged"
  warn "run:  sudo launchctl kickstart -k system/com.canonical.multipassd"
  fatal "cannot continue without daemon"
}

# Stop a single VM with a short SIGTERM grace, then SIGKILL via force-stop
# if it doesn't comply. Crucial that this returns BEFORE the daemon dies,
# so the qemu child gets a clean shutdown signal and releases the qcow2
# lock — otherwise a subsequent daemon restart spins at 100% CPU forever.
stop_clean() {
  local vm="$1"
  local s; s="$(multipass list 2>/dev/null | awk -v v="$vm" '$1==v{print $2}')"
  case "$s" in
    Stopped|Unknown|"") ;;
    *)
      log "stopping $vm cleanly (timeout 30s)"
      multipass stop -t 30 "$vm" >/dev/null 2>&1 || true
      ;;
  esac
  s="$(multipass list 2>/dev/null | awk -v v="$vm" '$1==v{print $2}')"
  if [[ "$s" != "Stopped" && -n "$s" ]]; then
    log "force-stopping $vm"
    multipass stop --force "$vm" >/dev/null 2>&1 || true
  fi
}

# Detect orphan qemu PIDs (running qemu instances whose multipassd parent
# is no longer alive, OR whose image is currently locked but no VM is
# tracked as Running). Returns space-separated PIDs on stdout.
orphan_qemus() {
  pgrep -f 'qemu-system-x86_64.*multipassd' 2>/dev/null | while read -r pid; do
    # Parent is launchd (1) only when multipassd died and left the qemu
    # behind. While multipassd is alive, the parent is multipassd's pid.
    ppid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
    if [[ -n "$ppid" && "$ppid" == "1" ]]; then
      echo "$pid"
    fi
  done
}

# Big-hammer recovery: clean-stop every Running VM (releases qcow2 locks),
# kickstart multipassd, wait for socket, restart target VM. Needs sudo.
big_hammer_recover() {
  log "──── big-hammer recovery ────"
  log "stopping all Running VMs first (avoids orphan qemus)"
  while read -r name s _; do
    [[ "$name" == "Name" || -z "$name" ]] && continue
    [[ "$s" == "Running" || "$s" == "Starting" || "$s" == "Unknown" ]] || continue
    stop_clean "$name"
  done < <(multipass list 2>/dev/null)

  log "kickstarting multipassd"
  if sudo -n true 2>/dev/null; then
    sudo launchctl kickstart -k system/com.canonical.multipassd
  else
    cat <<EOF >&2

────────────────────────────────────────────────────────────────────
multipassd needs to be restarted but sudo is not cached.
Run this in another terminal, then re-run \`make deploy\`:

    sudo launchctl kickstart -k system/com.canonical.multipassd

(or: \`sudo -v\` first to cache sudo for ~5 min, then re-run.)
────────────────────────────────────────────────────────────────────
EOF
    exit 2
  fi

  log "waiting for daemon socket"
  for _ in $(seq 1 30); do
    multipass list >/dev/null 2>&1 && break
    sleep 2
  done
  multipass list >/dev/null 2>&1 || fatal "daemon never came back"
  log "daemon back"

  log "starting $VM"
  multipass start "$VM" >/dev/null 2>&1 || true
}

# ──────────────────────────────────────────────────────────────────────
# Main state machine
# ──────────────────────────────────────────────────────────────────────

require_socket

s="$(state_of)"
[[ -z "$s" ]] && fatal "no VM named '$VM' (run: multipass launch 22.04 --name $VM --cpus 2 --memory 4G --disk 20G)"
log "$VM state: $s"

case "$s" in
  Running)
    # Already up.
    ;;

  Stopped)
    log "starting $VM"
    multipass start "$VM" >/dev/null 2>&1 || true
    ;;

  Unknown)
    log "$VM is Unknown — force-stop + start"
    multipass stop --force "$VM" >/dev/null 2>&1 || true
    sleep 1
    multipass start "$VM" >/dev/null 2>&1 || true
    ;;

  Starting)
    log "$VM is Starting — waiting up to 120s"
    ;;

  *)
    warn "unrecognized state '$s' — attempting force-stop + start anyway"
    multipass stop --force "$VM" >/dev/null 2>&1 || true
    sleep 1
    multipass start "$VM" >/dev/null 2>&1 || true
    ;;
esac

# ──────────────────────────────────────────────────────────────────────
# Wait for Running, with one big-hammer recovery if the daemon's SSH
# probe wedges (state stays Starting but the guest is fully reachable).
# ──────────────────────────────────────────────────────────────────────
deadline=$(( $(date +%s) + 120 ))
while :; do
  s="$(state_of)"; ip="$(ip_of)"
  if [[ "$s" == "Running" && -n "$ip" && "$ip" != "--" ]]; then
    log "$VM is Running at $ip"
    exit 0
  fi
  if (( $(date +%s) >= deadline )); then
    break
  fi
  sleep 4
done

warn "$VM still '$s' after 120s — checking if daemon SSH probe is wedged"
lip="$(leased_ip || true)"
if [[ -n "$lip" ]] && ssh_open "$lip"; then
  warn "DHCP lease $lip is reachable on :22 but multipass still says '$s'"
  warn "this is the known daemon-SSH-probe wedge — kickstarting daemon"
  big_hammer_recover

  # Final wait after recovery.
  deadline=$(( $(date +%s) + 120 ))
  while :; do
    s="$(state_of)"; ip="$(ip_of)"
    if [[ "$s" == "Running" && -n "$ip" && "$ip" != "--" ]]; then
      log "$VM is Running at $ip (post-recovery)"
      exit 0
    fi
    (( $(date +%s) >= deadline )) && break
    sleep 4
  done
fi

fatal "$VM did not reach Running. Last state: $s, IPv4: ${ip:-(none)}, lease: ${lip:-(none)}"
