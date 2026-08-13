#!/usr/bin/env bash
#
# scripts/preflight.sh — can this host actually run what we are about to install?
#
# Two roles, because the two halves of the platform have different needs:
#
#   --role controlplane   Docker, RAM, disk, free ports. No kernel demands: the
#                         control plane is an ordinary networked service.
#   --role agent          The kernel contract — ≥ 5.15, BTF, cgroup v2 — plus
#                         Tetragon's prerequisites. An agent on a host that
#                         fails these cannot enforce, so we refuse up front
#                         rather than install something that silently degrades.
#
#   ./scripts/preflight.sh --role agent                 # check this machine
#   ./scripts/preflight.sh --role agent --ssh <alias>   # check a remote machine
#
# Exit status: 0 all clear (warnings allowed), 1 at least one hard failure.

LOG_TAG="preflight"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

ROLE="controlplane"; SSH_TO=""; LOCAL=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)  ROLE="${2:?}"; shift 2 ;;
    --ssh)   SSH_TO="${2:?}"; shift 2 ;;
    --local) LOCAL=1; shift ;;            # internal: set when running on the target
    -h|--help) sed -n '3,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done
[[ "$ROLE" == "controlplane" || "$ROLE" == "agent" ]] || die "--role must be controlplane|agent"

# Remote mode: ship this script (plus the lib it sources) to the target and run
# it there with --local. One implementation, two execution sites.
if [[ -n "$SSH_TO" && "$LOCAL" == "0" ]]; then
  SSH_ALIAS="$SSH_TO"; export SSH_ALIAS
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    dim "dry-run: would run the '$ROLE' preflight on $SSH_TO"
    exit 0
  fi
  log "checking $SSH_TO (role: $ROLE)"
  tar -cz -C "$SCRIPTS_DIR" preflight.sh lib \
    | rssh "rm -rf /tmp/ebpf-preflight && mkdir -p /tmp/ebpf-preflight && tar -xz -C /tmp/ebpf-preflight"
  rssh "bash /tmp/ebpf-preflight/preflight.sh --role $ROLE --local; rc=\$?; rm -rf /tmp/ebpf-preflight; exit \$rc"
  exit $?
fi

FAILURES=0
pass() { ok "$1"; }
fail() { err "$1"; FAILURES=$((FAILURES + 1)); }

check_os() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    fail "not Linux ($(uname -s)) — the platform installs on Linux servers only"
    return
  fi
  local pretty="unknown"
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    pretty="$(. /etc/os-release && printf '%s' "$PRETTY_NAME")"
  fi
  pass "OS: $pretty ($(uname -m))"
  if [[ "$(uname -m)" != "x86_64" ]]; then
    fail "architecture $(uname -m) — the shipped binaries are linux/amd64"
  fi
}

check_kernel() {
  local rel major minor
  rel="$(uname -r)"; major="${rel%%.*}"; minor="${rel#*.}"; minor="${minor%%.*}"
  if (( major > 5 )) || { (( major == 5 )) && (( minor >= 15 )); }; then
    pass "kernel $rel (≥ 5.15)"
  else
    fail "kernel $rel is too old — Tetragon needs ≥ 5.15"
  fi
}

check_btf() {
  if [[ -f /sys/kernel/btf/vmlinux ]]; then
    pass "BTF present (/sys/kernel/btf/vmlinux)"
  else
    fail "no /sys/kernel/btf/vmlinux — Tetragon cannot attach without BTF"
  fi
}

check_cgroup2() {
  if [[ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" == "cgroup2fs" ]]; then
    pass "cgroup v2 unified hierarchy"
  else
    fail "cgroup v2 is not the unified hierarchy at /sys/fs/cgroup — the choke ladder (throttle/freeze) cannot work"
  fi
}

check_docker() {
  if have_cmd docker; then
    if docker info >/dev/null 2>&1 || sudo -n docker info >/dev/null 2>&1; then
      pass "Docker: $(docker --version 2>/dev/null | cut -d, -f1)"
    else
      warn "Docker is installed but the daemon is not reachable — it will be started during deploy"
    fi
    if docker compose version >/dev/null 2>&1 || sudo -n docker compose version >/dev/null 2>&1; then
      pass "docker compose plugin present"
    else
      fail "docker compose plugin missing — install docker-compose-plugin"
    fi
  else
    warn "Docker not installed — deploy will install it via get.docker.com"
  fi
}

check_resources() {
  local mem_kb mem_gb disk_gb cores
  mem_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  mem_gb=$(( mem_kb / 1024 / 1024 ))
  cores="$(nproc 2>/dev/null || echo 1)"
  disk_gb="$(df -BG --output=avail / 2>/dev/null | tail -1 | tr -dc '0-9' || echo 0)"

  local min_mem=1 min_disk=5
  if [[ "$ROLE" == "controlplane" ]]; then
    # Postgres + NATS + (ClickHouse|Keycloak) + the control plane on one box.
    min_mem=4; min_disk=20
    if (( cores >= 2 )); then pass "CPU: ${cores} cores"; else warn "CPU: ${cores} core — expect slow ingest"; fi
  fi

  if (( mem_gb >= min_mem )); then
    pass "RAM: ${mem_gb}G"
  else
    fail "RAM: ${mem_gb}G — role '$ROLE' needs ≥ ${min_mem}G"
  fi
  if (( disk_gb >= min_disk )); then
    pass "disk: ${disk_gb}G free on /"
  else
    fail "disk: ${disk_gb}G free on / — role '$ROLE' needs ≥ ${min_disk}G"
  fi
}

check_ports() {
  local ports=("$@") p busy
  for p in "${ports[@]}"; do
    busy=""
    if have_cmd ss; then
      busy="$(ss -tlnH "sport = :$p" 2>/dev/null | head -1)"
    fi
    if [[ -n "$busy" ]]; then
      # Our own control plane re-binding its port on a redeploy is expected.
      if [[ "$busy" == *controlplane* ]]; then
        pass "port $p held by our control plane (redeploy)"
      else
        fail "port $p is already in use: $(printf '%s' "$busy" | awk '{print $NF}')"
      fi
    else
      pass "port $p free"
    fi
  done
}

check_systemd() {
  if have_cmd systemctl && [[ -d /run/systemd/system ]]; then
    pass "systemd is the init system"
  else
    fail "systemd not detected — the install path is systemd units"
  fi
}

check_egress() {
  if curl -fsS --max-time 10 -o /dev/null https://get.docker.com 2>/dev/null; then
    pass "outbound HTTPS works"
  else
    warn "no outbound HTTPS — installing Docker/Tetragon images will fail on an air-gapped host"
  fi
}

check_clang() {
  if have_cmd clang; then
    pass "clang present ($(clang --version | head -1 | awk '{print $NF}')) — BPF data planes compilable"
  else
    warn "clang not installed — scripts/install-agent.sh installs it (needed to build choke.o)"
  fi
}

printf '\n%s── preflight: %s (role: %s) ──%s\n' "$C_BOLD" "$(hostname)" "$ROLE" "$C_RESET"

check_os
check_systemd
check_resources
check_egress

if [[ "$ROLE" == "controlplane" ]]; then
  check_docker
  check_ports 9443 9090 5432 4222
else
  check_kernel
  check_btf
  check_cgroup2
  check_docker      # Tetragon runs as a container
  check_clang
fi

printf '\n'
if (( FAILURES > 0 )); then
  err "$FAILURES blocking problem(s) — this host is not ready for role '$ROLE'"
  exit 1
fi
ok "host is ready for role '$ROLE'"
exit 0
