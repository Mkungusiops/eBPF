#!/usr/bin/env bash
# deploy/install.sh — install the engine as a real systemd service.
#
# Replaces the `systemd-run` transient unit used by `make deploy`. Idempotent:
# re-running upgrades the binary + unit + config without losing state.
#
# Layout after install:
#   /opt/ebpf-engine/engine            — binary (replaced atomically)
#   /opt/ebpf-engine/policies/         — TracingPolicy + ChokePolicy YAMLs
#   /opt/ebpf-engine/attacks/          — attack-simulation scripts
#   /opt/ebpf-engine/bpf/choke.o       — compiled BPF data plane
#   /etc/ebpf-engine/engine.yaml       — config file (preserved on reinstall)
#   /var/lib/ebpf-engine/              — SQLite DB, honeypots, audit chain
#   /etc/systemd/system/ebpf-engine.service

set -euo pipefail

SRC_ROOT="${SRC_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
PREFIX="${PREFIX:-/opt/ebpf-engine}"
ETC="${ETC:-/etc/ebpf-engine}"
STATE="${STATE:-/var/lib/ebpf-engine}"
UNIT="/etc/systemd/system/ebpf-engine.service"

[[ "$(id -u)" -eq 0 ]] || { echo "must run as root"; exit 1; }
[[ -x "$SRC_ROOT/engine/engine-linux-amd64" ]] || {
  echo "build the linux binary first: make build-linux"
  exit 1
}

install -d "$PREFIX" "$PREFIX/bpf" "$ETC" "$STATE" "$STATE/honey"

# Atomic binary swap: stage as .new, mv over the live one. Linux refuses
# to overwrite a running ELF directly (ETXTBSY) but rename(2) is fine —
# old inode keeps serving the running process until it exits.
install -m 0755 "$SRC_ROOT/engine/engine-linux-amd64" "$PREFIX/engine.new"
mv -f "$PREFIX/engine.new" "$PREFIX/engine"

# Policies + attacks: rsync semantics — copy without deleting operator-
# added local files. Using cp -r so we don't add an rsync dependency.
cp -r "$SRC_ROOT/policies" "$PREFIX/"
cp -r "$SRC_ROOT/attacks"  "$PREFIX/"

# BPF data plane: compile fresh against the running kernel headers if a
# .c source is present. setup.sh already does this on first deploy; we
# repeat here so reinstalls track kernel upgrades.
if [[ -f "$SRC_ROOT/engine/internal/enforce/bpfmap/bpf/choke.c" ]]; then
  install -m 0644 "$SRC_ROOT/engine/internal/enforce/bpfmap/bpf/choke.c" "$PREFIX/bpf/choke.c"
  declare -a CLANG_ARGS=(-O2 -g -target bpf)
  case "$(uname -m)" in
    x86_64)  CLANG_ARGS+=(-D__TARGET_ARCH_x86) ;;
    aarch64) CLANG_ARGS+=(-D__TARGET_ARCH_arm64) ;;
  esac
  CLANG_ARGS+=(-I"/usr/include/$(uname -m)-linux-gnu")
  clang "${CLANG_ARGS[@]}" -c "$PREFIX/bpf/choke.c" -o "$PREFIX/bpf/choke.o"
fi

# Config file: only seed if missing, preserve operator edits on reinstall.
if [[ ! -f "$ETC/engine.yaml" ]]; then
  install -m 0640 "$SRC_ROOT/deploy/engine.yaml.example" "$ETC/engine.yaml"
  echo "→ seeded $ETC/engine.yaml — edit before going to production"
fi

# Systemd unit: always overwrite (operators don't edit the unit, they
# edit engine.yaml). Drop-in overrides under /etc/systemd/system/ebpf-engine.service.d/
# survive this.
install -m 0644 "$SRC_ROOT/deploy/ebpf-engine.service" "$UNIT"
systemctl daemon-reload

# Stop any transient unit from the old `make deploy` path before
# enabling the persistent one. The transient unit shares the name so
# systemctl restart will pick up the new ExecStart.
systemctl stop ebpf-engine 2>/dev/null || true
systemctl reset-failed ebpf-engine 2>/dev/null || true
systemctl enable --now ebpf-engine

echo "──────────────────────────────────────────────────────────────"
systemctl --no-pager status ebpf-engine | head -10
echo
echo " config:  $ETC/engine.yaml"
echo " state:   $STATE"
echo " binary:  $PREFIX/engine"
echo " logs:    journalctl -u ebpf-engine -f"
echo "──────────────────────────────────────────────────────────────"
