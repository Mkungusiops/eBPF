#!/usr/bin/env bash
# OrbStack driver for scripts/deploy/lib.sh — provisions a local OrbStack Linux
# machine. Set MACHINE (default ebpf-soc) before sourcing.
MACHINE="${MACHINE:-ebpf-soc}"
DISTRO="${DISTRO:-ubuntu}"

command -v orb >/dev/null || die "OrbStack (orb) not found — install from https://orbstack.dev"

orb_ensure_machine() {
  if ! orb -m "$MACHINE" true 2>/dev/null; then
    log "creating OrbStack machine '$MACHINE' ($DISTRO)"
    orb create "$DISTRO" "$MACHINE" >/dev/null 2>&1 || true
    for _ in $(seq 1 30); do orb -m "$MACHINE" true 2>/dev/null && break; sleep 2; done
  fi
  TARGET_HOST="$(orb -m "$MACHINE" bash -c 'hostname -I' 2>/dev/null | awk '{print $1}')"
  [[ -n "$TARGET_HOST" ]] || die "could not determine machine IP for '$MACHINE'"
  ok "OrbStack machine '$MACHINE' at $TARGET_HOST"
}

RUN() { orb -m "$MACHINE" sudo bash -c "$1"; }
PUT() { orb -m "$MACHINE" sudo install -D -m0755 "$1" "$2"; }   # machine reads the Mac FS directly
# PKG is provided by lib.sh (shared, lock-aware, retrying).
# fast whole-dir copy — the machine can read the Mac path directly
put_dir() { RUN "rm -rf '$2'/* 2>/dev/null || true; mkdir -p '$2'; cp -R '$1/.' '$2/'"; }

orb_ensure_machine
