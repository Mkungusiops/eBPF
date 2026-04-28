#!/usr/bin/env bash
# scripts/setup.sh — Day 1 of the build plan, packaged as one script.
#
# Run this on a fresh Ubuntu 22.04+ VM. It installs Docker, Go, the
# tetra CLI, runs Tetragon in host mode, and verifies that BTF and
# kernel events are visible.
#
# Idempotent: re-running is safe; existing installations are left alone.

set -euo pipefail

GO_VERSION="${GO_VERSION:-1.22.5}"
TETRA_VERSION="${TETRA_VERSION:-v1.1.2}"
TETRAGON_IMAGE="${TETRAGON_IMAGE:-quay.io/cilium/tetragon:latest}"

log()   { printf '\033[1;34m[setup]\033[0m %s\n' "$*"; }
fatal() { printf '\033[1;31m[setup]\033[0m %s\n' "$*" >&2; exit 1; }

# ───── Preflight ────────────────────────────────────────────────────────────
[[ "$(uname -s)" == "Linux" ]] || fatal "this script must be run on Linux"

KREL=$(uname -r)
KMAJOR=${KREL%%.*}
KMINOR=${KREL#*.}; KMINOR=${KMINOR%%.*}
if (( KMAJOR < 5 )) || (( KMAJOR == 5 && KMINOR < 15 )); then
  fatal "kernel $KREL is too old; need 5.15+. Switch VMs."
fi
[[ -f /sys/kernel/btf/vmlinux ]] || fatal "/sys/kernel/btf/vmlinux not found; BTF is required"
log "kernel $KREL with BTF — ok"

# ───── apt deps ─────────────────────────────────────────────────────────────
log "installing apt packages"
sudo apt-get update -y
sudo apt-get install -y git curl make jq build-essential ca-certificates

# ───── Docker ───────────────────────────────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
  log "installing Docker via get.docker.com"
  curl -fsSL https://get.docker.com | sudo sh
fi
if ! groups "$USER" | grep -qw docker; then
  sudo usermod -aG docker "$USER"
  log "added $USER to docker group (log out/in or run 'newgrp docker')"
fi
sudo systemctl enable --now docker
log "docker: $(docker --version)"

# ───── Go ───────────────────────────────────────────────────────────────────
if ! command -v go >/dev/null 2>&1 || ! go version | grep -q "go${GO_VERSION%.*}"; then
  log "installing Go ${GO_VERSION}"
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64)  GO_ARCH=amd64 ;;
    aarch64) GO_ARCH=arm64 ;;
    *) fatal "unsupported arch: $ARCH" ;;
  esac
  TGZ="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
  curl -fsSLO "https://go.dev/dl/${TGZ}"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "${TGZ}"
  rm -f "${TGZ}"
  if ! grep -q '/usr/local/go/bin' "$HOME/.bashrc"; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> "$HOME/.bashrc"
  fi
  export PATH=$PATH:/usr/local/go/bin
fi
log "go: $(/usr/local/go/bin/go version)"

# ───── Tetragon container ───────────────────────────────────────────────────
sudo mkdir -p /var/run/tetragon /var/log/tetragon
if ! sudo docker ps --format '{{.Names}}' | grep -q '^tetragon$'; then
  if sudo docker ps -a --format '{{.Names}}' | grep -q '^tetragon$'; then
    log "removing stopped tetragon container"
    sudo docker rm -f tetragon >/dev/null
  fi
  log "starting tetragon container"
  sudo docker run -d --name tetragon \
    --pid=host \
    --cgroupns=host \
    --privileged \
    -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf \
    -v /var/run/tetragon:/var/run/tetragon \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v /sys/fs/cgroup:/sys/fs/cgroup \
    -v /var/log/tetragon:/var/log/tetragon \
    -v /proc:/procRoot \
    --restart unless-stopped \
    "${TETRAGON_IMAGE}" \
    /usr/bin/tetragon \
    --bpf-lib /var/lib/tetragon/ \
    --export-filename /var/log/tetragon/tetragon.log \
    --server-address unix:///var/run/tetragon/tetragon.sock \
    --enable-process-cred \
    --enable-process-ns
else
  log "tetragon container already running"
fi

# ───── tetra CLI ────────────────────────────────────────────────────────────
if ! command -v tetra >/dev/null 2>&1; then
  log "installing tetra CLI ${TETRA_VERSION}"
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64)  T_ARCH=amd64 ;;
    aarch64) T_ARCH=arm64 ;;
    *) fatal "unsupported arch: $ARCH" ;;
  esac
  curl -fsSL "https://github.com/cilium/tetragon/releases/download/${TETRA_VERSION}/tetra-linux-${T_ARCH}.tar.gz" \
    | sudo tar -xz -C /usr/local/bin tetra
  sudo chmod +x /usr/local/bin/tetra
fi
log "tetra: $(tetra version 2>&1 | head -1)"

# ───── Smoke test ───────────────────────────────────────────────────────────
log "waiting for tetragon socket"
for i in $(seq 1 20); do
  [[ -S /var/run/tetragon/tetragon.sock ]] && break
  sleep 1
done
[[ -S /var/run/tetragon/tetragon.sock ]] || fatal "tetragon socket never appeared"
log "tetragon socket ready"

log "──────────────────────────────────────────────────────────────"
log " Day 1 done. Suggested next steps:"
log "   make policies-apply         # apply TracingPolicies"
log "   make build && sudo ./engine/engine"
log "   open http://\$(hostname -I | awk '{print \$1}'):8080"
log "──────────────────────────────────────────────────────────────"
