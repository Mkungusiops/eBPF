#!/usr/bin/env bash
#
# Deploy the SINGLE-TENANT engine to an Ubuntu server over SSH, with REAL
# Tetragon eBPF detection. systemd-managed. Requires passwordless sudo + Docker
# (installed if absent) on the target.
#
#   SSH_HOST=user@host ./single-tenant-ubuntu.sh
#   ./single-tenant-ubuntu.sh user@host                 # or pass as $1
#   TARGET_HOST=soc.example.com SSH_HOST=... ./single-tenant-ubuntu.sh
#
export SSH_HOST="${1:-${SSH_HOST:?set SSH_HOST=user@host (or an ssh alias)}}"
export ENGINE_MODE="${ENGINE_MODE:-tetragon}"
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$D/lib.sh"
source "$D/driver-ssh.sh"
build_binaries engine
provision_engine
