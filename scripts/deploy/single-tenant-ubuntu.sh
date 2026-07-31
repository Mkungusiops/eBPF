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
# TLS=1 obtains a cert for TARGET_HOST first; provision_engine then detects it on
# disk and serves https with an :80 redirect. Needs TARGET_HOST to be a DNS name
# pointing here and :80 open to 0.0.0.0/0 for the HTTP-01 challenge.
if [[ "${TLS:-0}" == 1 ]]; then
  provision_tls "$TARGET_HOST" && export TARGET_SCHEME=https
fi
provision_engine
