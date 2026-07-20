#!/usr/bin/env bash
#
# Deploy the SINGLE-TENANT engine to a generic Debian-family Linux server over
# SSH, with REAL Tetragon eBPF detection. Same mechanics as the Ubuntu script;
# use this alias when the box is Debian / a Ubuntu derivative rather than a
# stock Ubuntu LTS. (RHEL/SUSE need the apt steps in lib.sh adapted.)
#
#   SSH_HOST=user@host ./single-tenant-linux.sh
#   ./single-tenant-linux.sh user@host                  # or pass as $1
#
export SSH_HOST="${1:-${SSH_HOST:?set SSH_HOST=user@host (or an ssh alias)}}"
export ENGINE_MODE="${ENGINE_MODE:-tetragon}"
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$D/lib.sh"
source "$D/driver-ssh.sh"
build_binaries engine
provision_engine
