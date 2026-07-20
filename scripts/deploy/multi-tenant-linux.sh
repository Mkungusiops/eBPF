#!/usr/bin/env bash
#
# Deploy the MULTI-TENANT control plane to a generic Debian-family Linux server
# over SSH. Same mechanics as the Ubuntu script; use this alias for Debian / a
# Ubuntu derivative. (RHEL/SUSE need the apt + Postgres init steps in lib.sh
# adapted.)
#
#   SSH_HOST=user@host TARGET_HOST=console.example.com ./multi-tenant-linux.sh
#   ./multi-tenant-linux.sh user@host                   # SSH_HOST via $1
#
export SSH_HOST="${1:-${SSH_HOST:?set SSH_HOST=user@host (or an ssh alias)}}"
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$D/lib.sh"
source "$D/driver-ssh.sh"
build_binaries controlplane
provision_controlplane
