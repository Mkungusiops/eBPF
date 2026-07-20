#!/usr/bin/env bash
#
# Deploy the MULTI-TENANT control plane to an Ubuntu server over SSH: Postgres
# (RLS) + Keycloak (OIDC/PKCE) + control plane + nginx + one sim-agent per tenant.
# systemd-managed. Requires passwordless sudo on the target. Point DNS for
# TARGET_HOST at the box and put TLS in front (see docs/deployment) for prod.
#
#   SSH_HOST=user@host TARGET_HOST=console.example.com ./multi-tenant-ubuntu.sh
#   ./multi-tenant-ubuntu.sh user@host                  # SSH_HOST via $1
#   TENANTS="acme globex" SSH_HOST=... ./multi-tenant-ubuntu.sh
#
export SSH_HOST="${1:-${SSH_HOST:?set SSH_HOST=user@host (or an ssh alias)}}"
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$D/lib.sh"
source "$D/driver-ssh.sh"
build_binaries controlplane
provision_controlplane
