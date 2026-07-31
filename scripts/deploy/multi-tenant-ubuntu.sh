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
# TLS=1 obtains a Let's Encrypt certificate for TARGET_HOST first and serves the
# console over https (the OIDC issuer, redirect URI and Secure session cookies
# all follow). Needs TARGET_HOST to be a real DNS name pointing here, and :80
# open to 0.0.0.0/0 for the HTTP-01 challenge:
#
#   TLS=1 TARGET_HOST=console.example.com SSH_HOST=... ./multi-tenant-ubuntu.sh
#
export SSH_HOST="${1:-${SSH_HOST:?set SSH_HOST=user@host (or an ssh alias)}}"
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$D/lib.sh"
source "$D/driver-ssh.sh"
build_binaries controlplane
# Get the cert BEFORE provisioning: provision_controlplane decides whether to
# emit a TLS server block by looking for the cert on disk, and bakes the scheme
# into Keycloak's issuer at the same time.
if [[ "${TLS:-0}" == 1 ]]; then
  provision_tls "$TARGET_HOST" && export TARGET_SCHEME=https
fi
provision_controlplane
