#!/usr/bin/env bash
#
# Deploy the MULTI-TENANT control plane (console.adanianlabs.io model) to a local
# OrbStack machine: Postgres (RLS) + Keycloak (OIDC/PKCE, tenant claim, password
# policy) + control plane + nginx + one sim-agent per tenant. All native systemd,
# survives reboot. Prints every login on completion.
#
#   ./multi-tenant-orbstack.sh [machine-name]           # default: ebpf-soc
#   TENANTS="acme globex" ./multi-tenant-orbstack.sh
#
export MACHINE="${1:-${MACHINE:-ebpf-soc}}"
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$D/lib.sh"
source "$D/driver-orbstack.sh"
build_binaries controlplane
provision_controlplane
