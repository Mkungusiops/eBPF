#!/usr/bin/env bash
#
# Deploy the SINGLE-TENANT engine (soc.adanianlabs.io model) to a local OrbStack
# machine. Runs in -fake mode — macOS has no real eBPF, so the engine synthesises
# events; the full console UI + API are live. systemd-managed, survives reboot.
#
#   ./single-tenant-orbstack.sh [machine-name]        # default: ebpf-engine
#
export MACHINE="${1:-${MACHINE:-ebpf-engine}}"
export ENGINE_MODE=fake
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$D/lib.sh"
source "$D/driver-orbstack.sh"
build_binaries engine
provision_engine
