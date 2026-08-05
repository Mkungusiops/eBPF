#!/usr/bin/env bash
#
# Deploy the SINGLE-TENANT engine (the engine.adanianlabs.io model) to a local OrbStack
# machine. systemd-managed, survives reboot.
#
#   ./single-tenant-orbstack.sh [machine-name]                 # REAL eBPF (default)
#   ENGINE_MODE=fake ./single-tenant-orbstack.sh [machine]     # synthesised events
#
# Modes:
#   tetragon (default) REAL kernel telemetry. An OrbStack machine is a full Linux
#            VM with its own kernel and /sys/kernel/btf/vmlinux, so Tetragon runs
#            here for real — verified on kernel 7.x: policies attach, real
#            exec_ids flow, and an attack script raises a scored chain alert.
#            (This used to default to fake, justified as "macOS has no eBPF" —
#            which confused the Mac host with the Linux VM running inside it.)
#            provision_engine probes the target and falls back to fake by itself
#            if the kernel is too old or BTF is missing, so this is safe.
#   fake     the engine synthesises events; nothing kernel-level runs. Useful for
#            UI work and CI. /api/policy-stats has no Tetragon to query.
export MACHINE="${1:-${MACHINE:-ebpf-engine}}"
export ENGINE_MODE="${ENGINE_MODE:-tetragon}"
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$D/lib.sh"
source "$D/driver-orbstack.sh"
build_binaries engine
provision_engine
