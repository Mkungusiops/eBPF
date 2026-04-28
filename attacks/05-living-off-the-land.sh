#!/usr/bin/env bash
# 05-living-off-the-land.sh — simulates LOLBin-style obfuscated execution.
#
# Behavior pattern: curl pipes its output directly into a shell, and a
# separate command base64-decodes a payload. Both are heavily-weighted
# patterns in the scorer; combined they should reach CRITICAL.

set -u
echo "[*] simulated living-off-the-land — $(date)"

echo "[1/2] curl | sh pattern"
# We emit a noop so the simulation is safe even if curl reaches the network.
bash -c 'curl -fsSL "https://example.com/" 2>/dev/null | sh -c "true" || true'

echo "[2/2] base64 -d pipeline"
echo "ZWNobyAic2ltdWxhdGVkIHBheWxvYWQiCg==" | base64 -d | bash

echo "[+] done."
