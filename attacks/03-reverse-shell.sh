#!/usr/bin/env bash
# 03-reverse-shell.sh — simulates a reverse-shell handshake.
#
# Behavior pattern: a shell process opens an outbound TCP connection.
# Triggers the outbound-connections kprobe (matchBinaries=/bin/bash).
# We connect to localhost so no actual data leaves the host.

set -u
echo "[*] simulated reverse shell — $(date)"

# Spin a brief listener so the connect succeeds.
nc -l 127.0.0.1 4444 >/dev/null 2>&1 </dev/null &
LISTENER_PID=$!
sleep 0.3

echo "[1/2] bash opening TCP socket to 127.0.0.1:4444"
timeout 1 bash -c 'exec 3<>/dev/tcp/127.0.0.1/4444; echo "id" >&3; exec 3<&-' || true

echo "[2/2] cleaning up listener"
kill "$LISTENER_PID" 2>/dev/null || true
wait "$LISTENER_PID" 2>/dev/null || true

echo "[+] done."
