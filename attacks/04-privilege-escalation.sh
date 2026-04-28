#!/usr/bin/env bash
# 04-privilege-escalation.sh — simulates a privilege-escalation chain.
#
# Behavior pattern: a non-root process triggers a setuid(0) syscall via
# `sudo -i`-like flows, then runs follow-up commands as root.

set -u
echo "[*] simulated privilege escalation — $(date)"

echo "[1/3] sudo -n true (triggers setuid(0))"
sudo -n true 2>/dev/null || sudo true 2>/dev/null || echo "(sudo not available, simulation will be partial)"

echo "[2/3] root reading /etc/shadow"
sudo cat /etc/shadow >/dev/null 2>&1 || true

echo "[3/3] root listing /root"
sudo ls /root >/dev/null 2>&1 || true

echo "[+] done."
