#!/usr/bin/env bash
# 02-credential-theft.sh — simulates credential reconnaissance.
#
# Behavior pattern: enumerates the standard credential locations
# (shadow, sudoers, SSH keys). Each access fires the
# sensitive-file-access kprobe; multiple in a short window compound.

set -u
echo "[*] simulated credential theft — $(date)"

TARGETS=(
  "/etc/shadow"
  "/etc/sudoers"
  "/root/.ssh/authorized_keys"
  "/root/.ssh/id_rsa"
  "$HOME/.ssh/id_rsa"
  "$HOME/.ssh/authorized_keys"
)

for f in "${TARGETS[@]}"; do
  echo "  read $f"
  sudo cat "$f" >/dev/null 2>&1 || cat "$f" >/dev/null 2>&1 || true
done

echo "[+] done."
