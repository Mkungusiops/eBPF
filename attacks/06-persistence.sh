#!/usr/bin/env bash
# 06-persistence.sh — simulates persistence staging.
#
# Behavior pattern: write a script to a user dotfile-adjacent location,
# chmod it executable, then enumerate dotfiles for hijack opportunities.

set -u
STAGE="$HOME/.poc-persist-$$"

cleanup() { rm -f "$STAGE" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[*] simulated persistence staging — $(date)"

echo "[1/3] dropping fake stager at $STAGE"
cat > "$STAGE" <<'EOF'
#!/usr/bin/env bash
echo "noop"
EOF

echo "[2/3] chmod +x $STAGE"
chmod +x "$STAGE"

echo "[3/3] dotfile recon"
for f in "$HOME/.bashrc" "$HOME/.profile" "$HOME/.bash_profile" "$HOME/.zshrc"; do
  [ -r "$f" ] && cat "$f" >/dev/null 2>&1 || true
done

echo "[+] done."
