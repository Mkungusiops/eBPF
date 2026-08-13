#!/usr/bin/env bash
#
# scripts/pki.sh — the trust root: the CA agents pin, and the key that signs
# the commands they obey.
#
# The control plane generates both on first start into its -state-dir:
#
#   ca.pem / ca.key   the CA that issues every agent's mTLS certificate. The
#                     agent's tenant_id lives in that cert's Subject — it IS
#                     tenant isolation Layer 1. Losing ca.key means every agent
#                     must re-enroll; leaking it means anyone can mint an agent
#                     identity for any tenant.
#   fleet.key         the ed25519 key that signs commands and policy bundles.
#                     Agents refuse anything not signed by it. Leaking it means
#                     an attacker can order the fleet to quarantine or sever.
#
#   ./scripts/pki.sh export  --ssh <alias> --out .deploy/x/artifacts
#   ./scripts/pki.sh inspect --ca <ca-bundle.pem>
#   ./scripts/pki.sh backup  --ssh <alias> --out <dir>     # includes the PRIVATE keys
#   ./scripts/pki.sh rotate  --ssh <alias>                 # destructive; re-enrolls the fleet

LOG_TAG="pki"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

STATE_DIR_REMOTE="/var/lib/ebpf-soc-controlplane"
CMD="${1:-}"; shift || true
SSH_TO=""; OUT_DIR="."; CA_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh) SSH_TO="${2:?}"; shift 2 ;;
    --out) OUT_DIR="${2:?}"; shift 2 ;;
    --ca)  CA_FILE="${2:?}"; shift 2 ;;
    -h|--help) sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done

need_ssh() {
  [[ -n "$SSH_TO" ]] || die "--ssh <alias> is required for '$CMD'"
  SSH_ALIAS="$SSH_TO"; export SSH_ALIAS
}

# ── export: the two PUBLIC artifacts agents need ───────────────────────────
# Not secret: the CA certificate and the fleet PUBLIC key. Both are pinned by
# agents at enrollment, so they have to travel to every host we install on.
cmd_export() {
  need_ssh
  mkdir -p "$OUT_DIR"
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    dim "dry-run: would export ca-bundle.pem + fleet.pub → $OUT_DIR"
    return 0
  fi

  # The control plane re-writes these on every start (-ca-out / -fleet-pubkey-out).
  # Read them as root: the state dir is 0700 and, under DynamicUser, actually
  # lives behind /var/lib/private.
  rsudo "cat $STATE_DIR_REMOTE/ca-bundle.pem" >"$OUT_DIR/ca-bundle.pem" \
    || die "no CA bundle on the server — is ebpf-soc-controlplane running?"
  rsudo "cat $STATE_DIR_REMOTE/fleet.pub" >"$OUT_DIR/fleet.pub" \
    || die "no fleet public key on the server"

  [[ -s "$OUT_DIR/ca-bundle.pem" ]] || die "the CA bundle came back empty"
  [[ -s "$OUT_DIR/fleet.pub" ]]     || die "the fleet public key came back empty"
  chmod 644 "$OUT_DIR/ca-bundle.pem" "$OUT_DIR/fleet.pub"

  ok "ca-bundle.pem + fleet.pub → $OUT_DIR"
  cmd_inspect_file "$OUT_DIR/ca-bundle.pem"
}

# ── inspect: is this CA the one I think it is, and when does it die? ────────
cmd_inspect_file() {
  local ca="$1"
  have_cmd openssl || { dim "openssl not installed — skipping certificate inspection"; return 0; }
  local subject notafter fingerprint
  subject="$(openssl x509 -in "$ca" -noout -subject 2>/dev/null | sed 's/^subject=//')"
  notafter="$(openssl x509 -in "$ca" -noout -enddate 2>/dev/null | cut -d= -f2)"
  fingerprint="$(openssl x509 -in "$ca" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"

  dim "subject     $subject"
  dim "expires     $notafter"
  dim "SHA-256     $fingerprint"

  # The CA is issued with a 10-year life; warn well before an expiry that would
  # break every agent's mTLS at once.
  if openssl x509 -in "$ca" -noout -checkend $((90 * 86400)) >/dev/null 2>&1; then
    ok "CA valid for more than 90 days"
  else
    warn "CA expires within 90 days — plan a rotation; every agent must re-enroll"
  fi
}

cmd_inspect() {
  [[ -n "$CA_FILE" ]] || die "--ca <file> is required for 'inspect'"
  [[ -f "$CA_FILE" ]] || die "no such file: $CA_FILE"
  cmd_inspect_file "$CA_FILE"
}

# ── backup: the PRIVATE keys — the crown jewels ────────────────────────────
cmd_backup() {
  need_ssh
  mkdir -p "$OUT_DIR"; chmod 700 "$OUT_DIR"
  local stamp; stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  local dest="$OUT_DIR/pki-backup-$stamp.tar.gz"

  warn "this copies the CA PRIVATE KEY and the fleet SIGNING KEY off the server"
  dim "anyone holding these can mint an agent identity for any tenant and sign"
  dim "commands the whole fleet will obey — store the result in a secrets manager,"
  dim "not on a laptop, and never in git."
  confirm "Continue?" n || { log "aborted"; exit 0; }

  rsudo "tar -cz -C $STATE_DIR_REMOTE ca.pem ca.key fleet.key" >"$dest" \
    || die "backup failed — is the control plane installed on this server?"
  chmod 600 "$dest"
  ok "PKI backup → $dest (0600)"

  if have_cmd age; then
    dim "encrypt it:  age -p -o $dest.age $dest && rm $dest"
  elif have_cmd gpg; then
    dim "encrypt it:  gpg -c $dest && rm $dest"
  fi
}

# ── rotate: deliberately destructive ───────────────────────────────────────
cmd_rotate() {
  need_ssh
  printf '\n'
  err "ROTATING THE CA INVALIDATES EVERY ENROLLED AGENT"
  dim "Agents pin this CA. After rotation they cannot complete mTLS, so they will"
  dim "keep enforcing locally (the autonomy contract holds) but stop reporting and"
  dim "stop accepting commands until each one is re-enrolled with a new token and"
  dim "the new CA bundle."
  dim ""
  dim "Do this only if the CA key is believed compromised, or it is nearing expiry."
  printf '\n'
  local answer
  answer="$(ask 'Type ROTATE to proceed')"
  [[ "$answer" == "ROTATE" ]] || { log "aborted"; exit 0; }

  local stamp; stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  log "archiving the current CA + fleet key on the server"
  rsudo "mkdir -p $STATE_DIR_REMOTE/rotated-$stamp && mv $STATE_DIR_REMOTE/ca.pem $STATE_DIR_REMOTE/ca.key $STATE_DIR_REMOTE/fleet.key $STATE_DIR_REMOTE/rotated-$stamp/ && chmod 700 $STATE_DIR_REMOTE/rotated-$stamp"

  log "restarting the control plane — it will generate a fresh CA + fleet key"
  rsudo "systemctl restart ebpf-soc-controlplane"
  wait_for 60 "control plane" rssh_quiet "curl -fsS http://127.0.0.1:9090/healthz" \
    || die "the control plane did not come back — the old keys are in $STATE_DIR_REMOTE/rotated-$stamp"

  ok "new CA + fleet key generated (old ones archived in $STATE_DIR_REMOTE/rotated-$stamp)"
  warn "every agent must now be re-enrolled:"
  dim "  1. ./scripts/pki.sh export --ssh $SSH_TO --out <artifacts-dir>"
  dim "  2. ./scripts/tenantctl enroll-token <tenant> --ssh $SSH_TO   (once per agent)"
  dim "  3. ./scripts/install-agent.sh --host <agent> … --reenroll"
}

case "$CMD" in
  export)    cmd_export ;;
  inspect)   cmd_inspect ;;
  backup)    cmd_backup ;;
  rotate)    cmd_rotate ;;
  -h|--help) sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) die "unknown command: ${CMD:-<none>} (try: export, inspect, backup, rotate)" ;;
esac
