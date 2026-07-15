#!/usr/bin/env bash
#
# scripts/backup.sh — take a restorable backup of a control-plane deployment.
#
# Four things, and they are NOT equally replaceable:
#
#   pki/          the CA key + fleet signing key. IRREPLACEABLE. Lose these and
#                 every agent in the fleet must be re-enrolled by hand; leak
#                 them and an attacker can mint agent identities and sign
#                 commands the fleet obeys. This is the reason to run backups.
#   postgres/     control state: tenants, agents, audit, telemetry.
#   clickhouse/   the events firehose (optional; usually recreated from agents).
#   config/       /etc/ebpf-soc — DSNs, admin token, compose .env.
#
# The archive therefore contains live secrets. It is written 0600 and this
# script will encrypt it for you if `age` or `gpg` is present.
#
#   ./scripts/backup.sh --deployment <name> [--out DIR] [--no-clickhouse]
#   ./scripts/backup.sh --ssh <alias> --out ./backups
#
# Restore with scripts/restore.sh. A backup you have never restored is a guess,
# not a backup — Phase 3's exit gate is a passed DR drill, so schedule one.

LOG_TAG="backup"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

DEPLOYMENT=""; SSH_TO=""; OUT_DIR=""; WITH_CH=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --deployment)    DEPLOYMENT="${2:?}"; shift 2 ;;
    --ssh)           SSH_TO="${2:?}"; shift 2 ;;
    --out)           OUT_DIR="${2:?}"; shift 2 ;;
    --no-clickhouse) WITH_CH=0; shift ;;
    -h|--help) sed -n '3,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done

if [[ -n "$DEPLOYMENT" ]]; then
  state_init "$DEPLOYMENT"; state_load
  SSH_TO="${SSH_TO:-$(state_get SSH_ALIAS)}"
  OUT_DIR="${OUT_DIR:-$DEPLOY_DIR/backups}"
fi
[[ -n "$SSH_TO" ]] || die "--deployment <name> or --ssh <alias> is required"
OUT_DIR="${OUT_DIR:-./backups}"
SSH_ALIAS="$SSH_TO"; export SSH_ALIAS

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/pki" "$WORK/postgres" "$WORK/config" "$WORK/clickhouse"
mkdir -p "$OUT_DIR"

printf '\n%s── backup: %s @ %s ──%s\n\n' "$C_BOLD" "$SSH_TO" "$STAMP" "$C_RESET"

# 1. The trust root. Everything else can be rebuilt; this cannot.
log "PKI (CA key + fleet signing key)"
rsudo "tar -cz -C /var/lib/ebpf-soc-controlplane ca.pem ca.key fleet.key" >"$WORK/pki/pki.tar.gz" \
  || die "could not read the PKI state — is the control plane installed?"
[[ -s "$WORK/pki/pki.tar.gz" ]] || die "the PKI archive came back empty"
ok "PKI captured ($(du -h "$WORK/pki/pki.tar.gz" | cut -f1))"

# 2. Control state. pg_dump inside the container: no client needed on the host,
# and the password never leaves the container's environment.
log "postgres (tenants, agents, audit, telemetry)"
rsudo "cd /etc/ebpf-soc/stack && docker compose exec -T postgres pg_dump -U soc -d ebpf_soc --clean --if-exists" \
  | gzip >"$WORK/postgres/ebpf_soc.sql.gz" \
  || die "pg_dump failed"
[[ -s "$WORK/postgres/ebpf_soc.sql.gz" ]] || die "the postgres dump is empty"
ok "postgres captured ($(du -h "$WORK/postgres/ebpf_soc.sql.gz" | cut -f1))"

# 3. The firehose. Big, and usually reconstructible from the agents' local WAL
# buffers, so it is opt-out.
if (( WITH_CH )) && rsudo_quiet "cd /etc/ebpf-soc/stack && docker compose ps -q clickhouse | grep -q ."; then
  log "clickhouse (events firehose)"
  rsudo "cd /etc/ebpf-soc/stack && docker compose exec -T clickhouse sh -c \
    'clickhouse-client --user \"\$CLICKHOUSE_USER\" --password \"\$CLICKHOUSE_PASSWORD\" -d ebpf_soc \
     --query \"SELECT * FROM telemetry FORMAT Native\"'" | gzip >"$WORK/clickhouse/telemetry.native.gz" \
    || warn "clickhouse export failed — continuing without it"
  ok "clickhouse captured ($(du -h "$WORK/clickhouse/telemetry.native.gz" 2>/dev/null | cut -f1 || echo 0))"
else
  dim "clickhouse: not running or skipped"
fi

# 4. Config — including the admin token and the DSNs.
log "config (/etc/ebpf-soc)"
rsudo "tar -cz -C /etc ebpf-soc" >"$WORK/config/etc-ebpf-soc.tar.gz" || die "config capture failed"
ok "config captured"

cat >"$WORK/MANIFEST" <<EOF
deployment   ${DEPLOYMENT:-$SSH_TO}
server       $SSH_TO
taken_at     $STAMP
contents     pki/ postgres/ config/$( ((WITH_CH)) && echo ' clickhouse/')
restore      ./scripts/restore.sh --ssh <alias> --archive <this file>
WARNING      contains the CA private key, the fleet signing key, database
             passwords and the control-plane admin token — treat as a secret.
EOF

ARCHIVE="$OUT_DIR/ebpf-soc-backup-$STAMP.tar.gz"
tar -czf "$ARCHIVE" -C "$WORK" .
chmod 600 "$ARCHIVE"
ok "backup → $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1), 0600)"

# Encrypt it if we can. An unencrypted backup of a security platform's CA key
# sitting on a laptop is a bigger risk than the outage it protects against.
if have_cmd age; then
  if confirm "Encrypt the archive with age (passphrase)?" y; then
    age -p -o "$ARCHIVE.age" "$ARCHIVE" && rm -f "$ARCHIVE"
    chmod 600 "$ARCHIVE.age"
    ok "encrypted → $ARCHIVE.age (the plaintext archive was removed)"
    ARCHIVE="$ARCHIVE.age"
  fi
elif have_cmd gpg; then
  if confirm "Encrypt the archive with gpg (passphrase)?" y; then
    gpg --symmetric --cipher-algo AES256 -o "$ARCHIVE.gpg" "$ARCHIVE" && rm -f "$ARCHIVE"
    chmod 600 "$ARCHIVE.gpg"
    ok "encrypted → $ARCHIVE.gpg"
    ARCHIVE="$ARCHIVE.gpg"
  fi
else
  warn "neither age nor gpg found — the archive is UNENCRYPTED and holds the CA key"
fi

printf '\n  Store it off this machine, then prove it: %s./scripts/restore.sh --archive %s --dry-run%s\n\n' \
  "$C_DIM" "$ARCHIVE" "$C_RESET"
