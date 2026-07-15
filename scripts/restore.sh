#!/usr/bin/env bash
#
# scripts/restore.sh — restore a deployment from a scripts/backup.sh archive.
#
# Restoring the PKI is the whole point: put the same CA key and fleet signing
# key back, and every already-enrolled agent reconnects to the rebuilt control
# plane as if nothing happened. Restore the database but NOT the PKI and you
# have a control plane with the right data that no agent will talk to.
#
#   ./scripts/restore.sh --ssh <alias> --archive backups/…tar.gz [--dry-run]
#   ./scripts/restore.sh --ssh <alias> --archive … --only pki
#
# --dry-run unpacks and validates the archive without touching the server. Use
# it to rehearse a DR drill (Phase 3's exit gate) without a real outage.

LOG_TAG="restore"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

SSH_TO=""; ARCHIVE=""; ONLY=""; DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh)     SSH_TO="${2:?}"; shift 2 ;;
    --archive) ARCHIVE="${2:?}"; shift 2 ;;
    --only)    ONLY="${2:?}"; shift 2 ;;   # pki | postgres | config
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) sed -n '3,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done
export DRY_RUN

[[ -n "$ARCHIVE" && -f "$ARCHIVE" ]] || die "--archive <file> is required"
if [[ "$DRY_RUN" == "0" ]]; then
  [[ -n "$SSH_TO" ]] || die "--ssh <alias> is required (or pass --dry-run to validate only)"
  SSH_ALIAS="$SSH_TO"; export SSH_ALIAS
fi

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# ── Unpack + validate ──────────────────────────────────────────────────────
log "unpacking $ARCHIVE"
case "$ARCHIVE" in
  *.age) have_cmd age || die "this archive is age-encrypted but age is not installed"
         age -d -o "$WORK/backup.tar.gz" "$ARCHIVE" || die "decryption failed"
         tar -xzf "$WORK/backup.tar.gz" -C "$WORK" ;;
  *.gpg) have_cmd gpg || die "this archive is gpg-encrypted but gpg is not installed"
         gpg -d -o "$WORK/backup.tar.gz" "$ARCHIVE" || die "decryption failed"
         tar -xzf "$WORK/backup.tar.gz" -C "$WORK" ;;
  *)     tar -xzf "$ARCHIVE" -C "$WORK" ;;
esac

[[ -f "$WORK/MANIFEST" ]] || die "no MANIFEST — this is not a scripts/backup.sh archive"
printf '\n'; sed 's/^/  /' "$WORK/MANIFEST"; printf '\n'

[[ -s "$WORK/pki/pki.tar.gz" ]] || die "the archive has no PKI — an agent-less control plane is not a restore"
[[ -s "$WORK/postgres/ebpf_soc.sql.gz" ]] || warn "the archive has no postgres dump"

if [[ "$DRY_RUN" == "1" ]]; then
  ok "archive is valid and complete"
  dim "pki       $(du -h "$WORK/pki/pki.tar.gz" | cut -f1)"
  dim "postgres  $(du -h "$WORK/postgres/ebpf_soc.sql.gz" 2>/dev/null | cut -f1 || echo '—')"
  dim "config    $(du -h "$WORK/config/etc-ebpf-soc.tar.gz" 2>/dev/null | cut -f1 || echo '—')"
  ok "dry run complete — nothing was changed"
  exit 0
fi

# ── Confirm ────────────────────────────────────────────────────────────────
warn "this OVERWRITES the control plane on $SSH_TO:"
dim "  · the CA + fleet signing key (agents will re-pin to the RESTORED CA)"
dim "  · the ebpf_soc database (pg_dump --clean: existing tables are DROPPED)"
dim "  · /etc/ebpf-soc (DSNs, admin token)"
confirm "Restore over the live deployment?" n || { log "aborted"; exit 0; }

restoring() { [[ -z "$ONLY" || "$ONLY" == "$1" ]]; }

log "stopping the control plane"
rsudo "systemctl stop ebpf-soc-controlplane 2>/dev/null || true"

# 1. PKI first — it defines the identity of the platform every agent trusts.
if restoring pki; then
  log "restoring the PKI (CA + fleet key)"
  rput_root "$WORK/pki/pki.tar.gz" /tmp/pki-restore.tar.gz 0600
  rsudo "mkdir -p /var/lib/ebpf-soc-controlplane && \
         tar -xzf /tmp/pki-restore.tar.gz -C /var/lib/ebpf-soc-controlplane && \
         chmod 700 /var/lib/ebpf-soc-controlplane && \
         chmod 600 /var/lib/ebpf-soc-controlplane/ca.key /var/lib/ebpf-soc-controlplane/fleet.key && \
         rm -f /tmp/pki-restore.tar.gz"
  ok "PKI restored — previously-enrolled agents will trust this control plane again"
fi

if restoring config; then
  if [[ -s "$WORK/config/etc-ebpf-soc.tar.gz" ]]; then
    log "restoring /etc/ebpf-soc"
    rput_root "$WORK/config/etc-ebpf-soc.tar.gz" /tmp/config-restore.tar.gz 0600
    rsudo "tar -xzf /tmp/config-restore.tar.gz -C /etc && rm -f /tmp/config-restore.tar.gz"
    ok "config restored"
  fi
fi

if restoring postgres; then
  if [[ -s "$WORK/postgres/ebpf_soc.sql.gz" ]]; then
    log "restoring postgres (this drops and recreates the tables)"
    rsudo "cd /etc/ebpf-soc/stack && docker compose up -d postgres"
    wait_for 120 "postgres" rsudo_quiet \
      "cd /etc/ebpf-soc/stack && docker compose exec -T postgres pg_isready -U soc -d ebpf_soc" \
      || die "postgres did not come up"

    # Stage the dump on the server rather than piping it into rsudo: when sudo
    # needs a password, rsudo owns stdin to deliver it, and anything piped in
    # would be eaten by sudo instead of reaching psql.
    rput_root "$WORK/postgres/ebpf_soc.sql.gz" /tmp/ebpf-restore.sql.gz 0600
    rsudo "cd /etc/ebpf-soc/stack && gunzip -c /tmp/ebpf-restore.sql.gz | \
           docker compose exec -T postgres psql -U soc -d ebpf_soc -v ON_ERROR_STOP=1 --quiet; \
           rc=\$?; rm -f /tmp/ebpf-restore.sql.gz; exit \$rc" \
      || die "the database restore failed — the control plane is still stopped"
    ok "postgres restored"
  fi
fi

log "starting the control plane"
rsudo "systemctl start ebpf-soc-controlplane"
wait_for 60 "control-plane /healthz" rssh_quiet "curl -fsS http://127.0.0.1:9090/healthz" \
  || die "the control plane did not come back — journalctl -u ebpf-soc-controlplane -n 50"

ok "restore complete"
printf '\n  Verify the trust root is the one you expect:\n'
printf '    ./scripts/pki.sh export --ssh %s --out /tmp/restored && ./scripts/pki.sh inspect --ca /tmp/restored/ca-bundle.pem\n' "$SSH_TO"
printf '  Then confirm an agent reconnects without re-enrolling.\n\n'
