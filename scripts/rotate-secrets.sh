#!/usr/bin/env bash
#
# scripts/rotate-secrets.sh — rotate a deployment's credentials in place.
#
# Roadmap Phase 0 calls for rotating the shipped `admin/ebpf-soc-demo`
# credential. More generally, a credential that has never been rotated is one
# nobody knows how to rotate — so this exists to make it routine rather than an
# incident-time improvisation.
#
#   ./scripts/rotate-secrets.sh --deployment <name> --what admin-token
#   ./scripts/rotate-secrets.sh --deployment <name> --what postgres
#   ./scripts/rotate-secrets.sh --deployment <name> --what all
#
# What each rotation costs:
#   admin-token   Instant. Any script or operator holding the old bearer breaks.
#                 Zero impact on agents (they authenticate with mTLS, not this).
#   postgres      Brief control-plane restart. Zero impact on agents: they buffer
#                 telemetry locally and keep enforcing while the uplink is down.
#   keycloak      Operators re-login. Agents unaffected.
#
# NOT here on purpose: the CA and the fleet signing key. Rotating those re-enrolls
# the entire fleet, so they live behind scripts/pki.sh rotate with its own
# confirmation. They are a different class of event.

LOG_TAG="rotate"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

DEPLOYMENT=""; WHAT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --deployment) DEPLOYMENT="${2:?}"; shift 2 ;;
    --what)       WHAT="${2:?}"; shift 2 ;;
    -h|--help) sed -n '3,23p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done

[[ -n "$DEPLOYMENT" ]] || die "--deployment <name> is required"
[[ -n "$WHAT" ]] || die "--what admin-token|postgres|keycloak|all is required"

state_init "$DEPLOYMENT"; state_load
SSH_ALIAS="$(state_get SSH_ALIAS)"; export SSH_ALIAS
[[ -n "$SSH_ALIAS" ]] || die "deployment '$DEPLOYMENT' has no SSH alias — was it deployed?"

doing() { [[ "$WHAT" == "all" || "$WHAT" == "$1" ]]; }

restart_cp() {
  log "restarting the control plane"
  rsudo "systemctl restart ebpf-soc-controlplane"
  wait_for 60 "control-plane /healthz" rssh_quiet "curl -fsS http://127.0.0.1:9090/healthz" \
    || die "the control plane did not come back — journalctl -u ebpf-soc-controlplane -n 50"
}

# ── The operator bearer token ──────────────────────────────────────────────
if doing admin-token; then
  step_header "Rotating the control-plane admin token"
  NEW="$(gen_secret 48)"
  rsudo "sed -i 's|^CP_ADMIN_TOKEN=.*|CP_ADMIN_TOKEN=$NEW|' /etc/ebpf-soc/controlplane.env"
  secret_set CP_ADMIN_TOKEN "$NEW"
  restart_cp
  ok "admin token rotated (new value in $SECRETS_FILE)"
  warn "any script still holding the old bearer now gets 401"
fi

# ── The database password ──────────────────────────────────────────────────
# Order matters: change it in Postgres first, then in the two places that use it
# (the compose .env and the control-plane DSN), then restart. Between the ALTER
# and the restart the control plane holds already-open connections, so there is
# no window where it is broken — only a window where a NEW connection would fail.
if doing postgres; then
  step_header "Rotating the Postgres password"
  NEW="$(gen_secret 32)"

  log "ALTER ROLE soc"
  rsudo "cd /etc/ebpf-soc/stack && docker compose exec -T postgres \
    psql -U soc -d ebpf_soc -v ON_ERROR_STOP=1 -c \"ALTER ROLE soc WITH PASSWORD '$NEW';\"" >/dev/null \
    || die "could not change the database password"

  log "updating the compose .env and the control-plane DSN"
  rsudo "sed -i 's|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$NEW|' /etc/ebpf-soc/stack/.env"
  rsudo "sed -i 's|^CP_PG_DSN=postgres://soc:[^@]*@|CP_PG_DSN=postgres://soc:$NEW@|' /etc/ebpf-soc/controlplane.env"
  secret_set POSTGRES_PASSWORD "$NEW"

  restart_cp
  ok "postgres password rotated"
  dim "agents were unaffected — they buffer locally and keep enforcing regardless"
fi

# ── The OIDC client secret ─────────────────────────────────────────────────
if doing keycloak; then
  step_header "Rotating the Keycloak client secret"
  if [[ "$(state_get AUTH_MODE)" != "oidc" ]]; then
    warn "this deployment uses admin-token auth — there is no Keycloak client to rotate"
  else
    NEW="$(gen_secret 40)"
    local_realm="ebpf-soc"; client_id="$(state_get OIDC_CLIENT_ID)"
    kc_pass="$(secret_get KEYCLOAK_ADMIN_PASSWORD)"

    rsudo "cd /etc/ebpf-soc/stack && docker compose exec -T keycloak sh -c '
      set -e
      /opt/keycloak/bin/kcadm.sh config credentials --server http://127.0.0.1:8080 \
        --realm master --user admin --password \"$kc_pass\"
      id=\$(/opt/keycloak/bin/kcadm.sh get clients -r $local_realm -q clientId=$client_id --fields id --format csv --noquotes)
      /opt/keycloak/bin/kcadm.sh update clients/\$id -r $local_realm -s secret=\"$NEW\"
    '" || die "could not rotate the Keycloak client secret"

    rsudo "sed -i 's|^CP_OIDC_CLIENT_SECRET=.*|CP_OIDC_CLIENT_SECRET=$NEW|' /etc/ebpf-soc/controlplane.env"
    secret_set KEYCLOAK_CLIENT_SECRET "$NEW"
    restart_cp
    ok "Keycloak client secret rotated — operators must log in again"
  fi
fi

printf '\n'
ok "rotation complete for '$DEPLOYMENT'"
dim "new values are in $SECRETS_FILE (0600) — back it up: ./scripts/backup.sh --deployment $DEPLOYMENT"
