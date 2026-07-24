#!/usr/bin/env bash
#
# scripts/deploy-platform.sh — deploy the eBPF-SOC control plane to a server.
#
# A resumable, multi-step wizard. Step 1 establishes the SSH access every later
# step uses: it collects the server address, picks or generates a key, installs
# the public key on the server, writes a ~/.ssh/config alias, and proves both
# SSH and sudo work non-interactively. From there each step is a checkpoint —
# it records completion, so a failed run is re-run with --resume and picks up
# where it stopped rather than redoing (or re-randomising) what already worked.
#
#   ./scripts/deploy-platform.sh                      # full wizard, prompts
#   ./scripts/deploy-platform.sh --resume             # continue after a failure
#   ./scripts/deploy-platform.sh --only controlplane  # re-run one step
#   ./scripts/deploy-platform.sh --from stack         # re-run this step onward
#   ./scripts/deploy-platform.sh --dry-run            # print, change nothing
#   ./scripts/deploy-platform.sh --list-steps
#
# State lives in .deploy/<name>/ (git-ignored, 0700): state.env (config +
# step ledger), secrets.env (generated passwords), artifacts/ (CA bundle,
# fleet public key — what agents pin).
#
# What lands on the server:
#   /opt/ebpf-soc/controlplane                 control-plane binary
#   /opt/ebpf-soc/agent                        agent binary (for local install)
#   /etc/ebpf-soc/controlplane.env      0600   DSN, admin token, OIDC secret
#   /etc/ebpf-soc/stack/                       compose file + .env for the data tier
#   /var/lib/ebpf-soc-controlplane/     0700   CA + fleet signing key (the trust root)
#   /etc/systemd/system/ebpf-soc-controlplane.service

# LOG_TAG is read by common.sh log() via ${LOG_TAG} (a sourced file shellcheck
# can't follow without -x), so it only looks unused here.
# shellcheck disable=SC2034
LOG_TAG="deploy"
# shellcheck source=/dev/null
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

STEPS=(ssh preflight config build stack migrate identity controlplane pki tenant smoke)

usage() {
  sed -n '3,26p' "$0" | sed 's/^# \{0,1\}//'
  printf '\nSteps: %s\n' "${STEPS[*]}"
  exit "${1:-0}"
}

# ── Argument parsing ───────────────────────────────────────────────────────
ARG_HOST=""; ARG_NAME=""; ONLY=""; FROM=""; RESUME=0; FORCE=0
DRY_RUN=0; ASSUME_YES=0
export DRY_RUN ASSUME_YES

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)       ARG_HOST="${2:?--host needs user@host}"; shift 2 ;;
    --name)       ARG_NAME="${2:?--name needs a value}"; shift 2 ;;
    --only)       ONLY="${2:?--only needs a step}"; shift 2 ;;
    --from)       FROM="${2:?--from needs a step}"; shift 2 ;;
    --resume)     RESUME=1; shift ;;
    --force)      FORCE=1; shift ;;
    --yes|-y)     ASSUME_YES=1; shift ;;
    --dry-run)    DRY_RUN=1; shift ;;
    --list-steps) printf '%s\n' "${STEPS[@]}"; exit 0 ;;
    -h|--help)    usage 0 ;;
    *)            err "unknown flag: $1"; usage 1 ;;
  esac
done

step_selected() { # honours --only / --from / --resume / --force
  local s="$1"

  if [[ -n "$ONLY" ]]; then
    if [[ "$s" == "$ONLY" ]]; then return 0; fi
    return 1
  fi

  # --from: run this step and everything after it, regardless of the ledger.
  if [[ -n "$FROM" ]]; then
    local seen=0 x
    for x in "${STEPS[@]}"; do
      if [[ "$x" == "$FROM" ]]; then seen=1; fi
      if [[ "$x" == "$s" ]]; then
        if (( seen == 1 )); then return 0; fi
        return 1
      fi
    done
    return 1
  fi

  if [[ $FORCE == 0 ]] && step_is_done "$s"; then
    ok "$s — already done (--force to re-run)"
    return 1
  fi
  return 0
}

# ═══════════════════════════════════════════════════════════════════════════
# Step 1 — ssh: establish the access every later step rides on.
# ═══════════════════════════════════════════════════════════════════════════
do_ssh() {
  step_header "1/11  SSH access"

  local host user port key
  host="$(state_get SERVER_HOST)"; user="$(state_get SERVER_USER)"
  port="$(state_get SERVER_PORT 22)"; key="$(state_get SSH_KEY)"

  if [[ -n "$ARG_HOST" ]]; then
    user="${ARG_HOST%@*}"; host="${ARG_HOST#*@}"
    [[ "$ARG_HOST" == *"@"* ]] || { host="$ARG_HOST"; user=""; }
  fi

  [[ -n "$host" ]] || host="$(ask 'Server address (IP or DNS name)')"
  [[ -n "$host" ]] || die "a server address is required"
  [[ -n "$user" ]] || user="$(ask 'SSH login user' 'ubuntu')"
  port="$(ask 'SSH port' "${port:-22}")"

  # Key selection. A deployment-specific key is the default: it is revocable on
  # its own, and it keeps this automation's access separable from your personal
  # login key.
  if [[ -z "$key" ]]; then
    local default_key
    default_key="$HOME/.ssh/ebpf-soc-$(slugify "$host")"
    local choice
    choice="$(ask_choice 'SSH key to authenticate with:' \
      "generate a new deployment key ($default_key)" \
      "use an existing private key")"
    if [[ "$choice" == use* ]]; then
      key="$(ask 'Path to private key' "$HOME/.ssh/id_ed25519")"
      key="${key/#\~/$HOME}"
      [[ -f "$key" ]] || die "no such key: $key"
    else
      key="$default_key"
      if [[ -f "$key" ]]; then
        ok "reusing existing deployment key $key"
      else
        log "generating ed25519 deployment key"
        run ssh-keygen -t ed25519 -N '' -C "ebpf-soc-deploy@$(hostname -s)" -f "$key"
        ok "created $key"
      fi
    fi
  fi
  [[ -f "${key}.pub" ]] || warn "no public key at ${key}.pub — key install may fail"

  state_set SERVER_HOST "$host"
  state_set SERVER_USER "$user"
  state_set SERVER_PORT "$port"
  state_set SSH_KEY "$key"

  # An ssh_config alias means every later command is just `ssh <alias>` — no
  # flag soup, and the operator can use the same alias by hand.
  local alias
  alias="ebpf-soc-$(slugify "$host")"
  state_set SSH_ALIAS "$alias"
  install_ssh_alias "$alias" "$host" "$user" "$port" "$key"  

  export SSH_ALIAS="$alias"

  # Is the key already trusted by the server? If not, install it — this is the
  # one moment a password may be needed.
  log "testing key-based login to $user@$host:$port"
  if [[ "$DRY_RUN" == "1" ]]; then
    dim "dry-run: would verify key auth and install it if needed"
  elif ssh -o BatchMode=yes -o ConnectTimeout=10 "$alias" true 2>/dev/null; then
    ok "key-based SSH already works"
  else
    warn "key not accepted yet — installing the public key on the server"
    dim "you will be asked for the server password once (or for the key's passphrase)"
    if have_cmd ssh-copy-id; then
      ssh-copy-id -i "${key}.pub" -o StrictHostKeyChecking=accept-new -p "$port" "$user@$host" \
        || die "ssh-copy-id failed — check the address, user, password, and that the server allows password auth"
    else
      # macOS without ssh-copy-id: append the key over a password session.
      ssh -o StrictHostKeyChecking=accept-new -p "$port" "$user@$host" \
        "install -d -m 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys" \
        <"${key}.pub" || die "could not install the public key"
    fi
    ssh -o BatchMode=yes "$alias" true 2>/dev/null \
      || die "key installed but key-based login still fails — inspect sshd config on the server"
    ok "public key installed; key-based SSH works"
  fi

  # sudo. Everything after this step writes to /opt, /etc and systemd, so root
  # is not optional. Prefer passwordless; otherwise hold the password in memory
  # for this run only (never written to disk, never on a command line).
  if [[ "$DRY_RUN" != "1" ]]; then
    if ssh -o BatchMode=yes "$alias" "sudo -n true" 2>/dev/null; then
      ok "passwordless sudo available"
    else
      warn "sudo needs a password on this server"
      REMOTE_SUDO_PASS="$(ask_secret "sudo password for $user@$host")"
      export REMOTE_SUDO_PASS
      rsudo true >/dev/null 2>&1 || die "sudo password rejected"
      ok "sudo password accepted (held in memory for this run only)"
      if confirm "Install a NOPASSWD sudoers rule for $user so future runs need no password?" n; then
        rsudo "echo '$user ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-ebpf-soc && chmod 440 /etc/sudoers.d/90-ebpf-soc && visudo -c"
        ok "passwordless sudo configured"
      fi
    fi
  fi

  ok "SSH ready — later steps use: ssh $alias"
  step_done ssh
}

install_ssh_alias() { # <alias> <host> <user> <port> <key>
  local alias="$1" host="$2" user="$3" port="$4" key="$5"
  local cfg="$HOME/.ssh/config"
  local begin="# >>> ebpf-soc:$alias >>>"
  local end="# <<< ebpf-soc:$alias <<<"

  if [[ "$DRY_RUN" == "1" ]]; then dim "dry-run: would add Host $alias to $cfg"; return 0; fi
  mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
  touch "$cfg"; chmod 600 "$cfg"

  # Delete any previous managed block for this alias, then append a fresh one,
  # so re-running the wizard updates the entry instead of stacking duplicates.
  local tmp; tmp="$(mktemp)"
  awk -v b="$begin" -v e="$end" '
    $0 == b { skip = 1; next }
    $0 == e { skip = 0; next }
    !skip   { print }
  ' "$cfg" >"$tmp"

  cat >>"$tmp" <<EOF
$begin
Host $alias
    HostName $host
    User $user
    Port $port
    IdentityFile $key
    IdentitiesOnly yes
    StrictHostKeyChecking accept-new
    ServerAliveInterval 30
$end
EOF
  mv "$tmp" "$cfg"; chmod 600 "$cfg"
  ok "Host $alias → $user@$host:$port in $cfg"
}

# ═══════════════════════════════════════════════════════════════════════════
# Step 2 — preflight: is this server actually able to host the control plane?
# ═══════════════════════════════════════════════════════════════════════════
do_preflight() {
  step_header "2/11  Server preflight"
  "$SCRIPTS_DIR/preflight.sh" --role controlplane --ssh "$(state_get SSH_ALIAS)" \
    || die "preflight failed — fix the findings above, then re-run with --resume"
  step_done preflight
}

# ═══════════════════════════════════════════════════════════════════════════
# Step 3 — config: everything the deployment needs, secrets generated once.
# ═══════════════════════════════════════════════════════════════════════════
do_config() {
  step_header "3/11  Configuration"

  local domain tenant auth store
  domain="$(ask 'Public DNS name for the control plane (blank = use the IP)' "$(state_get DOMAIN "$(state_get SERVER_HOST)")")"
  tenant="$(ask 'First tenant id (lowercase, no spaces)' "$(state_get TENANT acme)")"
  tenant="$(slugify "$tenant" | tr '[:upper:]' '[:lower:]')"

  auth="$(ask_choice 'Operator authentication:' \
    'admin-token (headless bearer token — simplest, no browser)' \
    'oidc (Keycloak login for real operators — needs a browser)')"
  auth="${auth%% *}"

  store="$(ask_choice 'Central store for telemetry:' \
    'postgres (control state + telemetry with row-level security)' \
    'clickhouse (high-volume events firehose)')"
  store="${store%% *}"

  state_set DOMAIN "$domain"
  state_set TENANT "$tenant"
  state_set AUTH_MODE "$auth"
  state_set STORE "$store"
  state_set CP_GRPC_PORT "9443"
  state_set CP_HTTP_PORT "9090"

  # Generated once, reused on every later run — re-running config must never
  # rotate a password out from under a database that is already using it.
  secret_ensure POSTGRES_PASSWORD 32   >/dev/null
  secret_ensure CLICKHOUSE_PASSWORD 32 >/dev/null
  secret_ensure KEYCLOAK_ADMIN_PASSWORD 32 >/dev/null
  secret_ensure KEYCLOAK_CLIENT_SECRET 40 >/dev/null
  secret_ensure CP_ADMIN_TOKEN 48      >/dev/null
  ok "secrets generated into $SECRETS_FILE (0600)"

  dim "domain      $domain"
  dim "tenant      $tenant"
  dim "auth        $auth"
  dim "store       $store"
  dim "agent gRPC  0.0.0.0:9443   (public — agents dial this)"
  dim "operator    127.0.0.1:9090 (loopback — reach it over an SSH tunnel)"
  step_done config
}

# ═══════════════════════════════════════════════════════════════════════════
# Step 4 — build: static linux binaries, built locally.
# ═══════════════════════════════════════════════════════════════════════════
do_build() {
  step_header "4/11  Build binaries"
  need_cmd go "install Go 1.25+"
  log "building control plane + agent (static, linux/amd64)"
  run make -C "$REPO_ROOT" build-controlplane-linux
  run make -C "$REPO_ROOT" build-agent-linux

  local cp="$REPO_ROOT/engine/controlplane-linux-amd64"
  local ag="$REPO_ROOT/engine/agent-linux-amd64"
  if [[ "$DRY_RUN" != "1" ]]; then
    for b in "$cp" "$ag"; do
      [[ -f "$b" ]] || die "expected binary missing: $b"
      file "$b" | grep -q 'statically linked' || die "$b is not statically linked"
    done
    ok "controlplane $(du -h "$cp" | cut -f1) · agent $(du -h "$ag" | cut -f1) — both static"
  fi
  step_done build
}

# ═══════════════════════════════════════════════════════════════════════════
# Step 5 — stack: Docker + the data tier (Postgres/NATS/ClickHouse/Keycloak).
# ═══════════════════════════════════════════════════════════════════════════
do_stack() {
  step_header "5/11  Data-tier stack"
  SSH_ALIAS="$(state_get SSH_ALIAS)"; export SSH_ALIAS
  local store auth
  store="$(state_get STORE)"
  auth="$(state_get AUTH_MODE)"

  if ! rssh_quiet "command -v docker"; then
    log "installing Docker on the server"
    rsudo "curl -fsSL https://get.docker.com | sh"
    rsudo "systemctl enable --now docker"
    ok "Docker installed"
  else
    ok "Docker already present"
  fi

  log "staging the compose stack into /etc/ebpf-soc/stack"
  rput_root "$REPO_ROOT/deploy/docker-compose.oss.yml" /etc/ebpf-soc/stack/docker-compose.yml 0644

  # The shipped compose file publishes every service on 0.0.0.0 — fine on a
  # laptop, a data breach on a public server. This override rebinds the whole
  # data tier to loopback: only the agent gRPC port is ever public.
  rwrite_root /etc/ebpf-soc/stack/docker-compose.override.yml 0644 <<'YAML'
# Written by scripts/deploy-platform.sh — do not edit by hand.
# Server hardening: the data tier listens on loopback only. Reach Keycloak or a
# database from your laptop with an SSH tunnel, never over the public internet.
services:
  nats:       { ports: ["127.0.0.1:4222:4222", "127.0.0.1:8222:8222"] }
  postgres:   { ports: ["127.0.0.1:5432:5432"] }
  clickhouse: { ports: ["127.0.0.1:8123:8123", "127.0.0.1:9000:9000"] }
  keycloak:   { ports: ["127.0.0.1:8080:8080"] }
  seaweedfs:  { ports: ["127.0.0.1:8333:8333", "127.0.0.1:9333:9333", "127.0.0.1:8888:8888"] }
YAML

  rwrite_root /etc/ebpf-soc/stack/.env 0600 <<EOF
POSTGRES_PASSWORD=$(secret_get POSTGRES_PASSWORD)
CLICKHOUSE_PASSWORD=$(secret_get CLICKHOUSE_PASSWORD)
KEYCLOAK_ADMIN_PASSWORD=$(secret_get KEYCLOAK_ADMIN_PASSWORD)
EOF
  ok "compose file, loopback override, and .env (0600) staged"

  # Bring up only what this deployment actually uses. ADR sequencing: control
  # state and identity first, then the bus, then the firehose. SeaweedFS stays
  # stopped until forensic export needs it.
  local services=(postgres nats)
  if [[ "$auth"  == "oidc"       ]]; then services+=(keycloak); fi
  if [[ "$store" == "clickhouse" ]]; then services+=(clickhouse); fi

  log "starting: ${services[*]}"
  rsudo "cd /etc/ebpf-soc/stack && docker compose up -d ${services[*]}"

  wait_for 180 "postgres" rsudo_quiet \
    "cd /etc/ebpf-soc/stack && docker compose exec -T postgres pg_isready -U soc -d ebpf_soc" \
    || die "postgres never became ready — ssh $SSH_ALIAS 'sudo docker compose -f /etc/ebpf-soc/stack/docker-compose.yml logs postgres'"

  if [[ "$store" == "clickhouse" ]]; then
    wait_for 180 "clickhouse" rssh_quiet "curl -fsS http://127.0.0.1:8123/ping" \
      || die "clickhouse never became ready"
  fi
  if [[ "$auth" == "oidc" ]]; then
    wait_for 300 "keycloak" rssh_quiet "curl -fsS http://127.0.0.1:8080/realms/master" \
      || die "keycloak never became ready"
  fi
  ok "data tier up"
  step_done stack
}

# ═══════════════════════════════════════════════════════════════════════════
# Step 6 — migrate: schema, tenant roles, RLS, retention.
# ═══════════════════════════════════════════════════════════════════════════
do_migrate() {
  step_header "6/11  Database migrations"
  SSH_ALIAS="$(state_get SSH_ALIAS)"; export SSH_ALIAS

  log "uploading migrations"
  if [[ "$DRY_RUN" != "1" ]]; then
    tar -cz -C "$SCRIPTS_DIR" migrations migrate.sh lib | rssh "cat > /tmp/ebpf-migrations.tgz"
    rsudo "rm -rf /opt/ebpf-soc/migrate && mkdir -p /opt/ebpf-soc/migrate && tar -xzf /tmp/ebpf-migrations.tgz -C /opt/ebpf-soc/migrate && rm -f /tmp/ebpf-migrations.tgz"
  fi

  rsudo "cd /opt/ebpf-soc/migrate && bash migrate.sh up --docker /etc/ebpf-soc/stack --engine postgres" \
    || die "postgres migrations failed"
  if [[ "$(state_get STORE)" == "clickhouse" ]]; then
    rsudo "cd /opt/ebpf-soc/migrate && bash migrate.sh up --docker /etc/ebpf-soc/stack --engine clickhouse" \
      || die "clickhouse migrations failed"
  fi
  ok "migrations applied"
  step_done migrate
}

# ═══════════════════════════════════════════════════════════════════════════
# Step 7 — identity: Keycloak realm, client, and the first operator (OIDC only).
# ═══════════════════════════════════════════════════════════════════════════
do_identity() {
  step_header "7/11  Identity (Keycloak)"
  if [[ "$(state_get AUTH_MODE)" != "oidc" ]]; then
    ok "admin-token mode — no Keycloak to seed, skipping"
    step_done identity; return 0
  fi
  SSH_ALIAS="$(state_get SSH_ALIAS)"; export SSH_ALIAS

  local realm="ebpf-soc" client="ebpf-soc-console"
  local domain; domain="$(state_get DOMAIN)"
  local redirect="http://127.0.0.1:9090/auth/callback"
  local kcadm="/opt/keycloak/bin/kcadm.sh"
  local kc_pass; kc_pass="$(secret_get KEYCLOAK_ADMIN_PASSWORD)"
  local cl_secret; cl_secret="$(secret_get KEYCLOAK_CLIENT_SECRET)"
  local op_pass; op_pass="$(secret_ensure OPERATOR_PASSWORD 24)"

  log "seeding realm '$realm', client '$client', operator 'operator'"
  # kcadm is idempotent-hostile (create fails when the object exists), so each
  # create is allowed to fail and the config is then re-applied with update.
  rsudo "cd /etc/ebpf-soc/stack && docker compose exec -T keycloak sh -c '
    set -e
    $kcadm config credentials --server http://127.0.0.1:8080 --realm master --user admin --password \"$kc_pass\"
    $kcadm create realms -s realm=$realm -s enabled=true 2>/dev/null || echo \"realm exists\"
    $kcadm create clients -r $realm \
      -s clientId=$client -s enabled=true -s protocol=openid-connect \
      -s publicClient=false -s standardFlowEnabled=true \
      -s secret=\"$cl_secret\" \
      -s \"redirectUris=[\\\"$redirect\\\",\\\"https://$domain/auth/callback\\\"]\" 2>/dev/null || echo \"client exists\"
    $kcadm create users -r $realm -s username=operator -s enabled=true -s email=operator@$domain 2>/dev/null || echo \"user exists\"
    $kcadm set-password -r $realm --username operator --new-password \"$op_pass\"
  '" || die "Keycloak seeding failed"

  state_set OIDC_ISSUER "http://127.0.0.1:8080/realms/$realm"
  state_set OIDC_CLIENT_ID "$client"
  state_set OIDC_REDIRECT "$redirect"
  ok "realm seeded — operator password is in $SECRETS_FILE (OPERATOR_PASSWORD)"
  step_done identity
}

# ═══════════════════════════════════════════════════════════════════════════
# Step 8 — controlplane: binary, env, systemd unit, running and healthy.
# ═══════════════════════════════════════════════════════════════════════════
do_controlplane() {
  step_header "8/11  Control plane"
  SSH_ALIAS="$(state_get SSH_ALIAS)"; export SSH_ALIAS
  local auth store domain
  auth="$(state_get AUTH_MODE)"; store="$(state_get STORE)"; domain="$(state_get DOMAIN)"

  log "installing /opt/ebpf-soc/controlplane"
  rput_root "$REPO_ROOT/engine/controlplane-linux-amd64" /opt/ebpf-soc/controlplane 0755
  rput_root "$REPO_ROOT/engine/agent-linux-amd64"        /opt/ebpf-soc/agent 0755

  # Secrets travel in the EnvironmentFile, never in ExecStart: /proc/<pid>/cmdline
  # is world-readable, /proc/<pid>/environ is not. The binary reads CP_ADMIN_TOKEN,
  # CP_PG_DSN and CP_OIDC_CLIENT_SECRET from the environment for exactly this reason.
  local dsn ch_dsn
  dsn="postgres://soc:$(secret_get POSTGRES_PASSWORD)@127.0.0.1:5432/ebpf_soc?sslmode=disable"
  ch_dsn="clickhouse://soc:$(secret_get CLICKHOUSE_PASSWORD)@127.0.0.1:9000/ebpf_soc"
  {
    printf 'CP_PG_DSN=%s\n' "$dsn"
    printf 'CP_CH_DSN=%s\n' "$ch_dsn"
    printf 'CP_ADMIN_TOKEN=%s\n' "$(secret_get CP_ADMIN_TOKEN)"
    if [[ "$auth" == "oidc" ]]; then
      printf 'CP_OIDC_CLIENT_SECRET=%s\n' "$(secret_get KEYCLOAK_CLIENT_SECRET)"
    fi
  } | rwrite_root /etc/ebpf-soc/controlplane.env 0600
  ok "/etc/ebpf-soc/controlplane.env written (0600)"

  # ExecStart is assembled per auth mode / store. -state-dir persists the CA and
  # the fleet signing key, so enrolled agents keep trusting this control plane
  # across restarts; -ca-out / -fleet-pubkey-out re-export what agents pin.
  local store_args auth_args
  # ${CP_CH_DSN}/${CP_PG_DSN} are intentionally literal: systemd expands them at
  # runtime from the EnvironmentFile so the DSN (with its password) never lands
  # in this script's process table or the unit's ExecStart on disk.
  # shellcheck disable=SC2016
  if [[ "$store" == "clickhouse" ]]; then
    store_args='-store clickhouse -ch-dsn ${CP_CH_DSN}'
  else
    store_args='-store postgres -pg-dsn ${CP_PG_DSN}'
  fi
  if [[ "$auth" == "oidc" ]]; then
    auth_args="-oidc-issuer $(state_get OIDC_ISSUER) -oidc-client-id $(state_get OIDC_CLIENT_ID) -oidc-redirect-url $(state_get OIDC_REDIRECT)"
  else
    auth_args=""   # CP_ADMIN_TOKEN is picked up from the environment
  fi

  rwrite_root /etc/systemd/system/ebpf-soc-controlplane.service 0644 <<EOF
[Unit]
Description=eBPF-SOC control plane (multi-tenant)
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/ebpf-soc/controlplane \\
  $store_args \\
  -grpc 0.0.0.0:$(state_get CP_GRPC_PORT) \\
  -http 127.0.0.1:$(state_get CP_HTTP_PORT) \\
  -server-name $domain \\
  -state-dir /var/lib/ebpf-soc-controlplane \\
  -ca-out /var/lib/ebpf-soc-controlplane/ca-bundle.pem \\
  -fleet-pubkey-out /var/lib/ebpf-soc-controlplane/fleet.pub \\
  $auth_args
EnvironmentFile=/etc/ebpf-soc/controlplane.env
Restart=always
RestartSec=2
TimeoutStopSec=15
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ebpf-soc-controlplane

DynamicUser=yes
StateDirectory=ebpf-soc-controlplane
StateDirectoryMode=0700
WorkingDirectory=/var/lib/ebpf-soc-controlplane

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
EOF

  log "starting ebpf-soc-controlplane"
  rsudo "systemctl daemon-reload && systemctl enable --now ebpf-soc-controlplane && systemctl restart ebpf-soc-controlplane"

  wait_for 60 "control-plane /healthz" rssh_quiet \
    "curl -fsS http://127.0.0.1:$(state_get CP_HTTP_PORT)/healthz" \
    || die "control plane did not come up — inspect: ssh $SSH_ALIAS 'sudo journalctl -u ebpf-soc-controlplane -n 50'"

  # The agent gRPC port is the only public surface. Open it if a firewall is on.
  if rssh_quiet "command -v ufw" && rsudo_quiet "ufw status | grep -q active"; then
    if rsudo "ufw allow $(state_get CP_GRPC_PORT)/tcp"; then
      ok "ufw: opened $(state_get CP_GRPC_PORT)/tcp for agents"
    else
      warn "could not open $(state_get CP_GRPC_PORT)/tcp in ufw — agents will not reach the control plane"
    fi
  fi
  ok "control plane healthy"
  step_done controlplane
}

# ═══════════════════════════════════════════════════════════════════════════
# Step 9 — pki: pull down what agents must pin.
# ═══════════════════════════════════════════════════════════════════════════
do_pki() {
  step_header "9/11  Trust material (CA + fleet key)"
  SSH_ALIAS="$(state_get SSH_ALIAS)"; export SSH_ALIAS
  "$SCRIPTS_DIR/pki.sh" export --ssh "$(state_get SSH_ALIAS)" --out "$ARTIFACTS_DIR" \
    || die "could not export the CA bundle / fleet public key"
  ok "CA bundle → $ARTIFACTS_DIR/ca-bundle.pem"
  ok "fleet key → $ARTIFACTS_DIR/fleet.pub"
  dim "back these up: losing the CA key means re-enrolling every agent (scripts/backup.sh)"
  step_done pki
}

# ═══════════════════════════════════════════════════════════════════════════
# Step 10 — tenant: create the first tenant and mint an enrollment token.
# ═══════════════════════════════════════════════════════════════════════════
do_tenant() {
  step_header "10/11  First tenant + enrollment token"
  SSH_ALIAS="$(state_get SSH_ALIAS)"; export SSH_ALIAS
  local tenant; tenant="$(state_get TENANT)"

  # Register the tenant before minting: the agent registry has a foreign key to
  # it, so an agent enrolling into an unregistered tenant would fail on first
  # heartbeat rather than at enrollment — a confusing place to find out.
  CP_ADMIN_TOKEN="$(secret_get CP_ADMIN_TOKEN)" \
    "$SCRIPTS_DIR/tenantctl" create "$tenant" --ssh "$(state_get SSH_ALIAS)" \
    || die "could not register tenant '$tenant'"

  CP_ADMIN_TOKEN="$(secret_get CP_ADMIN_TOKEN)" \
  CP_URL="http://127.0.0.1:$(state_get CP_HTTP_PORT)" \
    "$SCRIPTS_DIR/tenantctl" enroll-token "$tenant" \
      --ssh "$(state_get SSH_ALIAS)" \
      --out "$ARTIFACTS_DIR/enroll-token-$tenant.txt" \
    || die "could not mint an enrollment token"

  ok "enrollment token for '$tenant' → $ARTIFACTS_DIR/enroll-token-$tenant.txt"
  dim "tokens are single-use and expire in 15 minutes — mint a fresh one per agent"
  step_done tenant
}

# ═══════════════════════════════════════════════════════════════════════════
# Step 11 — smoke: prove the thing actually works.
# ═══════════════════════════════════════════════════════════════════════════
do_smoke() {
  step_header "11/11  Smoke test"
  SSH_ALIAS="$(state_get SSH_ALIAS)"; export SSH_ALIAS
  CP_ADMIN_TOKEN="$(secret_get CP_ADMIN_TOKEN)" \
    "$SCRIPTS_DIR/smoke.sh" --ssh "$(state_get SSH_ALIAS)" --tenant "$(state_get TENANT)" \
    || die "smoke test failed — the platform is up but not correct; see the failures above"
  step_done smoke
}

# ═══════════════════════════════════════════════════════════════════════════
summary() {
  local host alias tenant auth
  host="$(state_get SERVER_HOST)"; alias="$(state_get SSH_ALIAS)"
  tenant="$(state_get TENANT)"; auth="$(state_get AUTH_MODE)"

  printf '\n%s══ Deployment complete ══%s\n\n' "$C_BOLD" "$C_RESET"
  printf '  %sServer%s        ssh %s\n' "$C_BOLD" "$C_RESET" "$alias"
  printf '  %sAgents dial%s   %s:%s  (mTLS gRPC — the only public port)\n' "$C_BOLD" "$C_RESET" "$host" "$(state_get CP_GRPC_PORT)"
  printf '  %sOperator API%s  127.0.0.1:%s on the server (loopback by design)\n\n' "$C_BOLD" "$C_RESET" "$(state_get CP_HTTP_PORT)"

  printf '  %sReach the operator API from here:%s\n' "$C_BOLD" "$C_RESET"
  printf '    ssh -L 9090:127.0.0.1:9090 %s\n' "$alias"
  if [[ "$auth" == "oidc" ]]; then
    printf '    ssh -L 8080:127.0.0.1:8080 %s     # Keycloak (operator / see secrets.env)\n' "$alias"
  else
    # The $(grep ...) is copy-paste instructions printed for the operator, not
    # something to expand here.
    # shellcheck disable=SC2016
    printf '    curl -H "Authorization: Bearer $(grep ^CP_ADMIN_TOKEN "%s" | cut -d= -f2)" \\\n' "$SECRETS_FILE"
    printf '         http://127.0.0.1:9090/api/whoami\n'
  fi

  printf '\n  %sEnroll your first agent%s (on a Linux host with kernel ≥ 5.15 + BTF):\n' "$C_BOLD" "$C_RESET"
  printf '    ./scripts/install-agent.sh \\\n'
  printf '      --host <user>@<agent-host> \\\n'
  printf '      --controlplane %s:%s \\\n' "$host" "$(state_get CP_GRPC_PORT)"
  printf '      --tenant %s \\\n' "$tenant"
  printf '      --deployment %s\n' "$DEPLOY_NAME"

  printf '\n  %sState + trust material%s  %s\n' "$C_BOLD" "$C_RESET" "$DEPLOY_DIR"
  printf '    secrets.env   every generated password + the admin token (0600)\n'
  printf '    artifacts/    CA bundle + fleet public key — what agents pin\n'
  printf '\n  %sBack this up now:%s ./scripts/backup.sh --deployment %s\n' "$C_YEL" "$C_RESET" "$DEPLOY_NAME"
  printf '  Losing the CA key means every enrolled agent must re-enroll.\n\n'
}

# ═══════════════════════════════════════════════════════════════════════════
main() {
  need_cmd ssh; need_cmd scp

  # Name the deployment after the server, so several servers can be managed
  # side by side from the same checkout.
  local name="$ARG_NAME"
  if [[ -z "$name" ]]; then
    if [[ -n "$ARG_HOST" ]]; then
      name="$(slugify "${ARG_HOST#*@}")"
    else
      # Reuse the only existing deployment when resuming without a name.
      local existing=() d
      if [[ -d "$STATE_ROOT" ]]; then
        while IFS= read -r d; do existing+=("$(basename "$d")"); done \
          < <(find "$STATE_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
      fi
      if [[ ${#existing[@]} -eq 1 ]]; then
        name="${existing[0]}"
      elif [[ ${#existing[@]} -gt 1 ]]; then
        name="$(ask_choice 'Which deployment?' "${existing[@]}")"
      else
        name="default"
      fi
    fi
  fi

  state_init "$name"
  state_load
  if [[ "$RESUME" == 1 ]]; then log "resuming deployment '$name'"; fi
  if [[ "$DRY_RUN" == 1 ]]; then warn "DRY RUN — nothing will be changed"; fi

  printf '\n%seBPF-SOC platform deploy%s  ·  deployment: %s  ·  state: %s\n' \
    "$C_BOLD" "$C_RESET" "$name" "$DEPLOY_DIR"

  local s
  for s in "${STEPS[@]}"; do
    step_selected "$s" || continue
    "do_${s}"
    state_load   # a step may have written config the next one reads
  done

  [[ -n "$ONLY" ]] || summary
}

main "$@"
