#!/usr/bin/env bash
#
# scripts/deploy/lib.sh — shared provisioning for the eBPF-SOC deploy scripts.
#
# An OrbStack machine and a remote server are both just "a Linux host you run
# root commands on", so the provisioning is written once here and the per-target
# entrypoints only wire up a driver:
#
#   RUN "<bash>"          run a root shell snippet on the target
#   PUT  <local> <dst>    place a local file on the target (mode 0755)
#   PKG  <pkgs...>        install OS packages on the target
#   TARGET_HOST           the host/IP that browsers + OIDC issuer use
#
# Then they call provision_engine (single-tenant) or provision_controlplane
# (multi-tenant). Nothing here is target-specific.

set -euo pipefail
DEPLOY_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DEPLOY_LIB_DIR/../.." && pwd)"
LOG_TAG="${LOG_TAG:-deploy}"
# reuse the repo's log/ok/die/gen_secret helpers
source "$REPO_ROOT/scripts/lib/common.sh"

BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/.deploy-build}"

# ─── config knobs (entrypoints/env override) ────────────────────────────────
KC_VERSION="${KC_VERSION:-26.0.8}"
TETRAGON_IMAGE="${TETRAGON_IMAGE:-quay.io/cilium/tetragon:v1.6.1}"
ENGINE_MODE="${ENGINE_MODE:-fake}"          # fake | tetragon
ENGINE_PORT="${ENGINE_PORT:-8090}"
ENGINE_USER="${ENGINE_USER:-admin}"
ENGINE_PASS="${ENGINE_PASS:-}"              # generated if empty
LOGIN_RATE="${LOGIN_RATE:-5}"               # 0 disables (dev/E2E)
# multi-tenant
CP_HTTP_PORT="${CP_HTTP_PORT:-9090}"
KC_PORT="${KC_PORT:-8085}"
PG_PASS="${PG_PASS:-}"                       # generated if empty
CP_ADMIN_TOKEN="${CP_ADMIN_TOKEN:-}"        # generated if empty
TENANTS="${TENANTS:-adanian-internal acme-corp}"
PASSWORD_POLICY="length(14) and upperCase(1) and lowerCase(1) and digits(3) and specialChars(3)"

# ─── build (local, linux/amd64, static) ─────────────────────────────────────
build_binaries() { # engine | controlplane
  mkdir -p "$BUILD_DIR"
  log "building the console frontend (embedded via go:embed)"
  ( cd "$REPO_ROOT/web" && npm run build >/dev/null 2>&1 ) || die "web build failed"
  # stage the fresh dist into the engine's embed dir so it serves current UI
  rm -rf "$REPO_ROOT/engine/internal/api/web"/* 2>/dev/null || true
  cp -R "$REPO_ROOT/web/dist/." "$REPO_ROOT/engine/internal/api/web/" 2>/dev/null || true
  ( cd "$REPO_ROOT/engine"
    case "$1" in
      engine)
        log "cross-compiling engine (linux/amd64, static)"
        CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$BUILD_DIR/engine" ./cmd/engine ;;
      controlplane)
        log "cross-compiling control plane + agents (linux/amd64, static)"
        CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$BUILD_DIR/controlplane" ./cmd/controlplane
        CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$BUILD_DIR/simagent"     ./cmd/simagent
        CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$BUILD_DIR/agent"        ./cmd/agent ;;
    esac )
  ok "binaries in $BUILD_DIR"
}

require_driver() {
  for f in RUN PUT; do declare -F "$f" >/dev/null || die "driver did not define $f()"; done
  [[ -n "${TARGET_HOST:-}" ]] || die "driver did not set TARGET_HOST"
}

# PKG: install apt packages on the target (via the driver's RUN). Robust against
# the fresh-boot race where cloud-init / unattended-upgrades still holds the
# dpkg lock, and retries transient mirror failures. Surfaces the real apt error
# on final failure instead of dying silently. Defined here so every driver
# shares it; a driver may override for a non-apt target.
PKG() {
  local pkgs="$*"
  RUN "export DEBIAN_FRONTEND=noninteractive
    for _ in \$(seq 1 60); do
      fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock >/dev/null 2>&1 || break
      echo '  (waiting for apt lock — cloud-init/unattended-upgrades)'; sleep 5
    done
    apt-get update -qq >/dev/null 2>&1 || true
    for attempt in 1 2 3; do
      apt-get install -y -qq $pkgs >/tmp/deploy-apt.log 2>&1 && exit 0
      echo \"  (apt attempt \$attempt failed, retrying)\"; sleep 5
    done
    echo '  apt-get install failed:'; tail -20 /tmp/deploy-apt.log; exit 1" \
    || die "package install failed: $pkgs"
}

_systemd_unit() { # <name> <description> <ExecStart> [After]
  RUN "cat > /etc/systemd/system/$1.service <<'UNIT'
[Unit]
Description=$2
After=network-online.target ${4:-}
Wants=network-online.target
[Service]
$( [[ -n "${5:-}" ]] && echo "EnvironmentFile=$5" )
ExecStart=$3
Restart=always
RestartSec=5
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload"
}

# ─── single-tenant: the engine ──────────────────────────────────────────────
provision_engine() {
  require_driver
  [[ -f "$BUILD_DIR/engine" ]] || build_binaries engine
  [[ -n "$ENGINE_PASS" ]] || ENGINE_PASS="$(gen_engine_password)"

  log "installing packages"
  if [[ "$ENGINE_MODE" == tetragon ]]; then PKG ca-certificates curl; RUN "command -v docker >/dev/null || (curl -fsSL https://get.docker.com | sh)"; fi

  RUN "mkdir -p /var/lib/ebpf-engine/policies /var/lib/ebpf-engine/attacks /var/lib/ebpf-engine/honey /etc/ebpf-engine"
  log "installing engine binary"
  PUT "$BUILD_DIR/engine" /usr/local/bin/ebpf-engine

  if [[ "$ENGINE_MODE" == tetragon ]]; then
    log "starting Tetragon ($TETRAGON_IMAGE)"
    RUN "docker rm -f tetragon >/dev/null 2>&1 || true
      docker run -d --name tetragon --restart unless-stopped --privileged --pid=host \
        -v /sys/kernel:/sys/kernel -v /var/run/tetragon:/var/run/tetragon \
        $TETRAGON_IMAGE >/dev/null"
    # ship policies + attacks for real detection
    RUN "mkdir -p /var/lib/ebpf-engine/policies /var/lib/ebpf-engine/attacks"
    tar -C "$REPO_ROOT" -cf - policies attacks 2>/dev/null | RUN "tar -C /var/lib/ebpf-engine -xf - 2>/dev/null || true"
  fi

  # The password goes in a mode-0600 config file, never on the command line:
  # systemd expands $VAR in ExecStart (so a '$' in the password would be eaten)
  # and /proc/<pid>/cmdline is world-readable. -fake / -login-rate are non-secret
  # CLI-only flags, so they stay on ExecStart.
  local tetline=""; [[ "$ENGINE_MODE" == tetragon ]] && tetline="tetragon: unix:///var/run/tetragon/tetragon.sock"
  log "writing engine config (/etc/ebpf-engine/engine.yaml, 0600)"
  RUN "umask 077; cat > /etc/ebpf-engine/engine.yaml <<'YAML'
$tetline
pass: '$ENGINE_PASS'
store: sqlite
db: /var/lib/ebpf-engine/events.db
http: ':$ENGINE_PORT'
secret_path: /var/lib/ebpf-engine/secret
policies: /var/lib/ebpf-engine/policies
attacks: /var/lib/ebpf-engine/attacks
honeypots: /var/lib/ebpf-engine/honey
YAML"
  log "writing systemd unit (ebpf-engine)"
  local fakeflag=""; [[ "$ENGINE_MODE" == fake ]] && fakeflag="-fake"
  _systemd_unit ebpf-engine "eBPF SOC engine (single-tenant)" \
    "/usr/local/bin/ebpf-engine -config /etc/ebpf-engine/engine.yaml $fakeflag -login-rate $LOGIN_RATE"
  RUN "systemctl enable --now ebpf-engine >/dev/null 2>&1; sleep 3"

  local code; code="$(RUN "curl -s -o /dev/null -w '%{http_code}' http://localhost:$ENGINE_PORT/login" || true)"
  [[ "$code" == 200 ]] && ok "engine live at http://$TARGET_HOST:$ENGINE_PORT/ (login $ENGINE_USER / $ENGINE_PASS)" \
                       || die "engine did not come up (HTTP $code); check: systemctl status ebpf-engine"
}

# ─── multi-tenant: the control plane ────────────────────────────────────────
provision_controlplane() {
  require_driver
  [[ -f "$BUILD_DIR/controlplane" ]] || build_binaries controlplane
  [[ -n "$PG_PASS" ]]         || PG_PASS="$(gen_secret 24)"
  [[ -n "$CP_ADMIN_TOKEN" ]]  || CP_ADMIN_TOKEN="$(gen_token)"
  # Keycloak's admin is created ONLY on first start (start-dev persists it in H2),
  # so KC_BOOTSTRAP_ADMIN_PASSWORD is ignored on every later boot. Regenerating it
  # on a redeploy would leave kcadm unable to authenticate against the persisted
  # admin — breaking idempotency. Reuse the password already recorded on the host
  # when one exists; only mint a new one for a first-time deploy.
  local KC_ADMIN_PASS
  KC_ADMIN_PASS="$(RUN "grep -h '^KC_BOOTSTRAP_ADMIN_PASSWORD=' /etc/ebpf-soc/keycloak.env 2>/dev/null | tail -1 | cut -d= -f2-" 2>/dev/null || true)"
  [[ -n "$KC_ADMIN_PASS" ]] && log "reusing the existing Keycloak admin password (redeploy)" \
                            || KC_ADMIN_PASS="$(gen_engine_password)"
  local issuer="http://$TARGET_HOST:$KC_PORT/realms/ebpf-soc"
  local redirect="http://$TARGET_HOST/auth/callback"

  log "installing packages (postgres, nginx, java, unzip, curl)"
  PKG postgresql nginx openjdk-21-jre-headless unzip curl

  # Postgres
  log "configuring Postgres"
  RUN "sudo -u postgres psql -tAc \"ALTER USER postgres PASSWORD '$PG_PASS';\" >/dev/null
    sudo -u postgres psql -tAc \"SELECT 1 FROM pg_database WHERE datname='ebpf_soc'\" | grep -q 1 || sudo -u postgres createdb ebpf_soc"

  # Keycloak (native, systemd)
  log "installing Keycloak $KC_VERSION"
  RUN "test -d /opt/keycloak || (curl -fsSL -o /opt/kc.tgz https://github.com/keycloak/keycloak/releases/download/$KC_VERSION/keycloak-$KC_VERSION.tar.gz && cd /opt && tar xzf kc.tgz && mv keycloak-$KC_VERSION keycloak && rm kc.tgz)
    mkdir -p /etc/ebpf-soc
    cat > /etc/ebpf-soc/keycloak.env <<EOF
KC_BOOTSTRAP_ADMIN_USERNAME=admin
KC_BOOTSTRAP_ADMIN_PASSWORD=$KC_ADMIN_PASS
KC_HTTP_PORT=$KC_PORT
KC_HTTP_ENABLED=true
KC_HOSTNAME_STRICT=false
KC_HEALTH_ENABLED=true
EOF"
  _systemd_unit ebpf-keycloak "Keycloak (ebpf-soc SSO)" "/opt/keycloak/bin/kc.sh start-dev" "" /etc/ebpf-soc/keycloak.env
  RUN "systemctl enable --now ebpf-keycloak >/dev/null 2>&1"
  log "waiting for Keycloak"
  RUN "for i in \$(seq 1 40); do curl -fsS http://localhost:$KC_PORT/realms/master >/dev/null 2>&1 && break; sleep 6; done"

  # Self-heal the admin identity. The admin lives in Keycloak's persisted store and
  # is created only on first boot, so KC_BOOTSTRAP_ADMIN_PASSWORD is ignored on
  # every later start. If the stored admin has diverged from keycloak.env (a prior
  # partial run, a hand-edit), kcadm cannot authenticate and the whole realm setup
  # below fails. Prove auth works; if it does not, reset Keycloak's local store so
  # it re-bootstraps with the current env password. The realm/client/users are
  # fully re-declared just below, so a reset loses nothing this script owns.
  if ! RUN "/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:$KC_PORT --realm master --user admin --password '$KC_ADMIN_PASS' >/dev/null 2>&1"; then
    warn "Keycloak admin auth failed — resetting the local store to re-bootstrap with the current password"
    RUN "systemctl stop ebpf-keycloak; rm -rf /opt/keycloak/data/h2; systemctl start ebpf-keycloak"
    RUN "for i in \$(seq 1 40); do curl -fsS http://localhost:$KC_PORT/realms/master >/dev/null 2>&1 && break; sleep 6; done"
  fi

  # Realm, client, roles, tenant mapper, users, password policy
  log "configuring realm ebpf-soc"
  local first_tenant; first_tenant="$(echo $TENANTS | awk '{print $1}')"
  local CP_SECRET
  CP_SECRET="$(RUN "K(){ /opt/keycloak/bin/kcadm.sh \"\$@\"; }
    K config credentials --server http://localhost:$KC_PORT --realm master --user admin --password '$KC_ADMIN_PASS' >/dev/null 2>&1
    K create realms -s realm=ebpf-soc -s enabled=true -s sslRequired=NONE -s 'passwordPolicy=$PASSWORD_POLICY' >/dev/null 2>&1 || true
    K update users/profile -r ebpf-soc -s 'unmanagedAttributePolicy=ENABLED' >/dev/null 2>&1 || true
    K create roles -r ebpf-soc -s name=tenant-analyst >/dev/null 2>&1 || true
    K create roles -r ebpf-soc -s name=msoc-admin >/dev/null 2>&1 || true
    CID=\$(K create clients -r ebpf-soc -s clientId=console-bff -s enabled=true -s protocol=openid-connect -s publicClient=false -s standardFlowEnabled=true -s directAccessGrantsEnabled=true -s 'redirectUris=[\"$redirect\",\"http://$TARGET_HOST/*\"]' -s 'webOrigins=[\"http://$TARGET_HOST\"]' -i 2>/dev/null || K get clients -r ebpf-soc -q clientId=console-bff --fields id --format csv | tail -1 | tr -d '\"')
    K create clients/\$CID/protocol-mappers/models -r ebpf-soc -s name=tenant -s protocol=openid-connect -s protocolMapper=oidc-usermodel-attribute-mapper -s 'config.\"user.attribute\"=tenant' -s 'config.\"claim.name\"=tenant' -s 'config.\"jsonType.label\"=String' -s 'config.\"id.token.claim\"=true' -s 'config.\"access.token.claim\"=true' -s 'config.\"userinfo.token.claim\"=true' >/dev/null 2>&1 || true
    K get clients/\$CID/client-secret -r ebpf-soc | grep value | sed -E 's/.*\"value\" *: *\"([^\"]+)\".*/\1/'")"

  # one operator per tenant + one cross-tenant msoc-admin
  local userlist=""
  for t in $TENANTS; do
    local u; u="op-$(echo $t | cut -d- -f1)"; local pw; pw="$(gen_engine_password)"
    RUN "K(){ /opt/keycloak/bin/kcadm.sh \"\$@\"; }
      K config credentials --server http://localhost:$KC_PORT --realm master --user admin --password '$KC_ADMIN_PASS' >/dev/null 2>&1
      K create users -r ebpf-soc -s username=$u -s enabled=true -s email=$u@local -s firstName=$u -s lastName=op -s emailVerified=true -s 'attributes.tenant=[\"$t\"]' >/dev/null 2>&1 || true
      K add-roles -r ebpf-soc --uusername $u --rolename tenant-analyst >/dev/null 2>&1
      K set-password -r ebpf-soc --username $u --new-password '$pw' >/dev/null 2>&1"
    userlist+="  $u / $pw   (tenant-analyst, $t)\n"
  done
  local msoc_pw; msoc_pw="$(gen_engine_password)"
  RUN "K(){ /opt/keycloak/bin/kcadm.sh \"\$@\"; }
    K config credentials --server http://localhost:$KC_PORT --realm master --user admin --password '$KC_ADMIN_PASS' >/dev/null 2>&1
    K create users -r ebpf-soc -s username=msoc -s enabled=true -s email=msoc@local -s firstName=msoc -s lastName=admin -s emailVerified=true -s 'attributes.tenant=[\"$first_tenant\"]' >/dev/null 2>&1 || true
    K add-roles -r ebpf-soc --uusername msoc --rolename msoc-admin >/dev/null 2>&1
    K set-password -r ebpf-soc --username msoc --new-password '$msoc_pw' >/dev/null 2>&1"
  userlist+="  msoc / $msoc_pw   (msoc-admin, cross-tenant)\n"

  # Control plane
  log "installing control plane"
  PUT "$BUILD_DIR/controlplane" /usr/local/bin/ebpf-soc-controlplane
  PUT "$BUILD_DIR/simagent"     /usr/local/bin/ebpf-simagent
  # Secrets go through the EnvironmentFile, never the command line: the CP reads
  # CP_PG_DSN / CP_OIDC_CLIENT_SECRET / CP_ADMIN_TOKEN from the (owner-only)
  # environment so the DB password + bearer never appear in /proc/<pid>/cmdline.
  RUN "mkdir -p /var/lib/ebpf-soc
    umask 077; cat > /etc/ebpf-soc/controlplane.env <<EOF
CP_PG_DSN=postgres://postgres:$PG_PASS@127.0.0.1:5432/ebpf_soc?sslmode=disable
CP_OIDC_CLIENT_SECRET=$CP_SECRET
CP_ADMIN_TOKEN=$CP_ADMIN_TOKEN
EOF"
  _systemd_unit ebpf-soc-controlplane "ebpf-soc control plane (multi-tenant)" \
    "/usr/local/bin/ebpf-soc-controlplane -http 127.0.0.1:$CP_HTTP_PORT -grpc 127.0.0.1:9443 -server-name localhost -store postgres -oidc-issuer $issuer -oidc-client-id console-bff -oidc-redirect-url $redirect -app-url / -state-dir /var/lib/ebpf-soc -fleet-pubkey-out /var/lib/ebpf-soc/fleet.pub" \
    "postgresql.service ebpf-keycloak.service" /etc/ebpf-soc/controlplane.env
  RUN "systemctl enable --now ebpf-soc-controlplane >/dev/null 2>&1; sleep 3; chmod 0644 /var/lib/ebpf-soc/fleet.pub 2>/dev/null || true"

  # nginx: serve the console dist + proxy /api,/auth to the CP
  log "installing console frontend + nginx"
  RUN "mkdir -p /var/www/console"
  put_dir "$REPO_ROOT/web/dist" /var/www/console
  RUN "cat > /etc/nginx/sites-available/console <<'NGINX'
server {
    listen 80 default_server;
    server_name _;
    root /var/www/console;
    index index.html;
    location = /login      { return 302 \$scheme://\$http_host/auth/login; }
    location = /api/logout { return 302 \$scheme://\$http_host/auth/logout; }
    location /api/  { proxy_pass http://127.0.0.1:$CP_HTTP_PORT; proxy_http_version 1.1;
        proxy_set_header Host \$host; proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 1d; proxy_buffering off; }
    location /auth/ { proxy_pass http://127.0.0.1:$CP_HTTP_PORT; proxy_http_version 1.1;
        proxy_set_header Host \$host; proxy_set_header X-Forwarded-Proto \$scheme; }
    location /healthz { proxy_pass http://127.0.0.1:$CP_HTTP_PORT; }
    location / { try_files \$uri \$uri.html /index.html; }
}
NGINX
    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/console /etc/nginx/sites-enabled/console
    nginx -t && systemctl restart nginx && systemctl enable nginx >/dev/null 2>&1"

  # sim-agents (data seeders) — one per tenant
  log "starting a sim-agent per tenant"
  for t in $TENANTS; do
    local label; label="sim-$(echo $t | cut -d- -f1)"
    RUN "mkdir -p /var/lib/ebpf-$label"
    _systemd_unit "ebpf-$label" "ebpf-soc sim-agent ($t)" \
      "/usr/local/bin/ebpf-simagent -cp-http http://127.0.0.1:$CP_HTTP_PORT -cp-grpc 127.0.0.1:9443 -server-name localhost -admin-token $CP_ADMIN_TOKEN -tenant $t -state-dir /var/lib/ebpf-$label -label $label -fleet-pubkey /var/lib/ebpf-soc/fleet.pub" \
      "ebpf-soc-controlplane.service"
    RUN "systemctl enable --now ebpf-$label >/dev/null 2>&1"
  done
  RUN "sleep 8"

  local code; code="$(RUN "curl -s -o /dev/null -w '%{http_code}' http://localhost/" || true)"
  echo
  ok "control plane live at  http://$TARGET_HOST/   (console HTTP $code)"
  echo "  Keycloak admin:  http://$TARGET_HOST:$KC_PORT/admin/  (admin / $KC_ADMIN_PASS)"
  printf "  Console logins:\n%b" "$userlist"
  dim "credentials also written to $BUILD_DIR/credentials-$TARGET_HOST.txt"
  { echo "# ebpf-soc multi-tenant — $TARGET_HOST — $(date)"; echo "Keycloak admin: admin / $KC_ADMIN_PASS"; printf "%b" "$userlist"; echo "postgres: postgres / $PG_PASS"; echo "cp admin token: $CP_ADMIN_TOKEN"; echo "console-bff secret: $CP_SECRET"; } > "$BUILD_DIR/credentials-$TARGET_HOST.txt"
  chmod 0600 "$BUILD_DIR/credentials-$TARGET_HOST.txt"
}

# put_dir: copy a whole local directory's contents to a remote dir (per-file PUT
# is fine for small trees; overridden by drivers that can do it faster).
put_dir() { # <localdir> <remotedir>
  RUN "rm -rf $2/* 2>/dev/null || true"
  ( cd "$1" && find . -type f ) | while read -r f; do
    RUN "mkdir -p $2/$(dirname "$f")"
    PUT "$1/$f" "$2/$f"
  done
}

# gen_engine_password: policy-compliant (14+, upper/lower, 3 digits, 3 special),
# unambiguous alphabet (no l/I/1/O/0).
gen_engine_password() {
  local U=ABCDEFGHJKLMNPQRSTUVWXYZ l=abcdefghijkmnopqrstuvwxyz d=23456789 s='!@#$%&*+=-'
  printf '%s%s%s%s%s%s%s%s%s%s%s%s%s%s' \
    "${U:$((RANDOM%${#U})):1}" "${l:$((RANDOM%${#l})):1}" "${l:$((RANDOM%${#l})):1}" \
    "${d:$((RANDOM%${#d})):1}" "${s:$((RANDOM%${#s})):1}" "${l:$((RANDOM%${#l})):1}" \
    "${U:$((RANDOM%${#U})):1}" "${d:$((RANDOM%${#d})):1}" "${s:$((RANDOM%${#s})):1}" \
    "${l:$((RANDOM%${#l})):1}" "${d:$((RANDOM%${#d})):1}" "${s:$((RANDOM%${#s})):1}" \
    "${l:$((RANDOM%${#l})):1}" "${U:$((RANDOM%${#U})):1}"
}
