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
# TARGET_SCHEME is the scheme BROWSERS use, which is also the scheme baked into
# the OIDC issuer + redirect URI and the one Keycloak echoes in absolute URLs.
# Set to https once certs exist for TARGET_HOST (see provision_tls). It is a
# separate knob rather than part of TARGET_HOST because every consumer needs the
# bare hostname too (certificate paths, server_name, Host headers).
TARGET_SCHEME="${TARGET_SCHEME:-http}"
PG_PASS="${PG_PASS:-}"                       # generated if empty
CP_ADMIN_TOKEN="${CP_ADMIN_TOKEN:-}"        # generated if empty
TENANTS="${TENANTS:-adanian-internal acme-corp}"
# DATA_MODE governs where each tenant's telemetry comes from:
#   real — one REAL agent VM per tenant (Tetragon-observed kernel events); the
#          honest, multi-host story. Set by multi-tenant-orbstack.sh.
#   sim  — one sim-agent per tenant fabricating telemetry (fast, no VMs). The
#          legacy default, kept for environments that can't spin up agent VMs.
#   none — provision no data source at all, and disable any sim-agents left over
#          from an earlier sim deploy. Use when REAL agents are managed out of
#          band (scripts/deploy/provision-agent-ssh.sh). Without this, every
#          redeploy resurrects the sims alongside the real agents, and a tenant
#          then has two agents: enforcement can be dispatched to the sim, which
#          acks APPLIED for a process it never touched.
DATA_MODE="${DATA_MODE:-sim}"
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

_systemd_timer() { # <name> <description> <ExecStart> <OnCalendar>
  RUN "cat > /etc/systemd/system/$1.service <<'UNIT'
[Unit]
Description=$2
[Service]
Type=oneshot
ExecStart=$3
UNIT
cat > /etc/systemd/system/$1.timer <<'TIMER'
[Unit]
Description=$2 (scheduled)
[Timer]
OnCalendar=$4
# Catch up after downtime. Without this a host that was off at 03:30 simply
# skips that night, and the gap is invisible until someone needs the backup.
Persistent=true
RandomizedDelaySec=300
[Install]
WantedBy=timers.target
TIMER
systemctl daemon-reload
systemctl enable --now $1.timer >/dev/null 2>&1 || true"
}

# ─── backups ────────────────────────────────────────────────────────────────
#
# This was set up BY HAND on the previous deployment and did not survive the
# migration: no deploy script ever provisioned it, so the estate ran with zero
# backups of anything. It is provisioned here so it cannot be lost again.
#
# What is actually at risk differs per host, and only one of them is
# irreplaceable:
#
#   control plane — /var/lib/ebpf-soc holds the CA key and the FLEET SIGNING
#     KEY. Lose them and every agent must be re-enrolled by hand; leak them and
#     an attacker can mint agent identities and sign commands the fleet obeys.
#     Nothing regenerates these. /etc/ebpf-soc holds the DSNs and admin token.
#   engine — events.db is the evidence store. It is WAL-mode SQLite, so a plain
#     `cp` can capture a torn database; socbackup uses VACUUM INTO for a
#     consistent snapshot.
#
# Both archives therefore contain live secrets or evidence: 0600, root-owned.

provision_engine_backups() {
  require_driver
  [[ -f "$BUILD_DIR/socbackup" ]] || {
    log "cross-compiling socbackup (WAL-safe snapshotter)"
    ( cd "$REPO_ROOT/engine" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -o "$BUILD_DIR/socbackup" ./cmd/socbackup ) || die "socbackup build failed"
  }
  PUT "$BUILD_DIR/socbackup" /usr/local/bin/socbackup
  RUN "chmod 0755 /usr/local/bin/socbackup; install -d -m 0700 /var/backups/ebpf-soc"
  _systemd_timer ebpf-soc-backup "eBPF-SOC engine database backup" \
    "/usr/local/bin/socbackup -db /var/lib/ebpf-engine/events.db -dest /var/backups/ebpf-soc -keep 3" \
    "*-*-* 03:30:00"
  ok "engine backups: nightly 03:30, 3 retained, /var/backups/ebpf-soc"
}

provision_controlplane_backups() {
  require_driver
  # Written to a file and shipped, NOT heredoc'd through RUN. The script is full
  # of $VAR and quoting that has to survive the remote shell verbatim; nesting it
  # inside the transport's own quoting silently mangles it, which is exactly how
  # a backup job ends up "installed" and broken.
  mkdir -p "$BUILD_DIR"
  cat > "$BUILD_DIR/ebpf-soc-cp-backup" <<'SH'
#!/usr/bin/env bash
# Snapshot the control plane's IRREPLACEABLE material: the CA + fleet signing
# keys, and the config holding DSNs/tokens. Contains live secrets — 0600.
set -euo pipefail
DEST=/var/backups/ebpf-soc
KEEP=7
STAMP=$(date -u +%Y%m%d-%H%M%S)
ARCHIVE="$DEST/cp-pki-config-$STAMP.tar.gz"
install -d -m 0700 "$DEST"
umask 077
tar -czf "$ARCHIVE" -C / var/lib/ebpf-soc etc/ebpf-soc 2>/dev/null
chmod 0600 "$ARCHIVE"
# Fail loudly on a degenerate archive: a backup job that "succeeds" while
# writing nothing is worse than no job, because it is trusted.
[ -s "$ARCHIVE" ] || { echo 'backup archive is empty' >&2; exit 1; }
# `set -o pipefail` + `grep -q` is a trap: grep exits at the first match and
# closes the pipe, the producer takes SIGPIPE, and the pipeline reports failure
# even though the check PASSED. It only bites once the producer is slow enough
# to still be writing — so it passes on a small archive and fails on a real one.
set +o pipefail
tar -tzf "$ARCHIVE" | grep -q 'var/lib/ebpf-soc/ca.key' || {
  echo 'backup is missing the CA key — refusing to report success' >&2; exit 1; }
set -o pipefail
ls -1t "$DEST"/cp-pki-config-*.tar.gz 2>/dev/null | tail -n +$((KEEP+1)) | xargs -r rm -f
echo "wrote $ARCHIVE"

# ── The database ────────────────────────────────────────────────────────────
# The other irreplaceable thing on this host, and it was never captured. A PKI
# backup restores the platform's IDENTITY; it does not restore the record of
# what the platform DID. Measured the day this was added: 5.24M rows including
# 1,645 hash-chained decision rows, and no dump had ever been taken — the job
# above had been reporting success nightly while backing up 1,572 bytes.
#
# Fewer copies than the PKI archive because each is ~370 MB compressed, and the
# PKI tarball is small enough to keep many of.
DB=${EBPF_SOC_DB:-ebpf_soc}
KEEP_DB=3
DUMP="$DEST/db-$STAMP.sql.gz"
if command -v pg_dump >/dev/null 2>&1 && su -s /bin/sh postgres -c "psql -lqt" 2>/dev/null | cut -d'|' -f1 | grep -qw "$DB"; then
  su -s /bin/sh postgres -c "pg_dump --no-owner --no-privileges '$DB'" | gzip -1 > "$DUMP"
  chmod 0600 "$DUMP"
  # Same rule as above: a dump that exists but restores nothing is worse than
  # no dump, because it is trusted. Require the schema AND the payload table.
  [ -s "$DUMP" ] || { echo 'db dump is empty' >&2; exit 1; }
  gzip -t "$DUMP" || { echo 'db dump is not a valid gzip stream' >&2; exit 1; }
  set +o pipefail   # see the note on the CA-key check above
  gunzip -c "$DUMP" | grep -q 'CREATE TABLE public.telemetry' || {
    echo 'db dump has no telemetry schema — refusing to report success' >&2; exit 1; }
  set -o pipefail
  ls -1t "$DEST"/db-*.sql.gz 2>/dev/null | tail -n +$((KEEP_DB+1)) | xargs -r rm -f
  echo "wrote $DUMP ($(du -h "$DUMP" | cut -f1))"
else
  # Loud, not silent: a control plane whose database is not being backed up
  # must say so every night rather than look healthy.
  echo "WARNING: pg_dump unavailable or database '$DB' not found — NO DATABASE BACKUP TAKEN" >&2
fi
SH
  PUT "$BUILD_DIR/ebpf-soc-cp-backup" /usr/local/bin/ebpf-soc-cp-backup
  RUN "chmod 0700 /usr/local/bin/ebpf-soc-cp-backup; install -d -m 0700 /var/backups/ebpf-soc"
  _systemd_timer ebpf-soc-cp-backup "eBPF-SOC control-plane PKI + config backup" \
    "/usr/local/bin/ebpf-soc-cp-backup" "*-*-* 03:00:00"
  ok "control-plane backups: nightly 03:00, 7 retained, /var/backups/ebpf-soc"
}

# ─── single-tenant: the engine ──────────────────────────────────────────────
provision_engine() {
  require_driver
  [[ -f "$BUILD_DIR/engine" ]] || build_binaries engine

  # Credential stability: reuse the password already on the host instead of
  # minting a new one every deploy. Rotating on each run invalidates whatever the
  # operator last wrote down, which makes frequent redeploys painful. Rotation is
  # still available on demand — delete /etc/ebpf-engine/engine.yaml (or pass
  # ENGINE_PASS=…) and the next deploy generates a fresh one.
  if [[ -z "$ENGINE_PASS" ]]; then
    ENGINE_PASS="$(RUN "sed -n \"s/^pass: '\\(.*\\)'\$/\\1/p\" /etc/ebpf-engine/engine.yaml 2>/dev/null | tail -1" 2>/dev/null || true)"
    [[ -n "$ENGINE_PASS" ]] && log "reusing the existing engine password (redeploy)" \
                            || ENGINE_PASS="$(gen_engine_password)"
  fi

  # Graceful degrade, mirroring the agent's contract: tetragon mode needs a
  # kernel >= 5.15 WITH BTF. Probe the target and fall back to -fake rather than
  # failing the deploy, so the same command works on a host that cannot carry
  # eBPF (an older VM, a restricted cloud kernel) — it just detects less.
  if [[ "$ENGINE_MODE" == tetragon ]]; then
    local kcap
    kcap="$(RUN 'rel=$(uname -r); maj=${rel%%.*}; min=${rel#*.}; min=${min%%.*}
      if [ -f /sys/kernel/btf/vmlinux ] && { [ "$maj" -gt 5 ] || { [ "$maj" -eq 5 ] && [ "$min" -ge 15 ]; }; }; then
        echo ok
      else
        echo "no kernel=$rel btf=$([ -f /sys/kernel/btf/vmlinux ] && echo yes || echo no)"
      fi' 2>/dev/null | tr -d '\r')"
    if [[ "$kcap" != ok ]]; then
      warn "target cannot run Tetragon ($kcap) — falling back to -fake (synthesised events, no kernel detection)"
      ENGINE_MODE=fake
    else
      log "target supports real eBPF (kernel >= 5.15 + BTF)"
    fi
  fi

  log "installing packages"
  if [[ "$ENGINE_MODE" == tetragon ]]; then PKG ca-certificates curl; RUN "command -v docker >/dev/null || (curl -fsSL https://get.docker.com | sh)"; fi

  RUN "mkdir -p /var/lib/ebpf-engine/policies /var/lib/ebpf-engine/attacks /var/lib/ebpf-engine/honey /etc/ebpf-engine"
  log "installing engine binary"
  PUT "$BUILD_DIR/engine" /usr/local/bin/ebpf-engine

  if [[ "$ENGINE_MODE" == tetragon ]]; then
    log "starting Tetragon ($TETRAGON_IMAGE)"
    # --server-address is REQUIRED: Tetragon defaults to a TCP listener
    # (localhost:54321) and never creates a unix socket, but the engine is
    # configured below to dial unix:///var/run/tetragon/tetragon.sock. Without
    # this flag the socket never appears and the engine can't subscribe.
    RUN "docker rm -f tetragon >/dev/null 2>&1 || true
      docker run -d --name tetragon --restart unless-stopped --privileged --pid=host \
        -v /sys/kernel:/sys/kernel -v /var/run/tetragon:/var/run/tetragon \
        $TETRAGON_IMAGE --server-address unix:///var/run/tetragon/tetragon.sock >/dev/null"
    # ship policies + attacks for real detection
    RUN "mkdir -p /var/lib/ebpf-engine/policies /var/lib/ebpf-engine/attacks"
    tar -C "$REPO_ROOT" -cf - policies attacks 2>/dev/null | RUN "tar -C /var/lib/ebpf-engine -xf - 2>/dev/null || true"

    # Tetragon needs a moment to attach its BPF programs and open the gRPC socket;
    # the engine fails to subscribe if it starts first.
    log "waiting for the Tetragon socket"
    RUN "for i in \$(seq 1 40); do [ -S /var/run/tetragon/tetragon.sock ] && break; sleep 3; done
      [ -S /var/run/tetragon/tetragon.sock ] || { echo 'tetragon socket never appeared:'; docker logs --tail 30 tetragon 2>&1; exit 1; }" \
      || die "Tetragon did not start — this host may not permit privileged BPF (check: docker logs tetragon)"

    # Load the TracingPolicies. Without these Tetragon only emits bare execve
    # events: no setuid/sensitive-file/network kprobes, so the scorer never sees
    # the signals it grades and /api/policy-stats has nothing to report.
    # Load each policy with retries and FAIL LOUDLY if any never lands. Tetragon
    # can still be attaching sensors when the socket first appears, so an add
    # issued immediately after can bounce — that is transient, not fatal. What is
    # not acceptable is swallowing it: a missing TracingPolicy is a silent
    # detection blind spot, and the operator would never know the platform is
    # watching less than they think.
    #
    # We ALSO drop each policy into Tetragon's default --tracing-policy-dir
    # (/etc/tetragon/tetragon.tp.d) so they auto-load on every restart. A runtime
    # `tetra tracingpolicy add` is in-memory only: if Tetragon restarts (host
    # reboot, Docker daemon restart, OrbStack relaunch) the policies vanish and
    # detection silently drops to bare execve — events keep flowing but alerts
    # stop. The tp.d copy is the durable source of truth; the runtime add just
    # makes them live immediately without waiting for a restart.
    log "applying TracingPolicies (detection + enforcement)"
    RUN "applied=0; failed=''
      docker exec tetragon mkdir -p /etc/tetragon/tetragon.tp.d >/dev/null 2>&1 || true
      for p in /var/lib/ebpf-engine/policies/*.yaml; do
        [ -f \"\$p\" ] || continue
        name=\$(basename \"\$p\")
        docker cp \"\$p\" tetragon:/tmp/ >/dev/null 2>&1 || { failed=\"\$failed \$name(copy)\"; continue; }
        docker cp \"\$p\" \"tetragon:/etc/tetragon/tetragon.tp.d/\$name\" >/dev/null 2>&1 || true
        # ALWAYS delete-then-add. \`tetra tracingpolicy add\` is create-only, so a
        # policy whose CONTENT changed keeps running the version loaded when
        # Tetragon started — the file on disk and the rules in the kernel
        # silently diverge, and an allow-list fix or a Sigkill->detect switch
        # deploys with no effect. Deleting first makes the file authoritative.
        # The policy is keyed by metadata.name, NOT by filename — and they differ
        # (network-watch.yaml declares 'outbound-connections', sensitive-files
        # .yaml declares 'sensitive-file-access'). Deleting by filename silently
        # no-ops for those, so they would keep running whatever was loaded first
        # and could never receive a content update.
        pol=\$(awk '/^metadata:/{f=1;next} f&&/^[[:space:]]+name:/{gsub(/[\"'\''[:space:]]/,\"\",\$2);print \$2;exit}' \"\$p\")
        [ -n \"\$pol\" ] || pol=\$(basename \"\$name\" .yaml)
        ok=0
        for attempt in 1 2 3; do
          docker exec tetragon tetra tracingpolicy delete \"\$pol\" >/dev/null 2>&1
          docker exec tetragon tetra tracingpolicy add \"/tmp/\$name\" >/dev/null 2>&1
          # Verify against the LOADED policy list rather than the CLI's output:
          # success is 'the policy is running', not 'the command printed nothing'.
          if docker exec tetragon tetra tracingpolicy list 2>/dev/null | grep -q \"\$pol\"; then ok=1; break; fi
          sleep 2
        done
        if [ \"\$ok\" = 1 ]; then applied=\$((applied+1)); else failed=\"\$failed \$name\"; fi
      done
      echo \"  \$applied TracingPolicy file(s) loaded\"
      if [ -n \"\$failed\" ]; then echo \"  WARNING: policies that FAILED to load:\$failed\"; fi
      docker exec tetragon tetra tracingpolicy list 2>/dev/null | head -12 || true"
  fi

  # The password goes in a mode-0600 config file, never on the command line:
  # systemd expands $VAR in ExecStart (so a '$' in the password would be eaten)
  # and /proc/<pid>/cmdline is world-readable. -fake / -login-rate are non-secret
  # CLI-only flags, so they stay on ExecStart.
  local tetline=""; [[ "$ENGINE_MODE" == tetragon ]] && tetline="tetragon: unix:///var/run/tetragon/tetragon.sock"

  # Device-choke protect list — a SAFETY control, written even when the tc data
  # plane is not attached, so enabling enforcement later can never be a
  # self-inflicted outage. On a cloud host the ONLY device an engine discovers is
  # usually its own default gateway: without this, the first (and only) device an
  # operator can choke is the box's route to the world. The engine also auto-adds
  # its own NIC. Extend with DEVCHOKE_PROTECT="mac,mac".
  log "resolving the device-choke protect list (gateway + uplink)"
  local gwmac
  gwmac="$(RUN 'gw=$(ip -o -4 route show default | awk "{print \$3}" | head -1)
    [ -n "$gw" ] && ping -c1 -W1 "$gw" >/dev/null 2>&1
    ip -4 neigh show | awk -v gw="$gw" "\$1==gw {for(i=1;i<=NF;i++) if (\$i==\"lladdr\") print \$(i+1)}" | head -1' 2>/dev/null | tr -d '\r')"
  local protect="${DEVCHOKE_PROTECT:-}"
  [[ -n "$gwmac" ]] && protect="${protect:+$protect,}$gwmac"
  [[ -n "$protect" ]] && ok "protected MACs: $protect" \
                      || warn "could not resolve the gateway MAC — only the engine's own NIC is protected"

  # The tc data plane itself is opt-in (DEVCHOKE=1): it needs a compiled
  # devchoke.o, which means a clang/libbpf toolchain on the target. Without it
  # the device gateway still runs — audited, reversible, just not enforcing in
  # the kernel (the noop backend).
  local devlines=""
  [[ -n "$protect" ]] && devlines="devchoke_protect: $protect"
  if [[ "${DEVCHOKE:-0}" == 1 ]]; then
    local iface
    iface="$(RUN 'ip -o -4 route show default | awk "{print \$5}" | head -1' 2>/dev/null | tr -d '\r')"
    log "compiling the device-choke data plane for $iface"
    PKG clang libbpf-dev linux-libc-dev
    RUN "mkdir -p /var/lib/ebpf-engine/bpf"
    PUT "$REPO_ROOT/engine/internal/enforce/devbpf/bpf/devchoke.c" /var/lib/ebpf-engine/bpf/devchoke.c
    if RUN "cd /var/lib/ebpf-engine/bpf && clang -O2 -g -target bpf -I/usr/include/\$(uname -m)-linux-gnu -c devchoke.c -o devchoke.o" >/dev/null 2>&1; then
      devlines="$devlines
devchoke_obj: /var/lib/ebpf-engine/bpf/devchoke.o
devchoke_ifaces: $iface"
      ok "device data plane compiled (tc on $iface)"
    else
      warn "devchoke.o failed to compile — device gateway stays on the noop backend"
    fi
  fi

  # Fleet peer list. Without this the /fleet console and every /api/fleet/*
  # fanout answer 503, which reads to an operator as a broken page rather than
  # an unconfigured feature. Default to the engine itself: the Fleet view treats
  # the local host as a peer like any other, so a one-box deploy gets a working
  # page showing one host instead of an error.
  #
  # Self is addressed on LOOPBACK, never via TARGET_HOST. The fanout dials from
  # this box, and a public-hostname hairpin is exactly what crash-looped the
  # control plane's OIDC discovery — same trap, same fix. Add real peers with
  # FLEET_HOSTS="ebpf-2 https://peer.example.io" (one "name url" per line).
  log "writing fleet peer list (/etc/ebpf-engine/fleet.hosts)"
  local fleet_hosts="${FLEET_HOSTS:-}"
  if [[ -z "$fleet_hosts" ]]; then
    local selfname
    selfname="$(RUN 'hostname -s' 2>/dev/null | tr -d '\r')"
    fleet_hosts="${selfname:-engine} http://127.0.0.1:$ENGINE_PORT"
  fi
  RUN "umask 077; cat > /etc/ebpf-engine/fleet.hosts <<'HOSTS'
# name  base-url   — managed by scripts/deploy/lib.sh, edit FLEET_HOSTS to change
$fleet_hosts
HOSTS"

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
fleet_hosts: /etc/ebpf-engine/fleet.hosts
$devlines
YAML"
  log "writing systemd unit (ebpf-engine)"
  local fakeflag=""; [[ "$ENGINE_MODE" == fake ]] && fakeflag="-fake"
  _systemd_unit ebpf-engine "eBPF SOC engine (single-tenant)" \
    "/usr/local/bin/ebpf-engine -config /etc/ebpf-engine/engine.yaml $fakeflag -login-rate $LOGIN_RATE"
  # restart, not `enable --now`: the latter no-ops when the service is already
  # running, so a redeploy would keep the OLD process alive — still in -fake mode,
  # still holding the previous password — while the unit file and engine.yaml on
  # disk describe the new config. Every credential/mode change needs a restart.
  RUN "systemctl enable ebpf-engine >/dev/null 2>&1; systemctl restart ebpf-engine; sleep 3"

  local code; code="$(RUN "curl -s -o /dev/null -w '%{http_code}' http://localhost:$ENGINE_PORT/login" || true)"
  [[ "$code" == 200 ]] || die "engine did not come up (HTTP $code); check: systemctl status ebpf-engine"

  # Front the engine with nginx when TARGET_HOST is a DNS name, so it is reached
  # on a clean origin (and can carry TLS) instead of host:$ENGINE_PORT. Keeps the
  # engine's own port off the firewall entirely — one door, not two. Skipped for
  # a bare IP, where a vhost buys nothing.
  case "$TARGET_HOST" in
    *[a-zA-Z]*.*)
      log "fronting the engine with nginx on $TARGET_HOST"
      PKG nginx
      local has_tls=no
      RUN "test -s /etc/letsencrypt/live/$TARGET_HOST/fullchain.pem" >/dev/null 2>&1 && has_tls=yes
      RUN "mkdir -p /etc/nginx/snippets /var/www/certbot
cat > /etc/nginx/snippets/ebpf-engine.conf <<'NGINX'
    location / {
        proxy_pass http://127.0.0.1:$ENGINE_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        # /api/stream is server-sent events: never buffer, never time out.
        proxy_buffering off;
        proxy_read_timeout 1d;
    }
NGINX"
      if [[ "$has_tls" == yes ]]; then
        log "certs found for $TARGET_HOST — serving TLS, redirecting :80"
        RUN "cat > /etc/nginx/sites-available/engine <<'NGINX'
server {
    listen 80 default_server;
    server_name $TARGET_HOST _;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl default_server;
    http2 on;
    server_name $TARGET_HOST _;
    ssl_certificate     /etc/letsencrypt/live/$TARGET_HOST/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$TARGET_HOST/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    include /etc/nginx/snippets/ebpf-engine.conf;
}
NGINX"
      else
        RUN "cat > /etc/nginx/sites-available/engine <<'NGINX'
server {
    listen 80 default_server;
    server_name $TARGET_HOST _;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    include /etc/nginx/snippets/ebpf-engine.conf;
}
NGINX"
      fi
      RUN "rm -f /etc/nginx/sites-enabled/default
        ln -sf /etc/nginx/sites-available/engine /etc/nginx/sites-enabled/engine
        nginx -t && systemctl enable nginx >/dev/null 2>&1 && systemctl restart nginx"
      ok "engine live at $TARGET_SCHEME://$TARGET_HOST/ (login $ENGINE_USER / $ENGINE_PASS)"
      ;;
    *)
      ok "engine live at http://$TARGET_HOST:$ENGINE_PORT/ (login $ENGINE_USER / $ENGINE_PASS)"
      ;;
  esac
}

# console_password <username> — the STABLE password for a console user.
#
# Keycloak hashes passwords, so there is nothing to read back once a user exists;
# without a record of our own, every deploy would have to invent a new one and
# silently invalidate the operator's credentials. This keeps a 0600 record on the
# host and reuses it. Prints ONLY the password (callers capture stdout), so any
# diagnostics here must go to stderr.
#
# To rotate: delete the user's line from /etc/ebpf-soc/console-users.env (or the
# whole file) and redeploy.
console_password() {
  local user="$1" key pw
  key="USER_$(printf '%s' "$user" | tr -c 'A-Za-z0-9' '_')"
  pw="$(RUN "grep -h '^$key=' /etc/ebpf-soc/console-users.env 2>/dev/null | tail -1 | cut -d= -f2-" 2>/dev/null || true)"
  pw="${pw//[$'\r\n']/}"
  if [[ -z "$pw" ]]; then
    pw="$(gen_engine_password)"
    RUN "umask 077; mkdir -p /etc/ebpf-soc; touch /etc/ebpf-soc/console-users.env
      sed -i '/^$key=/d' /etc/ebpf-soc/console-users.env
      printf '%s=%s\n' '$key' '$pw' >> /etc/ebpf-soc/console-users.env" >/dev/null 2>&1
  fi
  printf '%s' "$pw"
}

# provision_tls <hostname> — obtain/renew a Let's Encrypt cert for the target.
#
# certonly, NOT --nginx: the nginx config is written by the provisioners in this
# file and rewritten on every deploy, so anything certbot edited there would be
# silently discarded the next time you redeploy — TLS would disappear with no
# error, while the OIDC issuer kept claiming https. Instead certbot only fetches
# the certificate and the provisioners detect it on disk and emit the TLS server
# block themselves.
#
# Validation is webroot on the already-open :80 (HTTP-01), which is why the
# provisioners keep /.well-known/acme-challenge/ unredirected. Requires :80
# reachable from the INTERNET — Let's Encrypt validates from arbitrary IPs, so an
# IP-scoped :80 rule fails here.
provision_tls() {
  require_driver
  local host="${1:-$TARGET_HOST}" email="${TLS_EMAIL:-admin@$TARGET_HOST}"
  case "$host" in
    *.*) : ;;
    *) die "TLS needs a DNS name, not '$host' — Let's Encrypt will not issue for a bare IP" ;;
  esac
  log "installing certbot"
  PKG certbot
  RUN "mkdir -p /var/www/certbot"
  if RUN "test -s /etc/letsencrypt/live/$host/fullchain.pem" >/dev/null 2>&1; then
    ok "certificate already present for $host (renewal is certbot's own timer)"
    return 0
  fi
  # Bootstrap the challenge path. On the FIRST TLS deploy of a host the live
  # nginx config predates the ACME location, so the SPA's try_files catch-all
  # answers the challenge with index.html and Let's Encrypt rejects it. Probe it
  # functionally rather than grepping the config, then stand up a throwaway :80
  # vhost only if needed, and put the previous sites back afterwards so a failed
  # run never leaves the box serving 404s.
  local restore=""
  RUN "mkdir -p /var/www/certbot/.well-known/acme-challenge
    echo probe > /var/www/certbot/.well-known/acme-challenge/.probe"
  if [[ "$(RUN "curl -s --max-time 5 http://127.0.0.1/.well-known/acme-challenge/.probe 2>/dev/null" 2>/dev/null | tr -d '\r\n')" != "probe" ]]; then
    log "installing a temporary :80 vhost so the ACME challenge is reachable"
    restore="$(RUN 'ls /etc/nginx/sites-enabled 2>/dev/null | tr "\n" " "' 2>/dev/null | tr -d '\r')"
    RUN "cat > /etc/nginx/sites-available/acme-bootstrap <<'ACME'
server {
    listen 80 default_server;
    server_name _;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 503; }
}
ACME
      rm -f /etc/nginx/sites-enabled/*
      ln -sf /etc/nginx/sites-available/acme-bootstrap /etc/nginx/sites-enabled/acme-bootstrap
      nginx -t && systemctl reload nginx" || warn "could not install the ACME bootstrap vhost"
  fi
  # Whatever happens below, put the original vhosts back.
  _restore_vhosts() {
    [[ -z "$restore" ]] && return 0
    RUN "rm -f /etc/nginx/sites-enabled/acme-bootstrap
      for v in $restore; do ln -sf /etc/nginx/sites-available/\$v /etc/nginx/sites-enabled/\$v 2>/dev/null || true; done
      nginx -t && systemctl reload nginx" >/dev/null 2>&1 || true
  }

  log "requesting a certificate for $host (HTTP-01 over :80)"
  RUN "certbot certonly --webroot -w /var/www/certbot -d $host \
        --non-interactive --agree-tos -m $email --keep-until-expiring" \
    || { _restore_vhosts; warn "certbot failed for $host — is :80 open to 0.0.0.0/0 and DNS pointing here? staying on http"; return 1; }
  _restore_vhosts
  RUN "test -s /etc/letsencrypt/live/$host/fullchain.pem" >/dev/null 2>&1 \
    || { warn "certbot reported success but no cert on disk — staying on http"; return 1; }
  ok "certificate issued for $host"
}

# ─── multi-tenant: the control plane ────────────────────────────────────────
provision_controlplane() {
  require_driver
  [[ -f "$BUILD_DIR/controlplane" ]] || build_binaries controlplane
  # Credential stability (same rationale as the engine): reuse what is already on
  # the host so a redeploy never invalidates credentials the operator is using.
  # Both live in /etc/ebpf-soc/controlplane.env, written 0600 further down.
  if [[ -z "$PG_PASS" ]]; then
    PG_PASS="$(RUN "grep -oE 'postgres://postgres:[^@]*' /etc/ebpf-soc/controlplane.env 2>/dev/null | head -1 | sed 's|postgres://postgres:||'" 2>/dev/null || true)"
    [[ -n "$PG_PASS" ]] && log "reusing the existing Postgres password (redeploy)" \
                        || PG_PASS="$(gen_secret 24)"
  fi
  if [[ -z "$CP_ADMIN_TOKEN" ]]; then
    CP_ADMIN_TOKEN="$(RUN "grep -h '^CP_ADMIN_TOKEN=' /etc/ebpf-soc/controlplane.env 2>/dev/null | tail -1 | cut -d= -f2-" 2>/dev/null || true)"
    [[ -n "$CP_ADMIN_TOKEN" ]] && log "reusing the existing control-plane admin token (redeploy)" \
                               || CP_ADMIN_TOKEN="$(gen_token)"
  fi
  # Keycloak's admin is created ONLY on first start (start-dev persists it in H2),
  # so KC_BOOTSTRAP_ADMIN_PASSWORD is ignored on every later boot. Regenerating it
  # on a redeploy would leave kcadm unable to authenticate against the persisted
  # admin — breaking idempotency. Reuse the password already recorded on the host
  # when one exists; only mint a new one for a first-time deploy.
  local KC_ADMIN_PASS
  KC_ADMIN_PASS="$(RUN "grep -h '^KC_BOOTSTRAP_ADMIN_PASSWORD=' /etc/ebpf-soc/keycloak.env 2>/dev/null | tail -1 | cut -d= -f2-" 2>/dev/null || true)"
  [[ -n "$KC_ADMIN_PASS" ]] && log "reusing the existing Keycloak admin password (redeploy)" \
                            || KC_ADMIN_PASS="$(gen_engine_password)"

  # Permanent admin. Keycloak's env-bootstrapped admin is flagged "temporary"
  # (the console nags to replace it). We create a real one — ebpf-admin — and
  # delete the temporary one at the end. Its password is persisted + reused like
  # the bootstrap one, so kcadm keeps authenticating on redeploys AFTER the temp
  # admin is gone. Alphanumeric so it never needs shell-escaping in kcadm calls.
  local PERM_ADMIN_USER="ebpf-admin"
  local PERM_ADMIN_PW
  PERM_ADMIN_PW="$(RUN "grep -h '^KC_PERM_ADMIN_PASSWORD=' /etc/ebpf-soc/keycloak-admin.env 2>/dev/null | tail -1 | cut -d= -f2-" 2>/dev/null || true)"
  [[ -n "$PERM_ADMIN_PW" ]] && log "reusing the existing permanent-admin password (redeploy)" \
                            || PERM_ADMIN_PW="Ebpf$(gen_secret 22)Zz9"

  # kcadm login that PREFERS the permanent admin and falls back to the bootstrap
  # admin (first deploy, before ebpf-admin exists). Substituted into every kcadm
  # block below so none of them depend on the temporary admin surviving.
  local KC_CFG="/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:$KC_PORT --realm master --user '$PERM_ADMIN_USER' --password '$PERM_ADMIN_PW' >/dev/null 2>&1 || /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:$KC_PORT --realm master --user admin --password '$KC_ADMIN_PASS' >/dev/null 2>&1"

  # Keycloak is reached THROUGH nginx on :80, not on its own port. Two reasons:
  # the console only needs one port open (browsers complete the OIDC flow on the
  # same origin they loaded the app from), and the control plane resolves OIDC
  # discovery by dialling this very URL — on a cloud host that is a hairpin to
  # the box's own public IP, which only works on a port the firewall/security
  # group actually admits. Pointing discovery at Keycloak's private port instead
  # is not an option: the issuer in the discovery document must match the issuer
  # browsers are redirected to, or the OIDC library rejects it.
  local base="$TARGET_SCHEME://$TARGET_HOST"
  local issuer="$base/realms/ebpf-soc"
  # The CP turns on Secure cookies iff this redirect is https, so the scheme here
  # is what makes session cookies https-only — not a separate flag.
  local redirect="$base/auth/callback"

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
# Behind nginx: trust the forwarded headers and emit absolute URLs on the public
# origin, so the login form posts back through the proxy instead of to :$KC_PORT.
KC_PROXY_HEADERS=xforwarded
KC_HOSTNAME=$TARGET_SCHEME://$TARGET_HOST
EOF"
  # Persist the permanent-admin password (0600) so redeploys reuse it.
  RUN "umask 077; cat > /etc/ebpf-soc/keycloak-admin.env <<EOF
KC_PERM_ADMIN_USER=$PERM_ADMIN_USER
KC_PERM_ADMIN_PASSWORD=$PERM_ADMIN_PW
EOF"

  # Install the eBPF-SOC themes BEFORE Keycloak starts, so they're discovered at
  # boot (Keycloak scans themes once, at startup). Properties/CSS only — no
  # FreeMarker overrides — so they survive Keycloak upgrades:
  #
  #   ebpf-soc/login        the SOC console sign-in (accent "SOC CONSOLE" pill)
  #   ebpf-soc/admin        rebrands the LOGGED-IN admin console (masthead logo,
  #                         favicon, tab title) — a different theme type
  #   ebpf-soc-admin/login  master-realm sign-in; inherits ebpf-soc and only
  #                         flips the pill to an amber "PLATFORM ADMIN"
  #
  # COPYFILE_DISABLE keeps macOS AppleDouble (._*) sidecar files out of the tar.
  log "installing the eBPF-SOC Keycloak themes (login + admin)"
  COPYFILE_DISABLE=1 tar -C "$DEPLOY_LIB_DIR/keycloak-theme" -cf - ebpf-soc ebpf-soc-admin 2>/dev/null | \
    RUN "rm -rf /opt/keycloak/themes/ebpf-soc /opt/keycloak/themes/ebpf-soc-admin; mkdir -p /opt/keycloak/themes; tar -C /opt/keycloak/themes -xf - 2>/dev/null; find /opt/keycloak/themes -name '._*' -delete 2>/dev/null; true"

  _systemd_unit ebpf-keycloak "Keycloak (ebpf-soc SSO)" "/opt/keycloak/bin/kc.sh start-dev" "" /etc/ebpf-soc/keycloak.env
  # Always (re)start so a newly-installed/updated theme is discovered — Keycloak
  # scans themes at boot. start-dev disables theme caching, so this is the only
  # restart the theme needs.
  RUN "systemctl enable ebpf-keycloak >/dev/null 2>&1; systemctl restart ebpf-keycloak"
  log "waiting for Keycloak"
  RUN "for i in \$(seq 1 40); do curl -fsS http://localhost:$KC_PORT/realms/master >/dev/null 2>&1 && break; sleep 6; done"

  # Self-heal the admin identity. The admin lives in Keycloak's persisted store and
  # is created only on first boot, so KC_BOOTSTRAP_ADMIN_PASSWORD is ignored on
  # every later start. If the stored admin has diverged from keycloak.env (a prior
  # partial run, a hand-edit), kcadm cannot authenticate and the whole realm setup
  # below fails. Prove auth works; if it does not, reset Keycloak's local store so
  # it re-bootstraps with the current env password. The realm/client/users are
  # fully re-declared just below, so a reset loses nothing this script owns.
  # Auth must succeed as EITHER the permanent admin (redeploys) or the bootstrap
  # admin (first deploy). Only if BOTH fail is the store genuinely wedged — then
  # reset so it re-bootstraps. Using KC_CFG (not just the bootstrap admin) is what
  # keeps a redeploy from wiping everything once the temp admin has been removed.
  if ! RUN "$KC_CFG"; then
    warn "Keycloak admin auth failed (both permanent and bootstrap) — resetting the local store to re-bootstrap"
    RUN "systemctl stop ebpf-keycloak; rm -rf /opt/keycloak/data/h2; systemctl start ebpf-keycloak"
    RUN "for i in \$(seq 1 40); do curl -fsS http://localhost:$KC_PORT/realms/master >/dev/null 2>&1 && break; sleep 6; done"
  fi

  # Ensure the permanent admin exists (idempotent): create if missing, (re)set its
  # persisted password, grant the master 'admin' role. After this, kcadm can rely
  # on ebpf-admin and the temporary bootstrap admin can be removed at the end.
  log "ensuring the permanent Keycloak admin ($PERM_ADMIN_USER)"
  RUN "K(){ /opt/keycloak/bin/kcadm.sh \"\$@\"; }
    $KC_CFG || { echo 'kcadm auth failed'; exit 1; }
    uid(){ K get users -r master -q username=\"\$1\" -q exact=true --fields id --format csv --noquotes 2>/dev/null | tail -1; }
    if [ -z \"\$(uid $PERM_ADMIN_USER)\" ]; then
      K create users -r master -s username=$PERM_ADMIN_USER -s enabled=true -s email=$PERM_ADMIN_USER@local -s emailVerified=true -s firstName=eBPF -s lastName=Admin >/dev/null 2>&1 || true
    fi
    K set-password -r master --username $PERM_ADMIN_USER --new-password '$PERM_ADMIN_PW' >/dev/null 2>&1
    K add-roles -r master --uusername $PERM_ADMIN_USER --rolename admin >/dev/null 2>&1"

  # Realm, client, roles, tenant mapper, users, password policy
  log "configuring realm ebpf-soc"
  local first_tenant; first_tenant="$(echo $TENANTS | awk '{print $1}')"
  local CP_SECRET
  CP_SECRET="$(RUN "K(){ /opt/keycloak/bin/kcadm.sh \"\$@\"; }
    { $KC_CFG; }
    K create realms -s realm=ebpf-soc -s enabled=true -s sslRequired=NONE -s 'passwordPolicy=$PASSWORD_POLICY' >/dev/null 2>&1 || true
    K update users/profile -r ebpf-soc -s 'unmanagedAttributePolicy=ENABLED' >/dev/null 2>&1 || true
    # Brand all three themeable surfaces (login / admin console / account console).
    # displayName drives the login tab title (\"Sign in to {displayName}\") AND the
    # label above the realm name in the admin realm-selector — that is where the
    # stock \"Keycloak\" text comes from. displayNameHtml is cleared because master
    # ships the Keycloak logo markup in it.
    K update realms/ebpf-soc -s loginTheme=ebpf-soc -s accountTheme=ebpf-soc \
      -s 'displayName=eBPF SOC' -s 'displayNameHtml=' >/dev/null 2>&1 || true
    K update realms/master   -s loginTheme=ebpf-soc-admin -s adminTheme=ebpf-soc -s accountTheme=ebpf-soc \
      -s 'displayName=eBPF SOC Platform Admin' -s 'displayNameHtml=' >/dev/null 2>&1 || true
    # sslRequired must be applied by UPDATE, not just at realm-create: the create
    # above is skipped on every redeploy, and master (which we never create) ships
    # with 'external' — i.e. HTTPS demanded for any non-localhost request. These
    # scripts bring the stack up on plain HTTP, so external breaks browser access
    # by IP. Put TLS in front for production and set this back to EXTERNAL.
    K update realms/ebpf-soc -s sslRequired=NONE >/dev/null 2>&1 || true
    K update realms/master   -s sslRequired=NONE >/dev/null 2>&1 || true
    K create roles -r ebpf-soc -s name=tenant-analyst >/dev/null 2>&1 || true
    K create roles -r ebpf-soc -s name=msoc-admin >/dev/null 2>&1 || true
    CID=\$(K create clients -r ebpf-soc -s clientId=console-bff -s enabled=true -s protocol=openid-connect -s publicClient=false -s standardFlowEnabled=true -s directAccessGrantsEnabled=true -s 'redirectUris=[\"$redirect\",\"$base/*\"]' -s 'webOrigins=[\"$base\"]' -i 2>/dev/null || K get clients -r ebpf-soc -q clientId=console-bff --fields id --format csv | tail -1 | tr -d '\"')
    # ALWAYS re-assert the URLs. The create above is a no-op on redeploy (the
    # client already exists), so without this an existing deployment keeps the
    # redirect URIs of whatever TARGET_HOST it was FIRST built with. Point the
    # same stack at a new hostname and Keycloak answers the authorize request
    # with 'Invalid parameter: redirect_uri' — a 400 on the login page, with the
    # console itself serving fine, which reads like a broken app rather than a
    # stale client registration.
    # baseUrl is NOT redundant with rootUrl. Keycloak's error template renders
    # its recovery link only when client.baseUrl has content, so with baseUrl
    # unset every Keycloak-side login error is a DEAD END: branded page, no
    # link, no way back except hand-editing the address bar. The common one is
    # "Cookie not found", which any reload of the one-shot
    # /login-actions/authenticate URL produces. rootUrl does not satisfy that
    # check -- it has to be baseUrl.
    K update clients/\$CID -r ebpf-soc -s 'redirectUris=[\"$redirect\",\"$base/*\"]' -s 'webOrigins=[\"$base\"]' -s 'rootUrl=$base' -s 'baseUrl=$base/' >/dev/null 2>&1 || true
    K create clients/\$CID/protocol-mappers/models -r ebpf-soc -s name=tenant -s protocol=openid-connect -s protocolMapper=oidc-usermodel-attribute-mapper -s 'config.\"user.attribute\"=tenant' -s 'config.\"claim.name\"=tenant' -s 'config.\"jsonType.label\"=String' -s 'config.\"id.token.claim\"=true' -s 'config.\"access.token.claim\"=true' -s 'config.\"userinfo.token.claim\"=true' >/dev/null 2>&1 || true
    K get clients/\$CID/client-secret -r ebpf-soc | grep value | sed -E 's/.*\"value\" *: *\"([^\"]+)\".*/\1/'")"

  # one operator per tenant + one cross-tenant msoc-admin
  local userlist=""
  for t in $TENANTS; do
    local u; u="op-$(echo $t | cut -d- -f1)"; local pw; pw="$(console_password "$u")"
    RUN "K(){ /opt/keycloak/bin/kcadm.sh \"\$@\"; }
      { $KC_CFG; }
      K create users -r ebpf-soc -s username=$u -s enabled=true -s email=$u@local -s firstName=$u -s lastName=op -s emailVerified=true -s 'attributes.tenant=[\"$t\"]' >/dev/null 2>&1 || true
      K add-roles -r ebpf-soc --uusername $u --rolename tenant-analyst >/dev/null 2>&1
      K set-password -r ebpf-soc --username $u --new-password '$pw' >/dev/null 2>&1"
    userlist+="  $u / $pw   (tenant-analyst, $t)\n"
  done
  local msoc_pw; msoc_pw="$(console_password msoc)"
  RUN "K(){ /opt/keycloak/bin/kcadm.sh \"\$@\"; }
    { $KC_CFG; }
    K create users -r ebpf-soc -s username=msoc -s enabled=true -s email=msoc@local -s firstName=msoc -s lastName=admin -s emailVerified=true -s 'attributes.tenant=[\"$first_tenant\"]' >/dev/null 2>&1 || true
    K add-roles -r ebpf-soc --uusername msoc --rolename msoc-admin >/dev/null 2>&1
    K set-password -r ebpf-soc --username msoc --new-password '$msoc_pw' >/dev/null 2>&1"
  userlist+="  msoc / $msoc_pw   (msoc-admin, cross-tenant)\n"

  # Remove Keycloak's temporary bootstrap admin now that the permanent ebpf-admin
  # is in place and proven (the console's "temporary admin" warning goes away).
  # EXACT username match — an infix search on "admin" also matches "ebpf-admin",
  # so a loose query + tail would delete the wrong account.
  log "removing Keycloak's temporary bootstrap admin"
  RUN "K(){ /opt/keycloak/bin/kcadm.sh \"\$@\"; }
    /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:$KC_PORT --realm master --user '$PERM_ADMIN_USER' --password '$PERM_ADMIN_PW' >/dev/null 2>&1 || { echo 'permanent admin auth failed — keeping temp admin'; exit 0; }
    AID=\$(K get users -r master -q username=admin -q exact=true --fields id --format csv --noquotes 2>/dev/null | tail -1)
    [ -n \"\$AID\" ] && K delete users/\$AID -r master >/dev/null 2>&1 && echo 'temp admin removed' || echo 'no temp admin present'"

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
  # gRPC binds 0.0.0.0 (not loopback) so real per-tenant agents on their OWN
  # OrbStack VMs can enroll + uplink real Tetragon telemetry. The cert SAN stays
  # `localhost`; agents pin the CA and pass -controlplane-servername localhost so
  # verification passes regardless of the IP they dial. Enrollment is
  # bootstrap-token-gated and the command channel is mTLS, so exposing 9443 on
  # the local OrbStack bridge is safe.
  _systemd_unit ebpf-soc-controlplane "ebpf-soc control plane (multi-tenant)" \
    "/usr/local/bin/ebpf-soc-controlplane -http 127.0.0.1:$CP_HTTP_PORT -grpc 0.0.0.0:9443 -server-name localhost -store postgres -oidc-issuer $issuer -oidc-client-id console-bff -oidc-redirect-url $redirect -app-url / -state-dir /var/lib/ebpf-soc -fleet-pubkey-out /var/lib/ebpf-soc/fleet.pub" \
    "postgresql.service ebpf-keycloak.service" /etc/ebpf-soc/controlplane.env
  # MUST be restart, not `enable --now`: the latter is a no-op when the service is
  # already running, so a redeploy would leave the control plane holding the OLD
  # Postgres password (PG_PASS is rotated above) while its env file has the new
  # one. Already-pooled connections keep working, but every NEW connection fails
  # auth — producing intermittent 500 "query failed" on the SOC read endpoints.
  RUN "systemctl enable ebpf-soc-controlplane >/dev/null 2>&1; systemctl restart ebpf-soc-controlplane; sleep 3; chmod 0644 /var/lib/ebpf-soc/fleet.pub 2>/dev/null || true"

  # nginx: serve the console dist + proxy /api,/auth to the CP
  log "installing console frontend + nginx"
  RUN "mkdir -p /var/www/console"
  put_dir "$REPO_ROOT/web/dist" /var/www/console
  # The console HTML links /favicon.svg, but Vite never emits one: in the
  # single-tenant build the ENGINE serves it from a go:embed handler. Here nginx
  # serves the SPA statically, so without these files the request falls through
  # try_files to index.html and the browser gets HTML instead of an icon (no
  # favicon at all). Ship the engine's embedded icons alongside the bundle.
  PUT "$REPO_ROOT/engine/internal/api/favicon.svg"       /var/www/console/favicon.svg
  PUT "$REPO_ROOT/engine/internal/api/favicon-light.svg" /var/www/console/favicon-light.svg
  # The routing lives in ONE snippet that both the :80 and :443 servers include.
  # Duplicating it per-scheme is how a TLS site ends up serving different rules
  # on http and https after someone edits only one copy.
  RUN "mkdir -p /etc/nginx/snippets /var/www/certbot
cat > /etc/nginx/snippets/ebpf-console.conf <<'NGINX'
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
    # /readyz was NOT proxied, so it fell through to the SPA catch-all below and
    # answered 200 with index.html — an uptime check pointed at it saw HTML and
    # called it healthy. It is the only probe that reports store reachability,
    # so it has to reach the control plane.
    location /readyz { proxy_pass http://127.0.0.1:$CP_HTTP_PORT; }
    # Keycloak, same origin. /realms + /resources carry the OIDC flow and its
    # login-page assets; /admin + /js are the admin console.
    location ~ ^/(realms|resources|admin|js|robots.txt) {
        proxy_pass http://127.0.0.1:$KC_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
    }
    # /favicon.ico is the one icon URL the app cannot version: browsers request
    # that exact path by convention, with no query, and several surfaces
    # (vertical tab strips, bookmark and history lists) prefer it over the
    # <link>. With no explicit Cache-Control nginx leaves it to heuristic
    # freshness, which for an old file can be days. Revalidate instead — the
    # ETag makes that a 304, and a corrected icon lands on the next load.
    # The =404 matters too: without it this path falls through to the SPA
    # catch-all and answers index.html, which the browser discards as an icon.
    location = /favicon.ico { try_files \$uri =404; add_header Cache-Control "public, no-cache" always; }
    # nginx's stock mime.types has no entry for .webmanifest, so this went out
    # as application/octet-stream — the engine, which serves its own copy from
    # Go, sent application/manifest+json for the identical bytes. This is the
    # file that carries theme_color and the whole icon list, so a client that
    # holds the spec to the letter ignores all of it and an installed console
    # keeps whatever icon it already had.
    location = /manifest.webmanifest { types {} default_type application/manifest+json; try_files \$uri =404; }
    location / { try_files \$uri \$uri.html /index.html; }
NGINX"

  # TLS is driven by whether certs EXIST on the target, not by a flag, so a
  # redeploy can never silently downgrade a site that already has them. certbot
  # is run with 'certonly' (see provision_tls) precisely so nginx config stays
  # owned here — letting certbot edit it would put TLS one redeploy away from
  # being overwritten, with no error to notice.
  local has_tls=no
  RUN "test -s /etc/letsencrypt/live/$TARGET_HOST/fullchain.pem" >/dev/null 2>&1 && has_tls=yes
  if [[ "$has_tls" == yes ]]; then
    log "certs found for $TARGET_HOST — serving TLS, redirecting :80"
    RUN "cat > /etc/nginx/sites-available/console <<'NGINX'
server {
    listen 80 default_server;
    server_name $TARGET_HOST _;
    # Keep the ACME path on :80 and unredirected, or renewals fail.
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl default_server;
    http2 on;
    server_name $TARGET_HOST _;
    ssl_certificate     /etc/letsencrypt/live/$TARGET_HOST/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$TARGET_HOST/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    include /etc/nginx/snippets/ebpf-console.conf;
}
NGINX"
  else
    RUN "cat > /etc/nginx/sites-available/console <<'NGINX'
server {
    listen 80 default_server;
    server_name $TARGET_HOST _;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    include /etc/nginx/snippets/ebpf-console.conf;
}
NGINX"
  fi
  RUN "rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/console /etc/nginx/sites-enabled/console
    nginx -t && systemctl restart nginx && systemctl enable nginx >/dev/null 2>&1"

  if [[ "$DATA_MODE" == real ]]; then
    # REAL agents — one per tenant, each on its OWN OrbStack VM running Tetragon
    # + the real engine, enrolled to the control plane. This is the "real data,
    # not demo data" path: the console shows telemetry the agents actually
    # observed, tenant-isolated because each tenant's events come from its own
    # host. Provisioning is delegated to provision-agent-orbstack.sh, which is
    # idempotent (a re-deploy reuses each VM's persisted mTLS identity).
    log "provisioning a REAL agent VM per tenant (DATA_MODE=real)"
    # The provisioner pushes these from the mac to each agent VM, so pull them
    # off the control-plane box first.
    RUN "cat /var/lib/ebpf-soc/ca.pem"   > "$BUILD_DIR/ca-bundle.pem" 2>/dev/null || true
    RUN "cat /var/lib/ebpf-soc/fleet.pub" > "$BUILD_DIR/fleet.pub"     2>/dev/null || true
    # Any legacy sim-agents from an earlier sim-mode deploy must not keep feeding
    # fabricated data alongside the real agents.
    for t in $TENANTS; do
      local label; label="sim-$(echo $t | cut -d- -f1)"
      RUN "systemctl disable --now ebpf-$label >/dev/null 2>&1 || true"
    done
    local prov="$DEPLOY_LIB_DIR/provision-agent-orbstack.sh"
    if [[ -x "$prov" && -f "$BUILD_DIR/ca-bundle.pem" && -f "$BUILD_DIR/fleet.pub" && -f "$BUILD_DIR/agent" ]]; then
      for t in $TENANTS; do
        "$prov" "$t" "$TARGET_HOST" "$CP_ADMIN_TOKEN" \
          "$BUILD_DIR/ca-bundle.pem" "$BUILD_DIR/fleet.pub" "$BUILD_DIR/agent" \
          || warn "agent provisioning for $t reported an error — see output above"
      done
    else
      warn "DATA_MODE=real but the provisioner or its inputs are missing — skipping agent VMs"
    fi
    RUN "sleep 4"
  elif [[ "$DATA_MODE" == none ]]; then
    log "DATA_MODE=none — no data seeders; disabling any leftover sim-agents"
    for t in $TENANTS; do
      local label; label="sim-$(echo $t | cut -d- -f1)"
      RUN "systemctl disable --now ebpf-$label >/dev/null 2>&1 || true"
    done
  else
    # sim-agents (data seeders) — one per tenant
    log "starting a sim-agent per tenant"
    for t in $TENANTS; do
      local label; label="sim-$(echo $t | cut -d- -f1)"
      RUN "mkdir -p /var/lib/ebpf-$label"
      _systemd_unit "ebpf-$label" "ebpf-soc sim-agent ($t)" \
        "/usr/local/bin/ebpf-simagent -cp-http http://127.0.0.1:$CP_HTTP_PORT -cp-grpc 127.0.0.1:9443 -server-name localhost -admin-token $CP_ADMIN_TOKEN -tenant $t -state-dir /var/lib/ebpf-$label -label $label -fleet-pubkey /var/lib/ebpf-soc/fleet.pub" \
        "ebpf-soc-controlplane.service"
      # restart, not `enable --now`: the unit's ExecStart embeds CP_ADMIN_TOKEN,
      # which is regenerated every deploy. Without a restart the running sim-agent
      # keeps presenting the old token and its uplink is rejected.
      RUN "systemctl enable ebpf-$label >/dev/null 2>&1; systemctl restart ebpf-$label"
    done
    RUN "sleep 8"
  fi

  local code; code="$(RUN "curl -s -o /dev/null -w '%{http_code}' http://localhost/" || true)"
  echo
  ok "control plane live at  $TARGET_SCHEME://$TARGET_HOST/   (console HTTP $code)"
  # Keycloak is proxied on the console origin, NOT on :$KC_PORT — that port is
  # deliberately closed to the internet.
  echo "  Keycloak admin:  $TARGET_SCHEME://$TARGET_HOST/admin/  ($PERM_ADMIN_USER / $PERM_ADMIN_PW)"
  printf "  Console logins:\n%b" "$userlist"
  dim "credentials also written to $BUILD_DIR/credentials-$TARGET_HOST.txt"
  { echo "# ebpf-soc multi-tenant — $TARGET_HOST — $(date)"; echo "Keycloak admin: $PERM_ADMIN_USER / $PERM_ADMIN_PW"; printf "%b" "$userlist"; echo "postgres: postgres / $PG_PASS"; echo "cp admin token: $CP_ADMIN_TOKEN"; echo "console-bff secret: $CP_SECRET"; } > "$BUILD_DIR/credentials-$TARGET_HOST.txt"
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
