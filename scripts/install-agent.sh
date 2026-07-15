#!/usr/bin/env bash
#
# scripts/install-agent.sh — install the Choke Agent on a Linux host and enroll
# it into a tenant of the control plane.
#
# The agent is deliberately NOT containerised: it is one static binary that runs
# next to Tetragon with the privileges enforcement needs. Installing it means
#
#   1. proving the kernel can carry it   (≥ 5.15, BTF, cgroup v2 — preflight.sh)
#   2. Tetragon + the TracingPolicies    (the event source)
#   3. the binary, policies, and BPF data plane
#   4. a ONE-TIME enrollment: the agent trades a bootstrap token for an mTLS
#      certificate whose Subject carries the tenant_id. That certificate is the
#      root of tenant isolation, and it is persisted — every later restart reuses
#      it, so the token is never needed again.
#   5. a systemd unit with NO token in it, running detect-only by default.
#
# Detect-only is the default on purpose. Enforcement freezes and kills processes;
# turning it on is a decision an operator makes about a specific host, not a
# default an installer makes for them. Pass --enforce when you mean it.
#
#   ./scripts/install-agent.sh --host ubuntu@10.0.0.5 \
#       --controlplane cp.example.com:9443 --tenant acme --deployment cp-example-com
#
#   ./scripts/install-agent.sh --host ubuntu@10.0.0.5 \
#       --controlplane cp.example.com:9443 --tenant acme \
#       --ca-bundle path/ca-bundle.pem --fleet-pubkey path/fleet.pub --token <tok>
#
# Flags:
#   --host user@ip        target host (omit to install on THIS machine)
#   --controlplane H:P    control-plane gRPC endpoint agents dial
#   --tenant ID           the tenant this agent belongs to
#   --deployment NAME     pull CA / fleet key / a fresh token from .deploy/NAME
#   --ca-bundle FILE      CA the agent pins            (instead of --deployment)
#   --fleet-pubkey FILE   command-signing key it pins  (instead of --deployment)
#   --token TOKEN         one-time bootstrap token     (instead of --deployment)
#   --enforce             enforce from the start (default: detect-only)
#   --reenroll            discard the persisted identity and enroll again
#   --standalone          no control plane — local console only

LOG_TAG="agent"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

TARGET=""; CP_ENDPOINT=""; TENANT=""; DEPLOYMENT=""
CA_BUNDLE=""; FLEET_PUB=""; TOKEN=""
ENFORCE=0; REENROLL=0; STANDALONE=0
TETRAGON_IMAGE="${TETRAGON_IMAGE:-quay.io/cilium/tetragon:v1.6.1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)         TARGET="${2:?}"; shift 2 ;;
    --controlplane) CP_ENDPOINT="${2:?}"; shift 2 ;;
    --tenant)       TENANT="${2:?}"; shift 2 ;;
    --deployment)   DEPLOYMENT="${2:?}"; shift 2 ;;
    --ca-bundle)    CA_BUNDLE="${2:?}"; shift 2 ;;
    --fleet-pubkey) FLEET_PUB="${2:?}"; shift 2 ;;
    --token)        TOKEN="${2:?}"; shift 2 ;;
    --enforce)      ENFORCE=1; shift ;;
    --reenroll)     REENROLL=1; shift ;;
    --standalone)   STANDALONE=1; shift ;;
    -h|--help)      sed -n '3,39p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done

# ── Resolve where the trust material and the token come from ───────────────
if [[ $STANDALONE == 0 ]]; then
  [[ -n "$CP_ENDPOINT" ]] || die "--controlplane <host:port> is required (or pass --standalone)"
  [[ -n "$TENANT" ]]      || die "--tenant <id> is required"

  if [[ -n "$DEPLOYMENT" ]]; then
    # The happy path: everything comes out of the deployment the wizard created.
    state_init "$DEPLOYMENT"
    state_load
    CA_BUNDLE="${CA_BUNDLE:-$ARTIFACTS_DIR/ca-bundle.pem}"
    FLEET_PUB="${FLEET_PUB:-$ARTIFACTS_DIR/fleet.pub}"
    [[ -f "$CA_BUNDLE" ]] || die "no CA bundle in $DEPLOYMENT — run: ./scripts/pki.sh export --ssh $(state_get SSH_ALIAS) --out $ARTIFACTS_DIR"

    # Tokens are single-use and expire in ~15 minutes, so a stale one on disk is
    # worse than useless. Always mint a fresh one for this install.
    if [[ -z "$TOKEN" ]]; then
      log "minting a fresh enrollment token for tenant '$TENANT'"
      CP_ADMIN_TOKEN="$(secret_get CP_ADMIN_TOKEN)" \
      CP_URL="http://127.0.0.1:$(state_get CP_HTTP_PORT 9090)" \
        "$SCRIPTS_DIR/tenantctl" enroll-token "$TENANT" \
          --ssh "$(state_get SSH_ALIAS)" --out "$ARTIFACTS_DIR/enroll-token-$TENANT.txt" >/dev/null \
        || die "could not mint an enrollment token"
      TOKEN="$(cat "$ARTIFACTS_DIR/enroll-token-$TENANT.txt")"
    fi
  fi

  [[ -n "$CA_BUNDLE" && -f "$CA_BUNDLE" ]] || die "--ca-bundle is required (or --deployment NAME)"
  [[ -n "$TOKEN" ]] || die "--token is required (or --deployment NAME to mint one)"
  if [[ -z "$FLEET_PUB" || ! -f "$FLEET_PUB" ]]; then
    warn "no --fleet-pubkey: the agent will report telemetry but REFUSE remote commands"
    warn "(a command channel with no signature to verify is one an attacker can drive)"
    FLEET_PUB=""
  fi
fi

# ── Transport: remote host, or this machine ────────────────────────────────
if [[ -n "$TARGET" ]]; then
  SSH_ALIAS=""; SSH_TARGET="$TARGET"; export SSH_TARGET
  REMOTE=1
else
  REMOTE=0
  [[ "$(uname -s)" == "Linux" ]] || die "the agent runs on Linux — use --host to target a Linux server"
  [[ "$(id -u)" == "0" ]] || die "run as root (or use --host)"
fi

# sh_run / sh_sudo: the same install logic, whether it runs here or over SSH.
sh_run()  { if (( REMOTE )); then rssh "$@"; else bash -c "$*"; fi; }
sh_sudo() { if (( REMOTE )); then rsudo "$@"; else bash -c "$*"; fi; }
sh_put()  { # <local> <remote> <mode>
  if (( REMOTE )); then rput_root "$1" "$2" "$3"; else install -D -m "$3" "$1" "$2"; fi
}
sh_write() { # <path> <mode>  (content on stdin)
  if (( REMOTE )); then rwrite_root "$1" "$2"; else install -D -m "$2" /dev/stdin "$1"; fi
}

HOSTLABEL="${TARGET:-$(hostname)}"
printf '\n%sInstalling the Choke Agent on %s%s\n' "$C_BOLD" "$HOSTLABEL" "$C_RESET"

# ── 1. Preflight — refuse a host that cannot enforce ───────────────────────
step_header "1/6  Kernel preflight"
if (( REMOTE )); then
  "$SCRIPTS_DIR/preflight.sh" --role agent --ssh "$TARGET" \
    || die "this host cannot run the agent — see the failures above"
else
  "$SCRIPTS_DIR/preflight.sh" --role agent --local \
    || die "this host cannot run the agent"
fi

# ── 2. Build ───────────────────────────────────────────────────────────────
step_header "2/6  Agent binary"
AGENT_BIN="$REPO_ROOT/engine/agent-linux-amd64"
if [[ ! -f "$AGENT_BIN" ]]; then
  log "building the static agent"
  run make -C "$REPO_ROOT" build-agent-linux
fi
[[ -f "$AGENT_BIN" ]] || die "no agent binary at $AGENT_BIN"

# ── 3. Tetragon — the event source ─────────────────────────────────────────
step_header "3/6  Tetragon + TracingPolicies"
if sh_run "sudo docker ps --format '{{.Names}}' 2>/dev/null | grep -qx tetragon"; then
  ok "Tetragon already running"
else
  log "starting Tetragon ($TETRAGON_IMAGE)"
  sh_sudo "command -v docker >/dev/null || curl -fsSL https://get.docker.com | sh"
  sh_sudo "docker rm -f tetragon 2>/dev/null || true"
  sh_sudo "docker run -d --name tetragon --privileged --pid=host --network=host \
      -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf:ro \
      -v /var/run/tetragon:/var/run/tetragon \
      -v /sys/fs/bpf:/sys/fs/bpf \
      --restart=unless-stopped $TETRAGON_IMAGE"
  wait_for 90 "the Tetragon socket" sh_run "test -S /var/run/tetragon/tetragon.sock" \
    || die "Tetragon did not come up — check: docker logs tetragon"
  ok "Tetragon running"
fi

log "shipping policies + attack scripts"
if (( REMOTE )); then
  tar -cz -C "$REPO_ROOT" policies attacks | rssh "cat > /tmp/ebpf-policies.tgz"
  rsudo "mkdir -p /opt/ebpf-soc && tar -xzf /tmp/ebpf-policies.tgz -C /opt/ebpf-soc && rm -f /tmp/ebpf-policies.tgz"
else
  mkdir -p /opt/ebpf-soc
  cp -R "$REPO_ROOT/policies" "$REPO_ROOT/attacks" /opt/ebpf-soc/
fi

log "applying TracingPolicies (detection + Sigkill/Override enforcement)"
sh_sudo "for p in /opt/ebpf-soc/policies/*.yaml /opt/ebpf-soc/policies/enforce/*.yaml; do
    [ -f \"\$p\" ] || continue
    docker cp \"\$p\" tetragon:/tmp/ >/dev/null 2>&1 || true
    docker exec tetragon tetra tracingpolicy add \"/tmp/\$(basename \"\$p\")\" >/dev/null 2>&1 || true
  done"
ok "policies applied"

# ── 4. Binary + config ─────────────────────────────────────────────────────
step_header "4/6  Agent + configuration"
sh_put "$AGENT_BIN" /opt/ebpf-soc/agent 0755
sh_sudo "mkdir -p /var/lib/ebpf-soc-agent /var/lib/ebpf-soc-agent/honey && chmod 700 /var/lib/ebpf-soc-agent"

if [[ $STANDALONE == 0 ]]; then
  sh_put "$CA_BUNDLE" /etc/ebpf-soc/ca-bundle.pem 0644
  if [[ -n "$FLEET_PUB" ]]; then sh_put "$FLEET_PUB" /etc/ebpf-soc/fleet.pub 0644; fi
fi

# The local debug console needs a password (the agent fails fast without one),
# and a password on the command line would be world-readable in /proc. The YAML
# config file is the channel that keeps it off there.
CONSOLE_PASS="$(gen_secret 24)"
sh_write /etc/ebpf-soc/agent.yaml 0600 <<EOF
# Written by scripts/install-agent.sh. Secrets live here (0600) rather than in
# the systemd ExecStart line, because /proc/<pid>/cmdline is world-readable.
tetragon: unix:///var/run/tetragon/tetragon.sock
db: /var/lib/ebpf-soc-agent/events.db
http: 127.0.0.1:8080          # local debug console — never exposed to the network
user: admin
pass: $CONSOLE_PASS
secret_path: /var/lib/ebpf-soc-agent/secret
policies: /opt/ebpf-soc/policies
attacks: /opt/ebpf-soc/attacks
choke_policies: /opt/ebpf-soc/policies/choke
honeypots: /var/lib/ebpf-soc-agent/honey
cgroup_root: /sys/fs/cgroup
enforce: $( ((ENFORCE)) && echo true || echo false )
# Tuned so sshd's MOTD churn (which scores ~85) can reach tarpit but never
# quarantine — freezing sshd would lock the operator out of their own box.
throttle_at: 20
tarpit_at: 50
quarantine_at: 120
sever_at: 200
log_format: json
log_level: info
EOF
ok "/etc/ebpf-soc/agent.yaml written (0600) — console password stored there"

# ── 5. Enrollment — the one-time token exchange ────────────────────────────
step_header "5/6  Enrollment"
if [[ $STANDALONE == 1 ]]; then
  ok "standalone mode — no control plane, no enrollment"
  ENROLL_ARGS=""
else
  if (( REENROLL )); then
    warn "discarding the persisted identity — this agent will enroll as a NEW agent"
    sh_sudo "rm -f /var/lib/ebpf-soc-agent/agent-cert.pem /var/lib/ebpf-soc-agent/agent-key.pem /var/lib/ebpf-soc-agent/ca-bundle.pem /var/lib/ebpf-soc-agent/identity.json"
  fi

  if sh_run "sudo test -f /var/lib/ebpf-soc-agent/agent-cert.pem" 2>/dev/null; then
    ok "already enrolled — reusing the persisted identity (no token needed)"
    ENROLL_ARGS=""
  else
    # The token is passed via the EnvironmentFile and expanded by systemd, so it
    # is not baked into the unit. Once the certificate is persisted we blank it
    # out (step 6) — a spent token should not linger on disk.
    log "enrolling into tenant '$TENANT' at $CP_ENDPOINT"
    ENROLL_ARGS="-bootstrap-token $TOKEN -ca-bundle /etc/ebpf-soc/ca-bundle.pem"
  fi
fi

# ── 6. systemd unit ────────────────────────────────────────────────────────
step_header "6/6  systemd unit"
CP_ARGS=""
if [[ $STANDALONE == 0 ]]; then
  CP_ARGS="-controlplane $CP_ENDPOINT -state-dir /var/lib/ebpf-soc-agent"
  if [[ -n "$FLEET_PUB" ]]; then CP_ARGS="$CP_ARGS -fleet-pubkey /etc/ebpf-soc/fleet.pub"; fi
fi

sh_write /etc/ebpf-soc/agent.env 0600 <<EOF
AGENT_ENROLL_ARGS=$ENROLL_ARGS
EOF

sh_write /etc/systemd/system/ebpf-soc-agent.service 0644 <<EOF
[Unit]
Description=eBPF-SOC Choke Agent (sensing + enforcement)
Documentation=https://github.com/jeffmk/ebpf-poc-engine
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
# \$AGENT_ENROLL_ARGS is unquoted on purpose: systemd word-splits it, so it is
# either the two enrollment flags or nothing at all once enrollment is done.
ExecStart=/opt/ebpf-soc/agent -config /etc/ebpf-soc/agent.yaml $CP_ARGS \$AGENT_ENROLL_ARGS
EnvironmentFile=/etc/ebpf-soc/agent.env
Restart=always
RestartSec=5
TimeoutStopSec=20
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ebpf-soc-agent

# The agent runs as root and keeps its capabilities. Unlike the control plane it
# CANNOT be sandboxed: freezing a cgroup, loading BPF, and killing a process are
# exactly the privileges a sandbox would take away.
User=root
AmbientCapabilities=CAP_BPF CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_PERFMON CAP_NET_ADMIN CAP_KILL
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

sh_sudo "systemctl daemon-reload && systemctl enable --now ebpf-soc-agent && systemctl restart ebpf-soc-agent"

if [[ $STANDALONE == 0 && -n "$ENROLL_ARGS" ]]; then
  wait_for 60 "enrollment to complete" sh_run "sudo test -f /var/lib/ebpf-soc-agent/agent-cert.pem" \
    || die "enrollment did not complete — check: journalctl -u ebpf-soc-agent -n 50
     Common causes: the token expired (15 min), it was already used, or
     $CP_ENDPOINT is unreachable from this host."
  ok "enrolled — mTLS identity persisted to /var/lib/ebpf-soc-agent"

  # Spend the token exactly once: the identity is now on disk and every restart
  # reuses it, so leaving the token in the env file only widens the blast radius.
  sh_write /etc/ebpf-soc/agent.env 0600 <<<'AGENT_ENROLL_ARGS='
  sh_sudo "systemctl restart ebpf-soc-agent"
  ok "bootstrap token cleared from /etc/ebpf-soc/agent.env"
fi

sleep 2
if sh_run "systemctl is-active --quiet ebpf-soc-agent"; then
  ok "ebpf-soc-agent is running"
else
  die "the agent is not running — check: journalctl -u ebpf-soc-agent -n 50"
fi

printf '\n%s══ Agent installed on %s ══%s\n\n' "$C_BOLD" "$HOSTLABEL" "$C_RESET"
if (( ENFORCE )); then
  printf '  %sMode%s        ENFORCING — the ladder will throttle, freeze and kill\n' "$C_BOLD" "$C_RESET"
else
  printf '  %sMode%s        detect-only — decisions are audited, the kernel is untouched\n' "$C_BOLD" "$C_RESET"
  printf '              turn it on later:  systemctl edit, or re-run with --enforce\n'
fi
if [[ $STANDALONE == 0 ]]; then
  printf '  %sTenant%s      %s → %s\n' "$C_BOLD" "$C_RESET" "$TENANT" "$CP_ENDPOINT"
fi
printf '  %sLogs%s        journalctl -u ebpf-soc-agent -f\n' "$C_BOLD" "$C_RESET"
printf '  %sConsole%s     127.0.0.1:8080 (loopback; password in /etc/ebpf-soc/agent.yaml)\n' "$C_BOLD" "$C_RESET"
printf '\n  Prove it works:  %s./scripts/../attacks/03-reverse-shell.sh%s on the host, then watch the logs.\n\n' "$C_DIM" "$C_RESET"
