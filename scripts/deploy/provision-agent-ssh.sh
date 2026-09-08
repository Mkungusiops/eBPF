#!/usr/bin/env bash
#
# provision-agent-ssh.sh — stand up a REAL per-tenant Choke Agent on an Ubuntu
# server over SSH and enroll it into the multi-tenant control plane.
#
# The SSH/systemd counterpart of provision-agent-orbstack.sh (Alpine/OpenRC).
# Same story — Tetragon observes real kernel events, the agent scores them, and
# real alerts/events/decisions are uplinked tenant-stamped — but on a server you
# actually own, and with the NETWORK choke data plane attached, which the local
# OrbStack path cannot do (its VMs are L2-isolated from each other).
#
# One host per tenant is deliberate: each tenant's telemetry must come from its
# OWN kernel. A shared kernel (e.g. LXC containers on one host) would report
# identical events to every tenant and make the separation cosmetic.
#
# Usage:
#   CP_SSH=control-plane ./provision-agent-ssh.sh \
#       <tenant-id> <agent-ssh-host> <cp-ip> <cp-admin-token> \
#       <ca-bundle-file> <fleet-pub-file> <agent-binary> [devchoke.o]
#
# Idempotent: re-running reuses the persisted mTLS identity (no token is spent).
set -uo pipefail

TENANT="${1:?tenant-id required}"
HOST="${2:?agent ssh host required}"
CP_IP="${3:?control-plane IP required}"
CP_ADMIN_TOKEN="${4:?cp admin token required}"
CA_BUNDLE="${5:?ca-bundle file required}"
FLEET_PUB="${6:?fleet.pub file required}"
AGENT_BIN="${7:?agent binary required}"
DEVCHOKE_OBJ="${8:-}"

CP_SSH="${CP_SSH:?set CP_SSH=<ssh host of the control plane> (to mint the enrollment token)}"

# DATA_MODE governs the SYNTHETIC ACTIVITY GENERATOR on this agent, and it is
# the reason this variable exists here at all.
#
# THE BUG THIS CLOSES. `ebpf-activity.service` runs a loop that every 20-45s
# fires a script from the attack catalogue, reads /etc/shadow, and connects to
# five hardcoded "threat actor" IPs. It is a demo aid and it is very effective —
# it produced a dead-flat ~2,000 alerts/hour, 24 hours a day, on the production
# estate, of which a third were CRITICAL. That pinned the console's executive
# posture dial at 93-97 "critical" permanently, on an estate where nothing was
# happening. A gauge that reads the same on a quiet Sunday as during a breach is
# not a measurement.
#
# It was installed and started UNCONDITIONALLY. `DATA_MODE=none` — the
# documented switch for "no synthetic data", carefully passed by estate.sh —
# governed only the control plane's sim-agents and had no effect here. So the
# estate's "no fake data" flag did not cover the estate's largest source of fake
# data, and scripts/ci/verify-deploy.sh asserted "no sim-agents running" and
# passed while three attack generators ran.
#
# Default stays `sim` to match scripts/deploy/lib.sh, so a bare run of this
# script behaves as it always has. estate.sh passes `none`.
# DATA_MODE governs SYNTHETIC data: the sim-agents on the control plane and, on
# an agent host, /opt/ebpf-soc/activity.sh — a root systemd service that fires a
# scripted attack every 20-45s — plus the attacks/ catalogue (reverse shell,
# persistence, credential theft).
#
# DEFAULT IS `none`. It used to be `sim`, which meant the documented install path
# put a synthetic attack generator and a reverse-shell script catalogue onto
# whatever host it touched. That is defensible on a laptop and indefensible on a
# customer's production estate: their own EDR sees it, their NOC sees it, and the
# alerts it manufactures are indistinguishable from real ones in every panel and
# every exported report. Only estate.sh passed `none`, and estate.sh is specific
# to this project's own AWS rig — nobody deploying for a customer would run it.
#
# Opt in with DATA_MODE=sim for a demo or a UI-only environment.
DATA_MODE="${DATA_MODE:-none}"
case "$DATA_MODE" in
  sim|real|none) ;;
  *) die "DATA_MODE must be sim, real or none (got '$DATA_MODE')" ;;
esac
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TETRAGON_IMAGE="${TETRAGON_IMAGE:-quay.io/cilium/tetragon:v1.6.1}"

log()  { printf '  \033[36m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

m()    { ssh -o BatchMode=yes "$HOST" "sudo bash -c $(printf '%q' "$1")"; }
push() { ssh -o BatchMode=yes "$HOST" "sudo tee $1 >/dev/null"; }

printf '\n\033[1m══ real agent for %s on %s ══\033[0m\n' "$TENANT" "$HOST"

# ── 1. Preflight ───────────────────────────────────────────────────────────
m 'true' || die "cannot ssh to $HOST"
m 'sudo -n true' >/dev/null 2>&1 || die "passwordless sudo required on $HOST"
m 'grep -q cgroup2 /proc/filesystems' || die "$HOST has no cgroup2"
m 'test -f /sys/kernel/btf/vmlinux'   || die "$HOST kernel has no BTF — Tetragon cannot attach"
ok "preflight OK (cgroup2 + BTF present)"

# ── 2. Docker + Tetragon (the real event source) ───────────────────────────
if m 'command -v docker >/dev/null'; then
  ok "Docker already installed"
else
  log "installing Docker (apt)"
  m 'export DEBIAN_FRONTEND=noninteractive
     apt-get update -qq >/dev/null 2>&1
     apt-get install -y -qq docker.io iproute2 curl netcat-openbsd >/dev/null 2>&1
     systemctl enable --now docker >/dev/null 2>&1
     sleep 3' || die "docker install failed"
  ok "Docker installed"
fi
m 'docker version --format "{{.Server.Version}}" >/dev/null 2>&1' \
  || { m 'systemctl restart docker; sleep 4'; m 'docker version >/dev/null 2>&1' || die "docker not running"; }

# "Already running" is not enough — it must also be running WITH the policy
# bind mount. A host provisioned before that mount existed keeps its detection
# set in the container's writable layer, where a `docker rm` deletes it and
# where the agent cannot write a pushed policy durably. Checking the mount
# rather than just the process makes this converge an existing estate instead
# of only helping new hosts.
if m 'docker ps --format "{{.Names}}" | grep -qx tetragon' \
   && m 'docker inspect tetragon --format "{{range .Mounts}}{{.Destination}} {{end}}" | grep -q /etc/tetragon/tetragon.tp.d'; then
  ok "Tetragon already running with the policy mount"
else
  m 'docker ps --format "{{.Names}}" | grep -qx tetragon' \
    && log "recreating Tetragon to add the policy bind mount (policies are re-applied below)"
  log "starting Tetragon ($TETRAGON_IMAGE) — image pull may take ~1-2m"
  # --server-address is REQUIRED: without it Tetragon opens a TCP listener on
  # localhost:54321 and never creates the unix socket the agent dials.
  # tetragon.tp.d is BIND-MOUNTED from the host, and that is load-bearing twice.
  #
  # (1) Without it the policy directory lives in the container's writable layer.
  #     `docker restart` keeps it, but `docker rm` + recreate DELETES ALL
  #     DETECTION and the host silently drops to bare execve with nothing
  #     reporting it — and `docker rm -f tetragon` is this project's own
  #     documented lockout-recovery step, so that path gets exercised.
  # (2) It is what lets the agent make a pushed policy DURABLE. Tetragon reads
  #     this directory only at startup, so a policy added over the gRPC API is
  #     forgotten on the next daemon restart. With the mount, the agent (root on
  #     the host) writes the file directly — no docker socket, which would be
  #     root-on-host and a serious privilege expansion for a security agent.
  m "mkdir -p /etc/tetragon/tetragon.tp.d"
  m "docker rm -f tetragon >/dev/null 2>&1
     docker run -d --name tetragon --privileged --pid=host --network=host \
       -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf:ro \
       -v /var/run/tetragon:/var/run/tetragon \
       -v /etc/tetragon/tetragon.tp.d:/etc/tetragon/tetragon.tp.d \
       -v /sys/fs/bpf:/sys/fs/bpf \
       --restart=unless-stopped $TETRAGON_IMAGE \
       --server-address unix:///var/run/tetragon/tetragon.sock --btf /var/lib/tetragon/btf >/dev/null 2>&1"
  up=0
  for _ in $(seq 1 60); do m 'test -S /var/run/tetragon/tetragon.sock' && { up=1; break; }; sleep 2; done
  [ "$up" = 1 ] || die "Tetragon socket never appeared — check: ssh $HOST sudo docker logs tetragon"
  ok "Tetragon socket up"
fi

# ── 3. Ship the agent, policies, attacks, trust material ───────────────────
log "shipping agent binary + policies + attacks + trust material"
m 'mkdir -p /opt/ebpf-soc/bpf /etc/ebpf-soc /var/lib/ebpf-soc-agent/honey'
tar --exclude='._*' -cz -C "$REPO_ROOT" policies attacks \
  | m 'cat > /tmp/pa.tgz && tar -xzf /tmp/pa.tgz -C /opt/ebpf-soc && rm -f /tmp/pa.tgz'

# ship_intel — threat-intelligence feeds. Same path as every other host in the
# estate, and MERGED rather than replaced: allow.txt is the operator's veto list,
# and a deploy that overwrote it would silently reinstate every false positive
# they had already suppressed. Only files absent on the box are written.
#
# A FUNCTION rather than an inline block so it can be EXECUTED against stubbed
# m/push in a test: this script runs top-to-bottom and ssh's during its own
# preflight, so it cannot be sourced, and the closing line here has been wrong in
# exactly the way lib.sh's _ship_intel was.
ship_intel() {
  if [[ ! -d "$REPO_ROOT/deploy/intel" ]]; then
    warn "threat-intel: $REPO_ROOT/deploy/intel is not there — NO feeds were shipped; the agent keeps"
    warn "whatever indicators it already had."
    return 0
  fi
  m 'install -d -m 0755 /etc/ebpf-soc/intel'
  local f base shipped=0 kept=0
  # *.txt AND feeds.yaml — the refresh configuration lives beside the indicators
  # it produces, and a glob that missed it left every agent matching only the
  # static starter set while reporting itself configured.
  for f in "$REPO_ROOT"/deploy/intel/*.txt "$REPO_ROOT/deploy/intel/feeds.yaml"; do
    [[ -e "$f" ]] || continue
    base="$(basename "$f")"
    # Operator-owned once present: allow.txt suppresses false positives,
    # feeds.yaml sets the confidence that decides whether a match can contain.
    case "$base" in
      allow.txt|feeds.yaml)
        if m "[ -e /etc/ebpf-soc/intel/$base ] && echo yes" 2>/dev/null | grep -q yes; then
          log "keeping the existing /etc/ebpf-soc/intel/$base (operator-owned)"
          kept=$((kept+1))
          continue
        fi
        ;;
    esac
    cat "$f" | push "/etc/ebpf-soc/intel/$base"
    shipped=$((shipped+1))
  done
  m 'chmod 0644 /etc/ebpf-soc/intel/*.txt 2>/dev/null || true'
  # COUNT what actually moved. This line was `log "threat-intel feeds shipped to
  # /etc/ebpf-soc/intel"`, printed unconditionally once the loop reached its end,
  # so an empty deploy/intel/ — a bad checkout, a tarball that lost the
  # directory, a glob that matched nothing — reported feeds shipped after
  # shipping none, while the agent went on matching whatever indicators it
  # already had. lib.sh's _ship_intel was fixed for this; the copy here was not.
  # Keep the two in step.
  local keptnote=""
  # NOT ${kept:+…}: kept is "0", not empty, so that spelling would append
  # ", 0 operator-owned file(s) kept" to every first deploy.
  (( kept > 0 )) && keptnote=", $kept operator-owned file(s) left untouched"
  if (( shipped > 0 )); then
    ok "threat-intel: $shipped file(s) shipped to /etc/ebpf-soc/intel$keptnote"
  elif (( kept > 0 )); then
    ok "threat-intel: nothing to ship — all $kept file(s) on the target are operator-owned and were kept"
  else
    warn "threat-intel: NO feed files were shipped ($REPO_ROOT/deploy/intel is empty) — the agent keeps"
    warn "whatever indicators it already had, and this deploy did not update them."
  fi
}
ship_intel
# Write-then-rename: `cat >` truncates the running executable in place and
# fails with "Text file busy", so a redeploy would silently keep the OLD agent
# while reporting success. rename(2) swaps the directory entry instead; the
# running process keeps its inode until the service restarts below.
cat "$AGENT_BIN"  | m 'cat > /opt/ebpf-soc/agent.new && chmod 755 /opt/ebpf-soc/agent.new && mv -f /opt/ebpf-soc/agent.new /opt/ebpf-soc/agent'
cat "$CA_BUNDLE"  | push /etc/ebpf-soc/ca-bundle.pem
cat "$FLEET_PUB"  | push /etc/ebpf-soc/fleet.pub
ok "agent stack shipped"

log "applying TracingPolicies to Tetragon"
# Also drop each policy into Tetragon's --tracing-policy-dir
# (/etc/tetragon/tetragon.tp.d) so they auto-load on restart. A runtime
# `tetra tracingpolicy add` is in-memory only — if Tetragon restarts the
# policies vanish and detection silently drops to bare execve: events keep
# flowing but alerts stop firing.
n=$(m '
  n=0
  docker exec tetragon mkdir -p /etc/tetragon/tetragon.tp.d >/dev/null 2>&1 || true
  for p in /opt/ebpf-soc/policies/*.yaml; do
    [ -f "$p" ] || continue
    case "$p" in */._*) continue;; esac
    base=$(basename "$p")
    docker cp "$p" tetragon:/tmp/ >/dev/null 2>&1
    docker cp "$p" "tetragon:/etc/tetragon/tetragon.tp.d/$base" >/dev/null 2>&1 || true
    # add is CREATE-ONLY: an existing policy whose content changed would keep
    # running the old rules, so a Sigkill->detect switch or an allow-list fix
    # would deploy and do nothing. Delete first so the file on disk is what runs.
    # Keyed by metadata.name, NOT filename — network-watch.yaml declares
    # "outbound-connections" and sensitive-files.yaml declares
    # "sensitive-file-access", so deleting by filename silently no-ops and those
    # policies could never receive a content update. metadata.name is the first
    # "name:" in these files. No single quotes below: this whole block is passed
    # as a single-quoted argument, so one would terminate it.
    pol=$(sed -n "s/^[[:space:]]*name:[[:space:]]*\"\{0,1\}\([^\"]*\)\"\{0,1\}[[:space:]]*$/\1/p" "$p" | head -1)
    [ -n "$pol" ] || pol=${base%.yaml}
    docker exec tetragon tetra tracingpolicy delete "$pol" >/dev/null 2>&1
    docker exec tetragon tetra tracingpolicy add "/tmp/$base" >/dev/null 2>&1
    docker exec tetragon tetra tracingpolicy list 2>/dev/null | grep -q "$pol" && n=$((n+1))
  done
  echo $n')
ok "applied ${n:-0} TracingPolicies (durable via tp.d)"

# ── 4. Network choke data plane + the protect list ─────────────────────────
# The protect list is a SAFETY control, not a nicety: on a flat subnet the
# devices an agent can see include its own default gateway and the control
# plane. Severing either cuts the agent off from the fleet — so both are
# resolved here and refused by the agent for the rest of its life. The agent
# also auto-adds its own NIC. Without this, "sever the first device you see"
# is a self-inflicted outage.
IFACE="$(m "ip -o -4 route show default | awk '{print \$5}' | head -1" | tr -d '\r')"
[ -n "$IFACE" ] || die "could not determine the default interface on $HOST"

if [ -n "$DEVCHOKE_OBJ" ] && [ -f "$DEVCHOKE_OBJ" ]; then
  cat "$DEVCHOKE_OBJ" | m 'cat > /opt/ebpf-soc/bpf/devchoke.o'
  ok "devchoke.o shipped (tc data plane on $IFACE)"
  DEV_OBJ_LINE="devchoke_obj: /opt/ebpf-soc/bpf/devchoke.o"
  DEV_IF_LINE="devchoke_ifaces: $IFACE"
else
  warn "no devchoke.o supplied — device choke will run the noop backend (audit-only)"
  DEV_OBJ_LINE=""
  DEV_IF_LINE=""
fi

PROTECT="$(m "
  gw=\$(ip -o -4 route show default | awk '{print \$3}' | head -1)
  # Nudge ARP so the neighbour entries exist, then resolve the MACs we must
  # never choke: the default gateway and the control plane.
  for ip in \$gw $CP_IP; do ping -c1 -W1 \$ip >/dev/null 2>&1 || true; done
  ip -4 neigh show | awk -v gw=\"\$gw\" -v cp=\"$CP_IP\" '\$1==gw || \$1==cp {for(i=1;i<=NF;i++) if(\$i==\"lladdr\") print \$(i+1)}' | sort -u | paste -sd, -
" | tr -d '\r')"
[ -n "$PROTECT" ] && ok "protected MACs: $PROTECT (gateway + control plane)" \
                  || warn "could not resolve gateway/CP MACs — only the agent's own NIC is protected"

# ── 5. Agent config (secrets in a 0600 file, never on the cmdline) ─────────
SHORT="$(echo "$TENANT" | cut -d- -f1)"
# Generate once and PERSIST on the host, rather than deriving from the tenant
# name. A formula in a committed script means anyone with the repo can compute
# every agent's console password from its tenant id. The agent's API binds
# 127.0.0.1 so the blast radius is small, but a security product should not ship
# guessable credentials. Reused across redeploys so an operator's note stays
# valid; rotate by deleting the file.
CONSOLE_PASS="$(m 'f=/etc/ebpf-soc/agent-console.env
  if [ -s "$f" ]; then cut -d= -f2- "$f"; else
    umask 077; mkdir -p /etc/ebpf-soc
    # Policy-compliant: 14+ chars, upper, lower, >=3 digits, >=3 special.
    p="A$(head -c 9 /dev/urandom | base64 | tr -dc A-Za-z | head -c 9)$(head -c 4 /dev/urandom | od -An -tu1 | tr -d " \n" | head -c 3)#%!"
    printf "AGENT_CONSOLE_PASS=%s\n" "$p" > "$f"; printf "%s" "$p"
  fi' | tr -d '\r')"
[ -n "$CONSOLE_PASS" ] || die "could not establish the agent console password"
{
  cat <<EOF
tetragon: unix:///var/run/tetragon/tetragon.sock
db: /var/lib/ebpf-soc-agent/events.db
http: 127.0.0.1:8080
user: admin
pass: $CONSOLE_PASS
secret_path: /var/lib/ebpf-soc-agent/secret
policies: /opt/ebpf-soc/policies
attacks: /opt/ebpf-soc/attacks
choke_policies: /opt/ebpf-soc/policies/choke
honeypots: /var/lib/ebpf-soc-agent/honey
cgroup_root: /sys/fs/cgroup
enforce: false
throttle_at: 20
tarpit_at: 50
quarantine_at: 120
sever_at: 200
log_format: json
log_level: info
EOF
  [ -n "$DEV_OBJ_LINE" ] && printf '%s\n%s\n' "$DEV_OBJ_LINE" "$DEV_IF_LINE"
  [ -n "$PROTECT" ]      && printf 'devchoke_protect: %s\n' "$PROTECT"
} | push /etc/ebpf-soc/agent.yaml
m 'chmod 600 /etc/ebpf-soc/agent.yaml'
ok "agent.yaml written (0600)"

# ── 6. Enrollment (one-time token → persisted mTLS identity) ───────────────
if m 'test -f /var/lib/ebpf-soc-agent/agent-cert.pem'; then
  ok "already enrolled — reusing persisted identity"
else
  log "minting a fresh enrollment token for $TENANT"
  TOKEN="$(ssh -o BatchMode=yes "$CP_SSH" "sudo curl -s -X POST http://127.0.0.1:9090/api/admin/enroll-token \
      -H 'Authorization: Bearer $CP_ADMIN_TOKEN' -H 'content-type: application/json' \
      -d '{\"tenant\":\"$TENANT\"}'" | sed -n 's/.*"token":"\([a-f0-9]*\)".*/\1/p')"
  [ -n "$TOKEN" ] || die "could not mint an enrollment token (is the CP admin token correct?)"
  log "enrolling into $TENANT at $CP_IP:9443"
  # Foreground under a timeout: enrollment completes in ~1s and persists the
  # identity; backgrounding races the session teardown.
  m "pkill -f /opt/ebpf-soc/agent 2>/dev/null; sleep 1; true"
  m "timeout 25 /opt/ebpf-soc/agent -config /etc/ebpf-soc/agent.yaml \
       -controlplane $CP_IP:9443 -controlplane-servername localhost \
       -state-dir /var/lib/ebpf-soc-agent -fleet-pubkey /etc/ebpf-soc/fleet.pub \
       -bootstrap-token $TOKEN -ca-bundle /etc/ebpf-soc/ca-bundle.pem \
       > /var/log/ebpf-agent-enroll.log 2>&1; true"
  m 'test -f /var/lib/ebpf-soc-agent/agent-cert.pem' \
    || die "enrollment did not complete — check: ssh $HOST sudo tail /var/log/ebpf-agent-enroll.log"
  ok "enrolled — mTLS identity persisted"
fi

# ── 7. systemd services: the agent, and continuous real activity ───────────
log "installing systemd units (agent + activity)"
cat <<EOF | push /etc/systemd/system/ebpf-agent.service
[Unit]
Description=eBPF-SOC Choke Agent (real Tetragon telemetry -> control plane)
After=docker.service network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/ebpf-soc/agent -config /etc/ebpf-soc/agent.yaml \\
  -controlplane $CP_IP:9443 -controlplane-servername localhost \\
  -state-dir /var/lib/ebpf-soc-agent -fleet-pubkey /etc/ebpf-soc/fleet.pub
Restart=always
RestartSec=5
StandardOutput=append:/var/log/ebpf-agent.log
StandardError=append:/var/log/ebpf-agent.log

[Install]
WantedBy=multi-user.target
EOF

# ── Log rotation ───────────────────────────────────────────────────────────
# The unit appends to /var/log/ebpf-agent.log with nothing rotating it.
# Measured on an IDLE estate host: 142 MB in 24 days, alongside a 576 MB
# events.db. On a busy production host that is much faster, and filling /var on
# a customer's server is a far more memorable incident than anything this
# platform would have detected there.
log "installing logrotate for the agent"
m 'cat > /etc/logrotate.d/ebpf-agent <<"ROT"
/var/log/ebpf-agent.log {
  daily
  rotate 7
  maxsize 100M
  compress
  delaycompress
  missingok
  notifempty
  copytruncate
}
ROT
chmod 0644 /etc/logrotate.d/ebpf-agent'

# ── Synthetic activity generator (DATA_MODE) ───────────────────────────────
# Removal is ACTIVE, not merely "skip the install". A host provisioned before
# this gate existed already has the unit enabled, so a redeploy that only
# declined to install it would leave it running and the estate would stay
# exactly as noisy. Stop, disable, then delete — and delete the script too, so
# a stale unit file cannot resurrect it.
if [[ "$DATA_MODE" == none ]]; then
  m 'systemctl stop ebpf-activity >/dev/null 2>&1
     systemctl disable ebpf-activity >/dev/null 2>&1
     rm -f /etc/systemd/system/ebpf-activity.service /opt/ebpf-soc/activity.sh
     pkill -9 -f /opt/ebpf-soc/activity.sh >/dev/null 2>&1
     systemctl daemon-reload
     true'
  ok "DATA_MODE=none — synthetic activity generator stopped and removed"
else

# Tuned to look like a real SOC feed, not a stress test.
cat <<'EOF' | push /opt/ebpf-soc/activity.sh
#!/bin/bash
A=/opt/ebpf-soc/attacks
PEERS="185.220.101.1 45.155.205.233 193.169.255.10 91.219.236.10 5.188.206.18"
while true; do
  set -- "$A"/0*.sh
  [ $# -gt 0 ] && { i=$((RANDOM % $# + 1)); eval "s=\${$i}"; [ -f "$s" ] && bash "$s" >/dev/null 2>&1; }
  # a real suspicious chain
  bash -c 'cat /etc/shadow; id' >/dev/null 2>&1
  # external peers (public IPs -> peer nodes in the correlation graph)
  for _ in 1 2; do
    n=$((RANDOM % 5 + 1)); ip=$(echo $PEERS | cut -d' ' -f$n)
    (echo x | nc -w1 "$ip" 4444 >/dev/null 2>&1) &
  done
  # LAN neighbours this host actually sees -> device nodes in the graph, and the
  # process->device edges the correlation view is built on.
  for d in $(ip -4 neigh show 2>/dev/null | awk '$1 ~ /^(10\.|192\.168\.|172\.)/ {print $1}' | head -3); do
    (echo x | nc -w1 "$d" 22 >/dev/null 2>&1) &
  done
  sleep $((20 + RANDOM % 25))
done
EOF
m 'chmod +x /opt/ebpf-soc/activity.sh'
cat <<'EOF' | push /etc/systemd/system/ebpf-activity.service
[Unit]
Description=continuous real activity for the agent to observe
After=network-online.target

[Service]
ExecStart=/opt/ebpf-soc/activity.sh
Restart=always
RestartSec=5
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
EOF

  warn "DATA_MODE=$DATA_MODE — installing the synthetic activity generator."
  warn "  It fabricates ~2,000 alerts/hour and will pin the console's posture dial."
  warn "  Use DATA_MODE=none for an estate whose numbers are meant to be real."
fi

m 'systemctl daemon-reload
   systemctl enable ebpf-agent >/dev/null 2>&1
   systemctl restart ebpf-agent'
if [[ "$DATA_MODE" != none ]]; then
  m 'systemctl enable ebpf-activity >/dev/null 2>&1; systemctl restart ebpf-activity'
fi
sleep 4
m 'systemctl is-active --quiet ebpf-agent' \
  || die "agent service did not start — check: ssh $HOST sudo tail /var/log/ebpf-agent.log"
if [[ "$DATA_MODE" == none ]]; then
  ok "agent running (no synthetic activity — this estate reports real numbers)"
else
  ok "agent + synthetic activity services running"
fi

printf '\n  \033[1m%s\033[0m → tenant \033[1m%s\033[0m  (iface %s)\n' "$HOST" "$TENANT" "$IFACE"
# The agent's console binds 127.0.0.1 (see agent.yaml above) and is deliberately
# not published — this is a sensor on a customer host, not a second console. The
# tunnel is the supported way in, so print that rather than a host:port an
# operator would try and find refused.
printf '  console: http://127.0.0.1:8080/  after  ssh -L 8080:127.0.0.1:8080 %s\n' "$HOST"
printf '           login admin / %s\n' "$CONSOLE_PASS"
printf '  logs:  ssh %s sudo tail -f /var/log/ebpf-agent.log\n\n' "$HOST"
