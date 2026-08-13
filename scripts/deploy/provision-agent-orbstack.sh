#!/usr/bin/env bash
#
# provision-agent-orbstack.sh — stand up a REAL per-tenant Choke Agent on its own
# OrbStack VM and enroll it into the multi-tenant control plane.
#
# This is the "real data, not demo data" path. Where the sim-agent fabricates
# telemetry and streams it over the uplink, a real agent runs the actual eBPF
# pipeline: Tetragon observes real kernel events on a real host, the engine
# scores them, and the resulting REAL alerts/events/decisions are uplinked,
# tenant-stamped, to the control plane. A small activity generator gives the
# agent real things to observe (real suspicious chains + real outbound
# connections) so an otherwise-idle VM produces a live, believable feed.
#
# One VM per tenant is deliberate: each tenant's telemetry must come from its
# OWN host, which is what makes the multi-tenant separation real rather than
# cosmetic (a single shared Tetragon would report identical events to everyone).
#
# Usage:
#   ./provision-agent-orbstack.sh <tenant-id> <cp-ip> <cp-admin-token> \
#       <ca-bundle-file> <fleet-pub-file> <agent-binary>
#
# Idempotent: re-running reuses the VM and the persisted mTLS identity (no new
# enrollment token is spent).

set -uo pipefail

TENANT="${1:?tenant-id required}"
CP_IP="${2:?control-plane IP required}"
CP_ADMIN_TOKEN="${3:?cp admin token required}"
CA_BUNDLE="${4:?ca-bundle file required}"
FLEET_PUB="${5:?fleet.pub file required}"
AGENT_BIN="${6:?agent binary required}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SHORT="$(echo "$TENANT" | cut -d- -f1)"
VM="ebpf-agent-$SHORT"
TETRAGON_IMAGE="${TETRAGON_IMAGE:-quay.io/cilium/tetragon:v1.6.1}"

log()  { printf '  \033[36m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

m() { orb -m "$VM" sudo sh -c "$1"; }               # run as root on the agent VM
push() { orb -m "$VM" sudo tee "$2" >/dev/null; }   # stdin → file on the agent VM

printf '\n\033[1m══ real agent for %s on %s ══\033[0m\n' "$TENANT" "$VM"

# ── 1. VM ──────────────────────────────────────────────────────────────────
# Alpine, not Ubuntu: OrbStack's Ubuntu image fails its `userdel ubuntu` setup
# step on this host, and Alpine is a fine host for a static (CGO_ENABLED=0)
# agent + a Docker-run Tetragon that shares the (BTF-enabled) OrbStack kernel.
if orb info "$VM" >/dev/null 2>&1; then
  ok "VM $VM already exists"
else
  log "creating Alpine VM $VM"
  orb create alpine "$VM" >/dev/null 2>&1 || die "could not create $VM"
  ok "VM $VM created"
fi
m 'grep -q cgroup2 /proc/filesystems' || die "$VM has no cgroup2"
m 'test -f /sys/kernel/btf/vmlinux'   || die "$VM kernel has no BTF — Tetragon cannot attach"

# ── 2. Docker + Tetragon (the real event source) ───────────────────────────
log "installing Docker"
m 'command -v docker >/dev/null || apk add --no-cache docker docker-cli iproute2 curl netcat-openbsd >/dev/null 2>&1
   rc-update add docker default >/dev/null 2>&1
   rc-service docker status >/dev/null 2>&1 || rc-service docker start >/dev/null 2>&1
   sleep 4' || die "docker install failed"
m 'docker version --format "{{.Server.Version}}" >/dev/null 2>&1' || { sleep 4; m 'rc-service docker start >/dev/null 2>&1; sleep 4'; }
ok "Docker running"

if m 'docker ps --format "{{.Names}}" | grep -qx tetragon'; then
  ok "Tetragon already running"
else
  log "starting Tetragon ($TETRAGON_IMAGE) — image pull may take ~1-2m"
  # --server-address is REQUIRED: without it Tetragon opens a TCP listener on
  # localhost:54321 and never creates the unix socket the agent dials.
  m "docker rm -f tetragon >/dev/null 2>&1
     docker run -d --name tetragon --privileged --pid=host --network=host \
       -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf:ro \
       -v /var/run/tetragon:/var/run/tetragon \
       -v /sys/fs/bpf:/sys/fs/bpf \
       --restart=unless-stopped $TETRAGON_IMAGE \
       --server-address unix:///var/run/tetragon/tetragon.sock --btf /var/lib/tetragon/btf >/dev/null 2>&1"
  ok_socket=0
  for _ in $(seq 1 60); do m 'test -S /var/run/tetragon/tetragon.sock' && { ok_socket=1; break; }; sleep 2; done
  [ "$ok_socket" = 1 ] || die "Tetragon socket never appeared — check: docker logs tetragon"
  ok "Tetragon socket up"
fi

# ── 3. Ship the agent, policies, attacks, trust material ───────────────────
log "shipping agent binary + policies + attacks + trust material"
m 'mkdir -p /opt/ebpf-soc /etc/ebpf-soc /var/lib/ebpf-soc-agent/honey'
# `--no-xattrs`/exclude AppleDouble so macOS ._* files don't reach the VM as
# unparseable YAML.
tar --exclude='._*' -cz -C "$REPO_ROOT" policies attacks | m 'cat > /tmp/pa.tgz && tar -xzf /tmp/pa.tgz -C /opt/ebpf-soc && rm -f /tmp/pa.tgz'
# Write-then-rename: `cat >` truncates the RUNNING executable in place and fails
# with "Text file busy", so a redeploy silently keeps the old agent while
# reporting success. rename(2) swaps the directory entry instead.
cat "$AGENT_BIN" | m 'cat > /opt/ebpf-soc/agent.new && chmod 755 /opt/ebpf-soc/agent.new && mv -f /opt/ebpf-soc/agent.new /opt/ebpf-soc/agent'
cat "$CA_BUNDLE" | push - /etc/ebpf-soc/ca-bundle.pem
cat "$FLEET_PUB" | push - /etc/ebpf-soc/fleet.pub
ok "agent stack shipped"

log "applying TracingPolicies to Tetragon"
# Also drop each policy into Tetragon's default --tracing-policy-dir
# (/etc/tetragon/tetragon.tp.d) so they auto-load on every restart. A runtime
# `tetra tracingpolicy add` is in-memory only — if Tetragon restarts (VM reboot,
# Docker/OrbStack relaunch) the policies vanish and detection silently drops to
# bare execve: events keep flowing but alerts stop firing. The tp.d copy is the
# durable source of truth; the runtime add just makes them live immediately.
n=$(m '
  n=0
  docker exec tetragon mkdir -p /etc/tetragon/tetragon.tp.d >/dev/null 2>&1 || true
  for p in /opt/ebpf-soc/policies/*.yaml; do
    [ -f "$p" ] || continue
    case "$p" in */._*) continue;; esac
    base=$(basename "$p")
    docker cp "$p" tetragon:/tmp/ >/dev/null 2>&1
    docker cp "$p" "tetragon:/etc/tetragon/tetragon.tp.d/$base" >/dev/null 2>&1 || true
    # add is CREATE-ONLY — see provision-agent-ssh.sh. Delete first so a changed
    # policy actually replaces the one already loaded.
    # Keyed by metadata.name, NOT filename — network-watch.yaml declares
    # "outbound-connections" and sensitive-files.yaml declares
    # "sensitive-file-access", so deleting by filename silently no-ops and those
    # policies could never receive a content update.
    # No single quotes: this block is passed as a single-quoted argument, so one
    # would terminate it. metadata.name is the first "name:" in these files.
    pol=$(sed -n "s/^[[:space:]]*name:[[:space:]]*\"\{0,1\}\([^\"]*\)\"\{0,1\}[[:space:]]*$/\1/p" "$p" | head -1)
    [ -n "$pol" ] || pol=${base%.yaml}
    docker exec tetragon tetra tracingpolicy delete "$pol" >/dev/null 2>&1
    docker exec tetragon tetra tracingpolicy add "/tmp/$base" >/dev/null 2>&1
    docker exec tetragon tetra tracingpolicy list 2>/dev/null | grep -q "$pol" && n=$((n+1))
  done
  echo $n')
ok "applied $n TracingPolicies (durable via tp.d)"

# ── 4. Agent config (secrets in a 0600 file, never on the cmdline) ─────────
# Generate once and PERSIST on the VM, rather than deriving from the tenant name.
# This used to be `Agent7${SHORT}93kx!@#Z` — a formula in a committed script, so
# anyone with the repo could compute every agent's console password from its
# tenant id. The agent's API binds 127.0.0.1 so the blast radius is small, but a
# security product should not ship guessable credentials. Matches
# provision-agent-ssh.sh: reused across redeploys so an operator's note stays
# valid; rotate by deleting the file.
CONSOLE_PASS="$(m 'f=/etc/ebpf-soc/agent-console.env
  if [ -s "$f" ]; then cut -d= -f2- "$f"; else
    umask 077; mkdir -p /etc/ebpf-soc
    # Policy-compliant: 14+ chars, upper, lower, >=3 digits, >=3 special.
    p="A$(head -c 9 /dev/urandom | base64 | tr -dc A-Za-z | head -c 9)$(head -c 4 /dev/urandom | od -An -tu1 | tr -d " \n" | head -c 3)#%!"
    printf "AGENT_CONSOLE_PASS=%s\n" "$p" > "$f"; printf "%s" "$p"
  fi' | tr -d '\r')"
[ -n "$CONSOLE_PASS" ] || die "could not establish the agent console password"
cat <<EOF | push - /etc/ebpf-soc/agent.yaml
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
m 'chmod 600 /etc/ebpf-soc/agent.yaml'
ok "agent.yaml written (0600)"

# ── 5. Enrollment (one-time token → persisted mTLS identity) ───────────────
if m 'test -f /var/lib/ebpf-soc-agent/agent-cert.pem'; then
  ok "already enrolled — reusing persisted identity"
else
  log "minting a fresh enrollment token for $TENANT"
  TOKEN="$(orb -m ebpf-soc sudo sh -c "curl -s -X POST http://127.0.0.1:9090/api/admin/enroll-token -H 'Authorization: Bearer $CP_ADMIN_TOKEN' -H 'content-type: application/json' -d '{\"tenant\":\"$TENANT\"}'" \
            | sed -n 's/.*\"token\":\"\([a-f0-9]*\)\".*/\1/p')"
  [ -n "$TOKEN" ] || die "could not mint an enrollment token (is the CP admin token correct?)"
  log "enrolling into $TENANT at $CP_IP:9443"
  # Run enrollment in the FOREGROUND under a timeout — no backgrounding.
  # Enrollment completes in ~1s and persists the mTLS identity to the state-dir;
  # `timeout` then stops the short-lived process. Backgrounding inside the orb
  # exec session is unreliable (the child is reaped when the session returns
  # before the cert is written), which is why this stays in the foreground.
  m "pkill -f /opt/ebpf-soc/agent 2>/dev/null; sleep 1; true"
  m "timeout 20 /opt/ebpf-soc/agent -config /etc/ebpf-soc/agent.yaml \
       -controlplane $CP_IP:9443 -controlplane-servername localhost \
       -state-dir /var/lib/ebpf-soc-agent -fleet-pubkey /etc/ebpf-soc/fleet.pub \
       -bootstrap-token $TOKEN -ca-bundle /etc/ebpf-soc/ca-bundle.pem \
       > /var/log/ebpf-agent-enroll.log 2>&1; true"
  m 'test -f /var/lib/ebpf-soc-agent/agent-cert.pem' \
    || die "enrollment did not complete — check: orb -m $VM sudo tail /var/log/ebpf-agent-enroll.log"
  ok "enrolled — mTLS identity persisted"
fi

# ── 6. OpenRC services: the agent, and continuous real activity ────────────
log "installing OpenRC services (agent + activity)"
cat <<EOF | push - /etc/init.d/ebpf-agent
#!/sbin/openrc-run
name="ebpf-agent"
description="eBPF-SOC Choke Agent (real Tetragon telemetry -> control plane)"
command="/opt/ebpf-soc/agent"
command_args="-config /etc/ebpf-soc/agent.yaml -controlplane $CP_IP:9443 -controlplane-servername localhost -state-dir /var/lib/ebpf-soc-agent -fleet-pubkey /etc/ebpf-soc/fleet.pub"
# supervise-daemon (not command_background): the agent runs in the foreground
# under a supervisor that RESPAWNS it — OpenRC's equivalent of systemd
# Restart=always. command_background gives no supervision, so a single exit
# (e.g. the stream dropping when the control plane restarts on redeploy) leaves
# the service dead. That is exactly what happened.
supervisor="supervise-daemon"
respawn_delay=5
respawn_max=0
output_log="/var/log/ebpf-agent.log"
error_log="/var/log/ebpf-agent.log"
depend() { need docker; after docker; }
EOF

# Tuned to look like a real SOC feed, not a stress test: 1-2 random attack
# scripts per cycle + one shell chain + a couple of outbound connects, every
# 20-45s. Everything here is REAL — the agent observes actual kernel events.
cat <<'EOF' | push - /opt/ebpf-soc/activity.sh
#!/bin/sh
A=/opt/ebpf-soc/attacks
PEERS="185.220.101.1 45.155.205.233 193.169.255.10 91.219.236.10 5.188.206.18"
rnd() { od -An -N1 -tu1 /dev/urandom 2>/dev/null | tr -d ' '; }
while true; do
  # one or two real attack scripts
  set -- "$A"/0*.sh
  i=$(( $(rnd) % $# + 1 )); eval "s=\${$i}"; [ -f "$s" ] && sh "$s" >/dev/null 2>&1
  [ $(( $(rnd) % 2 )) -eq 0 ] && { j=$(( $(rnd) % $# + 1 )); eval "s2=\${$j}"; [ -f "$s2" ] && sh "$s2" >/dev/null 2>&1; }
  # a real suspicious chain
  sh -c 'cat /etc/shadow; id' >/dev/null 2>&1
  # external peers (public IPs → peer nodes in the correlation graph)
  for _ in 1 2; do
    n=$(( $(rnd) % 5 + 1 )); ip=$(echo $PEERS | cut -d' ' -f$n)
    (echo x | nc -w1 "$ip" 4444 >/dev/null 2>&1) &
  done
  # LAN devices this host actually sees (the same neighbours the Devices page
  # inventories → device nodes in the graph). Connecting to a real device's IP is
  # what links a process to a device.
  for d in $(ip -4 neigh show 2>/dev/null | awk '$1 ~ /^(10\.|192\.168\.|172\.)/ {print $1}' | head -2); do
    (echo x | nc -w1 "$d" 22 >/dev/null 2>&1) &
  done
  sleep $(( 20 + ($(rnd) % 25) ))
done
EOF
m 'chmod +x /opt/ebpf-soc/activity.sh'
cat <<'EOF' | push - /etc/init.d/ebpf-activity
#!/sbin/openrc-run
name="ebpf-activity"
description="continuous real activity for the agent to observe"
command="/opt/ebpf-soc/activity.sh"
supervisor="supervise-daemon"
respawn_delay=5
respawn_max=0
output_log="/dev/null"
error_log="/dev/null"
EOF

m 'chmod +x /etc/init.d/ebpf-agent /etc/init.d/ebpf-activity
   rc-update add ebpf-agent default >/dev/null 2>&1
   rc-update add ebpf-activity default >/dev/null 2>&1'

# Clean slate, then start — each step in its own exec session so a fresh
# supervise-daemon is never a child of a session that is about to end. A
# previous command_background service leaves a supervisor a plain restart cannot
# reconcile, and the enroll agent can linger; stop + SIGKILL + zap clears all of
# that so the start is against a truly stopped unit.
m 'rc-service ebpf-agent stop >/dev/null 2>&1; rc-service ebpf-activity stop >/dev/null 2>&1
   pkill -9 -f "supervise-daemon ebpf-agent" 2>/dev/null
   pkill -9 -f /opt/ebpf-soc/agent 2>/dev/null
   pkill -9 -f /opt/ebpf-soc/activity.sh 2>/dev/null
   rc-service ebpf-agent zap >/dev/null 2>&1; rc-service ebpf-activity zap >/dev/null 2>&1
   true'
sleep 2
m 'rc-service ebpf-agent start >/dev/null 2>&1'
m 'rc-service ebpf-activity start >/dev/null 2>&1'

# supervise-daemon settles a moment after "started"; retry the status check.
started=0
for _ in 1 2 3 4 5 6; do sleep 2; m 'rc-service ebpf-agent status 2>/dev/null | grep -q started' && { started=1; break; }; done
[ "$started" = 1 ] || die "agent service did not start — check: orb -m $VM sudo tail /var/log/ebpf-agent.log"
ok "agent + activity services running"

AGENT_IP="$(orb list 2>/dev/null | awk -v v="$VM" '$1==v {print $NF}')"
printf '\n  \033[1m%s\033[0m → tenant \033[1m%s\033[0m  (agent VM %s)\n' "$VM" "$TENANT" "${AGENT_IP:-?}"
printf '  logs:  orb -m %s sudo tail -f /var/log/ebpf-agent.log\n\n' "$VM"
