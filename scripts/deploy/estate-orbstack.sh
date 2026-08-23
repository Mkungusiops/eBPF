#!/usr/bin/env bash
#
# scripts/deploy/estate-orbstack.sh — the whole platform, locally, on OrbStack.
#
#   ./scripts/deploy/estate-orbstack.sh                  # console + agents + engine
#   ./scripts/deploy/estate-orbstack.sh --only engine    # cp | agents | engine | verify
#   ./scripts/deploy/estate-orbstack.sh --data-mode sim  # fabricated telemetry, no agent VMs
#   ./scripts/deploy/estate-orbstack.sh --destroy        # delete every machine
#   ASSUME_YES=1 ./scripts/deploy/estate-orbstack.sh     # unattended
#
# The local counterpart of estate.sh, and it exists for the same reason: bringing
# the platform up is several commands in a specific order, each carrying
# environment whose omission fails quietly, and the ordering is not guessable.
# Agents enrol INTO the control plane, so running single-tenant-orbstack.sh first
# and multi-tenant-orbstack.sh second yields an engine and a console that have
# never heard of each other, both reporting success.
#
# It is a separate script from estate.sh rather than a flag on it. estate.sh
# reaches six SSH hosts, insists on TLS and real DNS names, and refuses to leave
# a sim-agent running beside a real one because that combination fakes
# containment in production. Here every machine is local, plaintext HTTP on the
# OrbStack bridge is the correct answer, and --data-mode sim is a legitimate
# choice. Teaching estate.sh a "local mode" would put those production rails
# behind an if-statement.
#
# Real eBPF is the default. An OrbStack machine is a full Linux VM with its own
# BTF-enabled kernel, so Tetragon attaches for real — on the engine and on every
# agent VM. macOS having no eBPF says nothing about the Linux VMs running on it.
#
# The device (per-MAC) choke stays audit-only: it enforces on a two-NIC inline
# bridge, which a single-interface OrbStack machine is not.

# shellcheck disable=SC2034  # consumed by log()/ok()/die() in lib/common.sh
LOG_TAG="estate-local"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

# ── Estate definition ──────────────────────────────────────────────────────
# One machine per role, mirroring the production split. Separate VMs rather than
# one box on two ports: the single-tenant engine and the multi-tenant control
# plane are separate products with separate trust models, and colocating them
# hides every assumption that only holds while they are apart.
CP_MACHINE="${CP_MACHINE:-ebpf-soc}"
ENGINE_MACHINE="${ENGINE_MACHINE:-ebpf-engine}"
TENANTS="${TENANTS:-adanian-internal acme-corp}"
ENGINE_PORT="${ENGINE_PORT:-8090}"
DATA_MODE="${DATA_MODE:-real}"
ENGINE_MODE="${ENGINE_MODE:-tetragon}"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/.deploy-build}"
export CP_MACHINE TENANTS BUILD_DIR

# Agent VM names are not free-form — provision-agent-orbstack.sh derives them
# from the tenant id, and this script has to predict them to verify and destroy.
agent_vm() { printf 'ebpf-agent-%s' "${1%%-*}"; }

ONLY=""; DESTROY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --only)        ONLY="${2:?--only needs cp|agents|engine|verify}"; shift 2 ;;
    --data-mode)   DATA_MODE="${2:?--data-mode needs real|sim|none}"; shift 2 ;;
    --engine-mode) ENGINE_MODE="${2:?--engine-mode needs tetragon|fake}"; shift 2 ;;
    --tenants)     TENANTS="${2:?--tenants needs a space-separated list}"; shift 2 ;;
    --destroy)     DESTROY=1; shift ;;
    -h|--help)     sed -n '3,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done

case "$ONLY"        in ""|cp|agents|engine|verify) ;; *) die "--only takes cp, agents, engine or verify" ;; esac
case "$DATA_MODE"   in real|sim|none) ;;             *) die "--data-mode takes real, sim or none" ;; esac
case "$ENGINE_MODE" in tetragon|fake) ;;             *) die "--engine-mode takes tetragon or fake" ;; esac
[[ -n "${TENANTS// /}" ]] || die "TENANTS is empty — the control plane needs at least one"

doing() { [[ -z "$ONLY" || "$ONLY" == "$1" ]]; }

cd "$REPO_ROOT" || die "cannot cd to $REPO_ROOT"

# ── Transport ──────────────────────────────────────────────────────────────
# Ubuntu machines (console, engine) run systemd and have bash. Agent VMs are
# Alpine — busybox sh, OpenRC, no bash — so they get their own runner, rather
# than a bash invocation whose failure would read like the agent being down.
cprun()  { orb -m "$CP_MACHINE"     sudo bash -c "$1"; }
engrun() { orb -m "$ENGINE_MACHINE" sudo bash -c "$1"; }
agrun()  { orb -m "$1"              sudo sh   -c "$2"; }

have_machine() { orb info "$1" >/dev/null 2>&1; }

# Every orb call below ends in `|| true`. Under `set -o pipefail` an assignment
# from a failing pipeline is itself a failed command, so `set -e` would abort the
# whole script — and because the failure is an assignment, with no message at
# all. Absence and unreachability are normal here (a machine that was never
# created, busybox lacking a flag), so they must read as an empty string.
machine_ip() {
  local m="$1" ip=""
  ip="$(orb -m "$m" hostname -I 2>/dev/null | awk '{print $1}' || true)"
  # busybox `hostname` has no -I, so Alpine agents need the fallback: `orb list`
  # prints the address in its last column for every distro.
  [[ -n "$ip" ]] || ip="$(orb list 2>/dev/null | awk -v v="$m" '$1 == v {print $NF}' || true)"
  printf '%s' "$ip"
}

# `orb list` and `orb info` block indefinitely while the OrbStack service is
# stopped, so the state must be settled before any other orb call — otherwise
# the first symptom is this script hanging with no output.
orb_state() { orb status 2>/dev/null | tr -d '[:space:]' || true; }

require_orbstack() {
  need_cmd orb "install OrbStack from https://orbstack.dev"
  local state; state="$(orb_state)"
  if [[ "$state" != "Running" ]]; then
    log "OrbStack is ${state:-not responding} — starting it"
    # `orb start` waits for the service and never returns if it cannot come up
    # (no desktop session, the app removed, virtualisation unavailable), so it
    # runs in the background against a deadline. Foregrounding it turns those
    # into this script hanging with no output, which is the least debuggable
    # failure available. `orb status` itself answers immediately in every state,
    # so polling it is safe where `orb list`/`orb info` would block too.
    orb start >/dev/null 2>&1 &
    local starter=$!
    for _ in $(seq 1 45); do
      state="$(orb_state)"
      [[ "$state" == "Running" ]] && break
      sleep 2
    done
    kill "$starter" 2>/dev/null || true
    wait "$starter" 2>/dev/null || true
  fi
  [[ "$state" == "Running" ]] \
    || die "OrbStack is ${state:-not responding} and did not start within 90s — open the app, then re-run"
  ok "OrbStack running ($(orb version 2>/dev/null | awk '/^Version:/ {print $2}' || true))"
}

# ── Destroy ────────────────────────────────────────────────────────────────
if (( DESTROY )); then
  step_header "Destroy — every local machine and its data"
  require_orbstack
  victims=("$CP_MACHINE" "$ENGINE_MACHINE")
  for t in $TENANTS; do victims+=("$(agent_vm "$t")"); done
  for m in "${victims[@]}"; do
    if have_machine "$m"; then dim "$m"; else dim "$m (absent)"; fi
  done
  printf '\n'
  confirm "delete these machines? every database, cert and enrolled identity goes with them" n \
    || die "stopped"
  for m in "${victims[@]}"; do
    have_machine "$m" || continue
    if run orb delete -f "$m" >/dev/null 2>&1; then ok "deleted $m"; else warn "could not delete $m"; fi
  done
  ok "local estate removed"
  exit 0
fi

# ── Preflight ──────────────────────────────────────────────────────────────
# All of it before anything is touched. A half-built local estate is not
# dangerous the way a half-deployed production one is, but it does waste the ten
# minutes the agent VMs spend pulling Tetragon.
step_header "Preflight"

require_orbstack
need_cmd go  "the binaries are cross-compiled locally"
need_cmd npm "the console is built locally and embedded via go:embed"

VERSION="$(git describe --tags --dirty --always 2>/dev/null || echo unknown)"
log "deploying: $VERSION ($(git rev-parse --short HEAD 2>/dev/null || echo '?'))"

printf '\n'
if [[ "$ONLY" == verify ]]; then
  log "verifying only — nothing will be built or deployed"
else
  log "plan:"
  if doing cp; then
    dim "control plane   $CP_MACHINE      Postgres + Keycloak + nginx    tenants: $TENANTS"
  fi
  if [[ "$DATA_MODE" == real ]] && { doing cp || doing agents; }; then
    for t in $TENANTS; do
      dim "agent           $(agent_vm "$t")   tenant=$t    real Tetragon"
    done
  elif doing cp; then
    dim "telemetry       DATA_MODE=$DATA_MODE — no agent VMs"
  fi
  if doing engine; then
    dim "engine          $ENGINE_MACHINE   ENGINE_MODE=$ENGINE_MODE    :$ENGINE_PORT"
  fi
  dim "device choke    audit-only — enforcement needs a two-NIC inline bridge"
  printf '\n'
  confirm "build $VERSION and deploy it to OrbStack?" y || die "stopped"
fi

WEB_BUILT=0

# ── Control plane ──────────────────────────────────────────────────────────
# First, and not merely for tidiness: with DATA_MODE=real this step also creates
# and enrols the per-tenant agent VMs, which need a control plane to enrol into.
if doing cp; then
  step_header "Control plane — $CP_MACHINE"
  run env MACHINE="$CP_MACHINE" CP_MACHINE="$CP_MACHINE" \
    DATA_MODE="$DATA_MODE" TENANTS="$TENANTS" \
    ./scripts/deploy/multi-tenant-orbstack.sh
  WEB_BUILT=1
fi

# ── Agents on their own ────────────────────────────────────────────────────
# Only for --only agents; a full run provisions them inside the control-plane
# step. The inputs are read off the running control plane rather than from
# anything this script caches, so the CA and the admin token have one source of
# truth even after a redeploy has rotated them.
if [[ "$ONLY" == agents ]]; then
  step_header "Agents — from the running control plane"
  [[ "$DATA_MODE" == real ]] || die "--only agents needs --data-mode real"
  have_machine "$CP_MACHINE" || die "$CP_MACHINE does not exist — run without --only first"

  mkdir -p "$BUILD_DIR"
  cprun "cat /var/lib/ebpf-soc/ca.pem"    > "$BUILD_DIR/ca-bundle.pem" 2>/dev/null || true
  cprun "cat /var/lib/ebpf-soc/fleet.pub" > "$BUILD_DIR/fleet.pub"     2>/dev/null || true
  TOKEN="$(cprun "grep -h '^CP_ADMIN_TOKEN=' /etc/ebpf-soc/controlplane.env 2>/dev/null | tail -1 | cut -d= -f2-" 2>/dev/null | tr -d '[:space:]' || true)"
  [[ -s "$BUILD_DIR/ca-bundle.pem" ]] || die "no CA on $CP_MACHINE — is the control plane deployed?"
  [[ -n "$TOKEN" ]]                   || die "could not read CP_ADMIN_TOKEN from $CP_MACHINE"

  if [[ ! -x "$BUILD_DIR/agent" ]]; then
    log "building the agent binary (linux/amd64, static)"
    ( cd engine && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$BUILD_DIR/agent" ./cmd/agent ) \
      || die "agent build failed"
  fi

  CP_IP="$(machine_ip "$CP_MACHINE")"
  [[ -n "$CP_IP" ]] || die "could not determine the IP of $CP_MACHINE"
  for t in $TENANTS; do
    run ./scripts/deploy/provision-agent-orbstack.sh "$t" "$CP_IP" "$TOKEN" \
      "$BUILD_DIR/ca-bundle.pem" "$BUILD_DIR/fleet.pub" "$BUILD_DIR/agent" \
      || warn "agent provisioning for $t reported an error — see above"
  done
fi

# ── Single-tenant engine ───────────────────────────────────────────────────
if doing engine; then
  step_header "Engine — $ENGINE_MACHINE"
  # The console was already built and staged for go:embed by the control-plane
  # step; rebuilding it produces identical bytes and costs another npm run.
  run env MACHINE="$ENGINE_MACHINE" ENGINE_MODE="$ENGINE_MODE" ENGINE_PORT="$ENGINE_PORT" \
    SKIP_WEB_BUILD="$WEB_BUILT" \
    ./scripts/deploy/single-tenant-orbstack.sh
fi

# ── Verify ─────────────────────────────────────────────────────────────────
# Always runs, --only or not. The question is never "did the scripts exit 0" but
# "is it serving" — and locally there is one failure the deploy cannot report on
# itself: the engine falling back to -fake because the kernel probe failed. It
# exits 0, serves a complete console, and observes nothing.
if [[ "${DRY_RUN:-0}" == "1" ]]; then
  printf '\n'
  ok "dry run — nothing was built, deployed or verified"
  exit 0
fi

step_header "Verify"
FAIL=0
CHECKS=0
fail()  { CHECKS=$((CHECKS + 1)); FAIL=$((FAIL + 1)); err "$1"; }
pass()  { CHECKS=$((CHECKS + 1)); ok "$1"; }
check() { # check <label> <got> <want>
  if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 — got '${2:-nothing}', want '$3'"; fi
}
yesno() { [[ "${1:-0}" -gt 0 ]] && printf 'yes' || printf 'no'; }

if have_machine "$CP_MACHINE"; then
  log "control plane ($CP_MACHINE)"
  for svc in postgresql ebpf-keycloak ebpf-soc-controlplane nginx; do
    check "  $svc active" "$(cprun "systemctl is-active $svc" 2>/dev/null || true)" "active"
  done
  code="$(cprun "curl -s -o /dev/null -w '%{http_code}' --max-time 15 http://127.0.0.1/" 2>/dev/null || true)"
  case "$code" in
    200|301|302) pass "  console serving ($code)" ;;
    *) fail "  console — got '${code:-nothing}'" ;;
  esac
  # A sim beside a real agent acks containment it never applied, so the two data
  # sources must not overlap. Only meaningful when real agents should exist.
  if [[ "$DATA_MODE" == real ]]; then
    sims="$(cprun "systemctl list-units --type=service --state=running 2>/dev/null | grep -ci ebpf-sim || true" 2>/dev/null | tr -d '[:space:]' || true)"
    check "  no sim-agents alongside the real ones" "${sims:-0}" "0"
  fi
elif doing cp; then
  fail "$CP_MACHINE does not exist"
fi

if [[ "$DATA_MODE" == real ]]; then
  log "agents"
  SUMS=()
  for t in $TENANTS; do
    vm="$(agent_vm "$t")"
    # An absent agent VM is only a failure if this run was supposed to create
    # one. Under --only engine it means "not deployed yet", which is not news.
    if ! have_machine "$vm"; then
      if doing cp || doing agents; then
        fail "  $vm ($t) does not exist"
      else
        dim "  $vm ($t) not deployed — out of scope for --only $ONLY"
      fi
      continue
    fi
    started="$(agrun "$vm" 'rc-service ebpf-agent status 2>/dev/null | grep -c started || true' 2>/dev/null | tr -d '[:space:]' || true)"
    check "  $vm agent running"      "$(yesno "$started")" "yes"
    tet="$(agrun "$vm" 'docker ps --format "{{.Names}}" 2>/dev/null | grep -c "^tetragon$" || true' 2>/dev/null | tr -d '[:space:]' || true)"
    check "  $vm tetragon observing" "$(yesno "$tet")" "yes"
    SUMS+=("$(agrun "$vm" 'sha256sum /opt/ebpf-soc/agent 2>/dev/null | cut -d" " -f1' 2>/dev/null | tr -d '[:space:]' || true)")
  done
  # Mixed builds within a tenant is the configuration where containment-routing
  # bugs surface, and nothing else here would notice it.
  if (( ${#SUMS[@]} > 1 )); then
    check "  every agent runs the same build" \
      "$(printf '%s\n' "${SUMS[@]}" | sort -u | grep -c . || true)" "1"
  fi
fi

if have_machine "$ENGINE_MACHINE"; then
  log "engine ($ENGINE_MACHINE)"
  check "  ebpf-engine active" "$(engrun "systemctl is-active ebpf-engine" 2>/dev/null || true)" "active"
  # 302 is the healthy answer: serving, and gated. A 200 on / would mean the
  # console is reachable without logging in.
  check "  redirects to login" \
    "$(engrun "curl -s -o /dev/null -w '%{http_code}' --max-time 15 http://127.0.0.1:$ENGINE_PORT/" 2>/dev/null || true)" "302"
  if [[ "$ENGINE_MODE" == tetragon ]]; then
    # provision_engine probes the kernel and silently downgrades to -fake when
    # BTF or the version check fails. Deploying anyway is the right call, but it
    # must not pass as real eBPF — so read back what the unit runs rather than
    # what was asked for.
    faked="$(engrun "systemctl cat ebpf-engine 2>/dev/null | grep -c -- ' -fake' || true" 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ "${faked:-0}" -gt 0 ]]; then
      fail "  engine fell back to -fake — synthesised events, nothing observed"
      dim "  orb -m $ENGINE_MACHINE sudo journalctl -u ebpf-engine -n 40"
    else
      pass "  running on real Tetragon telemetry"
      tet="$(engrun "docker ps --format '{{.Names}}' 2>/dev/null | grep -c '^tetragon\$' || true" 2>/dev/null | tr -d '[:space:]' || true)"
      check "  tetragon container up" "$(yesno "$tet")" "yes"
    fi
  fi
elif doing engine; then
  fail "$ENGINE_MACHINE does not exist"
fi

# ── Endpoints ──────────────────────────────────────────────────────────────
# Plaintext http, and correctly so: these are addresses on the OrbStack bridge,
# where a certificate would have nothing to attest to.
step_header "Endpoints"
SHOWED_AGENT=0
if have_machine "$CP_MACHINE"; then
  CP_IP="$(machine_ip "$CP_MACHINE")"
  endpoint console  "http://$CP_IP/"       "$CP_MACHINE"
  endpoint keycloak "http://$CP_IP/admin/" "same origin as the console"
fi
if have_machine "$ENGINE_MACHINE"; then
  endpoint engine "http://$(machine_ip "$ENGINE_MACHINE"):$ENGINE_PORT/" "$ENGINE_MACHINE"
fi
if [[ "$DATA_MODE" == real ]]; then
  for t in $TENANTS; do
    vm="$(agent_vm "$t")"
    have_machine "$vm" || continue
    endpoint agent "$vm" "tenant $t"
    SHOWED_AGENT=1
  done
fi
printf '\n'
if (( SHOWED_AGENT )); then
  dim "An agent's own console binds 127.0.0.1:8080 on its VM and is not published."
  dim "  ssh -L 8080:127.0.0.1:8080 <agent-vm>@orb   then http://127.0.0.1:8080/"
  dim "  user admin; password: orb -m <agent-vm> sudo cat /etc/ebpf-soc/agent-console.env"
fi
if [[ -n "${CP_IP:-}" && -f "$BUILD_DIR/credentials-$CP_IP.txt" ]]; then
  dim "Console and Keycloak logins: $BUILD_DIR/credentials-$CP_IP.txt"
fi
printf '\n'

if (( FAIL > 0 )); then
  err "$FAIL of $CHECKS check(s) failed"
  exit 1
fi
# Zero checks is not a pass. It means every machine this run cared about is
# absent — most likely `--only verify` against an estate that was never
# deployed — and reporting "verified" for that is how a green run comes to mean
# nothing at all.
if (( CHECKS == 0 )); then
  warn "nothing to verify — no machines exist yet"
  dim "deploy them: $0"
  exit 1
fi
if [[ "$ONLY" == verify ]]; then
  ok "local estate verified ($CHECKS checks)"
else
  ok "local estate deployed and verified: $VERSION ($CHECKS checks)"
fi
dim "logs:     orb -m $CP_MACHINE sudo journalctl -u ebpf-soc-controlplane -f"
dim "teardown: $0 --destroy"
