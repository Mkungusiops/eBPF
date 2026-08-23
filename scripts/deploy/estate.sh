#!/usr/bin/env bash
#
# scripts/deploy/estate.sh — deploy the whole production estate, in order.
#
#   ./scripts/deploy/estate.sh                 # everything, with a confirm gate
#   ./scripts/deploy/estate.sh --only agents   # cp | engine | agents | verify
#   ./scripts/deploy/estate.sh --skip-build    # reuse the current build
#   ASSUME_YES=1 ./scripts/deploy/estate.sh    # unattended
#
# Why this exists: the estate needs six commands in a specific order, each
# carrying environment variables that are NOT optional and whose omission fails
# silently. Every one of those omissions has already happened here and each cost
# an outage or a false result:
#
#   TLS=1 + a DNS hostname  the provisioner rewrites the nginx site on EVERY run
#                           and binds server_name to TARGET_HOST, emitting :443
#                           only when TLS is requested. Deploying with an IP
#                           replaced the TLS vhost with a plaintext one and took
#                           console.adanianlabs.io fully offline — while every
#                           systemd unit reported active and curl http://<ip>/
#                           returned 200, so every health check passed through
#                           the outage.
#   DATA_MODE=none          defaults to `sim`, and is needed in TWO places:
#                           - control plane: a plain redeploy resurrects the
#                             sim-agents beside the real ones, and a sim acks
#                             STATUS_APPLIED for a process it never touched,
#                             which is the false-containment condition.
#                           - each AGENT: the provisioner installs a synthetic
#                             attack loop (ebpf-activity.service). Until
#                             2026-08-19 that install was unconditional, so this
#                             flag governed the sims and not the far larger fake
#                             data source next to them: the estate ran a
#                             permanent scripted attack producing ~2,000
#                             alerts/hour, which pinned the executive posture
#                             dial at 93-97 "critical" around the clock.
#   the `Host` agent        second agent in acme-corp. Skipping it leaves a
#                           version-skewed multi-agent tenant — precisely the
#                           configuration where containment-routing bugs surface.
#
# `make deploy-release` was documented as this entry point but never had a
# recipe: it exited 0 having deployed nothing.
#
# victim_device is deliberately absent. It is the containment TARGET and must
# stay agent-less; giving it an agent invalidates every containment test.

# shellcheck disable=SC2034  # consumed by log()/ok()/die() in lib/common.sh
LOG_TAG="estate"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

# ── Estate definition ──────────────────────────────────────────────────────
CP_SSH="control-plane"
CP_DOMAIN="console.adanianlabs.io"
CP_PRIVATE_IP="172.31.45.193"     # agents dial this for gRPC, not the public IP
ENGINE_SSH="single_tenant_engine"
ENGINE_DOMAIN="engine.adanianlabs.io"

# The sixth host. It receives NO software: it is the containment target, and an
# agent on it would make every containment test meaningless (the agent would be
# both actor and victim). It is still checked, because "we deliberately deployed
# nothing here" and "we forgot this host" look identical without an assertion.
VICTIM_SSH="victim_device"

# Analyst assistant. Opt-in, and the key comes from the DEPLOYER's environment —
# never from this file, never from a flag:
#
#   ASSISTANT_URL=https://openweights.example.com/v1 \
#   OPEN_WEIGHT_API_KEY=... ./scripts/deploy/estate.sh
#
# Exported so the provisioners see them. Absent, both surfaces report the
# assistant as unconfigured, which is the correct default for a security
# product: no outbound dependency on an inference endpoint unless asked for.
export ASSISTANT_URL="${ASSISTANT_URL:-}"
export ASSISTANT_MODEL="${ASSISTANT_MODEL:-gpt-oss:120b}"
export OPEN_WEIGHT_API_KEY="${OPEN_WEIGHT_API_KEY:-}"

# "tenant=ssh-alias" — acme-corp intentionally appears twice.
AGENTS=(
  "adanian-internal=Tenant_A_agent"
  "acme-corp=Tenant_B_agent"
  "acme-corp=Host"
)

ONLY=""; SKIP_BUILD=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --only)       ONLY="${2:?}"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    -h|--help)    sed -n '3,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done

doing() { [[ -z "$ONLY" || "$ONLY" == "$1" ]]; }

cd "$REPO_ROOT" || die "cannot cd to $REPO_ROOT"

# ── Preflight ──────────────────────────────────────────────────────────────
# Checked BEFORE anything is touched: a half-deployed estate running mixed
# builds is worse than one that never started.
step_header "Preflight"

DEVCHOKE="engine/internal/enforce/devbpf/bpf/devchoke.o"
if [[ -f "$DEVCHOKE" ]]; then
  ok "devchoke.o present — tc device plane will ship"
else
  # Not fatal, but it must be a LOUD choice: without it the agent silently
  # downgrades the device plane to audit-only and still reports success.
  warn "$DEVCHOKE missing — the device plane will silently degrade to audit-only."
  warn "It cannot be built on macOS; copy /opt/ebpf-soc/bpf/devchoke.o off a live agent."
  confirm "deploy anyway, with the device plane degraded?" n || die "stopped"
fi

# The tag that is being deployed should be on the mainline. A release commit
# reachable only through its tag is not on the branch anyone clones.
VERSION="$(git describe --tags --dirty --always 2>/dev/null || echo unknown)"
log "deploying: $VERSION ($(git rev-parse --short HEAD))"
case "$VERSION" in
  *-dirty) warn "work tree is DIRTY — the estate will not match any tag" ;;
esac
if ! git merge-base --is-ancestor HEAD origin/main 2>/dev/null; then
  warn "HEAD is not on origin/main — push it first, or the deployed code is off-branch"
fi

for h in "$CP_SSH" "$ENGINE_SSH" "${AGENTS[@]#*=}"; do
  ssh -o BatchMode=yes -o ConnectTimeout=10 "$h" true 2>/dev/null \
    && ok "ssh $h" || die "cannot reach $h over ssh"
done

printf '\n'
log "plan:"
doing cp     && dim "control plane   $CP_SSH      TLS=1 DATA_MODE=none  $CP_DOMAIN"
doing engine && dim "engine          $ENGINE_SSH  TLS=1                 $ENGINE_DOMAIN"
doing agents && for a in "${AGENTS[@]}"; do dim "agent           ${a#*=}  tenant=${a%%=*}"; done
dim "victim_device   SKIPPED — containment target, must stay agent-less"
if [[ -n "$ASSISTANT_URL" ]]; then
  dim "assistant       $ASSISTANT_MODEL via $ASSISTANT_URL$([[ -z "$OPEN_WEIGHT_API_KEY" ]] && echo '  (NO KEY — will report unavailable)')"
else
  dim "assistant       off (set ASSISTANT_URL to enable)"
fi
printf '\n'
confirm "deploy $VERSION to the production estate?" n || die "stopped"

# ── Build ──────────────────────────────────────────────────────────────────
# `make build-linux`, never `go build ./cmd/engine`: the engine serves its
# console from go:embed, staged from web/dist by the Makefile's `web` target.
# A plain go build compiles fine and silently ships STALE UI.
if (( ! SKIP_BUILD )) && [[ -z "$ONLY" || "$ONLY" != "verify" ]]; then
  step_header "Build (make build-linux — go:embed needs the web target)"
  run make build-linux
fi

# ── Control plane ──────────────────────────────────────────────────────────
if doing cp; then
  step_header "Control plane — $CP_DOMAIN"
  run env TLS=1 DATA_MODE=none TARGET_HOST="$CP_DOMAIN" SSH_HOST="$CP_SSH" \
    ./scripts/deploy/multi-tenant-ubuntu.sh
fi

# ── Single-tenant engine ───────────────────────────────────────────────────
if doing engine; then
  step_header "Engine — $ENGINE_DOMAIN"
  run env TLS=1 TARGET_HOST="$ENGINE_DOMAIN" SSH_HOST="$ENGINE_SSH" \
    ./scripts/deploy/single-tenant-ubuntu.sh
fi

# ── Agents ─────────────────────────────────────────────────────────────────
if doing agents; then
  for a in "${AGENTS[@]}"; do
    tenant="${a%%=*}"; host="${a#*=}"
    step_header "Agent — $host (tenant $tenant)"
    run make deploy-agent TENANT="$tenant" AGENT_HOST="$host" \
      CP_SSH="$CP_SSH" CP_IP="$CP_PRIVATE_IP" DATA_MODE=none
  done
fi

# ── Verify ─────────────────────────────────────────────────────────────────
# Always runs, even with --only: the point of the whole exercise is not that the
# scripts exited 0 but that the estate is serving and every host runs the same
# build. A deploy reporting success while half the fleet runs the previous
# binary is the failure this catches, and it has happened here.
step_header "Verify — victim_device stays agent-less"
if ssh -o BatchMode=yes -o ConnectTimeout=10 "$VICTIM_SSH" true 2>/dev/null; then
  victim_agent="$(ssh -o BatchMode=yes "$VICTIM_SSH" 'systemctl is-active ebpf-agent 2>/dev/null || true' 2>/dev/null | tr -d '[:space:]')"
  if [[ "$victim_agent" == "active" ]]; then
    err "$VICTIM_SSH IS RUNNING AN AGENT — it must stay a non-agent containment target"
    err "every containment result from this rig is suspect until that is removed"
    exit 1
  fi
  ok "$VICTIM_SSH agent-less (ebpf-agent: ${victim_agent:-absent})"
  dim "victim-http: $(ssh -o BatchMode=yes "$VICTIM_SSH" 'systemctl is-active victim-http 2>/dev/null || echo absent' 2>/dev/null | tr -d '[:space:]')"
else
  warn "$VICTIM_SSH unreachable — cannot confirm it is still agent-less"
fi

step_header "Verify"
run env CP_HOST="$CP_SSH" ENGINE_HOST="$ENGINE_SSH" \
  AGENT_HOSTS="${AGENTS[*]}" \
  ./scripts/ci/verify-deploy.sh

step_header "Endpoints"
# Both surfaces are deployed with TLS=1 above, so https is the address that
# works — printing the plaintext one would hand out a URL that redirects at best.
endpoint console  "https://$CP_DOMAIN/"
endpoint keycloak "https://$CP_DOMAIN/admin/"
endpoint engine   "https://$ENGINE_DOMAIN/"
for a in "${AGENTS[@]}"; do
  endpoint agent "${a#*=}" "tenant ${a%%=*}"
done
endpoint victim "$VICTIM_SSH" "containment target, no agent by design"
printf '\n'
dim "An agent's own console binds 127.0.0.1:8080 and is not published. Reach one with"
dim "  ssh -L 8080:127.0.0.1:8080 <agent-host>   then http://127.0.0.1:8080/"
dim "  user admin; password: sudo cat /etc/ebpf-soc/agent-console.env"
dim "Console and Keycloak logins are in .deploy-build/credentials-<host>.txt (0600)."

printf '\n'
ok "estate deployed and verified: $VERSION"
dim "built_at from /api/version is the COMMIT time, not the build time — it reads"
dim "stale even on a good deploy. Compare on-box sha256sum against .deploy-build/."
