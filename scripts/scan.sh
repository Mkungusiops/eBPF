#!/usr/bin/env bash
#
# scripts/scan.sh — supply-chain and vulnerability scanning.
#
# CI already signs the image and produces an SBOM, which proves WHAT is in the
# artifact. It does not check whether any of it is vulnerable, or whether a
# secret was committed. That is this script's job, and for a security product
# the standard has to be higher than for the software it protects.
#
#   ./scripts/scan.sh              # everything installed, non-blocking summary
#   ./scripts/scan.sh --ci         # exit non-zero on any finding
#   ./scripts/scan.sh --only go    # go | web | secrets | image
#
# Missing tools are reported, not silently skipped — a scan that quietly checked
# nothing is worse than no scan, because it looks green.

LOG_TAG="scan"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

CI_MODE=0; ONLY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ci)   CI_MODE=1; shift ;;
    --only) ONLY="${2:?}"; shift 2 ;;
    -h|--help) sed -n '3,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done

FINDINGS=0; SKIPPED=()
scanning() { [[ -z "$ONLY" || "$ONLY" == "$1" ]]; }
found()    { err "$1"; FINDINGS=$((FINDINGS + 1)); }
skip()     { SKIPPED+=("$1"); warn "$1 not installed — $2"; }

# ── Go: known CVEs in dependencies AND in the toolchain ────────────────────
if scanning go; then
  step_header "Go — govulncheck"
  if have_cmd govulncheck; then
    if (cd "$REPO_ROOT/engine" && govulncheck ./...); then
      ok "no known-exploitable vulnerabilities in reachable code"
    else
      found "govulncheck reported vulnerabilities"
    fi
  else
    skip govulncheck "go install golang.org/x/vuln/cmd/govulncheck@latest"
  fi

  step_header "Go — staticcheck"
  if have_cmd staticcheck; then
    if (cd "$REPO_ROOT/engine" && staticcheck ./...); then
      ok "staticcheck clean"
    else
      found "staticcheck reported issues"
    fi
  else
    skip staticcheck "go install honnef.co/go/tools/cmd/staticcheck@latest"
  fi
fi

# ── Web ────────────────────────────────────────────────────────────────────
if scanning web; then
  step_header "Web — npm audit"
  if have_cmd npm; then
    # The console is served from the agent/control plane, so a compromised
    # dependency runs in an operator's browser inside the SOC. High/critical
    # only: moderate advisories in dev-only tooling are noise here.
    if (cd "$REPO_ROOT/web" && npm audit --audit-level=high); then
      ok "no high or critical advisories"
    else
      found "npm audit reported high/critical advisories"
    fi
  else
    skip npm "install Node 18+"
  fi
fi

# ── Secrets ────────────────────────────────────────────────────────────────
if scanning secrets; then
  step_header "Secrets — gitleaks"
  if have_cmd gitleaks; then
    if gitleaks detect --source "$REPO_ROOT" --no-banner --redact; then
      ok "no secrets found in the git history"
    else
      found "gitleaks found committed secrets — rotate them, do not just delete the commit"
    fi
  else
    skip gitleaks "brew install gitleaks"
  fi

  # The generated state must never be committed: it holds the CA key, database
  # passwords, and the admin bearer.
  step_header "Secrets — generated state is git-ignored"
  local_bad=0
  for p in ".deploy/" "deploy/.env"; do
    if git -C "$REPO_ROOT" check-ignore -q "$p" 2>/dev/null; then
      ok "$p is ignored"
    else
      found "$p is NOT git-ignored — secrets could be committed"
      local_bad=1
    fi
  done
  if git -C "$REPO_ROOT" ls-files --error-unmatch deploy/.env >/dev/null 2>&1; then
    found "deploy/.env is TRACKED IN GIT — rotate every credential in it now"
  fi
fi

# ── Container image ────────────────────────────────────────────────────────
if scanning image; then
  step_header "Image — trivy"
  if have_cmd trivy; then
    if [[ -f "$REPO_ROOT/deploy/controlplane.Dockerfile" ]]; then
      if trivy fs --scanners vuln,secret,misconfig --exit-code 1 --severity HIGH,CRITICAL "$REPO_ROOT"; then
        ok "no HIGH/CRITICAL findings"
      else
        found "trivy reported HIGH/CRITICAL findings"
      fi
    fi
  else
    skip trivy "brew install trivy"
  fi
fi

# ── Summary ────────────────────────────────────────────────────────────────
printf '\n'
if (( ${#SKIPPED[@]} > 0 )); then
  warn "not run: ${SKIPPED[*]}"
  if (( CI_MODE )); then
    err "in --ci mode every scanner must be present — a missing scanner is a false green"
    exit 1
  fi
fi

if (( FINDINGS > 0 )); then
  err "$FINDINGS scanner(s) reported findings"
  exit 1
fi
ok "all scans clean"
