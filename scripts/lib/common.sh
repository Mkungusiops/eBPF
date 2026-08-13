# shellcheck shell=bash
#
# scripts/lib/common.sh — shared foundation for every script under scripts/.
#
# Source it, don't execute it:
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
#
# Provides: logging, prompts, secret generation, a resumable key/value state
# store, and the SSH/sudo transport used by the remote-deploy scripts.

if [[ -n "${_EBPF_COMMON_SH:-}" ]]; then return 0; fi
_EBPF_COMMON_SH=1

set -euo pipefail

# ── Paths ──────────────────────────────────────────────────────────────────
SCRIPT_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="$(cd "$SCRIPT_LIB_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SCRIPTS_DIR/.." && pwd)"
export SCRIPTS_DIR REPO_ROOT

# Deploy state + artifacts live outside the tracked tree (see .gitignore).
STATE_ROOT="${EBPF_STATE_ROOT:-$REPO_ROOT/.deploy}"

# ── Output ─────────────────────────────────────────────────────────────────
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[1;31m'; C_GRN=$'\033[1;32m'; C_YEL=$'\033[1;33m'; C_BLU=$'\033[1;34m'
else
  C_RESET=''; C_BOLD=''; C_DIM=''; C_RED=''; C_GRN=''; C_YEL=''; C_BLU=''
fi

log()   { printf '%s[%s]%s %s\n' "$C_BLU" "${LOG_TAG:-ebpf}" "$C_RESET" "$*"; }
ok()    { printf '%s  ✓%s %s\n' "$C_GRN" "$C_RESET" "$*"; }
warn()  { printf '%s  ! %s%s\n' "$C_YEL" "$*" "$C_RESET" >&2; }
err()   { printf '%s  ✗ %s%s\n' "$C_RED" "$*" "$C_RESET" >&2; }
die()   { err "$*"; exit 1; }
dim()   { printf '%s    %s%s\n' "$C_DIM" "$*" "$C_RESET"; }

# A numbered wizard step header.
step_header() {
  printf '\n%s━━ %s ━━%s\n' "$C_BOLD" "$*" "$C_RESET"
}

# run CMD… — echo then execute; a no-op under DRY_RUN.
run() {
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    printf '%s    dry-run: %s%s\n' "$C_DIM" "$*" "$C_RESET"
    return 0
  fi
  "$@"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1${2:+ — $2}"
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# ── Prompts ────────────────────────────────────────────────────────────────
# ASSUME_YES=1 makes confirm() auto-accept and ask() take its default, so every
# wizard is drivable unattended (CI, re-runs) with the same code path.

confirm() { # confirm "question" [default y|n]
  local q="$1" def="${2:-y}" ans
  if [[ "${ASSUME_YES:-0}" == "1" ]]; then return 0; fi
  local hint="[y/N]"; [[ "$def" == "y" ]] && hint="[Y/n]"
  read -r -p "$(printf '%s?%s %s %s ' "$C_YEL" "$C_RESET" "$q" "$hint")" ans </dev/tty || true
  ans="${ans:-$def}"
  [[ "$ans" =~ ^[Yy] ]]
}

ask() { # ask VAR_NAME "question" [default] — echoes the answer
  local q="$1" def="${2:-}" ans
  if [[ "${ASSUME_YES:-0}" == "1" ]]; then printf '%s' "$def"; return 0; fi
  read -r -p "$(printf '%s?%s %s%s ' "$C_YEL" "$C_RESET" "$q" "${def:+ [$def]}")" ans </dev/tty || true
  printf '%s' "${ans:-$def}"
}

ask_secret() { # ask_secret "question" — echoes the answer, never displays it
  local q="$1" ans
  read -r -s -p "$(printf '%s?%s %s: ' "$C_YEL" "$C_RESET" "$q")" ans </dev/tty || true
  printf '\n' >&2
  printf '%s' "$ans"
}

# ask_choice "question" opt1 opt2 … — echoes the chosen option.
ask_choice() {
  local q="$1"; shift
  local opts=("$@") i choice
  if [[ "${ASSUME_YES:-0}" == "1" ]]; then printf '%s' "${opts[0]}"; return 0; fi
  printf '%s?%s %s\n' "$C_YEL" "$C_RESET" "$q" >&2
  for i in "${!opts[@]}"; do printf '    %d) %s\n' "$((i + 1))" "${opts[$i]}" >&2; done
  read -r -p "  choice [1]: " choice </dev/tty || true
  choice="${choice:-1}"
  if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#opts[@]} )); then
    die "invalid choice: $choice"
  fi
  printf '%s' "${opts[$((choice - 1))]}"
}

# ── Secrets ────────────────────────────────────────────────────────────────
# URL/DSN/env-safe: alphanumerics only, so a generated password never has to be
# escaped in a Postgres DSN, a compose .env, or a systemd EnvironmentFile.
#
# Note the bounded `head` FIRST, then the filter. The obvious spelling —
# `tr -dc … </dev/urandom | head -c "$n"` — has head close the pipe on tr, and
# under `set -o pipefail` that SIGPIPE becomes exit 141, killing the caller.
gen_secret() { # gen_secret [length]
  local n="${1:-32}" out=""
  while (( ${#out} < n )); do
    # ~62/256 of random bytes survive the filter, so 6n bytes is ample headroom;
    # the loop covers the vanishingly unlikely short read.
    out+="$(head -c $((n * 6)) /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9')"
  done
  printf '%s' "${out:0:n}"
}

gen_token() { gen_secret 48; }

# ── State store ────────────────────────────────────────────────────────────
# Two files per deployment under .deploy/<name>/:
#   state.env    0600  non-secret config + completed steps (resume ledger)
#   secrets.env  0600  generated passwords/tokens — never printed, never committed
#
# Both are plain `KEY=value` so they can be sourced, inspected, and hand-edited.

state_init() { # state_init <name>
  DEPLOY_NAME="$1"
  DEPLOY_DIR="$STATE_ROOT/$DEPLOY_NAME"
  STATE_FILE="$DEPLOY_DIR/state.env"
  SECRETS_FILE="$DEPLOY_DIR/secrets.env"
  ARTIFACTS_DIR="$DEPLOY_DIR/artifacts"
  mkdir -p "$DEPLOY_DIR" "$ARTIFACTS_DIR"
  chmod 700 "$DEPLOY_DIR"
  [[ -f "$STATE_FILE" ]]   || : >"$STATE_FILE"
  [[ -f "$SECRETS_FILE" ]] || : >"$SECRETS_FILE"
  chmod 600 "$STATE_FILE" "$SECRETS_FILE"
  export DEPLOY_NAME DEPLOY_DIR STATE_FILE SECRETS_FILE ARTIFACTS_DIR
}

_kv_set() { # _kv_set <file> <key> <value>
  local file="$1" key="$2" val="$3" tmp
  tmp="$(mktemp)"
  grep -v "^${key}=" "$file" 2>/dev/null >"$tmp" || true
  printf '%s=%s\n' "$key" "$val" >>"$tmp"
  mv "$tmp" "$file"
  chmod 600 "$file"
}

_kv_get() { # _kv_get <file> <key> [default]
  local file="$1" key="$2" def="${3:-}" line
  line="$(grep -m1 "^${key}=" "$file" 2>/dev/null || true)"
  if [[ -z "$line" ]]; then printf '%s' "$def"; else printf '%s' "${line#*=}"; fi
}

state_set()    { _kv_set "$STATE_FILE" "$1" "$2"; }
state_get()    { _kv_get "$STATE_FILE" "$1" "${2:-}"; }
secret_set()   { _kv_set "$SECRETS_FILE" "$1" "$2"; }
secret_get()   { _kv_get "$SECRETS_FILE" "$1" "${2:-}"; }

# Generate a secret once and reuse it forever after (idempotent re-runs).
secret_ensure() { # secret_ensure <key> [length]
  local key="$1" len="${2:-32}" cur
  cur="$(secret_get "$key")"
  if [[ -z "$cur" ]]; then cur="$(gen_secret "$len")"; secret_set "$key" "$cur"; fi
  printf '%s' "$cur"
}

# Load everything back into the environment on resume.
#
# The `if` blocks matter: on a first run both files exist but are EMPTY, and
# `[[ -s f ]] && source f` would evaluate to false — which under `set -e` aborts
# the script before the wizard has even started.
state_load() {
  set -a
  if [[ -s "$STATE_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$STATE_FILE"
  fi
  if [[ -s "$SECRETS_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$SECRETS_FILE"
  fi
  set +a
  return 0
}

# Step ledger — the resume mechanism.
step_done()    { state_set "STEP_${1//-/_}_DONE" "1"; }
step_is_done() { [[ "$(state_get "STEP_${1//-/_}_DONE")" == "1" ]]; }
step_reset()   { state_set "STEP_${1//-/_}_DONE" "0"; }

# ── SSH transport ──────────────────────────────────────────────────────────
# Every remote script talks to the server through these four helpers, so the
# auth story (key, alias, sudo) is defined in exactly one place.
#
# Requires SSH_ALIAS (a Host block in ~/.ssh/config) or SSH_TARGET (user@host).
# REMOTE_SUDO_PASS, when set, is fed to `sudo -S` over stdin — it is never
# written to disk and never appears in a command line or process list.

SSH_BASE_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15)

ssh_target() {
  printf '%s' "${SSH_ALIAS:-${SSH_TARGET:?SSH_ALIAS or SSH_TARGET must be set}}"
}

# rssh <command…> — run a command on the server as the login user.
rssh() {
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    printf '%s    dry-run: ssh %s -- %s%s\n' "$C_DIM" "$(ssh_target)" "$*" "$C_RESET"
    return 0
  fi
  ssh "${SSH_BASE_OPTS[@]}" "$(ssh_target)" -- "$@"
}

# rssh_quiet — same, but callers want the exit status, not the noise.
rssh_quiet() { ssh "${SSH_BASE_OPTS[@]}" -o BatchMode=yes "$(ssh_target)" -- "$@" >/dev/null 2>&1; }

# rsudo <command…> — run a command on the server as root.
#
# The command is passed to `bash -c` on the remote so pipes/redirects inside it
# behave. With REMOTE_SUDO_PASS set we use `sudo -S`, feeding the password on a
# dedicated stdin that carries nothing else — sudo is free to over-read its
# buffer without corrupting anything downstream. Otherwise we require
# passwordless sudo (`sudo -n`) and fail loudly if it is absent.
rsudo() {
  local cmd="$*"
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    printf '%s    dry-run: ssh %s -- sudo %s%s\n' "$C_DIM" "$(ssh_target)" "$cmd" "$C_RESET"
    return 0
  fi
  if [[ -n "${REMOTE_SUDO_PASS:-}" ]]; then
    printf '%s\n' "$REMOTE_SUDO_PASS" |
      ssh "${SSH_BASE_OPTS[@]}" "$(ssh_target)" -- "sudo -S -p '' bash -c $(printf '%q' "$cmd")"
  else
    ssh "${SSH_BASE_OPTS[@]}" "$(ssh_target)" -- "sudo -n bash -c $(printf '%q' "$cmd")"
  fi
}

# rsudo_quiet — exit status only. Use in wait_for / if-conditions.
rsudo_quiet() { rsudo "$@" >/dev/null 2>&1; }

# rput <local> <remote> — copy a file up. Lands in the login user's space; use
# rsudo afterwards to install it into a root-owned path.
rput() {
  local src="$1" dst="$2"
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    printf '%s    dry-run: scp %s → %s:%s%s\n' "$C_DIM" "$src" "$(ssh_target)" "$dst" "$C_RESET"
    return 0
  fi
  scp "${SSH_BASE_OPTS[@]}" -q "$src" "$(ssh_target):$dst"
}

# rget <remote> <local> — copy a file down.
rget() {
  local src="$1" dst="$2"
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    printf '%s    dry-run: scp %s:%s → %s%s\n' "$C_DIM" "$(ssh_target)" "$src" "$dst" "$C_RESET"
    return 0
  fi
  scp "${SSH_BASE_OPTS[@]}" -q "$(ssh_target):$src" "$dst"
}

# _stage_up <local-file> — scp a file to a private staging path and echo it.
#
# The destination is pre-created 0600 before the copy: scp only applies a mode
# when it creates the file, so pre-creating means a secret is never briefly
# world-readable in /tmp.
_stage_up() {
  local src="$1" stage
  stage="/tmp/.ebpf-stage.$$.${RANDOM}"
  ssh "${SSH_BASE_OPTS[@]}" "$(ssh_target)" -- "install -m 600 /dev/null '$stage'"
  scp "${SSH_BASE_OPTS[@]}" -q "$src" "$(ssh_target):$stage"
  printf '%s' "$stage"
}

# rput_root <local> <remote-root-path> [mode] — upload, then install as root.
rput_root() {
  local src="$1" dst="$2" mode="${3:-0644}" stage
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    printf '%s    dry-run: install %s → %s:%s (%s)%s\n' "$C_DIM" "$src" "$(ssh_target)" "$dst" "$mode" "$C_RESET"
    return 0
  fi
  stage="$(_stage_up "$src")"
  rsudo "install -D -m $mode -o root -g root '$stage' '$dst'"
  rssh "rm -f '$stage'"
}

# rwrite_root <remote-path> [mode] — write stdin to a root-owned remote file.
# Routed through a 0600 staging file rather than a command line, so a secret
# never appears in the server's process list (/proc/<pid>/cmdline).
rwrite_root() {
  local dst="$1" mode="${2:-0600}" tmp
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    cat >/dev/null
    printf '%s    dry-run: write %s (%s)%s\n' "$C_DIM" "$dst" "$mode" "$C_RESET"
    return 0
  fi
  tmp="$(mktemp)"; chmod 600 "$tmp"
  cat >"$tmp"
  rput_root "$tmp" "$dst" "$mode"
  rm -f "$tmp"
}

# ── Polling ────────────────────────────────────────────────────────────────
# wait_for <timeout-seconds> <description> <command…> — poll until it succeeds.
wait_for() {
  local timeout="$1" desc="$2"; shift 2
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    dim "dry-run: would wait for $desc"
    return 0
  fi
  local deadline=$(( $(date +%s) + timeout ))
  printf '    waiting for %s ' "$desc"
  while (( $(date +%s) < deadline )); do
    if "$@" >/dev/null 2>&1; then printf ' %sready%s\n' "$C_GRN" "$C_RESET"; return 0; fi
    printf '.'; sleep 3
  done
  printf ' %stimeout%s\n' "$C_RED" "$C_RESET"
  return 1
}

# ── Misc ───────────────────────────────────────────────────────────────────
# Sanitise a host/user string into a filesystem- and ssh-config-safe name.
slugify() { printf '%s' "$1" | LC_ALL=C tr -c 'A-Za-z0-9._-' '-' | sed 's/-\{2,\}/-/g; s/^-//; s/-$//'; }

# Redact a secret for display: first 4 chars, then dots.
redact() { local s="$1"; printf '%s…(%d chars)' "${s:0:4}" "${#s}"; }
