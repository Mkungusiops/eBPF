#!/usr/bin/env bash
# SSH driver for scripts/deploy/lib.sh — provisions a remote Debian/Ubuntu Linux
# server over SSH. Set before sourcing:
#   SSH_HOST     user@host, or a ~/.ssh/config alias   (required)
#   SSH_OPTS     extra ssh/scp flags, e.g. "-i key.pem" (optional)
#   TARGET_HOST  public DNS/IP browsers + OIDC use      (defaults to the ssh host)
SSH_HOST="${SSH_HOST:?set SSH_HOST=user@host (or an ssh alias)}"
SSH_OPTS="${SSH_OPTS:-}"

command -v ssh >/dev/null || die "ssh not found"
_ssh() { ssh $SSH_OPTS "$SSH_HOST" "$@"; }

ssh_probe() {
  _ssh true 2>/dev/null || die "cannot ssh to $SSH_HOST"
  _ssh 'sudo -n true' 2>/dev/null || die "passwordless sudo required on $SSH_HOST"
  _ssh 'command -v apt-get >/dev/null' 2>/dev/null || die "these scripts target Debian/Ubuntu (apt) servers"
  [[ -n "${TARGET_HOST:-}" ]] || TARGET_HOST="${SSH_HOST##*@}"
  ok "ssh + sudo OK on $SSH_HOST (URL host: $TARGET_HOST)"
}

RUN() { _ssh "sudo bash -c $(printf '%q' "$1")"; }
PUT() { local t="/tmp/.dep.$$.${2##*/}"; scp $SSH_OPTS -q "$1" "$SSH_HOST:$t"; _ssh "sudo install -D -m0755 $t $2 && rm -f $t"; }
# PKG is provided by lib.sh (shared, lock-aware, retrying).
put_dir() { ( cd "$1" && tar cf - . ) | _ssh "sudo bash -c 'rm -rf $2/* 2>/dev/null; mkdir -p $2; tar -C $2 -xf -'"; }

ssh_probe
