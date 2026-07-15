#!/usr/bin/env bash
#
# scripts/migrate.sh — versioned schema migrations for Postgres and ClickHouse.
#
# The Go stores self-bootstrap their base table on Open() (centralstore/postgres.go
# applies the telemetry DDL + RLS policy; clickhouse.go the ReplacingMergeTree).
# That is enough to start, but it cannot evolve: it has no version ledger, no way
# to add an index or a retention TTL, and nothing to create the control-state
# tables. This runner supplies that ledger. Every migration is written to be
# idempotent and to MATCH the app's DDL exactly where they overlap, so whichever
# runs first, the other is a no-op and the schema never forks.
#
#   ./scripts/migrate.sh up     --engine postgres --env-file deploy/.env
#   ./scripts/migrate.sh status --engine postgres --docker /etc/ebpf-soc/stack
#   ./scripts/migrate.sh up     --engine clickhouse --dsn clickhouse://…
#
# Connection, pick one:
#   --env-file FILE   local devstack (deploy/docker-compose.oss.yml + that .env)
#   --docker DIR      a compose stack on this host (server deploys use this)
#   --dsn DSN         talk directly, using psql / clickhouse-client from PATH
#
# A migration is applied at most once. Editing a file that has already been
# applied is a hard error — its checksum is recorded — because a silently
# changed migration means two environments disagree about what the schema is.

LOG_TAG="migrate"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

CMD="${1:-status}"; shift || true
if [[ "$CMD" == "-h" || "$CMD" == "--help" ]]; then
  sed -n '3,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0
fi
ENGINE="postgres"; ENV_FILE=""; DOCKER_DIR=""; DSN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --engine)   ENGINE="${2:?}"; shift 2 ;;
    --env-file) ENV_FILE="${2:?}"; shift 2 ;;
    --docker)   DOCKER_DIR="${2:?}"; shift 2 ;;
    --dsn)      DSN="${2:?}"; shift 2 ;;
    -h|--help)  sed -n '3,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done

MIG_DIR="$SCRIPTS_DIR/migrations/$ENGINE"
[[ -d "$MIG_DIR" ]] || die "no migrations for engine '$ENGINE' ($MIG_DIR)"

# ── Transport ──────────────────────────────────────────────────────────────
# Three ways to reach a database, one interface: sql_run reads SQL on stdin,
# sql_scalar reads SQL on stdin and echoes a single value.

COMPOSE=()
if [[ -n "$DOCKER_DIR" ]]; then
  COMPOSE=(docker compose -f "$DOCKER_DIR/docker-compose.yml")
  if [[ -f "$DOCKER_DIR/.env" ]]; then COMPOSE+=(--env-file "$DOCKER_DIR/.env"); fi
elif [[ -n "$ENV_FILE" ]]; then
  COMPOSE=(docker compose -f "$REPO_ROOT/deploy/docker-compose.oss.yml" --env-file "$ENV_FILE")
elif [[ -z "$DSN" ]]; then
  die "pick a connection: --env-file, --docker, or --dsn"
fi

sql_run() { # SQL on stdin; fails the whole file on the first error
  case "$ENGINE" in
    postgres)
      if [[ -n "$DSN" ]]; then
        need_cmd psql; psql "$DSN" -v ON_ERROR_STOP=1 --quiet -f -
      else
        "${COMPOSE[@]}" exec -T postgres psql -U soc -d ebpf_soc -v ON_ERROR_STOP=1 --quiet -f -
      fi ;;
    clickhouse)
      if [[ -n "$DSN" ]]; then
        need_cmd clickhouse-client; clickhouse-client --multiquery <"/dev/stdin"
      else
        # The password stays inside the container's environment — it is never
        # placed on a command line the host can see.
        "${COMPOSE[@]}" exec -T clickhouse sh -c \
          'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" -d ebpf_soc --multiquery'
      fi ;;
    *) die "unknown engine: $ENGINE" ;;
  esac
}

sql_scalar() { # SQL on stdin → one bare value on stdout
  case "$ENGINE" in
    postgres)
      if [[ -n "$DSN" ]]; then
        psql "$DSN" -tAq -f -
      else
        "${COMPOSE[@]}" exec -T postgres psql -U soc -d ebpf_soc -tAq -f -
      fi ;;
    clickhouse)
      if [[ -n "$DSN" ]]; then
        clickhouse-client --multiquery <"/dev/stdin"
      else
        "${COMPOSE[@]}" exec -T clickhouse sh -c \
          'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" -d ebpf_soc --multiquery'
      fi ;;
  esac
}

# ── Ledger ─────────────────────────────────────────────────────────────────
ensure_ledger() {
  case "$ENGINE" in
    postgres) sql_run <<'SQL'
CREATE TABLE IF NOT EXISTS schema_migrations (
  version    text PRIMARY KEY,
  checksum   text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now()
);
SQL
      ;;
    clickhouse) sql_run <<'SQL'
CREATE TABLE IF NOT EXISTS schema_migrations (
  version String, checksum String, applied_at DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(applied_at) ORDER BY version;
SQL
      ;;
  esac
}

applied_checksum() { # <version> → recorded checksum, or empty
  printf "SELECT checksum FROM schema_migrations WHERE version = '%s';" "$1" | sql_scalar | tr -d '[:space:]'
}

record() { # <version> <checksum>
  printf "INSERT INTO schema_migrations (version, checksum) VALUES ('%s', '%s');" "$1" "$2" | sql_run >/dev/null
}

checksum_of() { # <file>
  if have_cmd sha256sum; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# ── Commands ───────────────────────────────────────────────────────────────
cmd_up() {
  ensure_ledger
  local applied=0 f version sum recorded
  for f in "$MIG_DIR"/*.sql; do
    [[ -e "$f" ]] || die "no .sql files in $MIG_DIR"
    version="$(basename "$f" .sql)"
    sum="$(checksum_of "$f")"
    recorded="$(applied_checksum "$version")"

    if [[ -n "$recorded" ]]; then
      if [[ "$recorded" != "$sum" ]]; then
        die "$version was already applied but the file has changed since.
     recorded: $recorded
     on disk:  $sum
     An applied migration is immutable — add a new one instead of editing this."
      fi
      dim "$version — already applied"
      continue
    fi

    log "applying $version"
    sql_run <"$f" || die "$version failed — the database is unchanged for this file"
    record "$version" "$sum"
    ok "$version applied"
    applied=$((applied + 1))
  done
  if (( applied == 0 )); then ok "schema is up to date ($ENGINE)"; else ok "$applied migration(s) applied ($ENGINE)"; fi
}

cmd_status() {
  ensure_ledger
  printf '\n  %-42s %s\n' "MIGRATION" "STATE"
  local f version recorded
  for f in "$MIG_DIR"/*.sql; do
    [[ -e "$f" ]] || continue
    version="$(basename "$f" .sql)"
    recorded="$(applied_checksum "$version")"
    if [[ -z "$recorded" ]]; then
      printf '  %-42s %spending%s\n' "$version" "$C_YEL" "$C_RESET"
    elif [[ "$recorded" != "$(checksum_of "$f")" ]]; then
      printf '  %-42s %sMODIFIED AFTER APPLY%s\n' "$version" "$C_RED" "$C_RESET"
    else
      printf '  %-42s %sapplied%s\n' "$version" "$C_GRN" "$C_RESET"
    fi
  done
  printf '\n'
}

case "$CMD" in
  up)     cmd_up ;;
  status) cmd_status ;;
  *) die "unknown command: $CMD (try: up, status)" ;;
esac
