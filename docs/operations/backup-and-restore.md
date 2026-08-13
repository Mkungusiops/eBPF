# Backup and restore

What is backed up, how to verify it, how to restore it, and how to rebuild the
estate from nothing. Every procedure here has been executed against the live
AWS estate — none of it is theoretical.

---

## What is irreplaceable

Two things on the control plane, and they fail differently:

| | Restores | Lost forever if missing |
|---|---|---|
| **PKI + config** (`/var/lib/ebpf-soc`, `/etc/ebpf-soc`) | the platform's *identity* — the CA every agent pins, the fleet signing key, DSNs and tokens | every agent must re-enroll; signed policy bundles stop verifying |
| **Database** (`ebpf_soc`) | the record of what the platform *did* — tenants, telemetry, alerts, and the hash-chained decision audit | the audit trail. There is no second copy anywhere |

The distinction matters: a PKI backup restores the platform, not its history. For
a security product the decision audit is often the artefact a customer or
regulator actually asks for.

> **This was a real gap.** Until 2026-08-12 the nightly job captured only PKI and
> config — 1,572-byte tarballs — and reported success every night while the
> database, then 5.24M rows including 1,645 hash-chained decision rows, had never
> been dumped once.

## The nightly job

`ebpf-soc-cp-backup`, driven by a systemd timer at 03:00 UTC, writing to
`/var/backups/ebpf-soc` (mode 0700 — it contains live secrets).

```
cp-pki-config-<stamp>.tar.gz   keep 7    ~1.5 KB
db-<stamp>.sql.gz              keep 3    sized with the estate
```

It refuses to report success on a degenerate artefact, which is the point: a
backup job that "succeeds" while writing nothing is worse than no job, because
it is trusted. Specifically it fails if the archive is empty, if the CA key is
absent from it, if the dump is not a valid gzip stream, or if the dump contains
no `telemetry` schema. If `pg_dump` is unavailable it prints a loud warning
rather than passing quietly.

```bash
sudo /usr/local/bin/ebpf-soc-cp-backup     # run it by hand; exits non-zero on any doubt
systemctl list-timers ebpf-soc-cp-backup   # confirm the schedule is armed
```

> **A trap worth knowing.** These integrity checks are pipelines ending in
> `grep -q`, and the script runs under `set -o pipefail`. `grep -q` exits at the
> first match and closes the pipe; the producer takes SIGPIPE and the pipeline
> reports failure *even though the check passed*. It only bites once the
> producer is slow enough to still be writing — so it passes on a small archive
> and fails on a real one. The checks disable `pipefail` around themselves for
> exactly this reason; don't remove that.

## Verifying a backup

Integrity is not the same as restorability. Prove the second:

```bash
LATEST=$(sudo sh -c 'ls -1t /var/backups/ebpf-soc/db-*.sql.gz | head -1')

sudo -u postgres psql -qc "CREATE DATABASE restore_drill"
sudo sh -c "gunzip -c $LATEST" | sudo -u postgres psql -q restore_drill

sudo -u postgres psql restore_drill -tAc "select count(*) from telemetry"
sudo -u postgres psql restore_drill -tAc \
  "select count(*) from pg_indexes where tablename='telemetry'"

sudo -u postgres psql -qc "DROP DATABASE restore_drill"
```

A drill that restores into a scratch database costs a minute and is the only
evidence the backup is real. Do it after any schema change.

## Restoring the database

```bash
sudo systemctl stop ebpf-soc-controlplane          # stop ingest first
sudo -u postgres psql -qc "DROP DATABASE ebpf_soc"
sudo -u postgres psql -qc "CREATE DATABASE ebpf_soc"
sudo sh -c "gunzip -c /var/backups/ebpf-soc/db-<stamp>.sql.gz" \
  | sudo -u postgres psql -q ebpf_soc
sudo systemctl start ebpf-soc-controlplane
curl -s localhost:9090/readyz                      # expect {"status":"ready","store":"ok"}
```

The dump is taken `--no-owner --no-privileges`, so it restores cleanly into a
fresh database without needing the original role grants. The control plane
recreates its app role and RLS policies at startup.

## Restoring PKI

```bash
sudo systemctl stop ebpf-soc-controlplane
sudo tar -xzf /var/backups/ebpf-soc/cp-pki-config-<stamp>.tar.gz -C /
sudo systemctl start ebpf-soc-controlplane
```

Restoring the CA is what lets existing agents keep working. If the CA changes,
every agent's certificate is rejected (`x509: certificate signed by unknown
authority`) and each must re-enroll — telemetry keeps flowing from buffers while
choke, devices and fleet views go empty, which is a confusing failure to debug
from the console alone.

## Wiping the data plane

Clearing telemetry while keeping identity — useful before a demo, a customer
handover, or a clean-slate test. **Verified 2026-08-12** on the full estate.

Order matters: stop producers before consumers, start them in reverse.

```bash
# 1. Back up first. This is the only step that makes the rest reversible.
sudo /usr/local/bin/ebpf-soc-cp-backup

# 2. Stop: agents -> engine -> control plane
#    (on each agent host)   sudo systemctl stop ebpf-agent
#    (on the engine host)   sudo systemctl stop ebpf-engine
#    (on the control plane) sudo systemctl stop ebpf-soc-controlplane

# 3. Wipe the stores only
sudo -u postgres psql ebpf_soc -c "TRUNCATE TABLE telemetry;"     # control plane
sudo rm -f /var/lib/ebpf-engine/events.db*                        # engine
sudo rm -f /var/lib/ebpf-soc-agent/events.db*                     # each agent

# 4. Start: control plane -> agents -> engine
```

**Keep, do not delete:** `agent-cert.pem`, `agent-key.pem`, `identity.json`,
`ca-bundle.pem`, `secret`, and everything under `/etc/`. Preserving those means
agents re-attach with no re-enrollment.

Two things to expect afterwards, both normal:

- **Token-bucket counts start near zero and climb.** The per-PID choke map is
  in-memory and rebuilds as the agent re-observes activity. Process counts
  recover immediately, because those come from the live process table.
- **Anything currently contained is orphaned.** Kernel cgroup membership
  survives a restart while the agent's in-memory ladder does not, so a held
  process stays held with nothing tracking it. Check every tier is empty before
  stopping an agent:
  ```bash
  for t in throttled tarpit quarantined; do wc -l < /sys/fs/cgroup/choke-$t/cgroup.procs; done
  ```

## Full rebuild

Deploy scripts are idempotent and credential-stable — a redeploy reuses the
existing Postgres, Keycloak and console passwords, and the CA persists via
`-state-dir`, so agents survive it.

```bash
TLS=1 DATA_MODE=none TARGET_HOST=<console-host> SSH_HOST=<cp-ssh> \
  ./scripts/deploy/multi-tenant-ubuntu.sh
TLS=1 TARGET_HOST=<engine-host> SSH_HOST=<engine-ssh> \
  ./scripts/deploy/single-tenant-ubuntu.sh
```

Then verify with the live suite rather than by eye:

```bash
./scripts/e2e/all.sh     # 9 suites; exits non-zero if any assertion fails
```

## Related

- [reset-engine-and-policies.md](reset-engine-and-policies.md) — engine-local reset
- [../deployment/ubuntu-server.md](../deployment/ubuntu-server.md) — first-time deploy
- [../../CHANGELOG.md](../../CHANGELOG.md) — release history and the version contract
