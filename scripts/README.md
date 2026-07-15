# scripts/

Operational tooling for the eBPF-SOC platform. Everything here sources
[`lib/common.sh`](lib/common.sh), which owns logging, prompts, the resumable
state store, and the single SSH/sudo transport all remote scripts ride on.

## Deploy the platform to a server

```bash
./scripts/deploy-platform.sh
```

An eleven-step wizard. **Step 1 establishes the SSH access every later step
uses**: it asks for the server address and login user, generates a deployment
key (or takes an existing one), installs the public key on the server, writes a
`~/.ssh/config` alias, and proves both SSH and sudo work non-interactively.
Nothing after that prompts for a password.

| # | Step | What it does |
|---|------|--------------|
| 1 | `ssh` | Key generation, `ssh-copy-id`, `~/.ssh/config` alias, sudo check |
| 2 | `preflight` | OS, systemd, RAM/disk, Docker, free ports |
| 3 | `config` | Domain, tenant, auth mode, store; generates every secret once |
| 4 | `build` | Static linux `controlplane` + `agent` |
| 5 | `stack` | Docker + Postgres/NATS (+ClickHouse/Keycloak), **bound to loopback** |
| 6 | `migrate` | Versioned schema, RLS, retention |
| 7 | `identity` | Keycloak realm + client (OIDC mode only) |
| 8 | `controlplane` | Binary, `EnvironmentFile`, hardened systemd unit, health check |
| 9 | `pki` | Pulls down the CA bundle + fleet public key agents pin |
| 10 | `tenant` | Registers the first tenant, mints an enrollment token |
| 11 | `smoke` | Proves it works — including that cross-tenant reads are denied |

Each step is a checkpoint. A failed run resumes:

```bash
./scripts/deploy-platform.sh --resume          # continue where it stopped
./scripts/deploy-platform.sh --only stack      # re-run one step
./scripts/deploy-platform.sh --from migrate    # re-run from here onward
./scripts/deploy-platform.sh --dry-run         # print, change nothing
```

State lives in `.deploy/<name>/` (git-ignored, `0700`):

- `state.env` — config and the step ledger
- `secrets.env` — every generated password and the admin bearer (`0600`)
- `artifacts/` — CA bundle + fleet public key: **what agents pin**

Only the agent gRPC port (`9443`) is public. The operator API and the whole data
tier bind to loopback; reach them with `ssh -L 9090:127.0.0.1:9090 <alias>`.

## Enroll an agent

```bash
./scripts/install-agent.sh --host ubuntu@10.0.0.5 \
    --controlplane cp.example.com:9443 --tenant acme --deployment cp-example-com
```

Preflights the kernel (≥ 5.15, BTF, cgroup v2 — it refuses hosts that cannot
enforce), starts Tetragon, applies the TracingPolicies, installs the binary, and
performs the **one-time** enrollment: the agent trades a bootstrap token for an
mTLS certificate whose Subject carries the `tenant_id`. That certificate is
tenant isolation Layer 1. It is persisted, so restarts never need the token
again — and the installer wipes the spent token from disk.

Detect-only by default. Pass `--enforce` when you mean to freeze and kill.

## The rest

| Script | Purpose |
|--------|---------|
| `devstack.sh` | Local OSS data tier. Generates `deploy/.env` — without it `docker compose up` fails, because the compose file requires those passwords. |
| `preflight.sh` | `--role controlplane\|agent`, locally or `--ssh <alias>`. |
| `migrate.sh` | Versioned Postgres/ClickHouse migrations with a checksum ledger. |
| `pki.sh` | `export` / `inspect` / `backup` / `rotate` the CA and fleet signing key. |
| `tenantctl` | `create`, `list`, `enroll-token`, `whoami`, `telemetry`. |
| `smoke.sh` | Post-deploy correctness, not just liveness. |
| `isolation-test.sh` | The Phase-1 exit gate: all four isolation layers. **Run in CI.** |
| `backup.sh` / `restore.sh` | Postgres + config + **the PKI**. `restore.sh --dry-run` rehearses a DR drill. |
| `rotate-secrets.sh` | Admin token, database password, OIDC client secret. |
| `scan.sh` | `govulncheck`, `staticcheck`, `npm audit`, `gitleaks`, `trivy`. |
| `release.sh` | Clean-tree + tested + checksummed + cosign-signed artifacts. |
| `fleet-upgrade.sh` | Canary → early → rest, with per-host rollback. |

Pre-existing, unchanged: `setup.sh` (host bootstrap), `chokectl` (fleet CLI),
`multipass-doctor.sh`, `dev/netns-*.sh` (device-choke lab).

## Two things worth knowing

**The PKI is the only irreplaceable thing.** `ca.key` issues every agent's
identity; `fleet.key` signs every command agents obey. Lose them and the whole
fleet must re-enroll by hand. Leak them and an attacker can mint an agent for any
tenant and order the fleet to quarantine or sever. Back them up
(`backup.sh`), encrypted, off the box.

**Secrets never touch a command line.** `/proc/<pid>/cmdline` is world-readable,
so the admin token, DSNs, and OIDC secret travel in a systemd `EnvironmentFile`,
and the agent's console password lives in a `0600` YAML config — never in
`ExecStart`. The remote-write helpers in `lib/common.sh` stage through a
pre-created `0600` file for the same reason.
