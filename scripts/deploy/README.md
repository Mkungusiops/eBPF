# scripts/deploy/

Deploy scripts split along the two axes that actually matter:

- **What** you deploy — the **single-tenant engine** (the `engine.adanianlabs.io`
  model: one host, its own dashboard) or the **multi-tenant control plane** (the
  `console.adanianlabs.io` model: Keycloak SSO, per-tenant RLS, a fleet of
  agents).
- **Where** you deploy it — a local **OrbStack** machine, an **Ubuntu** server,
  or a generic Debian-family **Linux** server.

That's a 2×3 grid of thin entrypoints. All six share one provisioning library
([`lib.sh`](lib.sh)); the only thing that changes per target is *how commands
reach the host*, which lives in a small **driver**.

```
              OrbStack (local)          Ubuntu server            Linux server
            ┌────────────────────────┬────────────────────────┬────────────────────────┐
single-     │ single-tenant-orbstack │ single-tenant-ubuntu   │ single-tenant-linux    │
 tenant     │   engine + Tetragon    │   engine + Tetragon    │   engine + Tetragon    │
(engine)    │   (real eBPF)          │   (real eBPF)          │   (real eBPF)          │
            ├────────────────────────┼────────────────────────┼────────────────────────┤
multi-      │ multi-tenant-orbstack  │ multi-tenant-ubuntu    │ multi-tenant-linux     │
 tenant     │   full console stack   │   full console stack   │   full console stack   │
(control    │                        │                        │                        │
 plane)     └────────────────────────┴────────────────────────┴────────────────────────┘
```

## Quick start

**Deploying the production estate? Use one command, not these:**

```bash
./scripts/deploy/estate.sh        # or: make deploy-estate
```

[`estate.sh`](estate.sh) drives the whole six-host estate in order with every
required variable already set, preflights all hosts before touching any of them,
and verifies afterwards. The scripts below are the building blocks it calls, and
the reference for deploying somewhere new — but invoking them by hand against
production means re-supplying variables whose omission fails **silently**
(`TLS=1`, a DNS name rather than an IP, `DATA_MODE=none`, and every agent host).
Each of those omissions has already caused an outage or a false result here; see
[aws-multi-host.md §4](../../docs/deployment/aws-multi-host.md).

**Want the whole thing locally? Use one command, not two:**

```bash
./scripts/deploy/estate-orbstack.sh    # or: make deploy-local
```

[`estate-orbstack.sh`](estate-orbstack.sh) is the local counterpart of
`estate.sh`: control plane, one **real** agent VM per tenant, and the
single-tenant engine, in the order that works — agents enrol *into* the control
plane, so deploying the engine first and the console second leaves two systems
that have never heard of each other, both reporting success. It creates every
machine, verifies afterwards (including that the engine did **not** silently
fall back to `-fake`), and prints the URLs and logins. `--destroy` removes the
lot.

```bash
./scripts/deploy/estate-orbstack.sh --only engine     # cp | agents | engine | verify
./scripts/deploy/estate-orbstack.sh --data-mode sim   # fabricated telemetry, no agent VMs
./scripts/deploy/estate-orbstack.sh --destroy         # or: make destroy-local
```

The single scripts below remain the building blocks, and the reference for
deploying somewhere new.

```bash
# Local, on OrbStack — nothing to configure, creates the machine for you:
./scripts/deploy/single-tenant-orbstack.sh          # engine  -> http://<ip>:8090/
./scripts/deploy/multi-tenant-orbstack.sh           # console -> http://<ip>/

# A server, over SSH (needs passwordless sudo on the box):
SSH_HOST=ubuntu@10.0.0.5 ./scripts/deploy/single-tenant-ubuntu.sh
SSH_HOST=ubuntu@10.0.0.5 TARGET_HOST=console.example.com \
    ./scripts/deploy/multi-tenant-ubuntu.sh

# With TLS (needs TARGET_HOST to be a real DNS name pointing here, and :80 open
# to 0.0.0.0/0 — Let's Encrypt validates from arbitrary addresses):
TLS=1 TLS_EMAIL=you@example.com SSH_HOST=... TARGET_HOST=console.example.com \
    ./scripts/deploy/multi-tenant-ubuntu.sh

# A REAL agent per tenant, on its own host (multi-host; see
# ../../docs/deployment/aws-multi-host.md):
CP_SSH=control-plane ./scripts/deploy/provision-agent-ssh.sh \
    <tenant-id> <agent-ssh-host> <cp-ip> <cp-admin-token> \
    ca.pem fleet.pub .deploy-build/agent [devchoke.o]
```

Useful knobs:

| Env | Effect |
|-----|--------|
| `TLS=1` | Obtain a cert first, serve `:443`, redirect `:80`. The OIDC issuer, redirect URI and `Secure` cookies follow the scheme. |
| `TARGET_SCHEME` | Set implicitly by `TLS=1`; the scheme browsers use. |
| `DATA_MODE=sim` | Default. One sim-agent per tenant fabricating telemetry. |
| `DATA_MODE=none` | No data seeders, and disable any left over. **Use this when real agents are managed separately** — otherwise each redeploy resurrects the simulators alongside them. |

`DATA_MODE` governs **two** things, and for a long time it only reached the
first:

1. **Control plane** — the per-tenant sim-agents.
2. **Each agent** — `ebpf-activity.service`, a synthetic attack loop that runs
   the attack catalogue, reads `/etc/shadow` and connects to hardcoded
   "threat actor" IPs every 20-45s, forever.

The agent half was installed **unconditionally** until 2026-08-19, so an estate
deployed with `DATA_MODE=none` still fabricated ~2,000 alerts/hour and the
console's executive posture dial sat pinned at 93-97 "critical" around the clock.
`verify-deploy.sh` asserted "no sim-agents running" and passed throughout. See
[`../../docs/operations/synthetic-telemetry.md`](../../docs/operations/synthetic-telemetry.md).

`DATA_MODE=none` now **removes** the generator rather than merely declining to
install it — a host provisioned earlier already has the unit enabled — and
`verify-deploy.sh` fails the deploy if `ebpf-activity` is running on any agent.
| `DEVCHOKE=1` | Compile + attach the tc device data plane (single-tenant). |
| `TENANTS` | Space-separated tenant ids (multi-tenant). |

Every script **builds the current source** (Vite console + static Go binaries),
provisions the target, and prints the URLs and generated logins on success. All
are **idempotent** — re-run to redeploy the latest build onto the same host.

## What each deploys

**Single-tenant (engine)** — installs the `ebpf-engine` binary, a `0600`
`/etc/ebpf-engine/engine.yaml`, and a `systemd` unit; verifies `/login` serves.
It runs Tetragon in Docker and wires the engine to it for **real** kernel
detection, shipping the repo's `policies/` and `attacks/` — on OrbStack too,
which is a full Linux VM with its own BTF-enabled kernel. `provision_engine`
probes the target first and falls back to `-fake` only when the kernel is older
than 5.15 or has no BTF; pass `ENGINE_MODE=fake` to ask for that deliberately.

**Multi-tenant (control plane)** — provisions the whole console stack natively
under `systemd`:

| Component | Detail |
|-----------|--------|
| Postgres | tenant data, row-level security |
| Keycloak | realm `ebpf-soc`, OIDC/PKCE `console-bff` client, `tenant` claim mapper, the password policy, one operator per tenant + one cross-tenant `msoc-admin` |
| control plane | the BFF + gRPC(mTLS) + central store, secrets via `EnvironmentFile` |
| nginx | serves the console SPA, proxies `/api` + `/auth`, fixes the sign-out redirect |
| sim-agents | one per tenant — enroll over mTLS and stream telemetry so the console has data |

Override the tenant list with `TENANTS="acme globex"`; other knobs
(`KC_PORT`, `CP_HTTP_PORT`, `ENGINE_PORT`, `KC_VERSION`, …) are at the top of
[`lib.sh`](lib.sh). Generated credentials are also written to
`.deploy-build/credentials-<host>.txt` (`0600`, git-ignored).

## Files

| File | Role |
|------|------|
| `lib.sh` | shared: build, `provision_engine`, `provision_controlplane`, lock-aware `PKG`, systemd/nginx/realm templates, the policy-compliant password generator |
| `driver-orbstack.sh` | reaches an OrbStack machine: `RUN`=`orb … sudo`, `PUT`=machine reads the Mac FS, creates the machine if absent |
| `driver-ssh.sh` | reaches a server: `RUN`=`ssh … sudo`, `PUT`=`scp`, probes SSH + passwordless sudo |
| `single-tenant-*.sh`, `multi-tenant-*.sh` | thin entrypoints — set config + source `lib.sh` + a driver + call one `provision_*` |
| `estate.sh` | the production estate: six SSH hosts, in order, preflighted and verified |
| `estate-orbstack.sh` | the same platform locally on OrbStack: console + real agent VMs + engine, verified; `--destroy` tears it down |

Adding a target means writing one driver (`RUN`/`PUT` + `TARGET_HOST`); the
provisioning is reused unchanged. A driver may override `PKG`/`put_dir` for a
non-apt target.

## Prerequisites

- **Local build host** (your Mac): Go, Node/npm — the scripts cross-compile
  `linux/amd64` static binaries and build the console there.
- **OrbStack targets**: [OrbStack](https://orbstack.dev) installed.
- **Server targets**: reachable over SSH with **passwordless sudo**; the scripts
  target **Debian/Ubuntu (apt)**. `TARGET_HOST` should be the public DNS/IP that
  browsers and the OIDC issuer use (defaults to the SSH host). Put TLS in front
  for production — these bring the stack up on HTTP.

## Security notes (the same care as the rest of the repo)

- The engine's dashboard password lives in a `0600` YAML config, **never** in
  `ExecStart` — `systemd` expands `$VAR` in `ExecStart` (a `$` in the password
  would be silently eaten) and `/proc/<pid>/cmdline` is world-readable.
- The control plane's DB DSN, OIDC secret, and admin bearer travel in a
  `systemd` `EnvironmentFile`, read via `CP_PG_DSN` / `CP_OIDC_CLIENT_SECRET` /
  `CP_ADMIN_TOKEN` — off the command line for the same reason.

## Verifying a deploy

```bash
# engine: full auth round-trip (use a cookie jar — the app is session-based)
curl -s -c /tmp/j -o /dev/null -w '%{redirect_url}\n' \
  http://<ip>:8090/api/login --data-urlencode user=admin --data-urlencode pass='<printed>'
curl -s -b /tmp/j -o /dev/null -w '%{http_code}\n' http://<ip>:8090/api/alerts   # 200

# console: OIDC redirect + per-tenant data isolation
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' http://<ip>/auth/login  # 302 -> keycloak
```

## Relationship to `../deploy-platform.sh`

`deploy-platform.sh` is the older **monolithic, resumable** multi-tenant server
wizard: a Docker-Compose data tier, a step ledger under `.deploy/`, and tight
integration with `migrate.sh` / `pki.sh` / `tenantctl` / `smoke.sh`. These
scripts are the newer, **OrbStack-first, target-split** path with a native
`systemd` data tier. For local work and straightforward servers, use these; for
a production server that wants the full resumable/secret-ledger flow, that
wizard still stands. The two do not share state.
