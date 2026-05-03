# eBPF Threat Choke Gateway

A proactive, kernel-level threat **detection + enforcement** platform.
Tetragon emits kernel events; a Go correlation engine scores chains of
suspicious behaviour; the **Choke Gateway** converts those scores into
graduated, audited enforcement actions — throttle, tarpit, quarantine
(cgroup v2 freeze), or sever (SIGKILL) — keyed on Tetragon's stable
exec_id so a single process is the unit of control.

```
[ kernel ] -- eBPF kprobes --> [ Tetragon ] -- gRPC --> [ engine + choke gateway ]
                                                              │
                                                              ├── SOC dashboard (/)
                                                              ├── Choke console (/choke)
                                                              └── cgroup v2 tiers
                                                                  · choke-throttled    (5% CPU)
                                                                  · choke-tarpit       (1% CPU)
                                                                  · choke-quarantined  (frozen)
                                                                  + SIGKILL on sever
```

> **Production path is Multipass / real Linux only.** `make fake`
> exists for unit tests and frontend iteration but is **not** the
> deploy story. To exercise the gateway against real eBPF events,
> see [docs/operations/run-on-multipass-vm.md](docs/operations/run-on-multipass-vm.md).

| Doc                                                                                       | Purpose                                              |
|-------------------------------------------------------------------------------------------|------------------------------------------------------|
| **README.md** (this file)                                                                 | One-page overview + quick start                      |
| [docs/](docs/README.md)                                                                   | Full documentation index                             |
| [docs/architecture/overview.md](docs/architecture/overview.md)                            | How everything works, components, data flow          |
| [docs/architecture/state-ladder.md](docs/architecture/state-ladder.md)                    | Choke gateway state transitions                      |
| [docs/getting-started/multipass-vm-setup.md](docs/getting-started/multipass-vm-setup.md)  | Local Linux VM on macOS via Multipass                |
| [docs/deployment/linux-server.md](docs/deployment/linux-server.md)                        | Step-by-step deploy on a fresh Linux server          |
| [docs/deployment/azure.md](docs/deployment/azure.md)                                      | Azure deployment guide                               |
| [docs/deployment/commands.md](docs/deployment/commands.md)                                | Deployment command reference                         |
| [docs/operations/run-on-multipass-vm.md](docs/operations/run-on-multipass-vm.md)          | Day-to-day ops runbook once the VM is set up         |
| [docs/operations/reset-engine-and-policies.md](docs/operations/reset-engine-and-policies.md) | Reset the engine and reload policies              |
| [docs/reference/chokectl.md](docs/reference/chokectl.md)                                  | `chokectl` fleet CLI reference                       |
| [docs/development/build-plan.md](docs/development/build-plan.md)                          | Original 5-day build plan that produced this codebase|

## Repository layout

```
.
├── README.md                                # this file
├── Makefile                                 # build / test / fake / tarball / clean
├── docs/                                    # architecture, deployment, ops, reference, development
├── scripts/setup.sh                         # idempotent Day-1 install on a fresh VM
├── policies/                                # Tetragon TracingPolicy YAMLs
│   ├── network-watch.yaml                   # policy name: outbound-connections
│   ├── privilege-escalation.yaml
│   └── sensitive-files.yaml
├── engine/                                  # Go correlation engine
│   ├── cmd/engine/                          # main entrypoint (incl. -fake mode)
│   └── internal/
│       ├── api/                             # HTTP, SSE, auth, embedded UI
│       ├── score/                           # per-event + chain scoring rules
│       ├── store/                           # SQLite (events, alerts) — pure-Go driver
│       └── tree/                            # in-memory process tree (TTL'd)
└── attacks/                                 # 6 attack-simulation scripts
```

## Fast paths

| Goal                                  | Command                                                       |
|---------------------------------------|---------------------------------------------------------------|
| **Deploy to the Multipass `ebpf` VM** | **`make deploy`** (build + sync + restart + print URL)        |
| Fast iterate after first deploy       | `make redeploy`                                               |
| Tail engine logs on the VM            | `make vm-logs`                                                |
| Engine status + cgroup tier counts    | `make vm-status`                                              |
| Fire an attack inside the VM          | `make vm-attack SCRIPT=03-reverse-shell.sh`                   |
| Run unit tests                        | `make test`                                                   |
| Cross-compile for a Linux server      | `make build-linux`                                            |
| Bundle binary + policies + attacks    | `make tarball` → `ebpf-poc-amd64.tar.gz`                      |
| Local UI iteration only (test mode)   | `make fake` — never used for real deploys                     |

## Requirements

**For local UI development (any OS):**
- Go 1.22+

**For real Tetragon deployment:**
- Linux (Ubuntu 22.04 / 24.04 LTS), kernel ≥ 5.15
- `/sys/kernel/btf/vmlinux` present (BTF enabled)
- Docker (for the Tetragon container)
- `sudo` (Tetragon needs `--privileged --pid=host`)

The Go code itself builds on macOS for development convenience, but
Tetragon only runs on Linux — actual events flow only on a Linux host.

## Quick start — deploy to the Multipass VM

**Prerequisite**: a Multipass VM named `ebpf` running Ubuntu 22.04+
(kernel ≥ 5.15, BTF enabled). First-time setup:
[docs/getting-started/multipass-vm-setup.md](docs/getting-started/multipass-vm-setup.md).

```bash
make deploy
```

That single command:

1. cross-compiles `engine-linux-amd64` (no CGO),
2. transfers the binary + `policies/` + `attacks/` + `scripts/` into
   `ebpf:/home/ubuntu/ebpf-poc`,
3. runs `setup.sh` to install Docker / Go / Tetragon and enable cgroup
   v2 controllers,
4. applies every TracingPolicy under `policies/` and `policies/enforce/`
   (the latter has Tetragon `Sigkill`/`Override` actions),
5. (re)starts the engine as a transient systemd unit with the choke
   gateway enabled (`-enforce -choke-policies ... -cgroup-root ...`),
6. prints the URLs for the SOC dashboard and Choke console.

Open the printed `http://<vm-ip>:8080/choke` URL. Login: **`admin` /
`ebpf-soc-demo`**.

**Trigger a real attack and watch the gateway respond:**

```bash
make vm-attack SCRIPT=03-reverse-shell.sh
make vm-status        # see live cgroup tier populations
make vm-logs          # tail engine output
```

The reverse-shell process will move from `pristine` → `throttled` →
`tarpit` etc. as its chain score climbs — you'll see it both in the
console's Decision Tape and in the kernel:

```bash
multipass exec ebpf -- cat /sys/fs/cgroup/choke-throttled/cgroup.procs
multipass exec ebpf -- cat /sys/fs/cgroup/choke-quarantined/cgroup.procs
```

For the full step-by-step walkthrough (or to debug a `make deploy`
failure), see **[docs/operations/run-on-multipass-vm.md](docs/operations/run-on-multipass-vm.md)**.

## How detection works

1. **Tetragon** loads each TracingPolicy as an in-kernel eBPF program.
   Every `execve` already produces a `process_exec` event; the YAML
   policies add `process_kprobe` events for setuid, sensitive file
   access, and shell-driven outbound TCP connections.

2. **The engine** subscribes to Tetragon's gRPC `GetEvents` stream and
   maintains a process tree keyed by Tetragon's stable `exec_id` (which
   survives PID reuse). For every event it:
   - Inserts a row into `events`.
   - Adds the event's score to its node, then walks ancestors (up to 10
     hops) summing scores for the chain.
   - If chain score ≥ 10 it inserts an `alerts` row, classifies severity
     (`info` < `low` < `medium` < `high` < `critical`), and broadcasts to
     all SSE subscribers.

3. **The dashboard** (single-page app embedded in the binary) loads the
   recent slice via `/api/events` and `/api/alerts`, then subscribes to
   `/api/stream` for live updates. Auth is enforced by an HttpOnly
   cookie middleware; unauthenticated browser requests redirect to
   `/login`, API requests get 401.

### Scoring

| Trigger                          | Score |
|----------------------------------|-------|
| `curl \| sh` / `wget \| sh`        | +25   |
| `nc -e` / shell-arg netcat        | +20   |
| credential file (`shadow`,`.ssh`) | +20   |
| `base64 -d` in args               | +15   |
| setuid(0) kprobe                  | +15   |
| outbound TCP from a shell         | +12   |
| sensitive file (other)            | +8    |
| `chmod +x`                        | +5    |
| network tool exec                 | +5    |
| network downloader exec           | +3    |
| `bash -c`                         | +1    |

Severity thresholds: `low` ≥ 5, `medium` ≥ 10, `high` ≥ 20, `critical` ≥ 40.
Calibrated so any single event is at most "low"; "high"/"critical" requires
a chain — which is what makes detection proactive.

## Attack-simulation scripts

| Script                        | Triggers                                       | Expected severity |
|-------------------------------|------------------------------------------------|-------------------|
| `01-webshell.sh`              | exec(curl) + chmod +x + cat /etc/shadow        | high / critical   |
| `02-credential-theft.sh`      | reads of shadow, sudoers, ~/.ssh/*             | high              |
| `03-reverse-shell.sh`         | bash opens TCP socket (loopback)               | medium / high     |
| `04-privilege-escalation.sh`  | setuid(0) + root reads of credentials          | high              |
| `05-living-off-the-land.sh`   | curl \| sh pattern + base64 decode             | critical          |
| `06-persistence.sh`           | chmod +x of staged script + dotfile recon      | medium            |

All scripts are safe by construction: network calls go to `example.com` or
`127.0.0.1`, no real exfiltration occurs, and any temp file is cleaned up
on exit.

## HTTP API

| Method | Path                       | Auth | Returns                                      |
|--------|----------------------------|------|----------------------------------------------|
| GET    | `/`                        | yes  | the dashboard HTML                           |
| GET    | `/login`                   | no   | login page                                   |
| POST   | `/api/login`               | no   | sets `soc_session` cookie + 303 → `/`        |
| GET    | `/api/logout`              | no   | clears cookie + 303 → `/login`               |
| GET    | `/api/whoami`              | yes  | `{"user":"admin"}`                           |
| GET    | `/api/events`              | yes  | last 200 events                              |
| GET    | `/api/alerts`              | yes  | last 100 alerts                              |
| GET    | `/api/process/<exec_id>`   | yes  | `{chain, events}` for a given exec_id        |
| GET    | `/api/stream`              | yes  | SSE: `data: {"type":"alert"\|"event", ...}`  |
| GET    | `/favicon.svg`             | no   | the icon (also served at `/favicon.ico`)     |

## Validation status

Tested end-to-end during development:

- `make test` — all unit tests in `score`, `tree`, `store` pass.
- `make build` / `make build-linux` — produces a 24 MB statically-linked
  Linux ELF (no CGO, no runtime deps).
- `make fake` — synthesizes events through the production code path,
  the dashboard renders them, and the auth flow (login → cookie →
  protected fetch → logout) works as expected.
- Real Tetragon on Ubuntu 22.04 + kernel 5.15 in a Multipass VM —
  all six attack scripts produce the expected alerts; KPI counters,
  MITRE coverage, IOCs, and network panel populate correctly.

For component-level details and what was changed during the most recent
session, see [docs/architecture/overview.md](docs/architecture/overview.md).

## Limitations

- **Single host.** The engine talks to one Tetragon socket and writes
  one SQLite file. Multi-host needs a fan-in collector.
- **Single-user auth.** Sessions are in-memory and lost on engine
  restart. For multi-user / HA, swap `Auth.sessions` for Redis or
  similar.
- **HTTP only.** TLS termination should be done by a reverse proxy
  (Caddy/nginx) — see the deployment guide.
- **Fixed scoring rules.** No baseline learning; tuning is manual via
  `internal/score/scorer.go`.

## What's next

- Translate Sigma rules into TracingPolicies for broader coverage.
- Move from SQLite to ClickHouse when volume warrants it.
- Add OCSF event normalization for SIEM export.
- Switch policies from `Post` to `SIGKILL` to convert this from
  detection into in-kernel prevention.
