# eBPF Threat Choke Gateway

A proactive, kernel-level threat **detection + enforcement** platform.
Tetragon emits kernel events; a Go correlation engine scores chains of
suspicious behaviour; two **Choke Gateways** convert those scores (and
operator actions) into graduated, audited enforcement:

- **Process choke** — throttle → tarpit → quarantine (cgroup v2 freeze)
  → sever (SIGKILL), keyed on Tetragon's stable `exec_id` so a single
  process is the unit of control.
- **Network / device choke** — a *second, parallel* data plane that
  throttles or blocks a LAN device's forwarded traffic keyed by **MAC
  address**, using a `tc` clsact eBPF program on an inline transparent
  bridge.

Everything ships as a **single statically-linked Go binary** — the React
console is compiled to a static bundle and embedded with `go:embed`, so
there is no Node runtime and no external services in production. Storage
is a single SQLite file (WAL) by default, or Postgres when configured.

```
[ kernel ] --eBPF kprobes--> [ Tetragon ] --gRPC--> [ engine + choke gateways ]
     ▲                                                        │
     └── cgroup/tc BPF (choke.o, devchoke.o) ◀── enforcers ───┤
                                                              ├── SOC dashboard      (/)
                                                              ├── Process choke      (/choke)
                                                              ├── Network choke      (/devices)
                                                              ├── Fleet console      (/fleet)
                                                              └── cgroup v2 tiers
                                                                  · choke-throttled    (5% CPU)
                                                                  · choke-tarpit       (1% CPU)
                                                                  · choke-quarantined  (frozen)
                                                                  + SIGKILL on sever
```

> **Real eBPF runs on Linux only.** `make fake` exists for unit tests and
> frontend iteration but is **not** the deploy story. For local development use
> the [OrbStack mirror](docs/deployment/orbstack-local-mirror.md); to run the
> engine against real eBPF events, deploy to a Linux host
> ([docs/deployment/ubuntu-server.md](docs/deployment/ubuntu-server.md)).

## Documentation

| Doc | Purpose |
|-----|---------|
| **README.md** (this file) | One-page overview + quick start |
| [docs/](docs/README.md) | Full documentation index |
| [docs/getting-started/developer-onboarding.md](docs/getting-started/developer-onboarding.md) | **New here? Start here** — binaries, layout, build/test, local-run options |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Branch/commit/PR conventions + the local gates a change must pass |
| [docs/architecture/overview.md](docs/architecture/overview.md) | How everything works: components, data flow, full API surface |
| [docs/architecture/state-ladder.md](docs/architecture/state-ladder.md) | The five-rung per-process/per-device state machine |
| [docs/architecture/network-choke-gateway.md](docs/architecture/network-choke-gateway.md) | Per-device (MAC) enforcement via `tc` clsact on an inline bridge |
| [docs/deployment/ubuntu-server.md](docs/deployment/ubuntu-server.md) | Recommended step-by-step deploy on a fresh Ubuntu server |
| [docs/deployment/tarball-quickstart.md](docs/deployment/tarball-quickstart.md) | Fastest path: `make tarball`, scp, run |
| [docs/deployment/network-choke-gateway.md](docs/deployment/network-choke-gateway.md) | Inline transparent-bridge gateway for the device choke |
| [docs/deployment/azure.md](docs/deployment/azure.md) | Azure deployment guide |
| [docs/deployment/orbstack-local-mirror.md](docs/deployment/orbstack-local-mirror.md) | Durable local mirror of the multi-tenant console (OrbStack + systemd) |
| [docs/production-rollout/README.md](docs/production-rollout/README.md) | Mass-deployment + day-2 operating model for many gateways |
| [docs/operations/reset-engine-and-policies.md](docs/operations/reset-engine-and-policies.md) | Reset the engine and reload policies |
| [docs/reference/chokectl.md](docs/reference/chokectl.md) | `chokectl` fleet CLI reference |
| [docs/frontend-dev/README.md](docs/frontend-dev/README.md) | The embedded React console (stack, entries, parity gate) |
| [docs/development/build-plan.md](docs/development/build-plan.md) | Original build plan (historical) |

## Repository layout

```
.
├── README.md                                # this file
├── Makefile                                 # web / build / test / deploy / tarball / fleet
├── docs/                                    # architecture, deployment, ops, reference, frontend, rollout
├── web/                                     # Vite multi-entry React source (built + go:embed'd)
├── chokectl.hosts[.example]                 # fleet host list read by scripts/chokectl
├── scripts/
│   ├── setup.sh                             # idempotent host bootstrap (Docker/Go/Tetragon/clang/cgroup v2)
│   ├── chokectl                             # fleet CLI (status/preset/jail/device-*/…)
│   ├── multipass-doctor.sh                  # self-heals a wedged Multipass VM before deploy
│   └── dev/netns-*.sh                       # 3-netns lab for the device-choke data plane
├── policies/                                # Tetragon TracingPolicy YAMLs
│   ├── network-watch.yaml                   # policy name: outbound-connections
│   ├── privilege-escalation.yaml
│   ├── sensitive-files.yaml
│   ├── choke/                               # ChokePolicy DSL (agent-loop-cap, network-tools-tarpit, shell-egress-throttle)
│   └── enforce/                             # Tetragon Sigkill/Override (sever-pipe-to-shell, override-credential-read)
├── attacks/                                 # 6 attack-simulation scripts
├── deploy/                                  # install.sh, ebpf-engine.service, engine.yaml.example, nginx/
└── engine/                                  # Go correlation engine (single binary)
    ├── cmd/engine/main.go                   # entry: gRPC client, both gateways, -fake mode
    └── internal/
        ├── api/                             # HTTP, SSE, auth, embedded web, fleet + choke/device handlers
        ├── score/                           # per-event + chain scoring rules
        ├── store/                           # SQLite (WAL) + Postgres: events/alerts/decisions
        ├── tree/                            # in-memory exec_id process tree (TTL'd)
        ├── choke/                           # gateway, device gateway, circuit, tokens
        ├── enforce/                         # cgroupv2, severer, bpfmap (choke.c), devbpf (devchoke.c), seccomp
        ├── device/                          # MAC↔IP↔hostname table + DHCP/neigh discovery
        ├── origin/                          # SSH-session attribution (journald tailer)
        └── config/, logging/, metrics/, sysproc/
```

## Fast paths

| Goal | Command |
|------|---------|
| **Deploy to the Multipass `ebpf` VM** | **`make deploy`** (build + sync + restart + print URL) |
| Fast iterate after first deploy | `make redeploy` |
| Deploy to any SSH host (Azure/EC2/bare metal) | `make deploy-remote HOST=user@ip` |
| Production install (systemd + `/etc/ebpf-engine`) | `make install-vm` |
| Put nginx/TLS in front on :443 | `make tls-vm` |
| Bring up a Postgres 16 container on the VM | `make pg-vm` |
| Tail engine logs on the VM | `make vm-logs` |
| Engine status + cgroup tier counts | `make vm-status` |
| Fire an attack inside the VM | `make vm-attack SCRIPT=03-reverse-shell.sh` |
| Run Go unit tests | `make test` |
| Cross-compile for a Linux server | `make build-linux` |
| Compile the device-choke BPF object | `make devchoke` (Linux + clang) |
| End-to-end device-choke lab (3 netns) | `make netns-smoke` (Linux + root) |
| Bundle binary + policies + attacks + BPF C | `make tarball` → `ebpf-poc-amd64.tar.gz` |
| Local UI iteration only (test mode) | `make fake` — never used for real deploys |

## Requirements

**For local UI development (any OS):**
- Go 1.25+
- Node 18+ / npm (only to rebuild the React console via `make web`)

**For real Tetragon deployment:**
- Linux (Ubuntu 22.04 / 24.04 LTS), kernel ≥ 5.15
- `/sys/kernel/btf/vmlinux` present (BTF enabled)
- Docker (for the Tetragon container — pinned to `quay.io/cilium/tetragon:v1.6.1`)
- `sudo` (Tetragon needs `--privileged --pid=host`; enforcement needs cgroup v2)
- `clang` + kernel uapi headers to compile the BPF data planes (`setup.sh` installs these on the target)

The Go code itself builds on macOS for development convenience, but
Tetragon only runs on Linux — actual events flow only on a Linux host.

## Quick start

### Local development — the OrbStack mirror

For day-to-day work on the multi-tenant console + control plane, run the durable
local stack — Postgres + Keycloak + control plane + console, all systemd-managed
in one OrbStack machine, with a synthetic agent feeding realistic tenant data:

**[docs/deployment/orbstack-local-mirror.md](docs/deployment/orbstack-local-mirror.md)**
— one-machine setup, survives reboot, no eBPF required.

`make fake` (or `engine -fake`) synthesizes events with no kernel at all — handy
for pure UI iteration and tests.

### Engine against real eBPF

Real Tetragon events + kernel enforcement require a **Linux host** (a server, or
an OrbStack Ubuntu machine running Tetragon). Deploy the engine there, then run
the attack demo:

1. Deploy — **[docs/deployment/ubuntu-server.md](docs/deployment/ubuntu-server.md)**
   (recommended) or [tarball-quickstart.md](docs/deployment/tarball-quickstart.md).
2. Open `http://<host>:8080/choke`, trigger an attack from `attacks/` (e.g.
   `03-reverse-shell.sh`), and watch the process climb the state ladder
   (`pristine → throttled → tarpit → …`) in the Decision Tape and in the kernel
   cgroups (`/sys/fs/cgroup/choke-*/cgroup.procs`).

## How detection + enforcement works

1. **Tetragon** loads each TracingPolicy as an in-kernel eBPF program.
   Every `execve` already produces a `process_exec` event; the YAML
   policies add `process_kprobe` events for setuid, sensitive-file
   access (including the seeded **honeypot** decoys), and shell-driven
   outbound TCP connections.

2. **The engine** subscribes to Tetragon's gRPC `GetEvents` stream and
   maintains a process tree keyed by the stable `exec_id` (which survives
   PID reuse). For every event it:
   - inserts a row into `events`,
   - adds the event's score to its node, then walks ancestors (≤10 hops)
     summing scores into a **chain score**,
   - calls the **Choke Gateway** on *every* event (not just alert-worthy
     ones), so a process can transition to *throttled* before it ever
     raises an alert. The ladder is monotonic; below-threshold calls are
     no-ops. Crossing a rung runs the enforcer chain (cgroup move / freeze
     / SIGKILL) and appends a **hash-chained** row to the `decisions`
     audit table,
   - if the chain score ≥ 10, writes an `alerts` row, classifies severity,
     and broadcasts to all SSE subscribers.

3. **The consoles** (SOC / Choke / Devices / Fleet — one embedded React
   app, one HTML entry each) load the recent slice via `/api/events`,
   `/api/alerts`, `/api/decisions`, then subscribe to `/api/stream` for
   live updates. Auth is a bcrypt credential behind an HMAC-signed,
   **stateless** cookie (survives restart); unsafe writes also carry a
   CSRF token. Unauthenticated browser requests redirect to `/login`;
   API requests get 401.

The **process choke** follows `-enforce` and is flippable at runtime via
`/api/choke/mode`. The **device choke** is a separate, operator-driven
data plane that enforces whenever it has the `tc` backend and is neither
dry-run nor kill-switched — independent of `-enforce`. "Observe
processes, enforce on devices" is a valid posture.

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

**Alert severity** thresholds: `low` ≥ 5, `medium` ≥ 10, `high` ≥ 20,
`critical` ≥ 40. Calibrated so any single event is at most "low";
"high"/"critical" requires a chain — which is what makes detection
proactive.

**Choke thresholds** are separate from alert severity. The binary
defaults are `throttle 5 / tarpit 15 / quarantine 25 / sever 40`, but the
deploy path raises them to **`20 / 50 / 120 / 200`** so Ubuntu's sshd
MOTD churn (which scores ~85) only reaches *tarpit*, never quarantine
(which would freeze sshd and lock the operator out). See
[docs/architecture/state-ladder.md](docs/architecture/state-ladder.md).

## Attack-simulation scripts

| Script                        | Triggers                                       | Expected severity |
|-------------------------------|------------------------------------------------|-------------------|
| `01-webshell.sh`              | exec(curl) + chmod +x + cat /etc/shadow        | high / critical   |
| `02-credential-theft.sh`      | reads of shadow, sudoers, ~/.ssh/*             | high              |
| `03-reverse-shell.sh`         | bash opens TCP socket (loopback)               | medium / high     |
| `04-privilege-escalation.sh`  | setuid(0) + root reads of credentials          | high              |
| `05-living-off-the-land.sh`   | curl \| sh pattern + base64 decode             | critical          |
| `06-persistence.sh`           | chmod +x of staged script + dotfile recon      | medium            |

All scripts are safe by construction: network calls go to `example.com`
or `127.0.0.1`, no real exfiltration occurs, and any temp file is cleaned
up on exit.

## HTTP API

Everything is served by the engine on `:8080` (front with nginx/TLS in
production). All paths except the public ones require the `soc_session`
cookie; unsafe writes also require the `X-CSRF-Token` header.

- **Core / SOC** — `/`, `/login`, `/api/{login,logout,whoami}`,
  `/api/{events,alerts,process/<exec_id>,stream}`,
  `/api/{policies,attacks,run-attack,honeypots,policy-stats,origin}`,
  `/api/{version,system-health,decisions,verify-chain}`.
- **Process choke** (`/choke`) — `/api/choke/{state,circuits,buckets,thresholds,policies,cgroups,processes,process/<id>,proc/<pid>}`
  plus writes `{manual,bulk-manual,jail,forget,thaw,annotate,kill-switch,preset,mode,forensic-snapshot,policy/preview}`.
- **Device choke** (`/devices`) — `/api/choke/{devices,device-state,device-flows}`
  plus writes `{device-jail,device-thaw,device-mode,device-kill-switch}`.
- **Fleet** (`/fleet`, enabled by `-fleet-hosts`) — `/api/fleet/{hosts,state,cgroups,decisions,alerts,devices}`
  plus writes `{preset,thresholds,kill-switch,thaw,device-jail}`.

The full request/response table lives in
[docs/architecture/overview.md](docs/architecture/overview.md#http-api-surface).

## Configuration

Every setting is a CLI flag; long-running deployments can instead point
`-config` at a YAML file where each field maps 1:1 to a flag (**flags
always win**). See [deploy/engine.yaml.example](deploy/engine.yaml.example)
for the full annotated surface — storage backend, auth, choke thresholds,
BPF data-plane paths, device-choke interfaces, fleet hosts, logging, and
OTel metrics endpoint.

## Deployment modes

| Mode | How |
|------|-----|
| **Detect-only** | `enforce: false` — decisions audited, kernel untouched. The safe default. |
| **Enforcing (process)** | `-enforce` — real cgroup throttle/freeze + SIGKILL on the host. |
| **Enforcing (device/MAC)** | 2-NIC inline bridge + `-devchoke-obj/-devchoke-iface`; independent of `-enforce`. |
| **Dry-run** | `-dry-run` — records decisions, executes nothing (shadow a new policy). |
| **Fake** | `-fake` — synthesizes events, no Tetragon (unit tests / UI iteration only). |

## Observability

- **Structured logs** — `-log-format json` (for journald → Vector →
  Loki/Elastic), `-log-level debug|info|warn|error`.
- **Metrics** — OpenTelemetry meter provider; `-otlp-endpoint` exports
  over OTLP/HTTP (or `stdout` for dev). Covers event/alert counts,
  enforcement decisions, BPF map size + attached links, HTTP request
  latency, and Tetragon connection state.
- **Audit chain** — every enforcement decision is a hash-chained row;
  `GET /api/verify-chain` re-walks it and detects tampering.

## Validation status

- `make test` — Go unit tests across `score`, `tree`, `store`, `choke`,
  `enforce`, `device`, `origin`, `policy` pass.
- `make build` / `make build-linux` — statically-linked Linux ELF (no
  CGO, no runtime deps) with the React console embedded.
- `make fake` — synthesizes events through the production code path; the
  dashboard renders them and the auth flow works end-to-end.
- `make netns-smoke` — proves the device-choke data plane drops and
  restores forwarded traffic for one device MAC in a 3-netns lab (6/6).
- Real Tetragon on Ubuntu 22.04 + kernel 5.15 in a Multipass VM — all six
  attack scripts produce the expected alerts and ladder transitions.

For component-level details, see
[docs/architecture/overview.md](docs/architecture/overview.md).

## Limitations

- **Single host.** One engine ↔ one Tetragon socket. The Postgres backend
  and the `/fleet` fanout are the first steps toward multi-host, but there
  is no central fan-in collector yet — the fleet console drives peers
  individually.
- **Single-user auth.** One admin credential; no multi-user / RBAC model
  (sessions are stateless and survive restart).
- **HTTP only.** TLS termination is done by a reverse proxy (nginx/Caddy)
  — see the deployment guides (`make tls-vm`).
- **Fixed scoring rules.** No baseline learning; tuning is manual in
  [engine/internal/score/scorer.go](engine/internal/score/scorer.go) and
  via the thresholds.
- **Device choke is operator-driven.** A forwarding node has no per-device
  Tetragon telemetry, so there is no automatic score path for the MAC
  gateway yet — it's manual jail/thaw with an audit trail. MAC keying also
  assumes the gateway is the device's L2 neighbour.

## What's next

- A central fan-in collector so many engines report to one console.
- Translate Sigma rules into TracingPolicies for broader coverage.
- Move from SQLite to ClickHouse when volume warrants it.
- OCSF event normalization for SIEM export.
- An automatic score path for the device (MAC) gateway.
