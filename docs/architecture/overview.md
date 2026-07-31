# Architecture & system overview

What this project is, how the pieces fit together, and how an event
travels from the kernel to an enforcement action and onto the dashboard.

## What it is

A proactive, **kernel-level threat detection *and* enforcement** platform.
Tetragon emits syscall/kprobe events from inside the kernel via eBPF; a Go
correlation engine consumes them, builds a process tree, scores chains of
suspicious behaviour, and — this is the part that makes it more than a SOC
dashboard — drives a **Choke Gateway** that converts those scores into
graduated, audited enforcement actions: throttle → tarpit → quarantine
(cgroup v2 freeze) → sever (SIGKILL), keyed on Tetragon's stable `exec_id`
so a single process is the unit of control.

A **second, parallel data plane** extends the same model from *per-process*
to *per-device*: on an inline transparent bridge it throttles or blocks a
LAN device's forwarded traffic keyed by **MAC address** (see
[network-choke-gateway.md](network-choke-gateway.md)).

The whole thing ships as a **single Go binary, no external services
required**. The frontend is a Vite multi-entry **React** app (TypeScript,
Tailwind, Zustand, Radix, D3) built to a static bundle and embedded via
`go:embed` — there is no Node runtime in production. Storage is a single
SQLite file (WAL mode) by default, or Postgres when configured.

## High-level diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                      Linux host (kernel ≥ 5.15)                          │
│                                                                          │
│   ┌─────────────┐    syscalls    ┌────────────────┐                      │
│   │  attack.sh  │ ─────────────▶ │     KERNEL     │ ◀─ TracingPolicy YAML │
│   └─────────────┘                │  eBPF kprobes  │    (tetra add)        │
│                                  │  + cgroup/tc   │ ◀─ choke.o / devchoke.o│
│                                  │  BPF programs  │    (cilium/ebpf load)  │
│                                  └───┬────────┬───┘                       │
│                     process_exec /   │        │  per-PID / per-MAC        │
│                     process_kprobe   │        │  token buckets, verdicts  │
│                             ┌────────▼──┐     │                           │
│                             │ Tetragon  │     │                           │
│                             │ container │     │                           │
│                             └────────┬──┘     │                           │
│                        gRPC GetEvents│        │                           │
│                          (unix sock) │        │                           │
│   ┌──────────────────────────────────▼────────▼────────────────────────┐ │
│   │                          engine (Go, root)                          │ │
│   │  process tree · scorer · origin/SSH attribution · device table      │ │
│   │  Choke Gateway (process) ─┐        ┌─ Device Gateway (MAC)           │ │
│   │  circuit state machine    ├─ audit │  circuit state machine          │ │
│   │  enforcers: cgroupv2,     │ (hash- │  enforcer: devbpf/tc throttler  │ │
│   │   severer, bpfmap         │ chained│                                 │ │
│   │  store: SQLite(WAL)|Postgres  decisions)  metrics: OTel   HTTP :8080 │ │
│   └───────────────────────────────────┬─────────────────────────────────┘ │
└───────────────────────────────────────┼───────────────────────────────────┘
                                         │ HTTP (front with nginx/TLS)
                         ┌───────────────▼────────────────┐
                         │  Browser — embedded React SPA  │
                         │  SOC · Choke · Devices · Fleet  │
                         └────────────────────────────────┘
```

## Components

### Tetragon (Cilium)

Tetragon is the eBPF runtime that sources events for the **process** choke.
It loads each `TracingPolicy` YAML as one or more in-kernel eBPF programs
and streams structured events to userspace over gRPC. We pin to
**`quay.io/cilium/tetragon:v1.6.1`** (the `:latest` tag is no longer
published). It runs as a `--privileged --pid=host` container.

Policies live in [policies/](../../policies). All of them are **detection**
policies — `Post` action, feeding the scorer:

| Policy                  | Kprobe                     | Catches                                                             | MITRE          |
|-------------------------|----------------------------|---------------------------------------------------------------------|----------------|
| `outbound-connections`  | `tcp_connect`              | TCP connect from `bash`/`sh`/`nc`/`socat` (shells calling out)      | T1071 C2       |
| `privilege-escalation`  | setuid hooks               | `setuid(0)`, sudo to root                                           | T1548 PrivEsc  |
| `sensitive-file-access` | `security_file_permission` | Reads/writes of `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/root/.ssh/`, **`/var/lib/ebpf-engine/honey/`** | T1003 CredAccess + honeypot |
| `override-credential-read` | `security_file_permission` | Credential-path reads (`~/.ssh/`, `~/.aws/`, `~/.gnupg/`, …) by non-allowlisted binaries | T1003 CredAccess |

**Tetragon never enforces here — the engine does.** Every policy above declares
`policy-mode: monitor`, under which Tetragon suppresses `Sigkill`/`Override` in
the kernel while leaving `Post` untouched. That is deliberate: a Tetragon kill
is independent of the engine's choke mode, so it fires whatever the console says,
leaves no audit row, cannot be reversed, and is not covered by the kill-switch.
Twice it cost us real damage — an SSH lockout, and `debconf` killed mid-configure
on three hosts (`matchBinaries` matches the *executable*, so allow-listing an
interpreted script has no effect). Enforcement therefore belongs to the choke
gateway, which matches the process it actually scored and offers a reversible
ladder. See [threat-model](../plan/threat-model.md) EN-1b/EN-1c/EN-1d/EN-3.

Because the mode is declarative it survives a restart, and Tetragon reports it
over gRPC — so the agent carries the host's real kernel posture on its heartbeat
and the console flags any divergence rather than showing the engine's mode as if
it were the whole story.

The honeypot prefix is a directory the engine seeds with five decoy
credential-style files on startup
([honeypots.go](../../engine/internal/api/honeypots.go): `_passwd`,
`_shadow`, `_id_rsa`, `_aws_credentials`, `_db_backup.sql`). No legitimate
process should ever read them, so **any hit under that prefix is a
high-confidence signal** — the dashboard surfaces it with a 🍯 *honey*
badge.

`process_exec` events fire for **every** `execve` for free — they're the
spine of the process tree.

### Engine ([engine/](../../engine))

A Go binary, statically linked (`CGO_ENABLED=0`), no runtime dependencies.
Responsibilities, by package:

- **gRPC client** ([cmd/engine/main.go](../../engine/cmd/engine/main.go)) —
  subscribes to Tetragon's `GetEvents` stream.
- **Process tree** ([internal/tree](../../engine/internal/tree)) — in-memory
  tree keyed by `exec_id` (survives PID reuse), TTL-bounded (~10 min).
- **Scorer** ([internal/score](../../engine/internal/score)) — per-event
  scores; ancestors are summed (≤10 hops) to a chain score.
- **Store** ([internal/store](../../engine/internal/store)) — `events`,
  `alerts`, and the hash-chained `decisions` audit table. SQLite with
  `journal_mode=WAL` by default, or Postgres (`-store=postgres -pg-dsn …`).
- **Choke Gateway** ([internal/choke](../../engine/internal/choke)) — the
  per-process state machine + enforcement. See [state-ladder.md](state-ladder.md).
  - **circuit** ([internal/choke/circuit](../../engine/internal/choke/circuit))
    — the monotonic five-rung state machine (string-keyed, reused by both
    gateways).
  - **tokens** ([internal/choke/tokens](../../engine/internal/choke/tokens))
    — operator/session token accounting.
- **Enforcers** ([internal/enforce](../../engine/internal/enforce)) —
  composed via `Multi`: `cgroupv2` (throttle/tarpit/quarantine-freeze),
  `severer` (SIGKILL), and `bpfmap` (cilium/ebpf `choke.o` per-PID token
  buckets on cgroup/connect hooks) as a telemetry mirror; plus the device
  `devbpf`/`devthrottler` (tc data plane). A `seccomp` package exists but
  is not currently wired into the active chain.
- **Device Gateway + table** ([internal/choke/devgateway.go](../../engine/internal/choke/devgateway.go),
  [internal/device](../../engine/internal/device)) — MAC-keyed enforcement,
  passive DHCP/neigh discovery.
- **Origin tracker** ([internal/origin](../../engine/internal/origin)) —
  attributes processes to the SSH session (source IP + key fingerprint)
  that spawned them, by tailing sshd's journald log on Linux.
- **HTTP API + SSE fanout** ([internal/api](../../engine/internal/api)) —
  serves the embedded React consoles, JSON APIs, and a Server-Sent Events
  stream. Every alert/event/decision broadcasts to all subscribers.
- **Fleet fanout** ([internal/api/fleet.go](../../engine/internal/api/fleet.go))
  — when `-fleet-hosts` is set, `/api/fleet/*` logs into each peer and fans
  the operation out server-side (drives N hosts from one console).
- **Auth** ([internal/api/auth.go](../../engine/internal/api/auth.go)) —
  bcrypt credentials, HMAC-signed **stateless** cookie sessions, CSRF tokens.
- **Metrics** ([internal/metrics](../../engine/internal/metrics)) — OpenTelemetry
  meter provider; `-otlp-endpoint` exports to an OTLP/HTTP collector.
- **Config** ([internal/config](../../engine/internal/config)) — optional YAML
  file (`-config`); every field maps 1:1 to a CLI flag, and **flags always win**.

### Dashboard ([web/](../../web/) → embedded in the engine)

A Vite multi-entry **React** app (source under [`web/`](../../web/)) built
to a static bundle and embedded into the engine binary via `go:embed`
(staged into `engine/internal/api/web/` by `make web`). Tailwind is compiled
at build time; there are no runtime CDN dependencies — Go stays the only
production server. Five console entries, each its own HTML entry + route:

| Route      | Console                | Purpose                                                        |
|------------|------------------------|----------------------------------------------------------------|
| `/`        | **SOC dashboard**      | Executive summary, alert triage, MITRE coverage, IOCs, live event stream |
| `/choke`   | **Choke Gateway**      | Process state ladder, thresholds, manual override, kill-switch, policy workbench |
| `/devices` | **Network Choke**      | Per-device (MAC) discovery, flows, jail/thaw, enforcement mode |
| `/fleet`   | **Fleet Console**      | Drive N hosts as a unit (status, presets, thresholds, kill-switch) |
| `/login`   | **Login**              | Auth gate                                                      |

The console runs the **UI 2.0** redesign: a cool neutral-slate palette, a
unified enterprise header across all pages, an executive summary band on the
SOC dashboard, and decluttered toolbars. See
[frontend-dev/README.md](../frontend-dev/README.md) for the stack and the
78-panel parity gate.

### Auth ([engine/internal/api/auth.go](../../engine/internal/api/auth.go))

A single admin user with bcrypt-hashed credentials. The plaintext password
is hashed once at startup and never stored; prefer `pass_hash` in config so
plaintext never lands on disk at all.

| Property            | Value                                                                        |
|---------------------|------------------------------------------------------------------------------|
| Algorithm           | bcrypt (`golang.org/x/crypto/bcrypt`, default cost 10)                        |
| Username comparison | `crypto/subtle.ConstantTimeCompare`                                          |
| Cookie name         | `soc_session`                                                                |
| Session model       | **Stateless** — HMAC-signed cookie (secret at `-secret`, auto-generated 0600). Sessions survive engine restart. |
| CSRF                | `csrf_token` cookie echoed as `X-CSRF-Token` on unsafe writes                |
| Rate limit          | 10 login attempts per remote IP per minute                                   |
| Public paths        | `/login`, `/api/login`, favicons, PWA assets, `/assets/*`                    |
| Everything else     | 302 → `/login` for HTML, 401 JSON for `/api/*`                               |

There is **no baked-in credential**. You must set one via `-user`/`-pass` (or
`pass_hash` in config, preferred for production so plaintext never lands on
disk); the engine **fails fast at startup** if none is provided rather than
shipping a known default. The demo deploy paths (`make deploy`, the netns dev
labs) set `admin / ebpf-soc-demo` explicitly — change it for any real deployment.

## Scoring

Per-event scores accumulate down the process tree; the **chain score** is
the sum over the ancestor walk. An alert is raised when the chain crosses 10.

| Trigger                            | Score |
|------------------------------------|-------|
| `curl \| sh` / `wget \| sh`          | +25   |
| `nc -e` / shell-arg netcat          | +20   |
| credential file (`shadow`, `.ssh`)  | +20   |
| `base64 -d` in args                 | +15   |
| setuid(0) kprobe                    | +15   |
| outbound TCP from a shell           | +12   |
| sensitive file (other)              | +8    |
| `chmod +x`                          | +5    |
| network tool exec                   | +5    |
| network downloader exec             | +3    |
| `bash -c`                           | +1    |

**Alert severity** thresholds: `low` ≥ 5, `medium` ≥ 10, `high` ≥ 20,
`critical` ≥ 40 ([scorer.go](../../engine/internal/score/scorer.go)).
Calibrated so any single event is at most "low"; "high"/"critical" requires
a chain — which is what makes detection proactive.

**Choke thresholds** are separate from alert severity. The binary defaults
are `throttle 5 / tarpit 15 / quarantine 25 / sever 40`, but the deploy
path (Makefile / `engine.yaml`) raises them to **`20 / 50 / 120 / 200`** so
Ubuntu's sshd MOTD churn (which scores ~85) only reaches *tarpit*, never
quarantine (which would freeze sshd and lock the operator out) or sever.
See [state-ladder.md](state-ladder.md).

## HTTP API surface

Grouped by console. All except the public paths require the `soc_session`
cookie; unsafe writes also require the CSRF header.

### Core / SOC

| Method | Path                     | Returns / action                                            |
|--------|--------------------------|-------------------------------------------------------------|
| GET    | `/`                      | SOC dashboard HTML                                          |
| GET    | `/login`                 | login page (public)                                        |
| POST   | `/api/login`             | sets `soc_session` + `csrf_token`, 303 → `/` (public)      |
| GET    | `/api/logout`            | clears cookie, 303 → `/login`                              |
| GET    | `/api/whoami`            | `{user, hostname, server_ip, csrf}`                        |
| GET    | `/api/events`            | recent events                                              |
| GET    | `/api/alerts`            | recent alerts                                              |
| GET    | `/api/process/<exec_id>` | `{chain, events}` for one exec_id                          |
| GET    | `/api/stream`            | SSE: `alert` / `event` / `process_exit` / `decision`      |
| GET    | `/api/policies`          | detection TracingPolicy YAMLs (`-policies`)               |
| GET    | `/api/attacks`           | allow-listed attack scripts (`-attacks`)                  |
| POST   | `/api/run-attack`        | launches `id=<allowed-script>` async (202/429)            |
| GET    | `/api/honeypots`         | `{prefix, files}` of seeded decoys                        |
| GET    | `/api/policy-stats`      | parsed `tetra tracingpolicy list` (NPOST, mode, mem)      |
| GET    | `/api/origin`            | live SSH-session attribution snapshot                     |
| GET    | `/api/version`           | build/version + web-asset hash                            |
| GET    | `/api/system-health`     | store/BPF/Tetragon/OTLP live status                       |
| GET    | `/api/decisions`         | hash-chained gateway decision log                         |
| GET    | `/api/verify-chain`      | re-walks the audit chain; detects tampering               |

### Process Choke (`/choke`)

`GET /api/choke/{state,circuits,buckets,thresholds,policies,cgroups,processes,process/<id>,proc/<pid>}`,
plus writes `POST /api/choke/{manual,bulk-manual,jail,forget,thaw,annotate,kill-switch,preset,mode,forensic-snapshot}`,
`PUT /api/choke/thresholds`, and `POST /api/choke/policy/preview`.

### Device Choke (`/devices`)

`GET /api/choke/{devices,device-state,device-flows}`, writes
`POST /api/choke/{device-jail,device-thaw,device-mode,device-kill-switch}`.

### Fleet (`/fleet`, enabled by `-fleet-hosts`)

`GET /api/fleet/{hosts,state,cgroups,decisions,alerts,devices}`, writes
`POST /api/fleet/{preset,kill-switch,thaw,device-jail}`, `PUT /api/fleet/thresholds`.

## Event lifecycle

1. **Kernel** — a process calls `connect()` (or `setuid`, or reads
   `/etc/shadow`). The matching eBPF kprobe fires.
2. **Tetragon** — builds a `process_kprobe`/`process_exec` event with the
   policy name, args, and the calling process's `exec_id`; streams it over gRPC.
3. **Engine consumer** ([main.go](../../engine/cmd/engine/main.go)) — inserts
   the event, updates the process-tree node, adds the event's score, and
   walks ancestors summing the chain score.
4. **Gateway dispatch** — `dispatchGateway` calls the Choke Gateway with the
   latest chain score on **every** event (not just alert-worthy ones), so a
   process can transition to *throttled* before it ever raises an alert. The
   ladder is monotonic; below-threshold calls are no-ops.
5. **Enforcement** — if the score crossed a rung, the enforcer chain runs
   (cgroup move / freeze / SIGKILL) and a hash-chained row is appended to
   `decisions`.
6. **Alerter** — if the chain score ≥ 10, an `alerts` row is written and
   classified by severity.
7. **Broadcast** — the event, any alert, and any decision fan out over SSE
   to every connected console, which updates KPIs, the timeline, the panels,
   and the state ladder in real time.

## Repository layout

```
.
├── README.md                                # one-page overview + quick start
├── Makefile                                 # web/build/test/deploy/tarball/…
├── docs/                                    # architecture, deployment, ops, reference, frontend, dev, rollout
├── web/                                     # Vite multi-entry React source (built + embedded)
├── scripts/
│   ├── setup.sh                             # idempotent host bootstrap (Docker/Go/Tetragon/clang/cgroup v2)
│   ├── chokectl                             # fleet CLI (status/preset/jail/device-*/…)
│   └── dev/netns-*.sh                        # 3-netns lab for the device-choke data plane
├── policies/
│   ├── network-watch.yaml                   # → outbound-connections
│   ├── privilege-escalation.yaml
│   ├── sensitive-files.yaml
│   ├── override-credential-read.yaml         # credential-path reads (detect-only)
│   └── choke/                               # ChokePolicy DSL (agent-loop-cap, shell-egress-throttle, network-tools-tarpit)
├── attacks/                                 # 6 attack-simulation scripts
├── deploy/                                  # install.sh, ebpf-engine.service, engine.yaml.example, nginx conf
└── engine/
    ├── cmd/engine/main.go                   # entry; gRPC client, gateways, fake mode
    └── internal/
        ├── api/                             # HTTP, SSE, auth, embedded web, fleet, choke/device handlers
        ├── score/                           # per-event + chain scoring
        ├── store/                           # SQLite (WAL) + Postgres, events/alerts/decisions
        ├── tree/                            # in-memory exec_id process tree (TTL)
        ├── choke/                           # gateway, device gateway, circuit, tokens
        ├── enforce/                         # cgroupv2, severer, bpfmap (choke.c), devbpf (devchoke.c)
        ├── device/                          # MAC↔IP↔hostname table + DHCP/neigh discovery
        ├── origin/                          # SSH-session attribution (journald tailer)
        ├── config/, logging/, metrics/, sysproc/
```

## Deployment modes

| Mode                       | How                                                                 |
|----------------------------|---------------------------------------------------------------------|
| **Detect-only**            | `enforce: false` — decisions audited, kernel untouched. The safe default. |
| **Enforcing (process)**    | `-enforce` — real cgroup throttle/freeze + SIGKILL on the host it runs on. |
| **Enforcing (device/MAC)** | 2-NIC inline bridge + `-devchoke-obj/-devchoke-iface`; independent of `-enforce`. |
| **Dry-run**                | `-dry-run` — records decisions, executes nothing (shadow a new policy). |
| **Fake**                   | `-fake` — synthesizes events, no Tetragon (unit tests / UI iteration only). |

The two chokes have **independent postures**: the process choke follows
`-enforce` (flippable at runtime via `/api/choke/mode`), while the device
choke enforces whenever it has the tc backend and is neither `dry_run` nor
kill-switched. "Observe processes, enforce on devices" is a valid, common
posture.

## Limitations (current)

- **Single host.** One engine ↔ one Tetragon socket. The Postgres backend
  and the `/fleet` fanout are the first steps toward multi-host, but there
  is no central fan-in collector yet — the fleet console drives peers
  individually.
- **Single-user auth.** One admin credential. Sessions are stateless
  (survive restart) but there is no multi-user/RBAC model.
- **HTTP only.** TLS termination is done by a reverse proxy (nginx/Caddy) —
  see the deployment guides.
- **Fixed scoring rules.** No baseline learning; tuning is manual in
  [scorer.go](../../engine/internal/score/scorer.go) and via the thresholds.
- **Device choke is operator-driven.** A forwarding node has no per-device
  Tetragon telemetry, so there is no automatic score path for the MAC
  gateway yet — it's manual jail/thaw with an audit trail.
- **One L2 hop for device choke.** MAC keying assumes the gateway is the
  device's L2 neighbour; devices behind a downstream router collapse to that
  router's MAC.

## Related

- [state-ladder.md](state-ladder.md) — the five-rung per-process/per-device
  state machine and its design principles.
- [network-choke-gateway.md](network-choke-gateway.md) — the per-device (MAC)
  data plane and inline-bridge topology.
- [../deployment/ubuntu-server.md](../deployment/ubuntu-server.md) — the
  recommended production deployment path.
- [../reference/chokectl.md](../reference/chokectl.md) — the fleet CLI.
</content>
