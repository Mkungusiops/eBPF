# Architecture & system overview

What this project is, how the pieces fit together, and what was built or
hardened during the most recent work session.

## What it is

A proactive, **kernel-level threat observability** PoC. Tetragon emits
syscall and kprobe events from inside the kernel via eBPF; a Go correlation
engine consumes them, builds a process tree, scores chains of suspicious
behavior, persists to SQLite, and serves a real-time SOC-style dashboard.

The dashboard is **single-binary, no external services**. The engine
embeds the HTML, login page, and favicon via `go:embed`, talks to
Tetragon over a gRPC unix socket, and writes events to a single SQLite
file with WAL mode.

## High-level diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Linux host (kernel ≥ 5.15)                   │
│                                                                      │
│   ┌─────────────┐   /dev/tcp     ┌────────────────┐                  │
│   │  attack.sh  │ ─ syscalls ──▶ │     KERNEL     │                  │
│   └─────────────┘                │                │                  │
│                                  │  eBPF kprobes  │  ◀─ TracingPolicy │
│                                  │  (tcp_connect, │     YAML applied  │
│                                  │  setuid,       │     by tetra      │
│                                  │  security_file)│                   │
│                                  └────┬───────────┘                  │
│                                       │ ringbuf                       │
│                              ┌────────▼────────┐                      │
│                              │ Tetragon daemon │  (Docker container)  │
│                              │  --privileged   │                      │
│                              │  --pid=host     │                      │
│                              └────────┬────────┘                      │
│                                       │ gRPC: GetEvents               │
│                                       │ (unix socket)                 │
│                              ┌────────▼────────┐                      │
│                              │   engine (Go)   │                      │
│                              │  - process tree │                      │
│                              │  - scorer       │                      │
│                              │  - SQLite (WAL) │                      │
│                              │  - SSE fanout   │                      │
│                              │  - auth (bcrypt)│                      │
│                              │  - HTTP :8080   │                      │
│                              └────────┬────────┘                      │
└───────────────────────────────────────┼──────────────────────────────┘
                                        │ HTTPS-able cookie session
                                ┌───────▼────────┐
                                │   Browser UI   │
                                │ (React-free,   │
                                │ vanilla JS,    │
                                │ Tailwind CDN)  │
                                └────────────────┘
```

## Components

### Tetragon (Cilium)

Tetragon is the eBPF runtime. It loads each `TracingPolicy` YAML as one
or more in-kernel eBPF programs and emits structured events to userspace
via gRPC. We pin to **`quay.io/cilium/tetragon:v1.6.1`** because the
`:latest` tag is no longer published.

Three policies are loaded in [policies/](../policies):

| Policy                  | Kprobe                     | What it catches                                                     | MITRE              |
|-------------------------|----------------------------|---------------------------------------------------------------------|--------------------|
| `outbound-connections`  | `tcp_connect`              | TCP connect from `bash`/`sh`/`nc`/`socat` (shells calling out)      | T1071 C2           |
| `privilege-escalation`  | (setuid hooks)             | `setuid(0)`, sudo to root                                           | T1548 PrivEsc      |
| `sensitive-file-access` | `security_file_permission` | Reads/writes of `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/root/.ssh/`, **`/var/lib/ebpf-engine/honey/`** | T1003 CredAccess + honeypot |

The honeypot prefix is the directory the engine seeds with five decoy
credential-style files on startup ([honeypots.go](../engine/internal/api/honeypots.go)).
Because no legitimate process should ever read those files, **any hit
under that prefix is a high-confidence signal** — the dashboard surfaces
them with a 🍯 *honey* badge alongside the regular severity.

`process_exec` events are emitted for **every** `execve` for free —
they're the spine of the process tree.

### Engine ([engine/](../engine))

A Go binary, ~24 MB statically linked (`CGO_ENABLED=0`), no runtime
dependencies. Responsibilities:

- **gRPC client** — subscribes to Tetragon's `GetEvents` stream over
  `unix:///var/run/tetragon/tetragon.sock`.
- **Process tree** ([engine/internal/tree](../engine/internal/tree)) —
  in-memory tree keyed by Tetragon's stable `exec_id` (which survives PID
  reuse), TTL-bounded so old branches GC out.
- **Scorer** ([engine/internal/score](../engine/internal/score)) — adds
  per-event scores to nodes, walks ancestors (≤10 hops) summing, emits an
  alert when the chain crosses a severity threshold.
- **Store** ([engine/internal/store](../engine/internal/store)) — SQLite
  with `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`.
  Persists `events` and `alerts` tables.
- **HTTP API + SSE fanout** ([engine/internal/api/http.go](../engine/internal/api/http.go))
  — serves the embedded UI, JSON APIs, and a Server-Sent Events stream
  for live updates. Every alert/event broadcasts to all subscribers.
- **Auth** ([engine/internal/api/auth.go](../engine/internal/api/auth.go))
  — bcrypt-hashed credentials, HttpOnly cookie sessions with 24h TTL,
  constant-time comparison, simple per-IP rate limiting.

### Dashboard ([engine/internal/api/index.html](../engine/internal/api/index.html))

A single-page web app served from the engine binary via `go:embed`. No
build step, no node_modules. Uses Tailwind via CDN and zero JS frameworks.

#### Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│  ⬡ eBPF SOC   [search…]  ⊙  5m 30m 1h 24h  🔔 ⬇ ?  host …  ● live  user admin  ↪│
├─────────────────────────────────────────────────────────────────────┤
│  CRITICAL   HIGH    MEDIUM   EVENTS/SEC   ACTIVE PROCESSES         │
│   12 +3↑    34 -1↓  56 ±0    4.2 eps      280 unique exec_ids      │
├─────────────────────────────────────────────────────────────────────┤
│  Severity timeline (clickable 1-min buckets) ▆▇█▇▆▅▆▇█▇▆▅          │
├──────────────────────────────────┬──────────────────────────────────┤
│  Alert triage                    │  MITRE ATT&CK coverage           │
│  [crit][high][med] unack ✓ group │  T1071 ▓░░  T1548 ▓▓░  T1003 ▓▓▓│
│  ──────────────────              │                                  │
│  🔴 Suspicious chain… +5  ack… │  Top processes by score          │
│  🟠 Sensitive file…           │  /usr/bin/bash ▓▓▓▓▓▓ 188         │
│  🟡 …                          │                                  │
│                                  │  IOCs observed                   │
│                                  │  /etc/shadow ×7  127.0.0.1:4444 │
│                                  │                                  │
│                                  │  Network connections             │
│                                  │  127.0.0.1:4444  bash  ×1       │
├─────────────────────────────────────────────────────────────────────┤
│  Live event stream  hide self-noise ✓  pause  clear   123 events   │
└─────────────────────────────────────────────────────────────────────┘
```

#### Features built in this session

| Area              | Feature                                                                                                  |
|-------------------|----------------------------------------------------------------------------------------------------------|
| Layout            | Dark SOC theme with glassmorphic cards, slate gradient background                                        |
| Header            | Risk score gauge (animated SVG arc, pulses red ≥70), notification bell, JSON export, help modal          |
| KPIs              | Critical / High / Medium counts with sparklines AND trend deltas vs prior window                         |
| KPIs              | Events-per-second (60 s rolling), unique active processes (10 min window)                                |
| Timeline          | Stacked-severity bars per 1-min bucket; **click to filter** alerts to that minute                        |
| Alert triage      | Severity filter pills, free-text search, **unacked-only** filter, **group toggle** (collapse by exec_id) |
| Alert state       | New / Ack / Resolved state machine, persisted in browser localStorage with high-water marks              |
| Drill-down        | Slide-over panel: process lineage tree, generated narrative, IOCs, event timeline                        |
| MITRE             | Auto-maps policies to T1071 / T1548 / T1003 with technique counts                                        |
| Top processes     | Score-sorted with gradient bars, click → drill in                                                        |
| IOCs              | Auto-extracts file paths and IP:port from event args                                                     |
| Network panel     | Outbound TCP peers and source processes (separate from IOCs)                                             |
| Event stream      | Color-coded by event type, **hide self-noise** filter, pause, clear                                      |
| Notifications     | Browser desktop notification + Web Audio chime on critical alerts when tab is unfocused (toggleable)     |
| Keyboard          | `/` search · `j`/`k` next/prev · `Enter` open · `a` ack · `r` resolve · `c` clear · `e` export · `?` help |
| Resilience        | Explicit reconnect with exponential backoff, watchdog for wedged sockets, visibility-resume hook         |
| Catch-up          | On reconnect, fetches `/api/alerts` and `/api/events` and merges anything missed during the gap          |
| Cache             | Engine sets `Cache-Control: no-cache` on the dashboard so updates are picked up without hard-reloads     |

### Auth ([engine/internal/api/auth.go](../engine/internal/api/auth.go))

A single admin user with bcrypt-hashed credentials. The plaintext password
is hashed once at startup and never stored.

| Property            | Value                                                                  |
|---------------------|------------------------------------------------------------------------|
| Algorithm           | bcrypt (`golang.org/x/crypto/bcrypt`, default cost 10)                 |
| Username comparison | `crypto/subtle.ConstantTimeCompare`                                    |
| Cookie name         | `soc_session`                                                          |
| Cookie attributes   | `HttpOnly`, `SameSite=Lax`, `MaxAge=24h`, `Path=/`                     |
| Session storage     | In-memory map of token → expiry (lost on restart, fine for single instance) |
| Rate limit          | 10 login attempts per remote IP per minute                             |
| Public paths        | `/login`, `/api/login`, `/favicon.svg`, `/favicon.ico`                 |
| Everything else     | 302 to `/login` for HTML, 401 JSON for `/api/*`                        |

Default credentials are baked in for the demo: **`admin / ebpf-soc-demo`**.
Override with `-user` and `-pass` flags on the engine binary. Operators
should always change them in any real deployment — the deploy guide shows
how to wire this through systemd and an environment file.

## HTTP API surface

| Method | Path                       | Auth | Returns                                                                |
|--------|----------------------------|------|------------------------------------------------------------------------|
| GET    | `/`                        | yes  | the dashboard HTML                                                     |
| GET    | `/login`                   | no   | login page                                                             |
| POST   | `/api/login`               | no   | sets `soc_session` cookie + 303 → `/`                                  |
| GET    | `/api/logout`              | no¹  | clears cookie + 303 → `/login`                                         |
| GET    | `/api/whoami`              | yes  | `{"user":"admin"}`                                                     |
| GET    | `/api/events`              | yes  | last 200 events                                                        |
| GET    | `/api/alerts`              | yes  | last 100 alerts                                                        |
| GET    | `/api/process/<exec_id>`   | yes  | `{chain, events}` for a given exec_id                                  |
| GET    | `/api/stream`              | yes  | SSE: `data: {"type":"alert"\|"event", ...}`                            |
| GET    | `/api/policies`            | yes  | the 3 TracingPolicy YAMLs (Policies viewer, needs `-policies` flag)    |
| GET    | `/api/attacks`             | yes  | allow-listed attack scripts (Attacks panel, needs `-attacks` flag)     |
| POST   | `/api/run-attack`          | yes  | launches `id=<allowed-script>` async; 202 on success, 429 on throttle  |
| GET    | `/api/honeypots`           | yes  | `{prefix, files: […]}` describing the seeded decoy files               |
| GET    | `/api/policy-stats`        | yes  | parsed `tetra tracingpolicy list` (NPOST per policy, kernel mem, mode) |
| GET    | `/favicon.svg`             | no   | the icon (also served at `/favicon.ico`)                               |

¹ Logout is intentionally tolerant — it clears the cookie regardless of
whether the session is currently valid, so it works for already-expired
sessions.

### Engine flags (relevant to the dashboard's tooling endpoints)

| Flag         | Default                       | Effect on the dashboard                             |
|--------------|-------------------------------|-----------------------------------------------------|
| `-policies`  | `policies`                    | `/api/policies` reads YAMLs from this dir.          |
| `-attacks`   | `attacks`                     | `/api/attacks` and `/api/run-attack` look here.     |
| `-honeypots` | `/var/lib/ebpf-engine/honey`  | Decoy files seeded on startup (idempotent).         |
| `-user`      | `admin`                       | Dashboard username.                                 |
| `-pass`      | `ebpf-soc-demo`               | Bcrypt-hashed at startup, plaintext discarded.      |
| `-tetragon`  | `unix:///var/run/tetragon/tetragon.sock` | gRPC socket for Tetragon's GetEvents stream. |
| `-db`        | `events.db`                   | SQLite path. Must be **outside** any kprobe-watched path. |
| `-http`      | `:8080`                       | HTTP listen address.                                |
| `-fake`      | `false`                       | Synthesize events without Tetragon (UI dev mode).   |

## Event lifecycle

1. **Kernel** — a process calls `connect()` (or `setuid`, or accesses
   `/etc/shadow`). The matching eBPF kprobe fires.
2. **Tetragon** — receives the kprobe, builds a `process_kprobe` event
   with the policy name, args, and the `exec_id` of the calling process.
   Streams it over gRPC.
3. **Engine consumer** ([engine/cmd/engine/main.go](../engine/cmd/engine/main.go)):
   - Inserts the event into `events` (SQLite, WAL).
   - Looks up or creates the node in the process tree.
   - Adds the event's score to the node.
   - Walks the ancestor chain summing scores.
4. **Engine alerter** — if the chain score crosses 10, inserts an `alerts`
   row, classifies severity (`low ≥ 5`, `medium ≥ 10`, `high ≥ 20`,
   `critical ≥ 40`), and broadcasts both the event and the alert to all
   SSE subscribers.
5. **Browser** — the SSE handler dispatches to `onEvent` / `onAlert`,
   prepends to the live buffers, updates KPIs, sparklines, the gauge,
   the timeline, and the panels. If notifications are enabled and the
   tab is unfocused, fires a desktop notification + audio chime.

## Repository layout

```
.
├── README.md                                # one-page overview + quick start
├── Makefile                                 # build / test / fake / tarball / clean
├── ebpf-poc-amd64.tar.gz                    # produced by `make tarball`
├── docs/
│   ├── build.md                             # original 5-day build plan
│   ├── architecture.md                      # this file
│   ├── deploy-linux-server.md               # production deployment guide
│   └── multipass-mac-local-vm-deploy.md     # local Linux VM on macOS via Multipass
├── scripts/
│   └── setup.sh                             # idempotent Day-1 install on a fresh VM
├── policies/
│   ├── network-watch.yaml                   # policy name: outbound-connections (tcp_connect from shells)
│   ├── privilege-escalation.yaml            # setuid hooks
│   └── sensitive-files.yaml                 # /etc/shadow, /etc/passwd, /etc/sudoers, /root/.ssh
├── attacks/
│   ├── 01-webshell.sh                       # curl payload + chmod +x + read /etc/shadow
│   ├── 02-credential-theft.sh               # reads of shadow, sudoers, ssh keys
│   ├── 03-reverse-shell.sh                  # bash /dev/tcp redirect to localhost listener
│   ├── 04-privilege-escalation.sh           # setuid + root credential reads
│   ├── 05-living-off-the-land.sh            # base64-piped curl|sh
│   └── 06-persistence.sh                    # chmod +x staged script + dotfile recon
└── engine/
    ├── cmd/engine/main.go                   # main entry; gRPC client + fake mode
    ├── go.mod, go.sum
    └── internal/
        ├── api/
        │   ├── http.go                      # routes, SSE fanout, drill-down handler
        │   ├── auth.go                      # bcrypt + cookie sessions + middleware
        │   ├── index.go                     # //go:embed of HTML/SVG assets
        │   ├── index.html                   # dashboard SPA
        │   ├── login.html                   # login page
        │   └── favicon.svg                  # tab icon
        ├── score/scorer.go                  # per-event + chain scoring rules
        ├── store/sqlite.go                  # WAL-mode SQLite, events + alerts
        └── tree/processtree.go              # in-memory exec_id tree with TTL
```

## What was changed or fixed in this session

Beyond the dashboard rewrite and auth system, several latent issues were
fixed end-to-end. Listed here so anyone re-reading the codebase later
can correlate code with rationale:

| File                                       | Change                                                                                                        |
|--------------------------------------------|---------------------------------------------------------------------------------------------------------------|
| `Makefile`                                 | `tarball` target now references `docs/build.md` (was `build.md` at root, which moved)                          |
| `policies/sensitive-files.yaml`            | Removed the `/home/` prefix that caused a feedback loop: engine writing to `events.db` triggered the policy   |
| `engine/internal/store/sqlite.go`          | Open SQLite with `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000` — fixes `SQLITE_BUSY` under load |
| `engine/internal/api/index.go`             | Switched from a const string to `//go:embed` so the HTML lives in a real file (also embeds login + favicon)   |
| `engine/internal/api/http.go`              | Added `Cache-Control: no-cache, no-store, must-revalidate` on `/`; added auth middleware wrapping             |
| `engine/internal/api/index.html`           | Complete rewrite as the SOC dashboard described above                                                          |
| `engine/internal/api/auth.go`              | New: bcrypt + cookie sessions + middleware                                                                     |
| `engine/internal/api/login.html`           | New: login page matching the SOC theme                                                                         |
| `engine/internal/api/favicon.svg`          | New: tab icon (cyan hexagon on dark)                                                                           |
| `engine/cmd/engine/main.go`                | Added `-user` and `-pass` flags; wires `auth` into the server                                                 |
| `attacks/03-reverse-shell.sh`              | Replaced `( … & )` subshell + bare `$!` (broke under `set -u`); wrapped `/dev/tcp` redirect in `timeout 1`    |

The recommended deploy path also moved the engine's SQLite database from
`/home/ubuntu/ebpf-poc/events.db` to `/var/lib/ebpf-engine/events.db` so
it sits **outside** any path the credential-access policy watches. Even
with the `/home/` prefix removed from the policy, this is a belt-and-
suspenders best practice: the data dir should never live under a path
that the kprobes inspect.

## Testing posture

| What                          | Where tested                            | Status |
|-------------------------------|-----------------------------------------|--------|
| `make test` (unit tests)      | macOS host                              | passes |
| `make build`                  | macOS host (darwin/amd64)               | passes |
| `make build-linux`            | macOS host → linux/amd64                | passes |
| `make tarball`                | macOS host                              | passes |
| `make fake` + auth flow       | macOS host (`/tmp/ebpf-poc-fresh`)      | passes |
| Real Tetragon + kprobes       | Multipass Ubuntu 22.04 VM               | passes |
| Six attack scripts            | Multipass VM                            | 5/6 — `03-reverse-shell.sh` was fixed mid-session |
| Dashboard against real events | Multipass VM                            | passes |
| Auth (login / 401 / logout)   | macOS clone + Multipass VM              | passes |

## Limitations (current)

- **Single host.** One engine ↔ one Tetragon socket ↔ one SQLite. A
  multi-host story needs a fan-in collector (e.g., NATS or gRPC chain).
- **Detection only.** TracingPolicies use `Post`. Switching to
  `SIGKILL` / `Override` would convert this from observability to
  in-kernel prevention. Not done because the demo wants visibility,
  not enforcement.
- **No baseline learning.** Scoring is fixed in
  [scorer.go](../engine/internal/score/scorer.go). Real deployments
  would tune per-environment.
- **Single user, in-memory sessions.** Auth is a real gate, but it's
  one admin and sessions don't survive engine restart. For multi-user
  or HA, replace `Auth.sessions` with Redis or similar.
- **HTTP only.** TLS termination should be done by a reverse proxy
  (caddy/nginx) — see the deployment guide.
