# eBPF Threat Observability PoC

A proactive, kernel-level threat observability tool. Tetragon emits kernel
events; a Go correlation engine consumes them, builds process trees, scores
chains of suspicious behavior, persists to SQLite, and serves a real-time
SOC-style dashboard with auth, MITRE ATT&CK mapping, alert acknowledgement,
and live SSE updates.

```
[ kernel ] -- eBPF kprobes --> [ Tetragon ] -- gRPC --> [ engine ] -- HTTPS --> [ browser ]
```

| Doc                                                     | Purpose                                              |
|---------------------------------------------------------|------------------------------------------------------|
| **README.md** (this file)                               | One-page overview + quick start                      |
| [docs/architecture.md](docs/architecture.md)            | How everything works, components, data flow         |
| [docs/deploy-linux-server.md](docs/deploy-linux-server.md) | Step-by-step deploy on a fresh Linux server         |
| [docs/multipass-mac-local-vm-deploy.md](docs/multipass-mac-local-vm-deploy.md) | Local Linux VM on macOS via Multipass               |
| [docs/run-on-multipass-vm.md](docs/run-on-multipass-vm.md) | Day-to-day ops runbook once the VM is set up        |
| [docs/build.md](docs/build.md)                          | Original 5-day build plan that produced this codebase|

## Repository layout

```
.
├── README.md                                # this file
├── Makefile                                 # build / test / fake / tarball / clean
├── docs/                                    # architecture + deployment guides
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
| Run unit tests                        | `make test`                                                   |
| Run engine locally (no Tetragon)      | `make fake` then open <http://localhost:8080>                  |
| Cross-compile for a Linux server      | `make build-linux`                                            |
| Bundle binary + policies + attacks    | `make tarball` → `ebpf-poc-amd64.tar.gz`                      |
| Deploy on a fresh Linux server        | See [docs/deploy-linux-server.md](docs/deploy-linux-server.md) |
| Local Linux VM on macOS (Multipass)   | See [docs/multipass-mac-local-vm-deploy.md](docs/multipass-mac-local-vm-deploy.md) |

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

## Quick start

### A. Local dev / UI demo (any OS, no Tetragon required)

```bash
make fake          # builds engine, runs with -fake on :8080
open http://localhost:8080
```

You'll be redirected to `/login`. **Default credentials**:

| User    | Password         |
|---------|------------------|
| `admin` | `ebpf-soc-demo`  |

Override with `-user` and `-pass` flags. `make fake` synthesizes a
deterministic stream of attack-pattern events (webshell, reverse-shell,
credential theft, privilege escalation, LOLBin) through the same
handlers Tetragon would feed in production. Useful for iterating on
the UI, scoring rules, or storage schema without a Linux host.

### B. Real deploy on a Linux server

For a complete walkthrough including systemd, TLS, and hardening, see
**[docs/deploy-linux-server.md](docs/deploy-linux-server.md)**. Short
version:

1. **From your dev machine**, build the Linux artifact:
   ```bash
   make tarball                          # → ebpf-poc-amd64.tar.gz
   scp ebpf-poc-amd64.tar.gz user@server:~/
   ```
2. **On the server** (Ubuntu 22.04+, kernel ≥ 5.15):
   ```bash
   mkdir ~/ebpf-poc && tar -xzf ~/ebpf-poc-amd64.tar.gz -C ~/ebpf-poc
   cd ~/ebpf-poc
   TETRAGON_IMAGE=quay.io/cilium/tetragon:v1.6.1 bash scripts/setup.sh
   sudo make policies-apply
   sudo mkdir -p /var/lib/ebpf-engine
   sudo ./engine/engine-linux-amd64 \
     -tetragon unix:///var/run/tetragon/tetragon.sock \
     -db /var/lib/ebpf-engine/events.db \
     -http :8080 \
     -user admin -pass 'pick-something-strong'
   ```
3. **Open the UI** at `http://<server-ip>:8080` (use an SSH tunnel —
   the engine is HTTP-only; put TLS in front for anything beyond a demo).
4. **Trigger an attack scenario** in another shell on the server:
   ```bash
   sudo bash ~/ebpf-poc/attacks/01-webshell.sh
   ```
   An alert appears in the UI within ~1 s. Click it for the full chain.

> **Tetragon image tag**: pin to a versioned tag — the `:latest` tag is
> no longer published. v1.6.1 is the current stable.

### C. Local Linux VM on macOS (Multipass)

If you don't have a remote Linux server, you can run the full stack in
a local VM. See **[docs/multipass-mac-local-vm-deploy.md](docs/multipass-mac-local-vm-deploy.md)**.

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
session, see [docs/architecture.md](docs/architecture.md).

## Limitations

- **Detection only, no prevention.** Adding `enforcement` actions
  (`SIGKILL`, `Override`) to the policies would change that.
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
