# Deploy on an Ubuntu server — step by step

The fastest, supported path to a running **eBPF Threat Choke Gateway** on a
fresh **Ubuntu 22.04 or 24.04** server (cloud VM, bare metal, or hypervisor
guest). It uses the repo's own automation — [`scripts/setup.sh`](../../scripts/setup.sh)
for the host, [`deploy/install.sh`](../../deploy/install.sh) for the engine —
so there is nothing to copy-paste by hand beyond a few commands.

> Already deployed and just need to redeploy/upgrade? Jump to
> [§7 Operations](#7-operations). For the production runbook of the live
> `soc.adanianlabs.io` host (and its enforcing-mode traps) see
> [live-soc-adanianlabs.md](live-soc-adanianlabs.md).

---

## What you end up with

```
nginx (TLS :443)  ──►  engine (HTTP 127.0.0.1:8080)  ──►  Tetragon (kprobes, unix socket)
                              │
                              ├─ /opt/ebpf-engine/engine          binary
                              ├─ /etc/ebpf-engine/engine.yaml      config (edit the password!)
                              └─ /var/lib/ebpf-engine/             SQLite DB + honeypots + audit chain
```

- **Tetragon** (a privileged container) does the kernel observation.
- The **engine** (a `systemd` service, `ebpf-engine.service`) scores process
  behaviour, drives the choke state ladder, and serves the React dashboard.
- **nginx** terminates TLS and reverse-proxies to the engine.

---

## 0. Prerequisites

| Requirement | Notes |
|---|---|
| **Ubuntu 22.04 / 24.04** | 24.04 recommended. cgroup v2 unified (the default) is required. |
| **Kernel with BTF** | `test -f /sys/kernel/btf/vmlinux` must succeed. All stock Ubuntu ≥ 5.15 cloud/generic kernels have it. |
| **root / sudo** | The engine runs as root (cgroup freeze + cross-PID SIGKILL); install needs sudo. |
| **2 vCPU / 2 GB RAM / 10 GB disk** | Comfortable for a single host. Tetragon + the engine are light. |
| **A way to build the binary** | Either build on the server (needs Node 20 + Go ≥ 1.25) **or** build on a dev machine and ship a tarball (recommended — keeps toolchains off prod). |

> **Single-NIC vs. inline gateway.** On an ordinary single-NIC server the
> **per-process** Tetragon choke (the whole SOC/Choke console) works fully.
> The **per-device / per-MAC network choke** (`/devices`) only *enforces* on a
> 2-NIC inline bridge; on a single NIC it records audited decisions but drops no
> packets (`plane=noop`). See [network-choke-gateway.md](network-choke-gateway.md).

---

## 1. One-time host setup

Get the repo onto the server, then run the setup script. It is **idempotent** —
safe to re-run.

```bash
# On the Ubuntu server:
git clone https://github.com/jeffmk/ebpf-poc-engine.git ebpf-poc   # or your fork/mirror
cd ebpf-poc
bash scripts/setup.sh
```

`scripts/setup.sh` installs and verifies, in order:

1. **apt deps** — `git curl make jq build-essential clang llvm libbpf-dev linux-headers-$(uname -r)` (the BPF data-plane toolchain).
2. **Docker** — via `get.docker.com`, enabled at boot.
3. **Go** — the toolchain (only needed if you build on the server).
4. **Tetragon** — a `tetragon` container in host mode, exporting its gRPC socket at `/var/run/tetragon/tetragon.sock`.
5. **tetra CLI** — for inspecting Tetragon (`tetra tracingpolicy list`, etc.).
6. **cgroup v2** — enables the `+cpu +memory +io +pids` controllers the choke ladder needs.

When it finishes you should see *"tetragon socket ready"*. Verify:

```bash
test -S /var/run/tetragon/tetragon.sock && echo "Tetragon up"
sudo docker ps --format '{{.Names}}' | grep -x tetragon
```

---

## 2. Build the engine binary

The binary **embeds the built web UI**, so building runs the Vite build first.

### Option A — build on a dev machine, ship a tarball (recommended)

Keeps Node/Go off the production server. On your laptop or a build box (with
**Node 20+** and **Go ≥ 1.25**):

```bash
make tarball            # builds web + linux binary, bundles policies/attacks/scripts/deploy
# → produces ebpf-poc-<arch>.tar.gz
scp ebpf-poc-*.tar.gz ubuntu@SERVER:/home/ubuntu/
```

On the server:

```bash
tar xzf ebpf-poc-*.tar.gz && cd ebpf-poc-*    # (or wherever it extracts)
```

### Option B — build directly on the server

Install **Node 20** (Go is already installed by `setup.sh`), then build:

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
cd ~/ebpf-poc
make build-linux        # runs `npm run build` then cross-compiles engine/engine-linux-amd64
```

Either way you now have `engine/engine-linux-amd64` in the source tree.

---

## 3. Install as a systemd service

[`deploy/install.sh`](../../deploy/install.sh) installs the binary, config,
policies, and the `ebpf-engine.service` unit, and compiles the BPF data plane
(`choke.o`) against the running kernel. Idempotent — re-running upgrades in place.

```bash
sudo SRC_ROOT="$(pwd)" bash deploy/install.sh
```

It lays down:

| Path | Purpose |
|---|---|
| `/opt/ebpf-engine/engine` | the binary (swapped atomically on upgrade) |
| `/opt/ebpf-engine/policies/` | TracingPolicy + ChokePolicy YAMLs |
| `/opt/ebpf-engine/bpf/choke.o` | compiled BPF data plane |
| `/etc/ebpf-engine/engine.yaml` | config — **seeded once, then preserved** |
| `/var/lib/ebpf-engine/` | SQLite DB, honeypots, audit chain |
| `/etc/systemd/system/ebpf-engine.service` | the unit (CAP_BPF/NET_ADMIN/SYS_ADMIN/KILL) |

It then `systemctl enable --now ebpf-engine` and prints the status. Check it:

```bash
systemctl status ebpf-engine --no-pager
journalctl -u ebpf-engine -f          # live logs; Ctrl-C to stop
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/   # expect 302
```

---

## 4. Configure (change the password!)

Edit [`/etc/ebpf-engine/engine.yaml`](../../deploy/engine.yaml.example). Every
field maps 1:1 to a CLI flag (`/opt/ebpf-engine/engine -h`). The **must-change**
items before any real use:

```yaml
user: "admin"
# Prefer a pre-computed bcrypt hash so plaintext never sits on disk:
#   htpasswd -bnBC 10 "" 'your-strong-password' | tr -d ':\n'
pass_hash: "$2a$10$....replace-me...."
# (or set `pass:` for a plaintext password bcrypted at startup)
```

> **Start in detect-only, then enable enforcement.** For a first deploy set
> `enforce: false` so decisions are *audited but not applied* to the kernel.
> Watch the dashboard for a few minutes, confirm the score thresholds
> (`throttle_at/tarpit_at/quarantine_at/sever_at`) suit your workload, then flip
> to enforcing — from the UI, or by setting `enforce: true` and restarting.
> Enforcing too aggressively can sever high-scoring system binaries (e.g.
> `sudo`); the shipped thresholds (quarantine 120 / sever 200) are tuned to keep
> them safe. See the trap notes in [live-soc-adanianlabs.md §3](live-soc-adanianlabs.md).

Apply changes with a restart:

```bash
sudo systemctl restart ebpf-engine
```

---

## 5. Expose it with TLS (nginx)

The engine is HTTP-only and binds `:8080`; nginx terminates TLS. The repo ships
a ready proxy config tuned for the SSE event stream
([`deploy/nginx/ebpf-engine.conf`](../../deploy/nginx/ebpf-engine.conf)).

```bash
sudo apt-get install -y nginx
sudo cp deploy/nginx/ebpf-engine.conf /etc/nginx/sites-available/ebpf-engine.conf
sudo ln -sf /etc/nginx/sites-available/ebpf-engine.conf /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo mkdir -p /etc/nginx/ebpf
```

**Get a certificate** (pick one):

- **Let's Encrypt** (public DNS name pointing at the box):
  ```bash
  sudo apt-get install -y certbot
  sudo certbot certonly --webroot -w /var/www/html -d soc.example.com
  sudo ln -sf /etc/letsencrypt/live/soc.example.com/fullchain.pem /etc/nginx/ebpf/fullchain.pem
  sudo ln -sf /etc/letsencrypt/live/soc.example.com/privkey.pem   /etc/nginx/ebpf/privkey.pem
  ```
- **Self-signed** (lab / no DNS):
  ```bash
  sudo openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout /etc/nginx/ebpf/privkey.pem -out /etc/nginx/ebpf/fullchain.pem \
    -subj "/CN=$(hostname -f)"
  ```

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Open `https://<server>/` — you'll land on `/login`. PWA install (Add to Home
Screen) works once TLS is live.

> No public exposure? Skip nginx and use an SSH tunnel instead:
> `ssh -L 8080:127.0.0.1:8080 ubuntu@SERVER`, then browse `http://localhost:8080`.

---

## 6. Verify the deployment

```bash
# 1. Engine reachable + auth-gated
curl -s -o /dev/null -w 'root: %{http_code}\n' https://SERVER/          # 302 → /login
curl -s -o /dev/null -w 'api:  %{http_code}\n' https://SERVER/api/version # 401 (unauth)

# 2. Log in (replace creds), capture the cookie, hit an authed endpoint
J=$(mktemp)
curl -s -c "$J" -d 'user=admin&pass=YOUR_PASSWORD' https://SERVER/api/login >/dev/null
curl -s -b "$J" https://SERVER/api/whoami            # {"user":"admin","host":...}

# 3. Kernel events are flowing (drive an exec while tailing)
journalctl -u ebpf-engine -f &        # watch for ALERT lines
bash attacks/02-credential-theft.sh   # or any attacks/*.sh — should raise a critical alert
```

Then open the dashboard in a browser and confirm: the **Executive summary** band
shows a live posture, the **alert triage queue** fills, `/choke` shows tracked
processes with **Kernel sensor: Connected**, and `/devices` lists ARP neighbours.

---

## 7. Operations

**Upgrade / redeploy** — rebuild the binary (§2), then re-run install (atomic
binary swap, preserves config + DB):

```bash
sudo SRC_ROOT="$(pwd)" bash deploy/install.sh
```

**Logs / status / restart:**

```bash
journalctl -u ebpf-engine -f
systemctl status ebpf-engine --no-pager
sudo systemctl restart ebpf-engine
```

**Rollback** — the systemd unit keeps the previous binary inode running until
restart; to revert to an older build, point `install.sh` at that source tree (or
keep a copy of `/opt/ebpf-engine/engine`) and re-run. The DB lives in
`/var/lib/ebpf-engine/events.db` — back it up before risky changes.

**Reset the database:**

```bash
sudo systemctl stop ebpf-engine
sudo rm -f /var/lib/ebpf-engine/events.db
sudo systemctl start ebpf-engine     # recreated empty on boot
```

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Tetragon socket never appeared` | Docker not running, or kernel lacks BTF. Check `sudo docker logs tetragon` and `test -f /sys/kernel/btf/vmlinux`. |
| Dashboard loads but **no alerts / Kernel sensor Disconnected** | Engine can't reach the Tetragon socket. Confirm `tetragon:` path in `engine.yaml` matches `/var/run/tetragon/tetragon.sock` and the container is up. |
| `502` from nginx | Engine not listening on `:8080`. `systemctl status ebpf-engine`; check `http:` in config. |
| SSE stream keeps dropping | nginx not using the shipped config (it disables buffering for `/api/stream`). Ensure `deploy/nginx/ebpf-engine.conf` is the active site. |
| `apt` breaks after enabling enforcement | A Tetragon enforce TracingPolicy (e.g. `override-credential-read`, `Sigkill` on credential reads) killed an apt postinst. Reversible — see [live-soc-adanianlabs.md §4](live-soc-adanianlabs.md). |
| `sudo` gets killed in enforcing mode | Score thresholds too low for your workload. Boot detect-only, raise `quarantine_at`/`sever_at`, then re-enable. |
| `/devices` shows `plane=noop` | Expected on a single-NIC host. Per-MAC enforcement needs a 2-NIC inline bridge — see [network-choke-gateway.md](network-choke-gateway.md). |

---

### Related docs

- [linux-server.md](linux-server.md) — the longer, manual walkthrough (per-step rationale, alternate transfer methods, hardening checklist).
- [tarball-quickstart.md](tarball-quickstart.md) — the absolute fastest `make tarball` → run path.
- [../architecture/overview.md](../architecture/overview.md) — how the system fits together.
