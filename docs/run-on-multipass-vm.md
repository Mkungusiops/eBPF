# Run the engine on a Multipass VM (macOS host)

End-to-end recipe for spinning up the eBPF engine against real kernel events
inside an Ubuntu VM on macOS. Each block is labeled **[macOS host]** or
**[inside VM]** so you know where to run it.

> **Production path only.** This guide deploys the engine with the
> Choke Gateway enabled and `-enforce` on — so attack scripts will
> actually be choked (cgroup v2 throttle/tarpit/quarantine, SIGKILL on
> sever). `make fake` exists for unit-test/UI iteration only and is not
> used here.

## Fast path: `make deploy`

If your VM is already bootstrapped (Tetragon running, policies applied),
the entire deploy/restart loop collapses to one command from the macOS
host:

```bash
make deploy           # build → sync → restart → print URL
```

After the first `make deploy` you can use `make redeploy` for fast
iteration (skips setup.sh + policy re-apply). Other helpers:

```bash
make vm-logs                       # tail engine logs
make vm-status                     # engine + cgroup tier counts
make vm-attack SCRIPT=01-webshell.sh  # fire an attack inside the VM
```

The long-form steps below show what `make deploy` does under the hood.

## Prerequisites

- macOS with Homebrew
- ~5 GB free disk, ~4 GB free RAM
- The repo's `ebpf-poc-amd64.tar.gz` (run `make tarball` if missing)

---

## 1. Install Multipass — [macOS host]

```bash
brew install --cask multipass
multipass version
```

## 2. Launch the VM — [macOS host]

```bash
multipass launch 22.04 --name ebpf --cpus 2 --memory 4G --disk 20G
multipass info ebpf
```

## 3. Build & transfer the bundle — [macOS host]

```bash
make tarball
multipass transfer ebpf-poc-amd64.tar.gz ebpf:/home/ubuntu/
```

## 4. Open a shell in the VM — [macOS host]

```bash
multipass shell ebpf
```

## 5. Extract the bundle — [inside VM]

```bash
mkdir -p /home/ubuntu/ebpf-poc
tar -xzf /home/ubuntu/ebpf-poc-amd64.tar.gz -C /home/ubuntu/ebpf-poc
cd /home/ubuntu/ebpf-poc
```

> **Important:** finish extraction *before* step 8. If the engine binary
> isn't on disk yet, `nohup` exits with `No such file or directory` and
> nothing listens on port 8080.

## 6. Run setup.sh — [inside VM]

```bash
TETRAGON_IMAGE=quay.io/cilium/tetragon:v1.6.1 bash scripts/setup.sh
```

Installs Docker, Go 1.22.5, the `tetra` CLI, pulls Tetragon, starts it
`--privileged --pid=host`, and waits for the gRPC socket.

## 7. Apply TracingPolicies — [inside VM]

```bash
sudo make policies-apply
```

Three policies should report `enabled`: `outbound-connections`,
`privilege-escalation`, `sensitive-file-access`.

## 8. Start the engine — [inside VM]

Run the engine as a **transient systemd unit**. Compared to the older
`nohup ... & disown` form, this:

- detaches fully from the SSH session (no SIGHUP race),
- auto-restarts on crash (`Restart=always`),
- routes stdout/stderr to `/var/log/ebpf-engine.log` and `journalctl`,
- gives you `systemctl restart/stop/status` for lifecycle.

The first three lines make the block idempotent — safe to re-run if a
prior engine is already running or if the unit was left in a failed
state.

```bash
sudo mkdir -p /var/lib/ebpf-engine

sudo systemctl stop ebpf-engine 2>/dev/null || true
sudo systemctl reset-failed ebpf-engine 2>/dev/null || true
sudo pkill -f engine-linux-amd64 || true
sleep 2
sudo systemd-run \
  --unit=ebpf-engine \
  --description="eBPF Choke Gateway" \
  --property=Restart=always \
  --property=RestartSec=2 \
  --property=StandardOutput=append:/var/log/ebpf-engine.log \
  --property=StandardError=append:/var/log/ebpf-engine.log \
  --property=WorkingDirectory=/home/ubuntu/ebpf-poc \
  /home/ubuntu/ebpf-poc/engine-linux-amd64 \
    -tetragon       unix:///var/run/tetragon/tetragon.sock \
    -db             /var/lib/ebpf-engine/events.db \
    -http           :8080 \
    -user           admin -pass ebpf-soc-demo \
    -policies       /home/ubuntu/ebpf-poc/policies \
    -choke-policies /home/ubuntu/ebpf-poc/policies/choke \
    -attacks        /home/ubuntu/ebpf-poc/attacks \
    -honeypots      /var/lib/ebpf-engine/honey \
    -enforce \
    -cgroup-root    /sys/fs/cgroup
```

### Choke gateway flags

| Flag | Default | Purpose |
|---|---|---|
| `-enforce` | off (detect-only) | Wire the real enforcer chain. Without this the engine still records decisions but never moves a PID into a cgroup or sends SIGKILL. |
| `-dry-run` | off | Decisions recorded, no enforcement. Stack on top of `-enforce` to shadow-roll a new policy. |
| `-choke-policies <dir>` | `policies/choke` | DSL directory loaded at startup. |
| `-cgroup-root <path>` | `/sys/fs/cgroup` | Where the engine creates `choke-throttled`, `choke-tarpit`, `choke-quarantined`. Must be the cgroup v2 unified mount. |
| `-throttle-at` `-tarpit-at` `-quarantine-at` `-sever-at` | `5 / 15 / 25 / 40` | Chain-score thresholds for each tier. Tunable live via the choke console (PUT `/api/choke/thresholds`). |

### What the cgroup tiers actually do

When the engine starts with `-enforce`, the cgroup v2 backend creates
three sibling cgroups under `-cgroup-root` and applies these limits:

| Tier | `cpu.max` | `pids.max` | `io.weight` | `memory.high` | Behaviour |
|---|---|---|---|---|---|
| `choke-throttled`   | 5% of one core | 200 | 10 | 512 MiB | Real CPU throttle |
| `choke-tarpit`      | 1% of one core | 50  | 1  | 128 MiB | Severely degraded |
| `choke-quarantined` | (frozen)       | 10  | 1  | 64 MiB  | `cgroup.freeze=1` — process pauses immediately |

Sever is handled separately (SIGKILL via `kill(2)` from the userspace
severer) and additionally clears the BPF map entry so a future PID-reuse
doesn't inherit shaping.

Verify:

```bash
sudo systemctl is-active ebpf-engine     # → active
sudo ss -tlnp | grep 8080                # → LISTEN ... *:8080 ... engine-linux-am
sudo journalctl -u ebpf-engine -n 20 --no-pager
```

## 9. Open the UI — [macOS host]

```bash
multipass info ebpf | awk '/IPv4/{print $2}'
```

Two pages now serve from the same engine:

| Path | Purpose |
|---|---|
| `http://<vm-ip>:8080/`        | SOC dashboard (alerts, events, MITRE coverage, IOCs) |
| `http://<vm-ip>:8080/choke`   | **Choke Gateway Console** — process state, thresholds, manual override, kill-switch, policy workbench |

Login: **`admin` / `ebpf-soc-demo`**.

### Verify enforcement is live

```bash
# Choke tiers exist with the right limits
multipass exec ebpf -- bash -lc 'for t in throttled tarpit quarantined; do echo "=== choke-$t ==="; cat /sys/fs/cgroup/choke-$t/cpu.max /sys/fs/cgroup/choke-$t/pids.max 2>/dev/null; done'

# Engine reports its mode
VM=$(multipass info ebpf | awk '/IPv4/{print $2; exit}')
curl -s -c /tmp/c -d 'user=admin&pass=ebpf-soc-demo' http://$VM:8080/api/login -o /dev/null
curl -s -b /tmp/c http://$VM:8080/api/choke/state | jq .mode
# expect: "enforcing"
```

## 10. Smoke-test the API — [macOS host]

```bash
VM=$(multipass info ebpf | awk '/IPv4/{print $2}')

curl -sS -c /tmp/c.txt -o /dev/null \
  -X POST -d 'user=admin&pass=ebpf-soc-demo' \
  http://$VM:8080/api/login

for ep in /api/whoami /api/policies /api/attacks /api/honeypots /api/policy-stats; do
  printf '%-22s → ' "$ep"
  curl -sS -b /tmp/c.txt -o /dev/null -w '%{http_code}\n' "http://$VM:8080$ep"
done
```

All five should return `200`.

## 11. Fire attacks — [inside VM]

```bash
sudo bash /home/ubuntu/ebpf-poc/attacks/01-webshell.sh
sudo bash /home/ubuntu/ebpf-poc/attacks/02-credential-theft.sh
sudo bash /home/ubuntu/ebpf-poc/attacks/03-reverse-shell.sh
sudo bash /home/ubuntu/ebpf-poc/attacks/04-privilege-escalation.sh
sudo bash /home/ubuntu/ebpf-poc/attacks/05-living-off-the-land.sh
sudo bash /home/ubuntu/ebpf-poc/attacks/06-persistence.sh

# Honeypot trigger — fires a `critical` alert with a 🍯 badge
sudo cat /var/lib/ebpf-engine/honey/_id_rsa >/dev/null

multipass exec ebpf -- sudo bash /home/ubuntu/ebpf-poc/attacks/01-webshell.sh 
```

### Watch the choke gateway respond

With `-enforce` on, the gateway moves PIDs into the choke cgroups in
real time as their chain score climbs. To watch:

```bash
# 1. open the console in another tab
open "http://$(multipass info ebpf | awk '/IPv4/{print $2; exit}'):8080/choke"

# 2. fire a long-running attack
multipass exec ebpf -- sudo bash /home/ubuntu/ebpf-poc/attacks/03-reverse-shell.sh

# 3. observe (from macOS):
#    - state ladder counts move out of "pristine"
#    - decision tape shows pristine → throttled → tarpit → ...
#    - Choke Map (kernel) panel shows the live PID
#    - cgroup tier file confirms it
multipass exec ebpf -- cat /sys/fs/cgroup/choke-throttled/cgroup.procs
```

### Manual override from the console

Hover any process row → click `↓` (throttle), `≋` (tarpit), `⌖`
(quarantine), or `✕` (sever). Sever / quarantine require a typed
audit reason — that text lands in the hash-chained `decisions` table
alongside the operator's username.

## 12. Operational one-liners — [inside VM]

```bash
sudo journalctl -u ebpf-engine -f                        # engine logs (live)
sudo systemctl status  ebpf-engine                       # is engine up?
sudo systemctl restart ebpf-engine                       # bounce engine
sudo systemctl stop    ebpf-engine                       # stop engine
sudo docker exec tetragon tetra getevents -o compact     # raw Tetragon events
sudo docker exec tetragon tetra tracingpolicy list       # active policies
sudo docker restart tetragon                             # restart Tetragon
sudo ls -la /var/lib/ebpf-engine/honey/                  # list seeded honeypots
```

## 13. VM lifecycle — [macOS host]

```bash
# pause (preserves state)
multipass stop ebpf    

# resume
multipass start ebpf                         

# run policies
multipass exec ebpf -- bash -c 'cd /home/ubuntu/ebpf-poc && sudo make policies-apply' 2>&

# nuke entirely
multipass delete ebpf && multipass purge     
```

---

## Gotchas we've hit

### A. `engine-linux-amd64: No such file or directory`

You started the engine before the tarball finished extracting. Re-run
step 5, then step 8.

### B. `Failed to start transient service unit: Unit ebpf-engine.service already exists.`

A previous `systemd-run` left the unit defined (or failed). The first
three lines of step 8 (`systemctl stop` → `reset-failed` → `pkill`)
clear that — re-run step 8 from the top, not just the
`systemd-run` invocation.

### C. `multipass list: The client is not authenticated with the Multipass service`

Auto-update on macOS can desync the daemon's trusted-clients store from
your client cert. Recovery:

```bash
brew uninstall --cask multipass
sudo rm -rf "/var/root/Library/Application Support/multipass-client-certificate"
rm -rf "$HOME/Library/Application Support/multipass-client-certificate"
sudo rm -rf "/var/root/Library/Application Support/multipassd" \
            "/Library/Application Support/com.canonical.multipass/data"
brew install --cask multipass
multipass list
```

(Wipes daemon state — your VMs survive only if the underlying disk
images are intact; usually you'll need to relaunch from step 2.)

### D. `quay.io/cilium/tetragon:latest: not found`

Cilium no longer publishes a `:latest` tag. Always set
`TETRAGON_IMAGE=quay.io/cilium/tetragon:v1.6.1` (or a newer pinned tag)
when invoking `setup.sh`.

### E. Engine logs say `tetragon socket not ready`

Tetragon takes a few seconds after `docker run` to bind the gRPC
socket. `setup.sh` waits for it; if you started the engine yourself
before that, retry once.

### F. Flood of `sshd → /bin/sh → /usr/bin/env → /usr/bin/run-parts → ...` alerts

That's Ubuntu's login MOTD running on every SSH session — harmless
noise from `setup.sh` / `multipass exec` opening a session, not a real
attack chain.

**Why it scores `critical`** (and why the count balloons):

1. **`/etc/passwd` reads.** Several MOTD scripts
   (`50-landscape-sysinfo`, `91-release-upgrade`) and sshd itself read
   `/etc/passwd` to resolve user info. That trips the
   `sensitive-file-access` policy and tags the chain `T1003 Credential
   Access`.
2. **Score accumulates down the process tree.** Each child exec
   inherits + adds to its parent's score, so a 7-deep chain ends up at
   113-189 — well past the critical threshold. Every new descendant
   fires its own `[ALERT critical]`, so a handful of `multipass exec`
   calls can easily produce 90+ critical alerts.

#### Clean it up

```bash
# Option 1 — wipe the alert DB and restart the engine (clean slate)
multipass exec ebpf -- sudo systemctl stop ebpf-engine
multipass exec ebpf -- sudo rm -f /var/lib/ebpf-engine/events.db
multipass exec ebpf -- sudo systemctl start ebpf-engine

# verify
multipass exec ebpf -- sudo systemctl is-active ebpf-engine
multipass exec ebpf -- sudo ss -tlnp | grep 8080
```

```bash
# Option 2 — stop generating new noise
#   - run a single `multipass shell ebpf` and stay inside, instead of
#     repeated `multipass exec` calls (each one triggers MOTD)
#   - or disable the MOTD scripts:
multipass exec ebpf -- sudo chmod -x /etc/update-motd.d/*
```

Real attack chains (from step 11) are cleaner, tagged with the
attack's MITRE technique, and stand out clearly once the MOTD churn
stops.
