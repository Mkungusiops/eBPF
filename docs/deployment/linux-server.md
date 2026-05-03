# Deploy to a fresh Linux server

Step-by-step recipe for getting this PoC running on a freshly-provisioned
Linux server (cloud VM, bare metal, or hypervisor guest). Designed so the
person reading this hasn't seen the codebase before.

For the architecture and design rationale, see [architecture/overview.md](../architecture/overview.md).

## 1. Server prerequisites

| Requirement              | Why                                                              |
|--------------------------|------------------------------------------------------------------|
| **Linux**                | Tetragon's eBPF programs only run on Linux                       |
| Ubuntu 22.04 / 24.04 LTS | What `setup.sh` installs against; Debian 12 should also work     |
| Kernel **≥ 5.15**        | Stable verifier + BTF support                                    |
| `/sys/kernel/btf/vmlinux` | Tetragon needs BTF for portable type info                        |
| `sudo` available         | Tetragon container needs `--privileged --pid=host`               |
| Outbound HTTPS           | To pull the Tetragon image and Go toolchain                      |
| 2 vCPU, 4 GB RAM, 20 GB  | Minimum for the demo; production is policy-dependent             |

Quick preflight:

```bash
uname -r                          # must be ≥ 5.15
ls /sys/kernel/btf/vmlinux        # must exist
free -m | grep Mem                # ≥ 4 GB recommended
df -h /                           # ≥ 10 GB free
```

If `/sys/kernel/btf/vmlinux` is missing, your kernel was built without
`CONFIG_DEBUG_INFO_BTF`. On Ubuntu 22.04+ stock cloud images this is
already enabled. If you're on a custom kernel, rebuild with BTF or pick
a different distro image.

## 2. Get the bundle to the server

You have three options. Pick one based on your workflow.

### Option A — Build a tarball on a dev machine, scp it over (simplest)

On a machine with Go 1.22+ installed:

```bash
git clone <repo-url> ebpf-poc        # or download/extract a release
cd ebpf-poc
make tarball                          # produces ebpf-poc-amd64.tar.gz (~12 MB)
```

For ARM64 servers, build with `make tarball LINUX_ARCH=arm64` instead
(produces `ebpf-poc-arm64.tar.gz`).

#### Copy it over with scp

The minimal form, when SSH config / keys are already set up:

```bash
scp ebpf-poc-amd64.tar.gz user@server:~/
```

Common variants:

```bash
# Cloud VM with a downloaded key file (AWS / GCP style)
scp -i ~/.ssh/my-key.pem ebpf-poc-amd64.tar.gz ubuntu@1.2.3.4:~/

# Non-default SSH port (note capital -P; lowercase is for ssh)
scp -P 2222 ebpf-poc-amd64.tar.gz user@server:~/

# Show progress on a slow connection
scp -v ebpf-poc-amd64.tar.gz user@server:~/

# Resume / mirror with rsync — preferred for iterating during dev
rsync -avz --progress ebpf-poc-amd64.tar.gz user@server:~/
```

If your `~/.ssh/config` already has a `Host` block with `IdentityFile`,
`Port`, `User` etc., the minimal `scp ebpf-poc-amd64.tar.gz host:~/`
form picks all of that up automatically.

Verify what landed:

```bash
ssh user@server 'ls -lh ~/ebpf-poc-amd64.tar.gz'
```

#### Extract on the server

```bash
ssh user@server
mkdir -p ~/ebpf-poc
tar -xzf ~/ebpf-poc-amd64.tar.gz -C ~/ebpf-poc
cd ~/ebpf-poc
ls
# Makefile  README.md  attacks  build.md  engine  policies  scripts
```

> **Iterating?** When you rebuild the engine and want to push *just the
> binary* without re-shipping the whole tarball:
> ```bash
> # on the dev machine, after `make build-linux`
> scp engine/engine-linux-amd64 user@server:/tmp/
> # on the server
> sudo install -m 0755 /tmp/engine-linux-amd64 /usr/local/bin/ebpf-engine
> sudo systemctl restart ebpf-engine
> ```

### Option B — Clone and build directly on the server

```bash
sudo apt-get update
sudo apt-get install -y git
git clone <repo-url> ~/ebpf-poc
cd ~/ebpf-poc
# scripts/setup.sh below will install Go for you,
# then you can run `make build-linux` here.
```

### Option C — From a CI artifact

If your team publishes the tarball to S3 / GCS / Artifactory:

```bash
curl -fsSL https://your-artifact-store/ebpf-poc-amd64.tar.gz | tar -xzC ~/ebpf-poc
cd ~/ebpf-poc
```

## 3. Run setup.sh

`scripts/setup.sh` is idempotent: re-running it is safe, and it skips
anything already installed.

```bash
cd ~/ebpf-poc
TETRAGON_IMAGE=quay.io/cilium/tetragon:v1.6.1 bash scripts/setup.sh
```

What it does, in order:

1. Verifies kernel ≥ 5.15 and BTF.
2. `apt-get install` of `git curl make jq build-essential ca-certificates`.
3. Installs Docker via `get.docker.com` (skipped if already present).
4. Adds the current user to the `docker` group.
5. Installs Go 1.22.5 to `/usr/local/go` and adds it to `~/.bashrc`.
6. Pulls the Tetragon image and starts a container named `tetragon` with
   `--privileged --pid=host --cgroupns=host`, mounting the Tetragon socket
   at `/var/run/tetragon/`.
7. Installs the `tetra` CLI to `/usr/local/bin`.
8. Waits for the Tetragon gRPC socket to appear.

> **Important:** the `:latest` tag for `quay.io/cilium/tetragon` is no
> longer published. Always pin a versioned tag via `TETRAGON_IMAGE`.
> v1.6.1 is the current stable as of writing.

### 3a. Smoke-test that kernel events are flowing

Before going further, confirm Tetragon is actually seeing `execve` calls.
Without this, every later step looks fine but produces nothing.

```bash
# Tail live events for ~3 s while triggering an exec in another shell.
sudo tetra getevents -o compact \
  --server-address unix:///var/run/tetragon/tetragon.sock &
TETRA_PID=$!
sleep 1; ls /tmp >/dev/null; sleep 2
kill "$TETRA_PID" 2>/dev/null
wait "$TETRA_PID" 2>/dev/null || true
```

You should see at least one `process_exec` line mentioning `ls`. If the
stream is silent, the most likely causes are: container not running
(`docker ps | grep tetragon`), socket missing
(`ls -la /var/run/tetragon/tetragon.sock`), or BPF programs failed to
load (`docker logs tetragon --tail 50` looking for "verifier rejected").

## 4. Apply the TracingPolicies

```bash
sudo make policies-apply
```

You should see:

```
ID   NAME                    STATE     SENSORS          MODE
1    outbound-connections    enabled   generic_kprobe   enforce
2    privilege-escalation    enabled   generic_kprobe   enforce
3    sensitive-file-access   enabled   generic_kprobe   enforce
```

These are now eBPF programs **running in the kernel**. They will fire on
every matching syscall whether the engine is up or not. Tetragon will
buffer events for the engine to consume.

> **Note about `sensitive-file-access`:** the policy in this repo watches
> `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/root/.ssh/`, **and
> `/var/lib/ebpf-engine/honey/`** — the last prefix is the honeypot
> directory the engine seeds on startup (see §5a below). If you're
> upgrading from an older deploy that loaded the policy without the
> honeypot prefix, re-run `make policies-apply` after extracting the new
> tarball so Tetragon picks up the updated YAML.

### 4a. Spot-check that a policy fires

Trigger a `sensitive-file-access` event by reading `/etc/shadow`, then
confirm Tetragon's per-policy `NPOST` counter advanced:

```bash
sudo cat /etc/shadow >/dev/null
sudo docker exec tetragon tetra tracingpolicy list
```

The `sensitive-file-access` row's `NPOST` column should be ≥ 1. If it
stays at 0, the kprobe didn't match — check kernel symbol availability
(`grep security_file_permission /proc/kallsyms`) and confirm the policy
is in `enabled` state, not `error`.

## 5. Choose a place for the database

Best practice: put the engine's SQLite database **outside** any path the
credential-access policy watches.

```bash
sudo mkdir -p /var/lib/ebpf-engine
sudo chown root:root /var/lib/ebpf-engine
sudo chmod 700 /var/lib/ebpf-engine
```

If you put it under `/home/`, the engine's own writes will trigger the
sensitive-file-access kprobe and fill the DB with self-noise. The
included policy excludes `/home/` so this isn't an issue, but pinning
the data path to `/var/lib/` is the durable fix.

### 5a. Honeypot directory (auto-seeded)

The engine seeds five decoy credential-style files at
`/var/lib/ebpf-engine/honey/` on startup:

| File              | Purpose                                                 |
|-------------------|---------------------------------------------------------|
| `_passwd`         | decoy `/etc/passwd`-style file                          |
| `_shadow`         | decoy credential hashes                                 |
| `_id_rsa`         | decoy SSH private key                                   |
| `_aws_credentials`| decoy AWS access key + secret                           |
| `_db_backup.sql`  | decoy DB dump                                           |

Because the `sensitive-file-access` policy now watches that prefix,
**any read of these files immediately fires a `critical` alert** with a
🍯 *honey* badge. Honeypots are the highest-signal indicator in the
dashboard — the only legitimate caller is your own incident response
process, so any hit is unambiguous.

You don't need to create the directory manually; `EnsureHoneypots` is
called from the engine's `main()` and creates anything missing. To
override the location, pass `-honeypots <dir>` (see §6/§7). To disable,
point `-honeypots /tmp/disabled-honey-dir` and remove the prefix from
the sensitive-files YAML.

## 6. Set credentials

The default credentials (`admin / ebpf-soc-demo`) are baked into the
binary for the demo. **Change them in any real deployment.**

The clean way is an environment file consumed by systemd (next step).
For a quick manual run:

```bash
sudo ./engine/engine-linux-amd64 \
  -tetragon  unix:///var/run/tetragon/tetragon.sock \
  -db        /var/lib/ebpf-engine/events.db \
  -http      :8080 \
  -user      admin \
  -pass      'pick-something-strong' \
  -policies  ~/ebpf-poc/policies \
  -attacks   ~/ebpf-poc/attacks \
  -honeypots /var/lib/ebpf-engine/honey
```

| Flag         | Purpose                                                                    |
|--------------|----------------------------------------------------------------------------|
| `-tetragon`  | gRPC socket exposed by the Tetragon container                              |
| `-db`        | SQLite path. Must be **outside** any path watched by the kprobes.          |
| `-http`      | Listen address. Bind to `127.0.0.1:8080` if you'll front it with a proxy.  |
| `-user`/`-pass` | Dashboard credentials (bcrypt-hashed at startup, plaintext discarded).  |
| `-policies`  | Directory holding the TracingPolicy YAMLs. Required for the in-app **Policies** viewer panel. |
| `-attacks`   | Directory holding the allow-listed attack scripts. Required for the **Attacks** quick-fire panel; a missing dir returns 503. |
| `-honeypots` | Directory the engine seeds with decoy files at startup. Defaults to `/var/lib/ebpf-engine/honey`. |

Verify in the log lines:

```
honeypots: seeded at /var/lib/ebpf-engine/honey
HTTP listening on :8080 (auth: user=admin)
```

Note that `-pass` is read once, hashed with bcrypt, and discarded — it
doesn't linger in memory after startup. The plaintext is still visible
in `ps`/`/proc/<pid>/cmdline` while you launched it though, so prefer
the systemd env-file approach for anything beyond a quick test.

## 7. Run as a systemd service (recommended)

Create an environment file (root-readable only):

```bash
sudo install -m 0600 /dev/null /etc/ebpf-engine.env
sudo tee /etc/ebpf-engine.env > /dev/null <<EOF
EBPF_USER=admin
EBPF_PASS=pick-something-strong
EBPF_HTTP=:8080
EBPF_DB=/var/lib/ebpf-engine/events.db
EBPF_TETRAGON=unix:///var/run/tetragon/tetragon.sock
EBPF_POLICIES=/opt/ebpf-poc/policies
EBPF_ATTACKS=/opt/ebpf-poc/attacks
EBPF_HONEYPOTS=/var/lib/ebpf-engine/honey
EOF
```

Pin the policy and attack directories to a stable, root-owned path
(rather than `~/ebpf-poc/...`) so the systemd-run engine can read them
under the hardening directives below:

```bash
sudo mkdir -p /opt/ebpf-poc
sudo cp -r ~/ebpf-poc/policies ~/ebpf-poc/attacks /opt/ebpf-poc/
sudo chmod -R a+rX /opt/ebpf-poc
sudo chmod a+x /opt/ebpf-poc/attacks/*.sh
```

Place the engine binary somewhere stable:

```bash
sudo install -m 0755 ~/ebpf-poc/engine/engine-linux-amd64 /usr/local/bin/ebpf-engine
```

Create the unit file:

```bash
sudo tee /etc/systemd/system/ebpf-engine.service > /dev/null <<'EOF'
[Unit]
Description=eBPF Threat Observability — correlation engine
After=docker.service network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/ebpf-engine.env
ExecStart=/usr/local/bin/ebpf-engine \
  -tetragon  ${EBPF_TETRAGON} \
  -db        ${EBPF_DB} \
  -http      ${EBPF_HTTP} \
  -user      ${EBPF_USER} \
  -pass      ${EBPF_PASS} \
  -policies  ${EBPF_POLICIES} \
  -attacks   ${EBPF_ATTACKS} \
  -honeypots ${EBPF_HONEYPOTS}
Restart=on-failure
RestartSec=5s
# The engine itself doesn't need root once Tetragon owns the kprobes,
# but it does need to read the Tetragon socket. Easiest: run as root.
User=root
Group=root
StandardOutput=append:/var/log/ebpf-engine.log
StandardError=append:/var/log/ebpf-engine.log

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
# /var/lib/ebpf-engine    — DB + honey/  (engine writes both)
# /var/log                — engine.log
ReadWritePaths=/var/lib/ebpf-engine /var/log
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now ebpf-engine
sudo systemctl status ebpf-engine --no-pager
```

Watch the log:

```bash
sudo tail -f /var/log/ebpf-engine.log
```

## 8. Open the dashboard

The engine binds to `0.0.0.0:8080` (or whatever `EBPF_HTTP` says).
**Don't expose this directly to the internet.**

### Option A — SSH tunnel (simplest, secure)

From your laptop:

```bash
ssh -L 8080:localhost:8080 user@server
```

Then open <http://localhost:8080> in your browser.

### Option B — Bind to localhost + reverse proxy with TLS

In `/etc/ebpf-engine.env`:

```
EBPF_HTTP=127.0.0.1:8080
```

Then put Caddy in front for automatic TLS:

```caddyfile
soc.example.com {
    reverse_proxy localhost:8080
}
```

Or nginx with your own certs. See `caddy` / `nginx` docs.

### Option C — Cloud security group

If you must expose it directly (don't), restrict the security group to
your office IP range and require an authenticated user from a trusted
network. The dashboard's auth gate is real but bcrypt is your only line
of defense — TLS in front is mandatory.

## 9. Validate

Confirm the login redirect works with the credentials you set, then
drive the full attack-simulation matrix.

### 9a. Login

Loading `/` while unauthenticated should bounce you to `/login`. Submit
the credentials from `/etc/ebpf-engine.env`. After login the dashboard
KPI panels are visible and the **● connected** indicator (top-right)
confirms SSE is wired up.

### 9a-bis. Smoke-test the dashboard's tooling endpoints

Confirm each sidebar tool has its server-side wiring intact. From your
laptop, with an SSH tunnel open (`ssh -L 8080:localhost:8080 user@server`):

```bash
# Capture the session cookie once
curl -sS -c /tmp/c.txt -o /dev/null \
  -X POST -d "user=admin&pass=$EBPF_PASS" \
  http://localhost:8080/api/login

curl -sS -b /tmp/c.txt http://localhost:8080/api/whoami       # {"user":"admin"}
curl -sS -b /tmp/c.txt http://localhost:8080/api/policies     # 3 entries with YAML
curl -sS -b /tmp/c.txt http://localhost:8080/api/attacks      # 6 allow-listed scripts
curl -sS -b /tmp/c.txt http://localhost:8080/api/honeypots    # prefix + 5 decoy files
curl -sS -b /tmp/c.txt http://localhost:8080/api/policy-stats # NPOST counters from tetra
```

If `/api/policies` returns three rows but with empty `yaml` fields, the
`-policies` flag points at a directory the engine can't read. If
`/api/attacks` returns 200 but `POST /api/run-attack` returns 503, same
thing for `-attacks`. If `/api/honeypots` returns no files, the engine
couldn't write to `-honeypots`; check `ReadWritePaths` in the systemd
unit.

### 9b. Drive the attack-simulation matrix

Open a *second* SSH session on the server (keep the dashboard tab open
in the browser) and run each script. Expected severities are documented
in each script's header comments and reproduced here:

```bash
cd ~/ebpf-poc

sudo bash attacks/01-webshell.sh                 # → critical (curl|sh + chmod +x + shadow read)
sudo bash attacks/02-credential-theft.sh         # → critical (multiple credential reads)
sudo bash attacks/03-reverse-shell.sh            # → medium  (bash → tcp_connect kprobe)
sudo bash attacks/04-privilege-escalation.sh     # → high    (setuid(0) + root reads)
sudo bash attacks/05-living-off-the-land.sh      # → critical (curl|sh + base64 -d)
sudo bash attacks/06-persistence.sh              # → medium  (chmod +x + dotfile recon)

# Honeypot smoke test — touching any decoy file should produce a critical
# alert with a 🍯 honey badge in the dashboard.
sudo cat /var/lib/ebpf-engine/honey/_id_rsa >/dev/null
```

For each, the dashboard should within ~1 s:
- prepend the alert to **Alert triage**
- bump the corresponding severity KPI
- raise the **Risk gauge**
- populate the matching **MITRE ATT&CK** technique counter
- (where relevant) list the credential path under **IOCs observed**

Click any alert to expand the **Process chain** drilldown — you should
see the full ancestor walk (`bash → curl`, `bash → sudo`, etc.) with
PIDs, UIDs, per-node scores, and the events that contributed.

If a scenario doesn't trigger, work the chain top-down: kernel symbol →
Tetragon counter (`tetra tracingpolicy list`) → engine log
(`/var/log/ebpf-engine.log`) → SQLite. See [Troubleshooting](#12-troubleshooting).

### 9c. Verify what landed in SQLite

Belt-and-braces — the dashboard surfaces only the recent slice; the DB
is the source of truth.

```bash
sudo apt-get install -y sqlite3

sudo sqlite3 /var/lib/ebpf-engine/events.db <<'SQL'
SELECT COUNT(*) AS events,
       COUNT(DISTINCT exec_id) AS processes
FROM events;

SELECT id, severity, score, substr(title, 1, 80) AS title
FROM alerts
ORDER BY id DESC
LIMIT 10;
SQL
```

After all six scripts you should see a healthy event count (low
hundreds), a non-trivial number of distinct `exec_id`s, and at least
one row per severity level except `info`.

### 9d. (Optional) Record a 3-minute demo

Per build plan §5.3, a short recording makes the "alert fires while the
attack is unfolding" property concrete to anyone watching.

```bash
sudo apt-get install -y asciinema
asciinema rec ~/ebpf-poc/demo.cast
# In a second shell on the server, run a couple of attacks/*.sh while
# screen-recording the browser tab. Ctrl-D in the asciinema shell to stop.
```

Suggested 3-minute beat-sheet:
1. **0:00 – 0:30** — Architecture overview; show `docker ps` + `systemctl status ebpf-engine`.
2. **0:30 – 1:30** — Run `attacks/01-webshell.sh`, watch the alert appear, click into the process chain.
3. **1:30 – 2:15** — Run `attacks/02-credential-theft.sh`; show how multiple events compound into one critical alert.
4. **2:15 – 3:00** — Run `attacks/03-reverse-shell.sh`; show the network kprobe firing and the parent shell highlighted.

The narrative point: each alert fires *during* the attack script's
execution, before the script finishes — that's the proactive value.

## 10. Operations

| Goal                          | Command                                                          |
|-------------------------------|------------------------------------------------------------------|
| Tail engine log               | `sudo tail -f /var/log/ebpf-engine.log`                          |
| Tail raw Tetragon events      | `sudo docker exec tetragon tetra getevents -o compact`           |
| List active policies          | `sudo docker exec tetragon tetra tracingpolicy list`             |
| Restart engine                | `sudo systemctl restart ebpf-engine`                             |
| Restart Tetragon              | `sudo docker restart tetragon`                                   |
| Engine kprobe counters        | `sudo docker exec tetragon tetra tracingpolicy list` (NPOST col) |
| Engine resource usage         | `sudo systemctl status ebpf-engine`                              |
| Free disk used by SQLite      | `sudo du -sh /var/lib/ebpf-engine`                               |
| List honeypot files           | `ls -la /var/lib/ebpf-engine/honey/`                             |
| Verify honeypots from API     | `curl -sS -b /tmp/c.txt http://localhost:8080/api/honeypots`     |
| Verify kprobe perf endpoint   | `curl -sS -b /tmp/c.txt http://localhost:8080/api/policy-stats`  |
| Re-seed missing honeypots     | `sudo systemctl restart ebpf-engine` (idempotent on startup)     |

### Upgrading the engine

```bash
# Rebuild a new tarball on your dev machine, scp it over, then:
sudo systemctl stop ebpf-engine
sudo install -m 0755 ~/ebpf-poc/engine/engine-linux-amd64 /usr/local/bin/ebpf-engine
sudo systemctl start ebpf-engine
```

The SQLite file at `/var/lib/ebpf-engine/events.db` survives upgrades.

### Rotating the database

The schema has no built-in retention. Either:

```bash
# Wipe and recreate:
sudo systemctl stop ebpf-engine
sudo rm -f /var/lib/ebpf-engine/events.db /var/lib/ebpf-engine/events.db-*
sudo systemctl start ebpf-engine
```

Or run a periodic VACUUM/DELETE via cron once the dataset gets large.
For real deployments, swap SQLite for ClickHouse or similar.

## 11. Hardening checklist

Before treating this as anything more than a demo:

- [ ] `EBPF_PASS` rotated from the default in `/etc/ebpf-engine.env`
- [ ] Engine is **not** publicly reachable (SSH tunnel, VPN, or TLS proxy with IP allowlist)
- [ ] `/var/log/ebpf-engine.log` rotated by `logrotate`
- [ ] Tetragon container set to restart on host reboot (`--restart=unless-stopped`)
- [ ] Backup of `/var/lib/ebpf-engine/events.db` if alert history matters
- [ ] Monitoring of the engine systemd unit (alert on failure)
- [ ] All six `attacks/*.sh` scripts validated and detected end-to-end
- [ ] Honeypot smoke test passes (`cat /var/lib/ebpf-engine/honey/_id_rsa` produces a `critical` alert with a 🍯 badge)
- [ ] Default `admin` username changed if your team policy requires it
- [ ] Outbound network access from the host restricted to what the engine needs (Tetragon image pull only happens once)
- [ ] `EBPF_ATTACKS` points at a stable read-only path (e.g. `/opt/ebpf-poc/attacks`) — clients can fire these scripts via the dashboard, so treat the directory contents like signed artifacts

## 12. Troubleshooting

### `setup.sh` says "kernel too old"

Stuck on a stock kernel < 5.15. Either upgrade to a newer Ubuntu LTS or
boot a HWE kernel: `sudo apt install linux-generic-hwe-22.04`.

### `setup.sh` says "BTF not found"

Your kernel was built without `CONFIG_DEBUG_INFO_BTF`. Use a
distribution kernel that ships with it (Ubuntu 22.04 LTS does).

### Tetragon container exits immediately

```bash
sudo docker logs tetragon
```

Most common cause: missing `--privileged` or `--pid=host`. Re-run
`setup.sh`; it removes a stopped container before starting a fresh one.

### Engine log says `dial tetragon: …: connection refused`

Tetragon is up but the socket isn't bound yet. The engine doesn't retry
on cold boot. With systemd configured as above, `Restart=on-failure`
will retry every 5s and pick it up.

### Dashboard shows alerts about the engine itself

The engine is being detected reading or writing its own files. Check:
- DB path is under `/var/lib/`, not `/home/`.
- The `sensitive-files` policy doesn't include a path the engine reads.
- The log file path isn't watched.

### `outbound-connections` counter stays at 0

Confirm the kprobe target works: run
`sudo bash ~/ebpf-poc/attacks/03-reverse-shell.sh`. The counter in
`tetra tracingpolicy list` should bump by 1. If it doesn't, the
kernel's `tcp_connect` symbol may not match — check
`grep tcp_connect /proc/kallsyms`.

### Browser shows "connecting…" forever

The SSE connection isn't establishing. Hit `/api/whoami` and check the
response. If 401, your session expired — log in again. If 200 but the
dashboard still says connecting, hard-reload (`Cmd/Ctrl + Shift + R`)
to fetch fresh JS.

### Sidebar tools show empty / 503 / "ships next deploy"

You're running an older binary, or the engine was started without the
`-policies` / `-attacks` / `-honeypots` flags. Check:

```bash
# What flags is systemd actually passing?
ps -ef | grep ebpf-engine | grep -v grep

# Is the env file populated?
cat /etc/ebpf-engine.env

# Are the directories readable by the systemd-restricted unit?
sudo -u root ls /opt/ebpf-poc/policies /opt/ebpf-poc/attacks /var/lib/ebpf-engine/honey
```

A common gotcha: `ProtectSystem=strict` in the unit file blocks writes
outside `ReadWritePaths`. If you put the honeypot dir somewhere outside
`/var/lib/ebpf-engine/`, add it to `ReadWritePaths`.

### Honeypot accesses don't fire alerts

The `sensitive-file-access` policy must include the honeypot prefix.
Verify the loaded YAML:

```bash
sudo docker exec tetragon tetra tracingpolicy list
# `sensitive-file-access` should show NPOST > 0 once you `cat` a decoy.

# If it doesn't — the loaded policy is stale. Re-apply:
cd ~/ebpf-poc && sudo make policies-apply
```

## 13. Uninstall

```bash
sudo systemctl disable --now ebpf-engine
sudo rm -f /etc/systemd/system/ebpf-engine.service /etc/ebpf-engine.env
sudo rm -f /usr/local/bin/ebpf-engine
sudo rm -rf /var/lib/ebpf-engine /var/log/ebpf-engine.log
sudo docker rm -f tetragon
sudo docker rmi quay.io/cilium/tetragon:v1.6.1
# Policies are kernel-resident in Tetragon — gone with the container.
```

The kprobes unload as soon as the Tetragon container stops, leaving no
residual kernel state.
