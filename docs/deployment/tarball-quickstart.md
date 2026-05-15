# Tarball quickstart — build, ship, run

The fastest path from a clean checkout to the dashboard in a browser.
Build the tarball on any machine with Go 1.22+ (Linux or macOS), ship it
to a Linux host, run the engine, open the URL.

For the full deployment guide with TLS, systemd, and tuning, see
[linux-server.md](linux-server.md).

## Prerequisites

**Build machine** (any OS):
- Go 1.22+
- `make`, `tar`

**Target machine** (Linux):
- Ubuntu 22.04 / 24.04 LTS (Debian 12 also works)
- Kernel ≥ 5.15 with BTF (`ls /sys/kernel/btf/vmlinux` returns a file)
- `sudo`, outbound HTTPS, 2 vCPU / 4 GB RAM / 20 GB disk

Quick preflight on the target:

```bash
uname -r                       # ≥ 5.15
ls /sys/kernel/btf/vmlinux     # must exist
```

## 1. Build the tarball

From the repo root on your build machine:

```bash
make tarball
```

This cross-compiles `engine/engine-linux-amd64` and bundles it with the
policies, attack scripts, scripts, and docs into
`ebpf-poc-amd64.tar.gz` at the repo root (~12 MB).

For ARM64 servers (Graviton, Ampere, Raspberry Pi 5):

```bash
make tarball LINUX_ARCH=arm64
```

## 2. Copy it to the Linux host

```bash
scp ebpf-poc-amd64.tar.gz user@server:~/
```

If you use a downloaded key file:

```bash
scp -i ~/.ssh/my-key.pem ebpf-poc-amd64.tar.gz ubuntu@1.2.3.4:~/
```

## 3. Extract on the host

SSH in and unpack:

```bash
ssh user@server
mkdir -p ~/ebpf-poc
tar -xzf ~/ebpf-poc-amd64.tar.gz -C ~/ebpf-poc
cd ~/ebpf-poc
```

## 4. Run setup.sh

Installs Docker, Go, the Tetragon container, and the `tetra` CLI.
Idempotent — safe to re-run.

```bash
TETRAGON_IMAGE=quay.io/cilium/tetragon:v1.6.1 bash scripts/setup.sh
```

When it finishes you should have a running `tetragon` container:

```bash
sudo docker ps | grep tetragon
```

## 5. Load the TracingPolicies

```bash
sudo make policies-apply
```

Confirm they're enabled:

```bash
sudo docker exec tetragon tetra tracingpolicy list
```

All policies should show `STATE=enabled`.

## 6. Create the database directory

Keep the DB outside any path watched by the policies:

```bash
sudo mkdir -p /var/lib/ebpf-engine
sudo chown root:root /var/lib/ebpf-engine
sudo chmod 700 /var/lib/ebpf-engine
```

## 7. Run the engine

```bash
sudo ./engine/engine-linux-amd64 \
  -tetragon  unix:///var/run/tetragon/tetragon.sock \
  -db        /var/lib/ebpf-engine/events.db \
  -http      :8080 \
  -user      admin \
  -pass      'pick-something-strong' \
  -policies  ./policies \
  -attacks   ./attacks \
  -honeypots /var/lib/ebpf-engine/honey
```

You should see:

```
honeypots: seeded at /var/lib/ebpf-engine/honey
HTTP listening on :8080 (auth: user=admin)
```

To keep it running across SSH disconnects, prefix with `nohup … &` or
follow [linux-server.md](linux-server.md) to install it as a systemd
unit.

## 8. Open the dashboard

Find the server's IP:

```bash
hostname -I | awk '{print $1}'
```

In your browser:

```
http://<server-ip>:8080/
```

Log in with the user/pass you set in step 7.

If the page doesn't load:

```bash
# Confirm the engine is listening
sudo ss -tlnp | grep ':8080'

# Open the firewall (UFW)
sudo ufw allow 8080/tcp

# Cloud VM: also open :8080 in the security group / NSG
```

## What to try next

- **Choke console:** `http://<server-ip>:8080/choke` — live process state
  ladder and enforcement controls.
- **Fire an attack:** `sudo bash attacks/01-webshell.sh` — should appear
  in the dashboard within seconds and walk up the state ladder.
- **Production layout:** [linux-server.md](linux-server.md) for systemd,
  TLS via nginx, and credential rotation.
