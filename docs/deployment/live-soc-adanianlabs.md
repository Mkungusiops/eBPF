# Live deployment & verification runbook — `soc.adanianlabs.io`

Operational record + reproducible runbook for the live engine running on the
Azure host **`safeai-security-client`** (SSH alias; `20.238.49.130`,
user `azureuser`, key `~/Code/safeai-security-client-key.pem`).

Everything in this document was executed against that box on **2026-06-25**.
All scripts/source referenced here have local copies in this repo — nothing of
substance lives only on the server. The compiled `devchoke.o` on the box is a
build artifact regenerated from [`engine/internal/enforce/devbpf/bpf/devchoke.c`](../../engine/internal/enforce/devbpf/bpf/devchoke.c).

---

## 1. How the engine runs on this box

| Property | Value |
|---|---|
| Host | Ubuntu 24.04, kernel `6.17-azure`, **single logical NIC** (`eth0` + Azure SR-IOV slave) |
| Process | a **bare root background process** — *not* a systemd unit (`systemctl is-active ebpf-engine` = `inactive`); no auto-restart on crash/reboot |
| Working dir | `/home/azureuser/ebpf-poc` |
| Front door | nginx TLS (Certbot) `soc.adanianlabs.io` → `proxy_pass http://127.0.0.1:8080` |
| Login | `admin` / `ebpf-soc-demo` |
| Tetragon | container `tetragon` (`quay.io/cilium/tetragon:v1.6.1`), socket `/var/run/tetragon/tetragon.sock` |
| Also on box | Wazuh stack (`wazuh-monitor-app`, `wazuh-monitor-db`) |

Launch line (the `[-enforce]` flag is the mode trap — see §3):

```bash
cd /home/azureuser/ebpf-poc
./engine-linux-amd64 -tetragon unix:///var/run/tetragon/tetragon.sock \
  -policies policies -choke-policies policies/choke [-enforce] -http :8080
```

---

## 2. Deploy / redeploy procedure

The engine is a bare root process, so "deploy" = rebuild the linux binary
locally, ship it, atomic-swap, restart. No `make deploy-remote` target matches
this layout exactly; the steps below are what was actually run.

```bash
# 1. Build the linux binary locally (Go >=1.21; embeds the HTML/UI)
make build-linux                       # -> engine/engine-linux-amd64

# 2. Back up the live binary + stage the new one (no downtime yet)
ssh safeai-security-client 'cp -a /home/azureuser/ebpf-poc/engine-linux-amd64 \
    /home/azureuser/ebpf-poc/engine-linux-amd64.bak-$(date +%Y%m%d)'
scp engine/engine-linux-amd64 \
    safeai-security-client:/home/azureuser/ebpf-poc/engine-linux-amd64.new
ssh safeai-security-client 'chmod +x /home/azureuser/ebpf-poc/engine-linux-amd64.new'

# 3. Swap + restart — get the listener PID precisely, DO NOT use pkill (see warning)
ssh safeai-security-client 'set -e; cd /home/azureuser/ebpf-poc
  PID=$(sudo ss -tlnpH "sport = :8080" | grep -oE "pid=[0-9]+" | head -1 | cut -d= -f2)
  mv -f engine-linux-amd64.new engine-linux-amd64        # atomic; old inode keeps running
  [ -n "$PID" ] && sudo kill -TERM "$PID"                # graceful stop
  for i in $(seq 1 20); do sudo ss -tlnH "sport = :8080" | grep -q :8080 && sleep 0.3 || break; done
  # start DETECT-ONLY (omit -enforce) — see §3 for why
  sudo bash -c "cd /home/azureuser/ebpf-poc && setsid ./engine-linux-amd64 \
    -tetragon unix:///var/run/tetragon/tetragon.sock -policies policies \
    -choke-policies policies/choke -http :8080 >> /var/log/ebpf-engine.log 2>&1 < /dev/null &"'

# 4. Verify
curl -s -o /dev/null -w "%{http_code}\n" https://soc.adanianlabs.io/   # expect 302
curl -s -b <jar> https://soc.adanianlabs.io/api/version                # sha changes per build
```

> ### ⚠️ Never `pkill -f "engine-linux-amd64 -tetragon"` from a script
> The restart command's own text contains that string, so `pkill -f` matches the
> controlling shell and kills your SSH session (exit 255) **before** the swap/start
> runs — taking the live demo down mid-deploy. Always target the exact listener PID
> from `ss` (as above). This bit us once on 2026-06-25; recovered by reconnecting.

**Rollback:** `mv engine-linux-amd64.bak-before-ui engine-linux-amd64` (or
`.bak-YYYYMMDD`) then repeat step 3's swap/restart. DB rollback artifact:
`events.db.bak-20260625`.

---

## 3. Enforcement mode & the sudo-lockout trap

Boot mode is taken **only** from the `-enforce` flag
([`gateway.go:178`](../../engine/internal/choke/gateway.go#L178)) — it is *not*
restored from the store. The UI "ENFORCING / DETECT-ONLY" toggle is runtime-only
and does **not** survive a process restart.

In **ENFORCING** mode the process choke scores `/usr/bin/sudo` ~120+ and severs
it, so every `sudo` (and any deploy step that needs root) gets **SIGKILL'd
(exit 137)** and the box looks "locked." Fix: switch to **DETECT-ONLY** (UI, or
boot without `-enforce`). **Always deploy/operate in detect-only**, then flip to
enforcing from the UI when you specifically want live severing — knowing it will
again cut `sudo`.

---

## 4. Tetragon policies are INDEPENDENT of the engine's mode

> **Resolved.** This section described a box whose Tetragon policies enforced
> regardless of the engine's mode. That is no longer how the platform ships, and
> the fix is described below — but the hazard is kept on record because any host
> provisioned before this change still has the old policy set, and because the
> independence itself has not gone away. It is only disarmed.

Separate from the engine, the **tetragon container** loads its own
TracingPolicies. A `Sigkill` in one fires whatever the engine's mode says, with
no audit row, no reversal and no kill-switch — so switching the *engine* to
detect-only did **not** disable them.

### Operational side-effect: this broke `apt`
`override-credential-read` SIGKILLed any non-allowlisted process reading a
credential path. Package maintainer scripts run through `debconf` — a
`#!/usr/bin/perl` script, and `matchBinaries` matches the *executable*, so
allow-listing the script's own path had no effect. They were killed
mid-configure, leaving packages **half-configured (`iF`/`iU`)** and blocking all
further apt. Driven by `unattended-upgrades` on a timer, it degrades a fleet
silently over days. The same policy also SIGKILLed the OpenSSH login path and
locked an operator out of a host.

### The fix, as shipped now
Every policy in `policies/` declares `policy-mode: monitor`, under which Tetragon
suppresses enforcing actions **in the kernel** while leaving `Post` untouched —
verified on v1.6.1: a `Sigkill` policy returned exit 0 with the option and 137
without, with identical `Post` delivery. It is declarative, so it survives a
restart (`tetra tracingpolicy set-mode` does not). Enforcement lives in the
engine's choke gateway, which is mode-aware, reversible and audited.

```bash
sudo docker exec tetragon tetra tracingpolicy list
# every row should read MODE=monitor and NENFORCE=0
```

To repair a host still carrying the old set:

```bash
# finish any half-configured packages first
sudo docker exec tetragon tetra tracingpolicy disable override-credential-read
sudo DEBIAN_FRONTEND=noninteractive dpkg --configure -a
sudo docker exec tetragon tetra tracingpolicy enable  override-credential-read
# then redeploy the policies so they carry the monitor declaration
make policies-apply
```

`scripts/e2e/host-posture.sh` asserts all of this per host, and the console
reports it live via `kernel.diverged` on `/api/choke/state`.

---

## 5. Device-choke verification (netns lab) — proving real enforcement

### Why the live `/devices` shows `plane=noop`
This is a **single-NIC cloud VM**, not a 2-NIC inline bridge. The engine is
started without `-devchoke-obj`/`-devchoke-iface`, so `data_plane=noop,
links=0, frames=0`. The "devices" it lists are just ARP neighbours (Docker
containers + the Azure gateway). Device choking here records audited decisions
but drops **zero packets** — it cannot, structurally, on this host.

### Proving the data plane really enforces (safe, isolated)
[`scripts/dev/netns-smoke.sh`](../../scripts/dev/netns-smoke.sh) +
[`netns-lab.sh`](../../scripts/dev/netns-lab.sh) build a 3-namespace lab
(`ns-dev → ns-gw → ns-net`) that reproduces *forwarded* traffic, attach the real
TC/BPF plane to lab veths (**never** `eth0`/docker), and assert drop + restore.
The engine runs in `-fake` mode inside `ns-gw` binding `:8080` *in that
namespace* — fully isolated from the live engine.

**Prereqs installed on the box (were missing):** `clang`, `libbpf-dev`
(`devchoke.c` includes `<bpf/bpf_helpers.h>`). `setup.sh` also installs these.

```bash
# toolchain (one-time)
sudo apt-get update -y
sudo apt-get install -y clang libbpf-dev      # NOT the llvm meta — pulls a stale libxml2-dev (404)

# compile the data plane on the box
cd /home/azureuser/ebpf-poc/lab
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c devchoke.c -o devchoke.o

# run the lab against the existing engine binary (read-only execute)
sudo bash /home/azureuser/ebpf-poc/scripts/dev/netns-smoke.sh \
  /home/azureuser/ebpf-poc/lab/devchoke.o \
  /home/azureuser/ebpf-poc/engine-linux-amd64
```

**Result (2026-06-25): 6/6 PASSED.**

```
data_plane: "tc"   links_attached: 2   enforcing: true   frames_seen: 4
PASS: data plane attached (links=2)
PASS: baseline: device reaches upstream
PASS: data plane sees forwarded frames (frames_seen=4)
PASS: after sever: device traffic DROPPED        # real packet drop, keyed by MAC
PASS: API reports device state=severed
PASS: after thaw: device traffic RESTORED        # reversible
```

The lab auto-tears-down (trap) — no leftover namespaces, `eth0` untouched.

### To make the LIVE box actually enforce (not done)
Requires the intended topology: an inline 2-NIC bridge, then start the engine
with `-devchoke-obj .../devchoke.o -devchoke-iface eth0,eth1` and a
`-devchoke-protect` allow-list for the gateway/uplink MAC. On a single-NIC VM
it stays preview-only by design.

---

## 6. Change log — what was executed on the box (2026-06-25)

1. **Removed** an old Go 1.17.1 tree at `/usr/local/go` (local-machine fix, not the server).
2. **Deployed** the `feat/network_choke` engine (build → backup → atomic swap → start detect-only); verified.
3. **Redeployed** after the UI changes (Devices nav item, in-app modal); verified Devices nav + modal live.
4. **Killed** a stuck systemd `apt-daily` `apt-get update` (PID 101286, wedged 7m) holding the apt lock; stopped `apt-daily*`/`apt-news` services (timers left enabled).
5. **Installed** `clang` + `libbpf-dev` for BPF compilation.
6. **Reconfigured** `libpam-systemd` (was `iF`, killed by `override-credential-read`) via temporary policy disable → `dpkg --configure -a` → re-enable. Now `ii`; policy back to `enforce`.
7. **Compiled** `devchoke.o` and ran the netns lab → 6/6 pass; lab torn down.
8. Cleaned macOS `._*` AppleDouble files left by `tar`.

### Rollback / backup artifacts left on the box
- `/home/azureuser/ebpf-poc/engine-linux-amd64.bak-20260625` (pre–first-deploy)
- `/home/azureuser/ebpf-poc/engine-linux-amd64.bak-before-ui` (pre–UI-deploy)
- `/home/azureuser/ebpf-poc/events.db.bak-20260625`
- `/home/azureuser/ebpf-poc/lab/{devchoke.c,devchoke.o}` (lab build inputs/outputs)
