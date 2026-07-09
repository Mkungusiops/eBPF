# Deploy the Network Choke Gateway

Step-by-step recipe for running the **per-device (MAC) network choke** on an
inline Linux gateway — a transparent bridge placed in the traffic path so it
can throttle or block a LAN device's forwarded traffic.

This is a different deployment shape from the per-process choke
([linux-server.md](linux-server.md)): the box is **inline between the access
network and the internet**, it needs **two NICs**, and it does **not** require
Tetragon. For the design rationale read
[architecture/network-choke-gateway.md](../architecture/network-choke-gateway.md);
for the staged build read
[development/network-choke-build-plan.md](../development/network-choke-build-plan.md).

> **How this relates to the "XDP redirect" gateway shape.** A common inline
> design (e.g. a 5G UPF) attaches an **XDP** program on the ingress NIC that
> consults a userspace-programmed BPF map and `XDP_REDIRECT`s packets out the
> other NIC — the program *is* the forwarder. This gateway is the same idea
> with two deliberate differences: (1) it uses **TC clsact** (ingress **and**
> egress) instead of XDP, because XDP is RX-only and can't shape the download
> direction and XDP-native isn't available on bridge/veth paths; and (2) it
> **drops/passes** and lets the Linux **bridge** forward, rather than doing
> `XDP_REDIRECT` itself. Same control loop — userspace → BPF map → in-kernel
> per-packet decision — minus the redirect. An XDP fast-path is a planned v2
> add-on layered above this TC baseline.

---

## Validation status

The data plane and control path are validated end-to-end on a **real kernel**
(OrbStack Linux VM, **kernel 7.0.11**, Ubuntu 22.04) using the netns lab — no
router hardware:

| Check | Result |
|---|---|
| `devchoke.o` compiles (clang, real uapi headers) | ✅ |
| TCX attach (ingress + egress) — **verifier accepts the program** | ✅ 2 links |
| `frames_seen` increments on forwarded frames | ✅ |
| **throttle** (50/s) — flood passes | ✅ 0% loss |
| **quarantine** (1/s) — rate-limits, not block | ✅ flood 100% / slow ~33% loss |
| **sever** — blocks both directions | ✅ 100% loss |
| **DHCP/DNS whitelist** under quarantine (recover path) | ✅ UDP/53 8/8 pass, non-infra 0/8 |
| API path: login + CSRF + `device-jail`/`device-thaw` | ✅ |
| `make netns-smoke` automated gate | ✅ 6/6 |

Reproduce on your own kernel (≥ 6.6) with the one-command gate — it builds the
binary + `devchoke.o`, stands up a 3-namespace lab that reproduces *forwarded*
traffic, and asserts drop+restore, exiting non-zero on failure:

```bash
make netns-smoke        # Linux + root; the data-plane go/no-go gate
```

**On macOS via OrbStack** (how the above was validated), from the repo root:

```bash
orb create ubuntu ebpf        # once, if you don't already have a Linux machine
(cd engine && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o engine-linux-amd64 ./cmd/engine)
orb run -m ebpf make devchoke # compile devchoke.o against the VM's kernel headers
orb run -m ebpf sudo bash scripts/dev/netns-smoke.sh \
  "$PWD/engine/internal/enforce/devbpf/bpf/devchoke.o" "$PWD/engine/engine-linux-amd64"
```

(OrbStack mounts your macOS home, so the repo is at the same path inside the
VM. Go isn't needed in the VM — the binary is cross-built static on the Mac;
only `clang` + `iproute2` are, both preinstalled on the Ubuntu image.)

---

## 1. Prerequisites

| Requirement | Why |
|---|---|
| **Linux**, Ubuntu/Debian | `setup.sh` installs against apt |
| Kernel **≥ 6.6** | `link.AttachTCX` needs the kernel TCX API |
| **Two NICs** | one toward the ISP router/uplink, one toward the LAN switch |
| `clang` / `llvm` / `libbpf-dev` / `linux-headers-$(uname -r)` | compile `devchoke.o` |
| `iproute2` (`tc`, `ip`) | qdisc/attach + the neigh poller |
| `CAP_NET_ADMIN` + `CAP_BPF` | load/attach the tc program (granted in the unit) |
| `CAP_NET_RAW` | the passive DHCP hostname sniffer (granted in the unit) |
| `sudo` / root | bridge setup + BPF load |

Preflight:

```bash
uname -r                              # must be ≥ 6.6
ip -br link                           # confirm your two NICs (e.g. eth0, eth1)
which clang tc ip bpftool             # install if missing
```

> **Placement is everything.** A device can only be choked if its traffic
> physically transits this box. Devices on the ISP router's *own* WiFi or
> switch ports bypass the bridge. Wire the managed devices **behind** the
> downstream switch that hangs off this gateway.

---

## 2. Network topology

```
        Internet
            │
   ┌────────▼─────────┐
   │  ISP gateway/ONT  │   (unchanged — keeps DHCP / NAT / WiFi)
   └────────┬─────────┘
            │ LAN port
       ┌────▼────┐  eth0   (uplink side — bridge slave)
       │  THIS   │
       │  BOX    │  br0 = eth0 + eth1   ← attach devchoke to the SLAVES
       │         │  eth1   (LAN side — bridge slave)
       └────┬────┘
            │
   downstream switch ── managed devices (wired behind here)
```

`br0` bridges `eth0` and `eth1`; the box forwards transparently. The
`devchoke` programs attach to the **slaves** (`eth0`,`eth1`) — **never** the
bridge master `br0`, which only sees locally-terminated traffic.

**Fail-safe:** if this box dies, re-cable the switch straight into the ISP
router and the LAN is back online — the gateway is not a hard dependency.

> **Validate the data plane before touching real hardware.** On any Linux
> box with kernel ≥ 6.6 (no second NIC, no router needed), run the automated
> smoke test — it builds the binary + `devchoke.o`, stands up a 3-namespace
> lab that reproduces *forwarded* traffic, then asserts that a `sever` drops a
> device's traffic and `thaw` restores it, exiting non-zero on any failure:
>
> ```bash
> make netns-smoke      # Linux + root; the data-plane go/no-go gate
> ```
>
> This is the fastest way to confirm the verifier accepts the program and TCX
> attaches on *your* kernel before you wire the box inline. See
> [development/network-choke-build-plan.md](../development/network-choke-build-plan.md)
> for the manual Stage-0 walkthrough.

---

## 3. Get the bundle onto the box

```bash
# On a dev machine with Go 1.25+ and Node 18+:
git clone <repo-url> ebpf-poc && cd ebpf-poc
make build-linux                      # or: make tarball   (ships the .c sources + binary)
scp engine/engine-linux-amd64 user@gateway:~/
scp -r engine/internal/enforce/devbpf/bpf user@gateway:~/bpf      # devchoke.c
# (the tarball already bundles bpf/devchoke.c + bpf/choke.c)
```

ARM64 boxes: `make build-linux LINUX_ARCH=arm64`.

---

## 4. Create the transparent bridge

Bring up `br0` over the two NICs. Quick (non-persistent) form to test:

```bash
sudo ip link add name br0 type bridge
sudo ip link set eth0 master br0
sudo ip link set eth1 master br0
sudo ip link set eth0 up
sudo ip link set eth1 up
sudo ip link set br0 up
# give the box a management IP on the bridge if you need to reach the dashboard:
sudo dhclient br0        # or assign a static IP
```

Make it persistent with `netplan` (Ubuntu) so it survives reboot:

```yaml
# /etc/netplan/60-choke-bridge.yaml
network:
  version: 2
  ethernets:
    eth0: {dhcp4: no}
    eth1: {dhcp4: no}
  bridges:
    br0:
      interfaces: [eth0, eth1]
      dhcp4: yes          # or a static address: block for the mgmt IP
```

```bash
sudo netplan apply
ip -br link show master br0     # confirm eth0, eth1 are enslaved
```

---

## 5. Compile the data plane

`setup.sh` compiles `devchoke.o` with the same clang recipe as `choke.o`:

```bash
cd ~/ebpf-poc        # where you put the bundle
sudo bash scripts/setup.sh        # builds bpf/choke.o AND bpf/devchoke.o
ls -l bpf/devchoke.o              # confirm it built
```

Or compile it directly:

```bash
clang -O2 -g -target bpf \
  -I/usr/include/$(uname -m)-linux-gnu \
  -c bpf/devchoke.c -o bpf/devchoke.o
```

---

## 6. Configure and install the engine

Install the systemd unit and config (the unit already grants
`CAP_NET_ADMIN`/`CAP_BPF`/`CAP_NET_RAW`):

```bash
sudo install -D engine-linux-amd64 /opt/ebpf-engine/engine
sudo install -D bpf/devchoke.o /opt/ebpf-engine/bpf/devchoke.o
sudo install -D deploy/ebpf-engine.service /etc/systemd/system/ebpf-engine.service
sudo install -D deploy/engine.yaml.example /etc/ebpf-engine/engine.yaml
```

Edit `/etc/ebpf-engine/engine.yaml` — the network-choke keys:

```yaml
# Attach to the bridge SLAVE ports (NOT br0).
devchoke_obj:     "/opt/ebpf-engine/bpf/devchoke.o"
devchoke_ifaces:  "eth0,eth1"
# Allow-list: the engine REFUSES to quarantine/sever these MACs. Put the
# uplink/ISP-router MAC, the DHCP/DNS server, and your own workstation here.
# The bridge ports' own MACs are auto-added. Get the uplink MAC from
# `ip neigh` once traffic flows.
devchoke_protect: "aa:bb:cc:11:22:33"

# CHANGE THESE before exposing the dashboard:
user: "admin"
pass: "ebpf-soc-demo"
```

> **Roll out in dry-run first.** Set `dry_run: true`, start the engine, watch
> `/devices` populate and confirm identities/audit look right, **then** flip
> `dry_run: false` and restart. Populate `devchoke_protect` *before* the first
> enforcing start.

If you're running the engine purely as a network choke (no process choke /
Tetragon on this box), you can drop `-tetragon`-dependent flags; the device
path is independent.

> **The two chokes have independent postures.** The *process* choke's mode is
> the `-enforce` flag (`enforce:` in YAML, flippable at runtime via
> `/api/choke/mode`); the *device* choke does **not** look at `-enforce` — it
> enforces whenever it has the tc backend and is neither `dry_run` nor
> kill-switched. So the common posture **"observe processes, enforce on
> devices"** is just:
>
> ```yaml
> enforce: false          # process choke = DETECT-ONLY (audited, no kill/throttle)
> dry_run: false          # device choke = ENFORCING (real drops)
> devchoke_ifaces: "eth0,eth1"
> ```
>
> The `/devices` console badge shows the device posture (`ENFORCING` /
> `plane=tc` / `links` / `frames`); the process console at `/choke` shows
> `DETECT-ONLY` independently.

Start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ebpf-engine
journalctl -u ebpf-engine -f
```

Look for:

```
[devbpf] tc data plane loaded from /opt/ebpf-engine/bpf/devchoke.o on [eth0,eth1] (4 link(s), tier=tc)
[devgateway] network device choke ready (ifaces="eth0,eth1" protected=3 dry_run=false)
```

`4 link(s)` = ingress+egress on each of the two slaves. **If you see
`0 link(s)`, the box is NOT enforcing** — see Troubleshooting.

---

## 7. Verify

Auth is **cookie + CSRF** (not HTTP basic). Log in once into a cookie jar and
reuse it; POSTs also need the `X-CSRF-Token` header echoed from the jar:

```bash
J=$(mktemp)
curl -sc "$J" -d 'user=admin&pass=ebpf-soc-demo' http://localhost:8080/api/login
CSRF=$(awk '$6=="csrf_token"{print $7}' "$J")

# Confirm the box is actually enforcing (links_attached > 0, plane=tc):
curl -sb "$J" http://localhost:8080/api/choke/device-state

# See discovered devices (passive + DHCP + neigh):
curl -sb "$J" http://localhost:8080/api/choke/devices
```

> Or skip the curl dance entirely and use `chokectl device-status <host>` /
> `chokectl device-jail <host> <mac> <action> <reason>` — it handles login +
> CSRF for you.

Open the console at `http://<box-ip>:8080/devices` (login `admin` /
`ebpf-soc-demo`). The header shows an **ENFORCING / NOT ENFORCING** badge and
`plane=tc links=4`.

End-to-end smoke test against a real wired device behind the switch:

```bash
DEV=aa:bb:cc:dd:ee:ff     # a test device's MAC (from /api/choke/devices)
POST() { curl -sb "$J" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -X POST "$@"; }

# Throttle it, then confirm its throughput clamps while others are unaffected:
POST http://localhost:8080/api/choke/device-jail \
  -d "{\"macs\":[\"$DEV\"],\"action\":\"throttle\",\"reason\":\"smoke test\"}"

# Confirm the kernel bucket exists:
sudo bpftool map dump name choke_devs

# Sever (full block, both directions), then thaw:
POST http://localhost:8080/api/choke/device-jail \
  -d "{\"macs\":[\"$DEV\"],\"action\":\"sever\",\"reason\":\"block test\"}"
POST http://localhost:8080/api/choke/device-thaw \
  -d "{\"mac\":\"$DEV\",\"reason\":\"done\"}"
```

No router hardware? Run the automated gate (`make netns-smoke`) or drive the
lab by hand: `sudo bash scripts/dev/netns-lab.sh up` then
`run bpf/devchoke.o` (see the build plan).

---

## 8. Day-2 operations

| Task | How |
|---|---|
| **See what a device is talking to** | expand its row in `/devices`, or `GET /api/choke/device-flows?mac=<mac>` — lists destination IP : port : proto with packet/byte counts, busiest first. Use it to judge maliciousness (e.g. a device beaconing to `:4444`) **before** choking. |
| Choke a device | `/devices` console, or `POST /api/choke/device-jail`, or `chokectl device-jail HOST MAC ACTION REASON` |
| Release a device | console **Thaw**, or `POST /api/choke/device-thaw`, or `chokectl device-thaw HOST MAC` |
| Time-bound choke | add `revert_after_seconds` to a `device-jail` call — auto-reverts |
| **Switch enforcement mode** | `/devices` mode bar **Switch to detect-only / enforcing**, or `POST /api/choke/device-mode {"enforcing":false,"reason":"…"}`. Detect-only audits would-be chokes without dropping traffic — independent of the process choke's mode. |
| See enforcement state | `/devices` mode badge, `chokectl device-status HOST`, or `GET /api/choke/device-state` (`mode`/`enforcing`/`kill_switched`/`frames_seen`) |
| Emergency stop | `/devices` **Kill-switch** button, or `POST /api/choke/device-kill-switch {"on":true}` — audits but stops acting |
| Many gateways | start each with a `fleet_hosts` file; `POST /api/fleet/device-jail` fans out |
| Audit trail | `GET /api/decisions` / `GET /api/verify-chain` — device rows carry `device_mac`/`device_id` |

**State ladder (network semantics):** `throttle` 50/s · `tarpit` 5/s ·
`quarantine` 1/s (DHCP/DNS still allowed so the device can recover) · `sever`
= full drop both directions. Identity is the MAC, so a choke survives the
device's DHCP/IP changes.

---

## 9. Troubleshooting

**`0 link(s)` at startup / nothing gets choked.**
You attached to the bridge **master** (`br0`) instead of the **slaves**, or
named a non-existent interface. Set `devchoke_ifaces: "eth0,eth1"` (the
slaves). Confirm with `tc filter show dev eth0 ingress` — it should list a
`bpf` filter.

**`AttachTCX` fails / `ENOTSUPP`.**
Kernel is below 6.6. Check `uname -r`. (The legacy clsact+netlink fallback is
not in this build — upgrade the kernel.)

**Engine loads but `links=4` and traffic still flows under `sever`.**
Make sure the device is actually wired **behind** this box (not on the ISP
router's WiFi/ports). Confirm its MAC appears in `/api/choke/devices` —
if it doesn't, its traffic isn't transiting the bridge.

**Hostnames are empty in the console.**
The DHCP sniffer needs `CAP_NET_RAW` (granted in the shipped unit). If you run
the binary by hand without it, you'll get MAC + IP (from the seen map and
`ip neigh`) but no hostnames. Check the log for `need CAP_NET_RAW`.

**A quarantined device never recovers.**
Quarantine deliberately keeps DHCP/DNS open; if you used `sever` instead, the
device is fully blocked by design — `thaw` it.

**You locked out the uplink / your own workstation.**
That MAC wasn't in `devchoke_protect`. Engage the kill-switch
(`device-kill-switch {"on":true}`), `device-thaw` the MAC, then add it to
`devchoke_protect` and restart. (Quarantine/sever on the bridge ports' own
MACs is auto-refused.)

---

## Related

- [architecture/network-choke-gateway.md](../architecture/network-choke-gateway.md) — design & data-plane spec.
- [development/network-choke-build-plan.md](../development/network-choke-build-plan.md) — netns lab + staged build.
- [reference/chokectl.md](../reference/chokectl.md) — fleet CLI (now with `device-*` subcommands).
- [linux-server.md](linux-server.md) — the per-process choke deployment (single monitored host).
