# Network Choke Gateway

> **Status: BUILT (drafted 2026-06-17, implemented since).**
> This subsystem is live: `engine/internal/enforce/devbpf/`,
> `engine/internal/device/`, `engine/internal/choke/devgateway.go`, and
> `engine/internal/api/devchoke.go` all exist, the `/devices` console is
> shipped, and the data plane is proven **6/6 in the netns lab** (real
> per-MAC drop + restore of *forwarded* traffic — see
> [../deployment/network-choke-gateway.md](../deployment/network-choke-gateway.md)
> for validation results and `make netns-smoke` for the automated gate).
> This document is the design/architecture reference; the existing
> per-process Choke Gateway ([overview.md](overview.md),
> [state-ladder.md](state-ladder.md)) runs independently alongside it.

## What it is

The Network Choke Gateway extends the existing Choke Gateway from
**per-process** enforcement to **per-device** enforcement. Where the
process gateway throttles or kills a single `exec_id` on the host it runs
on, the network gateway throttles or blocks a **device on the LAN**,
keyed by its **MAC address**, from a Linux box placed inline in the
forwarding path.

It is the network-layer answer to the same question the process gateway
answers at the syscall layer: *"this thing is behaving badly — slow it
down, then cut it off, reversibly, with an audit trail."* The unit of
control is a device (MAC), not a process (PID).

## Why a second data plane

The existing data plane in
[`bpf/choke.c`](../../engine/internal/enforce/bpfmap/bpf/choke.c)
attaches to `cgroup/connect4`, `connect6`, `sendmsg4`, and `sendmsg6`
and keys on `bpf_get_current_pid_tgid()`. Those hooks fire **only on the
host's own outbound sockets**. A router/gateway's interesting traffic is
*forwarded* — it never opens a local socket on the box — so the cgroup
hooks **physically cannot see it**, and PID is meaningless for a frame
that originated on another machine.

So this is a **parallel data plane**, not a modification of the existing
one. Everything *above* the data plane — the state ladder, the token
bucket, the operator surfaces, the audit chain, the fleet fan-out — is
reused. Only the kernel hook and the key change:

| Dimension       | Process choke (existing)            | Network choke (this doc)                  |
|-----------------|-------------------------------------|-------------------------------------------|
| Kernel hook     | `cgroup/connect4/6`, `sendmsg4/6`   | `tc` clsact `classifier` (ingress+egress) |
| Attach point    | cgroup v2 root                      | bridge slave interfaces                   |
| Sees            | host's own sockets                  | **forwarded** LAN↔WAN frames              |
| Key             | `u32` PID                           | 6-byte source/destination **MAC**         |
| Unit of control | process (`exec_id`)                 | device (MAC / `DeviceID`)                 |
| Verdict         | `EPERM` on `connect()`              | `TC_ACT_SHOT` (drop) / `TC_ACT_OK` (pass) |

## Deployment topology

The enforcement node must sit **inline** in the path of the devices it
manages. The reference deployment places a small **transparent 2-NIC
Linux bridge box** between the existing (closed, ISP-provided) gateway
and the LAN's downstream switch. The ISP gateway keeps doing DHCP, NAT,
and WiFi; the bridge box does nothing to the traffic except observe and,
when an operator chokes a device, drop or rate-limit its frames.

```
        Internet
            │
   ┌────────▼─────────┐
   │  ISP gateway/ONT  │  closed appliance — DHCP / NAT / WiFi
   │  192.168.100.1    │  (cannot run eBPF)
   └────────┬─────────┘
            │ LAN port
   ┌────────▼───────────────────────────────────┐
   │  Network Choke node (Ubuntu ≥ 6.6)           │
   │                                              │
   │     eth0 ──────┐                             │
   │                ├── br0 (transparent bridge)  │
   │     eth1 ──────┘                             │
   │       ▲                                       │
   │       └── devchoke TC clsact (ingress+egress) attached to eth0 & eth1
   │                                              │
   │   engine: DeviceGateway · DeviceTable · HTTP :8080
   └────────┬───────────────────────────────────┘
            │
   ┌────────▼─────────┐
   │  downstream switch │
   └───┬────┬────┬─────┘
       │    │    │
     device device device   ← all forwarded frames transit br0
```

**Why transparent bridge, not "make the Linux box the router":**

- The ISP gateway stays the gateway — DHCP/NAT/WiFi are untouched, so a
  failure of the choke node degrades gracefully (cable the switch
  straight back to the ISP gateway and the LAN is online again).
- `br0` carries every device↔internet frame with **intact src/dst MAC**,
  which is exactly what MAC-keyed enforcement needs. Attaching clsact to
  the bridge **slave** ports (`eth0`/`eth1`) — *never the bridge master*,
  which only sees locally-terminated traffic — sees all transit frames.

**Placement constraint (feasibility-critical):** a device can only be
choked if its traffic physically transits the bridge. Devices on the ISP
gateway's *own* WiFi or *own* switch ports bypass the box and are out of
reach. The reference deployment assumes managed devices are **wired
behind the downstream switch** that hangs off the bridge.

**One-hop constraint:** MAC keying works because the gateway is the
device's L2 neighbor. A device behind a *downstream* router would appear
with that router's MAC, collapsing per-device identity. Multi-hop is
out of scope for v1 (would require IP/LPM-trie keying — see Limitations).

## Components

```
┌──────────────────────────────────────────────────────────────────┐
│ engine (Go)                                                        │
│                                                                    │
│  ┌────────────────┐   observe    ┌───────────────────────────┐    │
│  │ device.DeviceTable │ ◀──────── │ passive DHCP/mDNS sniffer  │    │
│  │  MAC↔IP↔hostname │            │ + ip neigh + choke_devs_seen │  │
│  └───────┬────────┘              └───────────────────────────┘    │
│          │ identity                                                │
│  ┌───────▼─────────────┐  decide   ┌────────────────────────────┐ │
│  │ choke.DeviceGateway  │ ───────▶ │ circuit.Circuit (REUSED)    │ │
│  │  Manual / revert /    │          │  MAC string key             │ │
│  │  kill-switch / audit  │          └────────────────────────────┘ │
│  └───────┬─────────────┘                                           │
│          │ Update(mac, bucket) / Delete(mac)                       │
│  ┌───────▼──────────────────────────────────────────────────────┐ │
│  │ devbpf.DeviceChokeDataPlane  (interface — sibling of bpfmap.Backend) │
│  │   • CiliumTCBackend (linux): loads devchoke.o, AttachTCX       │ │
│  │   • NoopDeviceBackend (dev/tests, non-linux)                   │ │
│  └───────┬──────────────────────────────────────────────────────┘ │
└──────────┼─────────────────────────────────────────────────────────┘
           │ writes choke_devs map
   ┌───────▼───────────────────────────────────────────────┐
   │ kernel — devchoke.c (BPF_PROG_TYPE_SCHED_CLS)           │
   │   choke_devs      HASH<dev_key, dev_bucket>            │
   │   choke_devs_seen LRU_HASH<dev_key, seen>             │
   └───────────────────────────────────────────────────────┘
```

| Component | Path | Role |
|-----------|----------------|------|
| Data plane | `engine/internal/enforce/devbpf/bpf/devchoke.c` | TC clsact ingress+egress classifier; MAC lookup → token bucket → drop/pass |
| Backend interface | `engine/internal/enforce/devbpf/devbpf.go` | `DeviceChokeDataPlane` (Open/Close/Update/Delete/Snapshot), `DeviceBucket`, MAC helpers, `NoopDeviceBackend` |
| Linux loader | `engine/internal/enforce/devbpf/cilium_linux.go` | Mirrors [`cilium_linux.go`](../../engine/internal/enforce/bpfmap/cilium_linux.go); `link.AttachTCX` per interface |
| Throttler | `engine/internal/enforce/devthrottler.go` | Action → `DeviceBucket`; clone of [`throttler.go`](../../engine/internal/enforce/throttler.go) + MAC allow-list guard |
| Identity | `engine/internal/device/table.go` | `DeviceTable`, cloned from [`origin.Tracker`](../../engine/internal/origin/origin.go) — MAC-keyed, TTL, field-merge |
| Discovery | `engine/internal/device/{dhcp,neigh}_linux.go` | Passive DHCP/mDNS sniff on `br0`; `ip neigh` poller |
| Device gateway | `engine/internal/choke/devgateway.go` | Reuses [`circuit.Circuit`](../../engine/internal/choke/circuit/circuit.go); manual jail/thaw/revert, kill-switch, audit |
| HTTP API | `engine/internal/api/devchoke.go` | `/api/choke/devices`, `device-jail`, `device-thaw`, `device-state` |
| Fleet | edit [`fleet.go`](../../engine/internal/api/fleet.go) | `/api/fleet/device-jail`, `/api/fleet/devices` over `fleet.fanout` |
| CLI | edit [`scripts/chokectl`](../../scripts/chokectl) | `device-status` / `device-jail` / `device-thaw` |

## The data plane: `devchoke.c`

A CO-RE-free BPF object compiled with the **same** `clang -O2 -g -target bpf`
recipe that [`setup.sh`](../../scripts/setup.sh) already uses for
`choke.o`, with `-I` added for `<linux/if_ether.h>` and
`<linux/pkt_cls.h>`.

- **Program type:** `BPF_PROG_TYPE_SCHED_CLS`, two `SEC("classifier")`
  functions — `devchoke_ingress` and `devchoke_egress` — operating on
  `struct __sk_buff`.
- **Attach:** a `clsact` qdisc per configured LAN interface, attached via
  cilium/ebpf `link.AttachTCX{Attach: AttachTCXIngress | AttachTCXEgress}`
  (kernel ≥ 6.6). Attach is **non-fatal** (mirrors the existing loader),
  but a debug counter must prove forwarded frames are seen — see Safety.
- **Match:** bounds-check the Ethernet header
  (`data + sizeof(struct ethhdr) > data_end → TC_ACT_OK`), then key on
  `eth->h_source` on **ingress** (device→WAN) and `eth->h_dest` on
  **egress** (WAN→device). Skip multicast/broadcast (`h_dest[0] & 1`).
- **Decision:** reuses `decide()` / `refill_and_consume()` **verbatim**
  from `choke.c`. `FLAG_SEVER | FLAG_QUARANTINE → TC_ACT_SHOT`;
  `FLAG_THROTTLE | FLAG_TARPIT →` token available `TC_ACT_OK` else
  `TC_ACT_SHOT`. Not in map / no flags → `TC_ACT_OK` (**fail-open**).

### Maps

```c
struct dev_key   { __u8 mac[6]; __u8 _pad[2]; };          // 8 bytes
struct dev_bucket {                                        // 24 bytes — IDENTICAL to pid_bucket
    __u64 last_ns;        // last refill (ns since boot)
    __u32 rate_per_sec;   // tokens added per second
    __u32 burst;          // max accumulated tokens
    __u32 tokens;         // current tokens (kernel-owned)
    __u32 flags;          // FLAG_THROTTLE|TARPIT|QUARANTINE|SEVER
};
struct seen { __u64 last_ns; __u64 pkts; __u32 last_saddr_be; };
```

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `choke_devs` | `HASH` (max 4096) | `dev_key` | `dev_bucket` | The enforcement map. Userspace writes; kernel reads/refills. |
| `choke_devs_seen` | `LRU_HASH` (max 4096) | `dev_key` | `seen` | Passive discovery — sampled writes record last-seen + source IP. |

`dev_bucket` is byte-for-byte the existing 24-byte
[`PIDBucket`](../../engine/internal/enforce/bpfmap/bpfmap.go) layout, so
the Go side reuses the same `encoding/binary` tight-packing discipline
and the same `FLAG_*` constants. A unit test asserts
`encoding/binary.Size(DeviceBucket) == 24`.

> The non-atomic token-bucket race inherited from `choke.c` is an
> accepted bounded over-allocation — this is a smoothing filter, not a
> hard quota. `PERCPU_HASH` is a later option if multi-RX-queue
> contention shows.

## Device identity & discovery

**Identity is the MAC**, because it survives DHCP renewals and IP churn —
which is exactly why the enforcement map is MAC-keyed, not IP-keyed.

- **Canonical label:** lowercased colon MAC `aa:bb:cc:dd:ee:ff` (the
  device analog of `exec_id`). **`DeviceID = "dev:" + colonless-mac`**,
  deterministic and stable across IP changes and reboots.
- **Kernel handle:** the 8-byte `dev_key` (MAC + 2 pad bytes, zeroed so
  verifier key-hashing and Go tight-packing agree).
- **`device.DeviceTable`** is a near-verbatim clone of
  [`origin.Tracker`](../../engine/internal/origin/origin.go): a
  concurrent map keyed by MAC, value
  `Device{MAC, DeviceID, LastIP, Hostname, Vendor(OUI), FirstSeen, LastSeen, Source}`,
  with the same field-wise `merge()` so a DHCP observation updates
  `{LastIP, Hostname}` without wiping earlier fields.

Because DHCP lives on the **closed** ISP gateway, there is no lease file
to tail. Identity is recovered from three layered sources merged into
the table, in priority order:

1. **Passive DHCP/mDNS sniffing on `br0`** (primary). DHCP `REQUEST`/`ACK`
   and mDNS frames *transit the bridge*, so an `AF_PACKET` listener
   recovers `MAC ↔ IP ↔ hostname` (DHCP option 12/81, mDNS names) with no
   router access.
2. **`ip neigh` / `RTM_GETNEIGH` poll** for the MAC↔IP binding of
   static-IP devices.
3. **`choke_devs_seen`** drained on the existing 10 s snapshot ticker —
   zero-dependency "this MAC exists and is active" even before any
   DHCP/mDNS is observed.

> **Trust model.** MAC is forgeable, so this is a **same-trust-domain LAN
> policy tool, not a hostile-root boundary.** A seen-IP (from
> `choke_devs_seen.last_saddr_be`) that disagrees with the DHCP-observed
> IP is surfaced as a spoof signal. For a hard boundary, pair with
> DHCP reservations / static ARP / 802.1X port security out of band.

## The device state ladder

The device gateway reuses
[`circuit.Circuit`](../../engine/internal/choke/circuit/circuit.go)
**verbatim** — its state map is `map[string]State`, so the canonical MAC
string is the key and the monotonic ladder, thresholds, `Force`, and
`ScheduleRevert` all work unchanged. The five rungs map to network
semantics:

| Rung            | Network effect                                                                 | Reversible? |
|-----------------|--------------------------------------------------------------------------------|-------------|
| **pristine**    | Not in `choke_devs` — frames pass at line rate                                 | n/a         |
| **throttled**   | Token bucket `rate=50/s burst=100` — gentle cap                                | yes         |
| **tarpit**      | Token bucket `rate=5/s burst=10` — severely degraded                           | yes         |
| **quarantined** | Token bucket `rate=1/s burst=2`, **but DHCP (67/68) + DNS (53) whitelisted** so the device can re-lease and be recovered | yes (thaw) |
| **severed**     | Unconditional `TC_ACT_SHOT` in both directions — device is offline             | per-device delete |

Rates come straight from
[`DefaultThrottlerConfig`](../../engine/internal/enforce/throttler.go).
The crucial difference from the process gateway's `quarantine`: a
network quarantine **whitelists gateway-local DHCP/DNS** so a quarantined
device isn't cut off from the very services it needs to recover.

See [state-ladder.md](state-ladder.md) for the shared design principles
(monotonicity; graduated response over binary block/allow).

## Control plane & operator flow

Operator flow: **discover → see → choke → verify → thaw.** Every endpoint
is a near-clone of an existing process-choke handler, so behavior
(reason-required, per-target outcome list, synthetic audit key, optional
auto-revert) is identical.

| Method | Path | Action |
|--------|------|--------|
| GET  | `/api/choke/devices`     | `DeviceTable` ⋈ circuit ⋈ bucket — the device list for the UI |
| POST | `/api/choke/device-jail` | `{macs:[…], action:"throttle\|tarpit\|quarantine\|sever", reason (required), revert_after_seconds}` |
| POST | `/api/choke/device-thaw` | `{mac}` — **precise per-device** unblock (`Delete(mac)`), unlike the per-tier cgroup thaw |
| GET  | `/api/choke/device-state`| `{data_plane:"tc", capabilities, links_attached, buckets}` — surfaces whether the box is actually enforcing |
| POST | `/api/fleet/device-jail` | Same, fanned out across every gateway in `chokectl.hosts` |

`chokectl` gains `device-status` / `device-jail` / `device-thaw`
subcommands cloned from the existing `jail` command. Kill-switch,
dry-run, detect-only mode, and incident-response presets from
[`gateway.go`](../../engine/internal/choke/gateway.go) all apply, since
they operate on a `Decision` + string key.

## Safety guardrails

These ship in the **first enforcing cut**, not "later":

- **MAC allow-list** — the device analog of `SystemCriticalBinaries`
  ([gateway.go](../../engine/internal/choke/gateway.go)). Userspace
  **refuses** to write a quarantine/sever bucket for the gateway's own,
  the uplink, the DHCP/DNS server, or the operator's MAC. Prevents
  control-plane lockout.
- **DHCP/DNS-whitelisted quarantine** — see the ladder above; a
  quarantined device can always still re-lease.
- **Bridge-slave attach + debug counter** — attach to slaves, never the
  master; a debug-counter map must increment on forwarded frames, and
  the count is surfaced in `/api/choke/device-state` and warned about at
  boot if zero after traffic (catches the silent "attached to master /
  attached to wrong iface" failure).
- **Fail-open** — a MAC not in `choke_devs`, or with no enforcement
  flags, always passes. The choke is an explicit allow-list of *bad*
  devices, never a default-deny.
- **Roll out under `-dry-run` first** — records decisions, writes nothing
  to the kernel — to validate discovery/identity/audit before flipping
  to enforcing.

## Deployment & build

- **Target:** self-managed Ubuntu/Debian, **kernel ≥ 6.6** (for
  `AttachTCX`). The 5.15 legacy `clsact`+`tc filter` fallback and OpenWRT
  packaging are explicitly **out of scope for v1**.
- **Build:** extend the [`setup.sh`](../../scripts/setup.sh) clang block
  to also compile `devchoke.c → devchoke.o` (same `CLANG_ARGS`, plus the
  two extra `-I` headers); ensure `tc`/`iproute2` are present and
  `clsact` is supported.
- **Flags:** new `-devchoke-obj` (empty → `NoopDeviceBackend`),
  `-devchoke-iface` (repeatable — name the bridge slave ports). Wired in
  [`main.go`](../../engine/cmd/engine/main.go) by mirroring the existing
  `-bpf-obj`/`-bpf-cgroup` backend-selection block, with matching YAML
  keys in [`config.go`](../../engine/internal/config/config.go).
- **Capabilities:** **no change** — the systemd unit
  ([ebpf-engine.service](../../deploy/ebpf-engine.service)) already grants
  `CAP_NET_ADMIN` (tc qdisc/filter, TCX attach, `RTM_GETNEIGH`) and
  `CAP_BPF`, and `/sys/fs/bpf` is already in `ReadWritePaths`. Add the
  bridge node's management requirements (host netns) only.

## Verification (no hardware required for the core)

A 3-netns lab reproduces transit traffic the cgroup hooks can't see:

```
ns-dev ──veth── ns-gw (br0 + ip_forward + NAT, runs the engine) ──veth── ns-net (upstream echo)
```

1. **Baseline:** `iperf3` dev→net at full throughput; the device MAC
   appears in `/api/choke/devices` via `choke_devs_seen` alone (proves
   data-plane-as-discovery).
2. **Throttle:** `device-jail {action:throttle}` → `device-state` shows
   the bucket with `FlagThrottle`; `iperf3` pps clamps to the token rate
   while a bystander device is unaffected (proves per-MAC keying).
3. **Sever:** `iperf3` *and* `ping` fail in **both** directions while the
   gateway's own traffic is unaffected.
4. **Thaw:** `device-thaw {mac}` → `bpftool map dump` shows the key gone
   and throughput restored within a packet.
5. **Identity across IP change** (headline correctness): release/renew
   the lease so the device's IP changes; the choke **still applies**
   (MAC-keyed) and `DeviceTable.LastIP` updates with `DeviceID`
   unchanged.
6. **Layout check:** `bpftool map dump name choke_devs` confirms the
   8-byte key + 24-byte value match the Go layout.

A **bridged variant** (br0 with two veth slaves) additionally asserts
`tc filter show dev <slave> ingress` lists the BPF filter **and** the
debug counter increments — the regression test for the bridge-master
mistake.

## Implementation stages

All four stages below are **complete** — this is the record of how it was
built. `make netns-smoke` is the standing regression gate for Stage 0–1.

| Stage | Goal | Exit criteria |
|-------|------|---------------|
| **0 — netns PoC** | `devchoke.c` ingress-only drop-on-flag, loaded via `tc`/`bpftool` | Writing a MAC into `choke_devs` drops exactly that device's forwarded traffic; deleting restores it; debug counter proves transit is seen |
| **1 — data plane + backend** | Both directions + token bucket; `devbpf` package + loader; `DeviceThrottler` | Engine with `-devchoke-obj/-devchoke-iface` throttles/severs/thaws a device in both directions; tier logged at boot |
| **2 — identity + control** | `DeviceTable` + passive DHCP/mDNS/neigh discovery; `DeviceGateway`; jail/thaw/state API + UI device tab; allow-list + whitelisted quarantine | Operator jails/thaws a device with audited reason; allow-listed MACs refused; identity survives IP change |
| **3 — fleet + deploy** | `/api/fleet/device-*`, `chokectl device-*`, `setup.sh` builds `devchoke.o`, systemd flags | `make deploy` stands up enforcing device choke; fleet jail hits ≥2 gateways |

## Limitations & deferred work

- **v2 fast-path:** an XDP-native ingress path for NICs that support it,
  layered *above* the TC baseline (TC stays the portable floor and the
  only egress path). Same `DeviceChokeDataPlane` interface, no changes
  above it.
- **v2 fallback:** an **nftables** backend (`ether` set drop + per-MAC
  `limit rate` + `tc htb` tiers) for kernels lacking TC-BPF.
- **No auto-graduation in v1.** There is no Tetragon per-device telemetry
  on a forwarding node, so device choke is **operator/manual-driven**. A
  later per-device flow-scoring source (connection rate / scan detection
  from `choke_devs_seen`) could feed `circuit.Evaluate` — the network
  analog of the process chain score.
- **One L3 hop only.** Devices behind a downstream router need IP/LPM-trie
  keying (deferred), which re-introduces DHCP-churn handling.
- **WiFi/placement.** Devices on the ISP gateway's own WiFi or ports
  bypass the bridge and cannot be choked until they sit behind it.

## Related

- [overview.md](overview.md) — the broader system; where the process
  Choke Gateway fits in the engine.
- [state-ladder.md](state-ladder.md) — the shared five-rung state machine
  and its design principles.
- [`internal/choke/circuit/circuit.go`](../../engine/internal/choke/circuit/circuit.go)
  — the (string-keyed, hence reusable) state machine.
- [`internal/enforce/bpfmap/`](../../engine/internal/enforce/bpfmap/)
  — the process data plane this one mirrors (`choke.c`, the cilium
  loader, `PIDBucket`).
- [`internal/enforce/throttler.go`](../../engine/internal/enforce/throttler.go)
  — the action→bucket logic the device throttler clones.
- [`internal/origin/origin.go`](../../engine/internal/origin/origin.go)
  — the tracker `DeviceTable` is cloned from.
- [`internal/api/fleet.go`](../../engine/internal/api/fleet.go)
  — the fan-out the device endpoints extend.
