# Network Choke Gateway — Build Plan

> A staged plan to add **per-device (MAC) network enforcement** to the
> existing engine: throttle or block a device on the LAN from a Linux
> box placed inline in the forwarding path. Designed to be buildable
> incrementally, each stage independently demoable, reusing the existing
> token bucket, state ladder, and control surfaces.
>
> **Read the design first:**
> [docs/architecture/network-choke-gateway.md](../architecture/network-choke-gateway.md).
> This doc is the *how-to-build*; that doc is the *what-and-why*.
>
> **Status:** none of the `devbpf` / `device` / `devgateway` code below
> exists yet — this plan creates it. The existing per-process choke
> ([overview.md](../architecture/overview.md)) is untouched.

---

## Table of contents

1. [The approach](#the-approach)
2. [Prerequisites & lab setup](#prerequisites--lab-setup)
3. [Stage 0 — netns PoC: drop one MAC](#stage-0--netns-poc-drop-one-mac)
4. [Stage 1 — data plane complete + Go backend](#stage-1--data-plane-complete--go-backend)
5. [Stage 2 — identity, discovery, control plane, UI](#stage-2--identity-discovery-control-plane-ui)
6. [Stage 3 — fleet, CLI, deploy](#stage-3--fleet-cli-deploy)
7. [Troubleshooting](#troubleshooting)
8. [References](#references)

---

## The approach

The existing data plane
([`bpf/choke.c`](../../engine/internal/enforce/bpfmap/bpf/choke.c)) hooks
`cgroup/connect4/6` and keys on PID — it sees only the host's own
sockets, never forwarded traffic. So we build a **second, parallel data
plane**: a `tc` clsact classifier that sees forwarded L2 frames and keys
on **MAC**. Everything above it is reused.

| Reused **verbatim or near-verbatim** | New |
|---|---|
| `refill_and_consume()` / `decide()` token-bucket math ([choke.c:68](../../engine/internal/enforce/bpfmap/bpf/choke.c#L68)) | `devchoke.c` (TC clsact ingress+egress) |
| 24-byte `PIDBucket` layout + `FLAG_*` ([bpfmap.go](../../engine/internal/enforce/bpfmap/bpfmap.go)) | `devbpf` package (interface + loader + Noop) |
| cilium loader pattern ([cilium_linux.go](../../engine/internal/enforce/bpfmap/cilium_linux.go)) — swap `AttachCgroup` → `AttachTCX` | `devthrottler.go` (action → MAC bucket) |
| `circuit.Circuit` — already string-keyed ([circuit.go:126](../../engine/internal/choke/circuit/circuit.go#L126)), use the MAC string | `device.DeviceTable` (cloned from `origin.Tracker`) |
| `handleChokeJail` / `parseAction` / `ScheduleRevert` | `devgateway.go`, `api/devchoke.go` |
| `fleet.fanout` ([fleet.go](../../engine/internal/api/fleet.go)) | `/api/fleet/device-*` one-liners |

**Build order rationale:** prove the kernel can name-and-drop a device
*before* writing any Go (Stage 0), then make the data plane complete and
loadable (Stage 1), then layer identity + operator control (Stage 2),
then ship it across a fleet (Stage 3).

---

## Prerequisites & lab setup

**Target:** Ubuntu/Debian, **kernel ≥ 6.6** (for `link.AttachTCX`).

```bash
uname -r                      # ≥ 6.6
sudo apt install -y clang llvm libbpf-dev iproute2 linux-headers-$(uname -r)
which tc bpftool ip clang     # all must resolve
go version                    # 1.22+ (the engine's existing requirement)
```

Everything through **Stage 1** runs in **network namespaces — no extra
hardware**. The lab models the real topology (device ↔ gateway ↔
upstream) so the cgroup hooks' blind spot is reproduced honestly:

```bash
# scripts/dev/netns-lab.sh  — create once, tear down with `down`
set -euo pipefail
GW_LAN=veth-gw-lan; GW_WAN=veth-gw-wan

up() {
  ip netns add ns-dev
  ip netns add ns-gw
  ip netns add ns-net

  # device <-> gateway
  ip link add veth-dev type veth peer name $GW_LAN
  ip link set veth-dev netns ns-dev
  ip link set $GW_LAN  netns ns-gw
  # gateway <-> upstream
  ip link add $GW_WAN type veth peer name veth-net
  ip link set $GW_WAN netns ns-gw
  ip link set veth-net netns ns-net

  ip -n ns-dev addr add 10.0.0.2/24 dev veth-dev
  ip -n ns-dev link set veth-dev up
  ip -n ns-dev route add default via 10.0.0.1

  ip -n ns-gw addr add 10.0.0.1/24 dev $GW_LAN
  ip -n ns-gw addr add 10.0.1.1/24 dev $GW_WAN
  ip -n ns-gw link set $GW_LAN up
  ip -n ns-gw link set $GW_WAN up
  ip netns exec ns-gw sysctl -qw net.ipv4.ip_forward=1
  ip netns exec ns-gw iptables -t nat -A POSTROUTING -o $GW_WAN -j MASQUERADE

  ip -n ns-net addr add 10.0.1.2/24 dev veth-net
  ip -n ns-net link set veth-net up
  ip -n ns-net route add default via 10.0.1.1

  echo "device MAC:"; ip -n ns-dev link show veth-dev | awk '/link\/ether/{print $2}'
}
down() {
  for n in ns-dev ns-gw ns-net; do ip netns del $n 2>/dev/null || true; done
}
"$@"
```

```bash
sudo bash scripts/dev/netns-lab.sh up
# sanity: device reaches upstream through the gateway
sudo ip netns exec ns-dev ping -c2 10.0.1.2
```

The choke programs attach **inside `ns-gw`** on `veth-gw-lan` — that's
the "gateway" the device's frames transit. On a real deployment this is
the bridge slave port; in the lab it's the LAN-side veth.

---

## Stage 0 — netns PoC: drop one MAC

**Goal:** prove the kernel can identify a device by source MAC and drop
exactly its forwarded traffic — with **no Go**, loaded by hand via `tc`.

**Time budget:** half a day.

> **Shortcut once the code exists:** `make netns-smoke` (Linux + root) now
> automates Stages 0–1 end-to-end — it builds the binary + `devchoke.o`,
> stands up the lab below, and asserts sever-drops / thaw-restores, exiting
> non-zero on failure. The manual steps below are for understanding the
> moving parts and for debugging when the automated gate goes red.

### 0.1 Minimal `devchoke.c` (ingress, drop-on-flag only)

`engine/internal/enforce/devbpf/bpf/devchoke.c`:

```c
// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

#define FLAG_THROTTLE   (1u << 0)
#define FLAG_TARPIT     (1u << 1)
#define FLAG_QUARANTINE (1u << 2)
#define FLAG_SEVER      (1u << 3)

struct dev_key   { __u8 mac[6]; __u8 _pad[2]; };          // 8 bytes
struct dev_bucket {                                        // 24 bytes — must equal pid_bucket
    __u64 last_ns;
    __u32 rate_per_sec;
    __u32 burst;
    __u32 tokens;
    __u32 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct dev_key);
    __type(value, struct dev_bucket);
} choke_devs SEC(".maps");

// Stage 0: flag set -> drop, else pass. (Token bucket arrives in Stage 1.)
static __always_inline int decide(struct dev_key *k)
{
    struct dev_bucket *b = bpf_map_lookup_elem(&choke_devs, k);
    if (!b)
        return TC_ACT_OK;                 // not managed -> pass (fail-open)
    if (b->flags & (FLAG_SEVER | FLAG_QUARANTINE | FLAG_THROTTLE | FLAG_TARPIT))
        return TC_ACT_SHOT;
    return TC_ACT_OK;
}

SEC("tc")
int devchoke_ingress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)     // bounds check (verifier requires)
        return TC_ACT_OK;
    if (eth->h_dest[0] & 1)               // skip multicast/broadcast
        return TC_ACT_OK;

    struct dev_key k = {};
    __builtin_memcpy(k.mac, eth->h_source, 6);   // ingress: device is the source
    return decide(&k);
}

char _license[] SEC("license") = "GPL";
```

### 0.2 Compile with the existing recipe

Same `clang -O2 -g -target bpf` invocation
[`setup.sh`](../../scripts/setup.sh) already uses for `choke.o`, plus the
two extra uapi headers:

```bash
cd engine/internal/enforce/devbpf/bpf
clang -O2 -g -target bpf \
  -I/usr/include -I/usr/include/$(uname -m)-linux-gnu \
  -c devchoke.c -o devchoke.o
```

### 0.3 Load by hand inside the gateway netns

```bash
DEV_MAC=$(sudo ip -n ns-dev link show veth-dev | awk '/link\/ether/{print $2}')

sudo ip netns exec ns-gw tc qdisc add dev veth-gw-lan clsact
sudo ip netns exec ns-gw tc filter add dev veth-gw-lan ingress \
     bpf da obj devchoke.o sec tc

# baseline: still works
sudo ip netns exec ns-dev ping -c2 10.0.1.2

# choke: write the device MAC into the map (flags=8 = FLAG_SEVER)
sudo ip netns exec ns-gw bpftool map update name choke_devs \
     key hex $(echo $DEV_MAC | tr -d ':' | sed 's/../& /g') 00 00 \
     value hex  00 00 00 00 00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  08 00 00 00

# now the device is cut off; bystander/gateway traffic is not
sudo ip netns exec ns-dev ping -c2 -W1 10.0.1.2 || echo "DROPPED as expected"

# restore
sudo ip netns exec ns-gw bpftool map delete name choke_devs \
     key hex $(echo $DEV_MAC | tr -d ':' | sed 's/../& /g') 00 00
sudo ip netns exec ns-dev ping -c2 10.0.1.2
```

> Add a `debug_counter` per-CPU array map incremented on every frame and
> `bpftool map dump` it — this is the regression check that the program
> actually sees forwarded frames (the #1 silent failure on real bridges).

### 0.4 Stage 0 exit checklist

- [ ] `devchoke.o` compiles with the existing clang recipe + 2 headers
- [ ] `tc filter show dev veth-gw-lan ingress` lists the BPF filter
- [ ] Writing the device MAC into `choke_devs` drops **exactly** that
      device's forwarded traffic; deleting the key restores it
- [ ] A debug counter proves the program sees forwarded frames
- [ ] The 8-byte key + 24-byte value dump matches the C structs

---

## Stage 1 — data plane complete + Go backend

**Goal:** full token-bucket data plane in **both directions**, loaded and
attached by the engine through a clean, swappable interface.

**Time budget:** 1–2 days.

### 1.1 Finish `devchoke.c`

- Add `devchoke_egress` keying on `eth->h_dest` (WAN→device direction).
- Copy `refill_and_consume()` from `choke.c` **verbatim**; replace
  `decide()`'s body with the token logic:

```c
static __always_inline int decide(struct dev_key *k)
{
    struct dev_bucket *b = bpf_map_lookup_elem(&choke_devs, k);
    if (!b) return TC_ACT_OK;
    if (b->flags & (FLAG_SEVER | FLAG_QUARANTINE)) return TC_ACT_SHOT;
    if (b->flags & (FLAG_THROTTLE | FLAG_TARPIT)) {
        if (b->rate_per_sec == 0) return TC_ACT_SHOT;        // misconfig -> drop
        return refill_and_consume(b) ? TC_ACT_OK : TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}
```

- Add `choke_devs_seen` (`BPF_MAP_TYPE_LRU_HASH`) populated **sampled**
  (every Nth packet / on map-miss) with `last_ns` and, for IPv4 frames,
  the source IP — this is the passive-discovery feed for Stage 2.

### 1.2 The backend interface (`engine/internal/enforce/devbpf/devbpf.go`)

Mirror [`bpfmap.go`](../../engine/internal/enforce/bpfmap/bpfmap.go):

```go
package devbpf

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

// DeviceBucket MUST stay byte-for-byte identical to bpfmap.PIDBucket (24 bytes).
type DeviceBucket struct {
	LastNs     uint64
	RatePerSec uint32
	Burst      uint32
	Tokens     uint32
	Flags      uint32
}

const (
	FlagThrottle   uint32 = 1 << 0
	FlagTarpit     uint32 = 1 << 1
	FlagQuarantine uint32 = 1 << 2
	FlagSever      uint32 = 1 << 3
)

type MAC [6]byte

func ParseMAC(s string) (MAC, error) {
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return MAC{}, fmt.Errorf("devbpf: bad MAC %q", s)
	}
	var m MAC
	copy(m[:], hw)
	return m, nil
}
func (m MAC) String() string { return net.HardwareAddr(m[:]).String() }

var ErrClosed = errors.New("devbpf: backend closed")

// DeviceChokeDataPlane is the sibling of bpfmap.Backend, keyed by MAC.
type DeviceChokeDataPlane interface {
	Open() error
	Close() error
	Update(mac MAC, b DeviceBucket) error
	Delete(mac MAC) error
	Snapshot() (map[MAC]DeviceBucket, error)
	SeenSnapshot() (map[MAC]Seen, error)
	AttachedLinks() int
	DataPlaneTier() string // "tc" (later: "xdp", "nftables")
}

type Seen struct {
	LastNs      uint64
	Packets     uint64
	LastSrcIPv4 uint32 // big-endian
}

// NoopDeviceBackend: in-memory mirror for dev/tests/non-linux. Mirrors
// bpfmap.NoopBackend exactly.
type NoopDeviceBackend struct {
	mu    sync.RWMutex
	open  bool
	state map[MAC]DeviceBucket
}

func NewNoopDeviceBackend() *NoopDeviceBackend {
	return &NoopDeviceBackend{state: make(map[MAC]DeviceBucket)}
}
// Open/Close/Update/Delete/Snapshot: copy NoopBackend; SeenSnapshot returns nil;
// DataPlaneTier() returns "noop"; AttachedLinks() returns 0.
```

### 1.3 The Linux loader (`engine/internal/enforce/devbpf/cilium_linux.go`)

Clone the loader from
[`cilium_linux.go`](../../engine/internal/enforce/bpfmap/cilium_linux.go),
swapping `link.AttachCgroup` for `link.AttachTCX` per interface:

```go
//go:build linux

package devbpf

import (
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type CiliumTCBackend struct {
	objPath string
	ifaces  []string // bridge slave / LAN ports

	mu      sync.RWMutex
	open    bool
	coll    *ebpf.Collection
	links   []link.Link
	devMap  *ebpf.Map
	seenMap *ebpf.Map
}

func NewCiliumTCBackend(objPath string, ifaces []string) *CiliumTCBackend {
	return &CiliumTCBackend{objPath: objPath, ifaces: ifaces}
}

func (c *CiliumTCBackend) Open() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open {
		return nil
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("devbpf: remove memlock: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpec(c.objPath)
	if err != nil {
		return fmt.Errorf("devbpf: load %s: %w", c.objPath, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("devbpf: new collection: %w", err)
	}
	c.coll = coll
	c.devMap = coll.Maps["choke_devs"]
	c.seenMap = coll.Maps["choke_devs_seen"]
	if c.devMap == nil {
		coll.Close()
		return fmt.Errorf("devbpf: choke_devs map not found")
	}

	for _, ifn := range c.ifaces {
		iface, err := netInterfaceByName(ifn) // net.InterfaceByName wrapper
		if err != nil {
			fmt.Fprintf(os.Stderr, "[devbpf] iface %s: %v (skipped)\n", ifn, err)
			continue
		}
		for _, a := range []struct {
			prog   string
			attach ebpf.AttachType
		}{
			{"devchoke_ingress", ebpf.AttachTCXIngress},
			{"devchoke_egress", ebpf.AttachTCXEgress},
		} {
			prog := coll.Programs[a.prog]
			if prog == nil {
				continue
			}
			l, err := link.AttachTCX(link.TCXOptions{
				Interface: iface.Index,
				Program:   prog,
				Attach:    a.attach,
			})
			if err != nil {
				// non-fatal: keep the map usable for telemetry (mirrors bpfmap)
				fmt.Fprintf(os.Stderr, "[devbpf] attach %s to %s: %v (map remains usable)\n",
					a.prog, ifn, err)
				continue
			}
			c.links = append(c.links, l)
		}
	}
	c.open = true
	return nil
}

func (c *CiliumTCBackend) Update(mac MAC, b DeviceBucket) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.open || c.devMap == nil {
		return ErrClosed
	}
	key := devKey(mac) // [8]byte: mac + 2 zero pad
	return c.devMap.Update(&key, &b, ebpf.UpdateAny)
}
// Delete/Snapshot/SeenSnapshot/Close/AttachedLinks/DataPlaneTier: mirror
// cilium_linux.go. DataPlaneTier() returns "tc".
```

Add `cilium_other.go` (`//go:build !linux`) returning a noop stub, exactly
like [`cilium_other.go`](../../engine/internal/enforce/bpfmap/cilium_other.go).

### 1.4 The device throttler (`engine/internal/enforce/devthrottler.go`)

Clone [`throttler.go`](../../engine/internal/enforce/throttler.go),
keyed by MAC and with the lockout guard:

```go
package enforce

import (
	"fmt"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/devbpf"
)

type DeviceThrottler struct {
	Backend   devbpf.DeviceChokeDataPlane
	Config    ThrottlerConfig          // reuse the SAME defaults: 50/100, 5/10, 1/2
	Protected map[devbpf.MAC]bool      // allow-list: gateway/uplink/DHCP-DNS/operator
}

func (t *DeviceThrottler) Apply(mac devbpf.MAC, action circuit.Action) error {
	if t.Backend == nil {
		return ErrUnsupported
	}
	if (action == circuit.ActQuarantine || action == circuit.ActSever) && t.Protected[mac] {
		return fmt.Errorf("devthrottler: refusing to %s protected MAC %s", action, mac)
	}
	cfg := t.Config
	if cfg == (ThrottlerConfig{}) {
		cfg = DefaultThrottlerConfig()
	}
	var b devbpf.DeviceBucket
	switch action {
	case circuit.ActThrottle:
		b = devbpf.DeviceBucket{RatePerSec: cfg.ThrottleRate, Burst: cfg.ThrottleBurst, Flags: devbpf.FlagThrottle}
	case circuit.ActTarpit:
		b = devbpf.DeviceBucket{RatePerSec: cfg.TarpitRate, Burst: cfg.TarpitBurst, Flags: devbpf.FlagTarpit}
	case circuit.ActQuarantine:
		b = devbpf.DeviceBucket{RatePerSec: cfg.QuarantineRate, Burst: cfg.QuarantineBurst, Flags: devbpf.FlagQuarantine}
	case circuit.ActSever:
		b = devbpf.DeviceBucket{Flags: devbpf.FlagSever}
	default:
		return ErrUnsupported
	}
	return t.Backend.Update(mac, b)
}
```

### 1.5 Wire into `main.go` and verify

Mirror the existing `-bpf-obj` backend-selection block in
[`main.go`](../../engine/cmd/engine/main.go):

```go
devchokeObj   = flag.String("devchoke-obj", "", "compiled devchoke.o; empty => noop device backend")
devchokeIface = flag.String("devchoke-iface", "", "comma-separated LAN/bridge-slave interfaces to attach")
```

```go
var devBackend devbpf.DeviceChokeDataPlane
if *devchokeObj != "" {
	tc := devbpf.NewCiliumTCBackend(*devchokeObj, splitCSV(*devchokeIface))
	if err := tc.Open(); err != nil {
		log.Printf("[devbpf] tc backend failed (%v) — falling back to noop", err)
		devBackend = devbpf.NewNoopDeviceBackend(); _ = devBackend.Open()
	} else {
		log.Printf("[devbpf] tc data plane from %s on [%s] (%d link(s), tier=%s)",
			*devchokeObj, *devchokeIface, tc.AttachedLinks(), tc.DataPlaneTier())
		devBackend = tc
	}
} else {
	devBackend = devbpf.NewNoopDeviceBackend(); _ = devBackend.Open()
}
defer devBackend.Close()
```

Verify in the lab — both directions, per-MAC isolation, and a layout
assertion:

```bash
go build -o engine ./engine/cmd/engine
sudo ip netns exec ns-gw ./engine -devchoke-obj .../devchoke.o -devchoke-iface veth-gw-lan -http :8080 &

# direct map writes via a tiny test harness or the Stage-2 API:
#   throttle  -> iperf3 clamps to token rate, bystander unaffected
#   sever     -> ping fails BOTH directions, gateway traffic fine
#   thaw      -> restored within a packet
sudo bpftool map dump name choke_devs   # 8B key + 24B value matches Go
```

Unit test the struct contract:

```go
func TestDeviceBucketLayout(t *testing.T) {
	if got := binary.Size(devbpf.DeviceBucket{}); got != 24 {
		t.Fatalf("DeviceBucket size = %d, want 24 (must match pid_bucket)", got)
	}
}
```

### 1.6 Stage 1 exit checklist

- [ ] Ingress + egress both attach; `AttachedLinks() == 2 × len(ifaces)`
- [ ] `throttle` clamps a device's throughput to the token rate; a
      bystander device on the same link is unaffected
- [ ] `sever` drops the device in **both** directions; gateway-local
      traffic unaffected
- [ ] `thaw` (`Delete(mac)`) restores throughput immediately
- [ ] `binary.Size(DeviceBucket) == 24` test passes
- [ ] `-devchoke-obj ""` cleanly uses the noop backend (engine still runs)
- [ ] Active tier logged at boot

---

## Stage 2 — identity, discovery, control plane, UI

**Goal:** devices are discovered and bound (MAC↔IP↔hostname), survive IP
churn, and an operator can jail/thaw them through the same surfaces as a
process — with the lockout guard live.

**Time budget:** 2–3 days.

### 2.1 `device.DeviceTable` (`engine/internal/device/table.go`)

Clone [`origin.Tracker`](../../engine/internal/origin/origin.go): a
concurrent map keyed by MAC, with the same field-wise `merge()` and TTL
`Sweep()`. `DeviceID = "dev:" + strings.ReplaceAll(mac, ":", "")`.

```go
type Device struct {
	MAC        string    `json:"mac"`
	DeviceID   string    `json:"device_id"`
	LastIP     string    `json:"last_ip,omitempty"`
	Hostname   string    `json:"hostname,omitempty"`
	Vendor     string    `json:"vendor,omitempty"`   // OUI lookup
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Source     string    `json:"source"`             // dhcp | mdns | neigh | passive
}
```

### 2.2 Discovery sources

Since DHCP runs on the closed ISP router, there is **no lease file** —
recover identity from three sources, merged by priority:

1. `engine/internal/device/dhcp_linux.go` — an `AF_PACKET` listener on
   the bridge that parses DHCP `REQUEST`/`ACK` (option 12/81) and mDNS
   names off the wire. Model the file-tailer shape on
   [`sshd_tailer_linux.go`](../../engine/internal/origin/sshd_tailer_linux.go),
   but read from a raw socket instead of journald.
2. `engine/internal/device/neigh_linux.go` — poll `ip -j neigh`
   (or `RTM_GETNEIGH`) for static-IP devices.
3. Drain `choke_devs_seen` on the existing 10 s metrics ticker
   ([main.go](../../engine/cmd/engine/main.go)) → `DeviceTable.Record`.
   Zero-dependency "this MAC is active", with the last source IP.

> **Eviction:** tie expiry to passive idle (`last_ns` from the seen map),
> **not** lease expiry alone — otherwise a still-active device's choke
> could be silently lifted.

### 2.3 `choke.DeviceGateway` (`engine/internal/choke/devgateway.go`)

Reuse [`circuit.Circuit`](../../engine/internal/choke/circuit/circuit.go)
with the MAC string as the key — no structural change:

```go
type DeviceGateway struct {
	circuit  *circuit.Circuit          // string-keyed by MAC
	thr      *enforce.DeviceThrottler
	table    *device.DeviceTable
	store    *store.Store
	bcast    Broadcaster
	killSw   atomic.Bool
	// ... reverts, annotations: copy from gateway.go
}

func (g *DeviceGateway) ManualDevice(ctx context.Context, mac string, a circuit.Action, reason, actor string) (*circuit.Decision, error) {
	m, err := devbpf.ParseMAC(mac)
	if err != nil { return nil, err }
	prev, _ := g.circuit.Force(mac, actionToState(a))   // reuse circuit.Force
	if !g.killSw.Load() {
		if err := g.thr.Apply(m, a); err != nil { /* record outcome, still audit */ }
	}
	d := &circuit.Decision{ExecID: "device:" + mac, From: prev, To: actionToState(a), Action: a,
		Reason: reason + " (by " + actor + ")", Timestamp: time.Now().UTC()}
	// InsertDecision with DeviceMAC/DeviceID columns; Broadcast("decision", ...)
	return d, nil
}
```

Add nullable `DeviceMAC` / `DeviceID` columns to
[`decisions.go`](../../engine/internal/store/decisions.go) following the
existing `OriginIP`/`OriginFingerprint` pattern, folded into the same
hash chain.

### 2.4 API (`engine/internal/api/devchoke.go`)

Near-clones of `handleChokeJail` / `handleChokeProcesses`, registered in
[`http.go`](../../engine/internal/api/http.go):

| Method | Route | Handler |
|---|---|---|
| GET  | `/api/choke/devices`      | `DeviceTable` ⋈ circuit ⋈ bucket |
| POST | `/api/choke/device-jail`  | `{macs, action, reason (required), revert_after_seconds}` → `ManualDevice` + `ScheduleRevert` |
| POST | `/api/choke/device-thaw`  | `{mac}` → `Backend.Delete` (precise per-device) |
| GET  | `/api/choke/device-state` | `{data_plane, capabilities, links_attached, buckets}` |

Reuse `parseAction`, the reason-required check, the per-target outcome
list, and the synthetic-execID audit pattern verbatim.

### 2.5 UI

Add a **Devices** tab to the choke console (clone the jail
process-picker table): MAC / IP / hostname / vendor + circuit state,
ladder bars, a device-jail modal with action + reason + optional
auto-revert, per-device thaw, and a **data-plane tier badge** (so an
operator can see the box is actually enforcing vs. silently a no-op).

### 2.6 Network state ladder semantics

Reuse the five rungs ([state-ladder.md](../architecture/state-ladder.md)),
mapped to network effects:

| Rung | Effect |
|---|---|
| throttled | token bucket 50/100 |
| tarpit | 5/10 |
| quarantined | 1/2 **with DHCP(67/68) + DNS(53) whitelisted** so the device can re-lease |
| severed | unconditional drop both directions |

### 2.7 Stage 2 exit checklist

- [ ] A previously-unseen device appears in `/api/choke/devices` via
      passive observation alone (no DHCP configured)
- [ ] After a DHCP release/renew, the device's `DeviceID` is unchanged
      and `LastIP` updates (MAC-keyed identity survives IP churn)
- [ ] `device-jail` throttles/quarantines/severs with a **required**
      audited reason; the `DeviceID` column folds into the verify-chain
- [ ] `device-thaw` and `revert_after_seconds` both release **exactly**
      that MAC
- [ ] Allow-listed MACs (gateway/uplink/DHCP-DNS/operator) are **refused**
      for quarantine/sever
- [ ] Quarantined device can still DHCP-renew and DNS-resolve

---

## Stage 3 — fleet, CLI, deploy

**Goal:** multi-gateway operation, scripted control, and a packaged
deploy onto the inline bridge box.

**Time budget:** 1–2 days.

### 3.1 Fleet fan-out

Add `handleFleetDevices` + `handleFleetDeviceJail` to
[`fleet.go`](../../engine/internal/api/fleet.go) — one-line wrappers over
`fleet.fanout`, gated by `requireFleet`, exactly like the existing
`/api/fleet/*` handlers.

### 3.2 `chokectl` subcommands

Add `device-status` / `device-jail` / `device-thaw` to
[`scripts/chokectl`](../../scripts/chokectl), cloning the existing `jail`
command (same `$CHOKE_USER`/`$CHOKE_PASS` auth, same hosts file).

### 3.3 Build & deploy

- **`setup.sh`:** extend the existing clang block to also compile
  `devchoke.c → devchoke.o` (same `CLANG_ARGS` + the 2 extra headers);
  verify `tc`/`iproute2` and `clsact` support.
- **`Makefile` / `deploy/install.sh`:** transfer `devchoke.c` next to
  `choke.c`; add `-devchoke-obj .../bpf/devchoke.o -devchoke-iface <slaves>`
  to the systemd `ExecStart`.
- **`config.go` / `engine.yaml.example`:** add `devchoke_obj`,
  `devchoke_ifaces` keys near `bpf_obj`.
- **Capabilities:** **no change** — the unit
  ([ebpf-engine.service](../../deploy/ebpf-engine.service)) already grants
  `CAP_NET_ADMIN` + `CAP_BPF` and has `/sys/fs/bpf` in `ReadWritePaths`.
- **Rollout:** ship with `-dry-run` first to validate
  discovery/identity/audit, populate the MAC allow-list, **then** flip to
  enforcing.

### 3.4 Real-hardware bring-up (bridge box)

```bash
# transparent bridge: ISP-router-LAN <-> eth0 [br0] eth1 <-> downstream switch
sudo ip link add name br0 type bridge
sudo ip link set eth0 master br0
sudo ip link set eth1 master br0
sudo ip link set br0 up; sudo ip link set eth0 up; sudo ip link set eth1 up
# attach devchoke to the SLAVES, never br0 itself:
#   -devchoke-iface eth0,eth1
```

### 3.5 Stage 3 exit checklist

- [ ] `make deploy` stands up an enforcing device choke from config
- [ ] `/api/fleet/device-jail` chokes a device across **two** gateways,
      returning per-host result envelopes
- [ ] `chokectl device-jail` / `device-thaw` work against the hosts file
- [ ] On real hardware, attaching to bridge **slaves** drops a wired
      device's traffic; the debug counter confirms forwarded frames are
      seen (catches the bridge-master mistake)

---

## Troubleshooting

**`tc filter` attaches but nothing is choked.**
You attached to the bridge **master** (sees only locally-terminated
traffic) instead of the **slave** ports. Attach to `eth0`/`eth1`, not
`br0`. Confirm with the debug counter — it must increment on forwarded
frames.

**`link.AttachTCX` returns `ENOTSUPP` / `EINVAL`.**
TCX needs kernel ≥ 6.6. Check `uname -r`. (The legacy clsact+netlink
fallback is explicitly out of scope for v1 — upgrade the box.)

**The verifier rejects the program.**
Almost always a missing bounds check. Every packet read needs
`if ((void *)(ptr + 1) > data_end) return TC_ACT_OK;` before dereference.
For IPv4 parsing in the seen map, re-check `data_end` after the eth
header.

**One direction still flows under `sever`.**
You only attached ingress (or egress). Both `devchoke_ingress`
(key = `h_source`) and `devchoke_egress` (key = `h_dest`) must attach.
`ping` device→net **and** net→device must both fail.

**Go map update fails / chokes the wrong device.**
Key layout mismatch. The kernel key is 8 bytes (`mac[6]` + 2 zero pad);
the Go side must write `[8]byte` with the pad zeroed, and
`binary.Size(DeviceBucket) == 24`. Dump with `bpftool map dump name choke_devs`.

**A quarantined device never comes back.**
Quarantine must whitelist gateway-local DHCP (67/68) and DNS (53) so the
device can re-lease/resolve. Without it the device is effectively
severed. Use `sever` only when you mean permanent.

**Engine locked the operator/uplink out.**
The MAC allow-list wasn't populated before enforcing. Engage the
kill-switch, `Delete` the offending MAC, and add it to `Protected`.

**Devices on the ISP router's WiFi can't be choked.**
They bypass the bridge. They must sit **behind** the box (disable ISP
WiFi + run an AP downstream, or make the Linux box the gateway).

---

## References

- [docs/architecture/network-choke-gateway.md](../architecture/network-choke-gateway.md)
  — the design this plan builds.
- [docs/architecture/state-ladder.md](../architecture/state-ladder.md)
  — the shared five-rung state machine.
- [cilium/ebpf TCX example](https://github.com/cilium/ebpf/tree/main/examples)
  — `link.AttachTCX` usage.
- [tc-bpf(8)](https://man7.org/linux/man-pages/man8/tc-bpf.8.html)
  — classifier/action model.
- [TC_ACT_* return codes](https://docs.kernel.org/bpf/prog_sched_cls.html)
  — `TC_ACT_OK` / `TC_ACT_SHOT`.
- The patterns this mirrors:
  [`bpfmap/`](../../engine/internal/enforce/bpfmap/),
  [`throttler.go`](../../engine/internal/enforce/throttler.go),
  [`circuit/circuit.go`](../../engine/internal/choke/circuit/circuit.go),
  [`origin/origin.go`](../../engine/internal/origin/origin.go),
  [`fleet.go`](../../engine/internal/api/fleet.go).

---

*Build it in stages on the same boring stack: one MAC dropped in a netns,
then a fleet of gateways choking devices by name.*
</content>
