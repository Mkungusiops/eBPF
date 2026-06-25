// SPDX-License-Identifier: GPL-2.0
//
// devchoke.c — kernel data plane for the NETWORK choke gateway.
//
// Sibling of choke.c. Where choke.c hooks cgroup/connect{4,6} and keys on
// PID (the host's own sockets), devchoke.c attaches to a `tc` clsact qdisc
// and keys on the device MAC address — so it can shape FORWARDED LAN<->WAN
// frames on an inline Linux bridge/router, which the cgroup hooks never see.
//
// Map: BPF_MAP_TYPE_HASH<struct dev_key, struct dev_bucket>. Userspace writes
// entries via cilium/ebpf; the kernel reads them on every forwarded frame
// and decides whether to pass (TC_ACT_OK) or drop (TC_ACT_SHOT).
//
// Decision policy (in order) — identical semantics to choke.c:
//   FLAG_SEVER     -> drop outright
//   FLAG_QUARANTINE-> drop outright
//   FLAG_TARPIT    -> token bucket, drop when empty
//   FLAG_THROTTLE  -> token bucket, drop when empty
//   (no flags / not in map) -> pass (fail-open)
//
// The token-bucket math (refill_and_consume) is copied verbatim from
// choke.c so the two data planes behave identically and share the 24-byte
// bucket layout (struct dev_bucket == struct pid_bucket == Go PIDBucket).
//
// Hooks:
//   tc ingress — frames arriving from the LAN device  (key = eth->h_source)
//   tc egress  — frames heading toward the LAN device (key = eth->h_dest)
// Attaching BOTH directions is what makes `sever` cut the device off
// completely rather than only choking its uploads.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

#define FLAG_THROTTLE   (1u << 0)
#define FLAG_TARPIT     (1u << 1)
#define FLAG_QUARANTINE (1u << 2)
#define FLAG_SEVER      (1u << 3)

#define NSEC_PER_SEC 1000000000ULL
#define ETH_P_IP_BE  0x0008 /* htons(0x0800) on little-endian */

#ifndef __bpf_htons
#define __bpf_htons(x) __builtin_bswap16(x)
#endif

// dev_key: the device MAC plus 2 zero pad bytes so the 8-byte key hashes
// cleanly and matches the Go side's tight-packed [8]byte. Pad MUST be zeroed.
struct dev_key {
    __u8 mac[6];
    __u8 _pad[2];
};

// dev_bucket: byte-for-byte identical to choke.c's pid_bucket and to the Go
// devbpf.DeviceBucket (24 bytes). last_ns first so u64 alignment introduces
// no padding the Go encoding/binary side won't emit.
struct dev_bucket {
    __u64 last_ns;
    __u32 rate_per_sec;
    __u32 burst;
    __u32 tokens;
    __u32 flags;
};

// seen: passive-discovery record. last_saddr_be is the device's source IPv4
// (network byte order) sampled from forwarded IPv4 frames; pad keeps the
// struct at 24 bytes so Go reads a stable size.
struct seen {
    __u64 last_ns;
    __u64 pkts;
    __u32 last_saddr_be;
    __u32 _pad;
};

// flow_key identifies one (device -> destination) network flow: which LAN
// device (mac) is talking to which destination (daddr:dport/proto). 16 bytes,
// explicitly padded so the Go side's tight-packed key matches byte-for-byte
// and uninitialised pad never causes spurious key misses.
struct flow_key {
    __u8   mac[6];
    __u8   _pad[2];
    __be32 daddr;
    __be16 dport;
    __u8   proto;
    __u8   _pad2;
};

// flow_stat counts a flow. 24 bytes.
struct flow_stat {
    __u64 packets;
    __u64 bytes;
    __u64 last_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct dev_key);
    __type(value, struct dev_bucket);
} choke_devs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct dev_key);
    __type(value, struct seen);
} choke_devs_seen SEC(".maps");

// choke_flows records, per device, the destinations it is contacting. LRU so
// the busiest/most-recent flows stay and the map self-bounds. Drained by
// userspace to power the per-device "what is this device talking to?" view —
// the operator's signal for whether a device looks malicious before choking.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_key);
    __type(value, struct flow_stat);
} choke_flows SEC(".maps");

// refill_and_consume — copied verbatim from choke.c. Lazy token refill +
// consume one token. Returns 1 if a token was available (allow), 0 if empty.
static __always_inline int refill_and_consume(struct dev_bucket *b)
{
    __u64 now = bpf_ktime_get_ns();
    __u64 last = b->last_ns;
    __u64 elapsed = now > last ? (now - last) : 0;

    __u64 refill = (elapsed * (__u64)b->rate_per_sec) / NSEC_PER_SEC;
    if (refill > 0) {
        __u32 t = b->tokens + (__u32)refill;
        if (t > b->burst)
            t = b->burst;
        b->tokens = t;
        b->last_ns = now;
    }

    __u32 cur = b->tokens;
    if (cur == 0)
        return 0;
    b->tokens = cur - 1;
    return 1;
}

// is_infra reports whether the frame is gateway-local DHCP (UDP 67/68) or
// DNS (UDP 53) in either direction. A quarantined device is allowed to send
// and receive these so it can keep its lease and resolve names — i.e. it can
// recover — which is what distinguishes quarantine from sever. Comparisons
// are against network-order ports so no byte-swap is needed. Heavily
// bounds-checked: this reads attacker-influenced bytes off the wire.
static __always_inline int is_infra(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    if (eth->h_proto != __bpf_htons(ETH_P_IP))
        return 0;
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return 0;
    if (iph->protocol != 17) // IPPROTO_UDP
        return 0;
    __u32 ihl = (__u32)(iph->ihl & 0x0f) * 4;
    if (ihl < sizeof(struct iphdr))
        return 0;
    struct udphdr *udp = (void *)iph + ihl;
    if ((void *)(udp + 1) > data_end)
        return 0;
    __u16 sp = udp->source, dp = udp->dest;
    if (sp == __bpf_htons(53) || dp == __bpf_htons(53))
        return 1; // DNS
    if (sp == __bpf_htons(67) || dp == __bpf_htons(67))
        return 1; // DHCP server
    if (sp == __bpf_htons(68) || dp == __bpf_htons(68))
        return 1; // DHCP client
    return 0;
}

// decide returns TC_ACT_OK (pass) or TC_ACT_SHOT (drop) for a device MAC.
// `infra` is 1 when the frame is DHCP/DNS (see is_infra) — used only to keep
// quarantined devices able to recover.
static __always_inline int decide(struct dev_key *k, int infra)
{
    struct dev_bucket *b = bpf_map_lookup_elem(&choke_devs, k);
    if (!b)
        return TC_ACT_OK; // not managed: pass (fail-open)
    if (b->flags & FLAG_SEVER)
        return TC_ACT_SHOT; // terminal: block everything, including DHCP/DNS
    if (b->flags & FLAG_QUARANTINE) {
        if (infra)
            return TC_ACT_OK; // let a quarantined device re-lease / resolve
        // else fall through to the (near-zero) token bucket below
    }
    if (b->flags & (FLAG_THROTTLE | FLAG_TARPIT | FLAG_QUARANTINE)) {
        if (b->rate_per_sec == 0)
            return TC_ACT_SHOT; // misconfigured rate tier: drop on the safe side
        return refill_and_consume(b) ? TC_ACT_OK : TC_ACT_SHOT;
    }
    return TC_ACT_OK; // no enforcement flags: pass
}

// observe records the device into choke_devs_seen for passive discovery.
// Best-effort: failures are ignored, IPv4 source is sampled when present.
static __always_inline void observe(struct __sk_buff *skb, struct dev_key *k)
{
    __u32 saddr = 0;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) <= data_end &&
        eth->h_proto == __bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) <= data_end)
            saddr = iph->saddr;
    }

    struct seen *s = bpf_map_lookup_elem(&choke_devs_seen, k);
    if (s) {
        s->last_ns = bpf_ktime_get_ns();
        s->pkts += 1;
        if (saddr)
            s->last_saddr_be = saddr;
        return;
    }
    struct seen fresh = {};
    fresh.last_ns = bpf_ktime_get_ns();
    fresh.pkts = 1;
    fresh.last_saddr_be = saddr;
    bpf_map_update_elem(&choke_devs_seen, k, &fresh, BPF_ANY);
}

// record_flow logs the destination a device is contacting into choke_flows.
// Called on ingress only (device -> WAN), so the key's MAC is the device's
// source MAC. Best-effort + heavily bounds-checked; non-IP frames are skipped.
static __always_inline void record_flow(struct __sk_buff *skb, __u8 mac[6])
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return;
    if (eth->h_proto != __bpf_htons(ETH_P_IP))
        return;
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return;
    __u32 ihl = (__u32)(iph->ihl & 0x0f) * 4;
    if (ihl < sizeof(struct iphdr))
        return;

    struct flow_key fk = {};
    __builtin_memcpy(fk.mac, mac, 6);
    fk.daddr = iph->daddr;
    fk.proto = iph->protocol;
    if (iph->protocol == 6 || iph->protocol == 17) { // TCP / UDP
        void *l4 = (void *)iph + ihl;
        if (l4 + 4 <= data_end) {
            __u16 *ports = l4;
            fk.dport = ports[1]; // destination port, network order
        }
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 len = skb->len;
    struct flow_stat *fs = bpf_map_lookup_elem(&choke_flows, &fk);
    if (fs) {
        fs->packets += 1;
        fs->bytes += len;
        fs->last_ns = now;
        return;
    }
    struct flow_stat init = {};
    init.packets = 1;
    init.bytes = len;
    init.last_ns = now;
    bpf_map_update_elem(&choke_flows, &fk, &init, BPF_ANY);
}

// classify is the shared body. ingress=1 keys on the source MAC (the LAN
// device that sent the frame); ingress=0 keys on the destination MAC (the
// LAN device the frame is headed to).
static __always_inline int classify(struct __sk_buff *skb, int ingress)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK; // runt / non-ethernet: pass

    struct dev_key k = {};
    if (ingress) {
        if (eth->h_source[0] & 1)
            return TC_ACT_OK; // multicast/broadcast source is bogus: pass
        __builtin_memcpy(k.mac, eth->h_source, 6);
    } else {
        if (eth->h_dest[0] & 1)
            return TC_ACT_OK; // don't choke broadcast/multicast delivery
        __builtin_memcpy(k.mac, eth->h_dest, 6);
    }

    observe(skb, &k);
    if (ingress)
        record_flow(skb, k.mac); // device -> destination: what is it talking to?
    return decide(&k, is_infra(skb));
}

SEC("tc")
int devchoke_ingress(struct __sk_buff *skb)
{
    return classify(skb, 1);
}

SEC("tc")
int devchoke_egress(struct __sk_buff *skb)
{
    return classify(skb, 0);
}

char _license[] SEC("license") = "GPL";
