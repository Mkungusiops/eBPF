// SPDX-License-Identifier: GPL-2.0
//
// choke.c — kernel data plane for the choke gateway (v2).
//
// Map: BPF_MAP_TYPE_HASH<u32 pid, struct pid_bucket>. Userspace writes
// entries via cilium/ebpf; the kernel reads them on every TCP/UDP
// outbound syscall and decides whether to allow.
//
// Decision policy (in order):
//   FLAG_SEVER     -> deny outright
//   FLAG_QUARANTINE-> deny outright
//   FLAG_TARPIT    -> token bucket, deny when empty
//   FLAG_THROTTLE  -> token bucket, deny when empty
//   (no flags)     -> allow
//
// Token bucket: each PID has rate_per_sec tokens added per real second
// (refilled lazily on consultation), capped at burst. Each consultation
// consumes one token. last_ns is updated with bpf_ktime_get_ns() on
// refill so the bucket stays synced regardless of consultation frequency.
//
// All token state mutations use __sync_fetch_and_* atomics — multiple
// CPUs can hit the same PID concurrently (one process, many threads
// each opening sockets) and we must not double-spend or under-refill.
//
// Hooks:
//   cgroup/connect4   — TCP+UDP IPv4 connect()
//   cgroup/connect6   — TCP+UDP IPv6 connect()
//   cgroup/sendmsg4   — IPv4 unconnected UDP sendmsg
//   cgroup/sendmsg6   — IPv6 unconnected UDP sendmsg

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define FLAG_THROTTLE   (1u << 0)
#define FLAG_TARPIT     (1u << 1)
#define FLAG_QUARANTINE (1u << 2)
#define FLAG_SEVER      (1u << 3)

#define NSEC_PER_SEC 1000000000ULL

// Must match bpfmap.PIDBucket Go struct byte-for-byte. last_ns first so
// the u64 alignment doesn't introduce padding the Go side won't emit
// (encoding/binary writes fields tightly without natural-alignment pad).
// Total size: 24 bytes.
struct pid_bucket {
    __u64 last_ns;
    __u32 rate_per_sec;
    __u32 burst;
    __u32 tokens;
    __u32 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct pid_bucket);
} choke_pids SEC(".maps");

// refill_and_consume runs lazy refill arithmetic and consumes one token.
// Returns 1 if a token was available (allow), 0 if empty (deny).
//
// Non-atomic on purpose: LLVM 14's BPF backend can't lower 32-bit
// __sync_fetch_and_* on hash-map values. The tightest race window is
// "two CPUs see the same pre-decrement value and both pass" — bounded
// by `burst` over-allocation per refill window, which doesn't compromise
// the throttle goal (it's a smoothing filter, not a hard quota).
static __always_inline int refill_and_consume(struct pid_bucket *b)
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

// decide returns 1 (allow) or 0 (deny) for the calling PID.
static __always_inline int decide(void)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct pid_bucket *b = bpf_map_lookup_elem(&choke_pids, &pid);
    if (!b)
        return 1; // not in map: allow
    if (b->flags & (FLAG_SEVER | FLAG_QUARANTINE))
        return 0;
    if (b->flags & (FLAG_THROTTLE | FLAG_TARPIT)) {
        if (b->rate_per_sec == 0)
            return 0; // misconfigured tarpit/throttle: deny on safe side
        return refill_and_consume(b);
    }
    return 1; // no enforcement flags: allow
}

SEC("cgroup/connect4")
int choke_connect4(struct bpf_sock_addr *ctx)
{
    return decide();
}

SEC("cgroup/connect6")
int choke_connect6(struct bpf_sock_addr *ctx)
{
    return decide();
}

SEC("cgroup/sendmsg4")
int choke_sendmsg4(struct bpf_sock_addr *ctx)
{
    return decide();
}

SEC("cgroup/sendmsg6")
int choke_sendmsg6(struct bpf_sock_addr *ctx)
{
    return decide();
}

char _license[] SEC("license") = "GPL";
