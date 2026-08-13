# Tech stack & eBPF program inventory

Two reference tables:

1. **[Tech stack](#1-tech-stack)** — every technology in the platform and the
   reason it was chosen over the alternative.
2. **[eBPF programs](#2-ebpf-programs)** — every program that attaches to the
   kernel, what it hooks, and the function it serves.

Companion docs: [overview.md](overview.md) (how the components fit together),
[state-ladder.md](state-ladder.md) (the five-rung enforcement machine),
[network-choke-gateway.md](network-choke-gateway.md) (the TC data plane in
depth), and [../plan/d4c-tech-decisions.md](../plan/d4c-tech-decisions.md)
(infrastructure ADRs).

---

## 1. Tech stack

The **Where it lives** column is the first file to open when you need to touch
that technology — the wrapper package for a library, or the config that stands
up an external service.

| Layer | Technology | Where it lives | Why it was chosen |
| --- | --- | --- | --- |
| Kernel telemetry | **Tetragon v1.6.1** (`quay.io/cilium/tetragon`) + `cilium/tetragon/api` Go client | `engine/cmd/engine/main.go`, `engine/cmd/agent/main.go` (gRPC stream consumers) | Ships pre-written, CO-RE eBPF programs, a declarative policy language (TracingPolicy YAML), stable `exec_id` process-tree tracking, and a gRPC event stream. [build-plan.md](../development/build-plan.md) records the call explicitly: writing libbpf+C from scratch would have added ~2 weeks. |
| Kernel enforcement | **Hand-written eBPF C** compiled with `clang -target bpf`, loaded via **`cilium/ebpf` v0.21.0** | `engine/internal/enforce/bpfmap/` (PID plane), `engine/internal/enforce/devbpf/` (device plane); loaders in `cilium_linux.go`, C in `bpf/` | Tetragon can detect and `Sigkill`, but cannot do per-PID token buckets or MAC-keyed shaping of *forwarded* traffic. Those two data planes had to be custom. `cilium/ebpf` is a pure-Go loader — no libbpf at runtime, so the binary stays static. |
| Non-BPF enforcement | **cgroup v2** (`cpu.max`, freezer), **seccomp**, `SIGKILL` | `engine/internal/enforce/cgroupv2/`, `engine/internal/enforce/seccomp/`, `engine/internal/enforce/severer.go` | Gives the rungs eBPF can't express: CPU throttling (5% / 1%), full process freeze (quarantine), and syscall denial — the ladder below `sever`. |
| Engine / agent / control plane | **Go 1.25** | `engine/go.mod`; five binaries under `engine/cmd/` (`engine`, `agent`, `controlplane`, `simagent`, `socbackup`) | Single statically-linked binary per role, trivial cross-compile to `linux/amd64` + `arm64`, and Tetragon's first-class Go bindings. |
| Wire protocol | **gRPC 1.80 + Protobuf 1.36** | `engine/proto/` (`.proto` sources) → `engine/gen/ebpfsoc/v1/` (generated) | Five typed services — enrollment, heartbeat, telemetry, policy, command — with generated clients on both ends and streaming for telemetry. |
| Transport auth | **mTLS** | `engine/internal/mtls/` | Mutual agent ↔ control-plane authentication; an agent identity can't be spoofed by holding only a bearer token. |
| Command integrity | **Ed25519** | `engine/internal/signing/` | "Signed-everything-downstream": the fleet service signs commands and policy bundles; agents hold only the public key, so a compromised channel can't forge a `sever`. |
| Identity / SSO | **Keycloak 26** + **OIDC** (`coreos/go-oidc/v3`) | `engine/internal/identity/` (OIDC + Keycloak client), `engine/internal/authz/` (RBAC); container in `deploy/docker-compose.oss.yml` | Multi-tenant realms, RBAC, and token lifecycle for the MSSP model — no hand-rolled auth. |
| Edge store | **SQLite (WAL)** via `modernc.org/sqlite` | `engine/internal/store/sqlite.go` | Pure-Go, cgo-free — the reason the gateway can be one static binary. One file per gateway; survives control-plane loss. |
| Central store | **PostgreSQL 16** (`pgx/v5`) | `engine/internal/centralstore/postgres.go`; schema in `scripts/migrations/postgres/` | Relational, transactional system-of-record for tenants, fleets, devices, policies. |
| Analytics store | **ClickHouse 24.8** (`clickhouse-go/v2`) | `engine/internal/centralstore/clickhouse.go`; schema in `scripts/migrations/clickhouse/` | Kernel events arrive in the millions; columnar storage makes SOC aggregations and time-range queries fast where Postgres would not scale. |
| Event bus | **NATS 2.10** (`nats.go` + embeddable `nats-server`) | `engine/internal/bus/` (interface), `engine/internal/bus/natsbus/` (impl) | Fan-out of telemetry/commands between services; embeddable, so single-process dev runs need no broker. |
| Object storage | **SeaweedFS 3.73** | `deploy/docker-compose.oss.yml` | Blob/artifact store in the OSS compose stack. |
| Observability | **OpenTelemetry** SDK + OTLP/HTTP metrics exporter | `engine/internal/metrics/metrics.go` | Vendor-neutral metrics; export to whatever the customer already runs. |
| Console | **React 18 + TypeScript 5.7 + Vite 6** | `web/src/` (`entries/`, `features/`, `components/`); build config `web/vite.config.ts` | SPA compiled to a static bundle; Vite for fast HMR during panel work. |
| UI layer | **Tailwind 3.4**, **Radix UI** (dialog / dropdown / popover), **lucide-react**, **cmdk** | `web/tailwind.config.ts`, `web/postcss.config.cjs`, `web/src/styles.css`; usage in `web/src/features/` | Accessible unstyled primitives + utility CSS instead of a heavyweight component framework — keeps the bundle small enough to embed. |
| Client state & viz | **Zustand 5**, **D3 7**, **@tanstack/react-virtual** | `web/src/stores/stream.ts` (store), `web/src/features/soc/SocRoute.tsx` (D3 charts), `web/src/components/VirtualList.tsx` | Minimal store (no Redux boilerplate); custom D3 charts; virtualization so multi-thousand-row event tables stay smooth. |
| Reporting | **jsPDF + jspdf-autotable** | `web/src/features/soc/SocRoute.tsx` | Client-side SOC report export — no server-side render service. |
| Offline / install | **vite-plugin-pwa** | `web/vite.config.ts` | Installable console. |
| Bundle delivery | **`go:embed`** | `engine/internal/api/web_embed.go` (`//go:embed all:web`) | The React build is compiled *into* the Go binary — zero Node runtime and no external web server in production. |
| Testing | **Vitest 2** + Testing Library + jsdom; **Playwright 1.49** e2e; Go `testing` | `web/src/test/` + `web/vitest.config.ts`; `web/e2e/` + `web/playwright.config.ts`; `*_test.go` beside each Go package | Unit coverage on both sides plus real-browser E2E against the deployed stack. |
| Edge / TLS | **nginx** | `deploy/nginx/ebpf-engine.conf` | TLS termination and reverse proxy in front of the control plane. |
| Packaging & runtime | **Docker + docker-compose**, **systemd** units, **OrbStack** for the local mirror | `deploy/docker-compose.oss.yml`, `deploy/controlplane.Dockerfile`, `deploy/*.service`, `scripts/deploy/*-orbstack.sh` | Compose for the OSS stack; systemd for bare-metal gateways; OrbStack mirrors prod locally on macOS. |
| Infrastructure-as-code | **Terraform** (`hashicorp/kubernetes`, `hashicorp/helm`) | `deploy/terraform/` | Repeatable multi-tenant cluster provisioning. |
| Build & CI | **GNU Make**, **clang/LLVM**, **GitHub Actions** | `Makefile` (root), `.github/workflows/ci.yml` | One `make` entry point for BPF objects, Go cross-builds, tarballs and deploys. |

---

## 2. eBPF programs

**12 programs attach to the kernel: 6 hand-written (across 2 ELF objects), plus
6 kprobe programs Tetragon generates from 5 TracingPolicies.**

| # | Program / hook | Source | Attach point | Function & why it exists |
| --- | --- | --- | --- | --- |
| **A. Hand-written — process choke data plane (`choke.o`)** | | | | |
| 1 | `choke_connect4` — `SEC("cgroup/connect4")` | `engine/internal/enforce/bpfmap/bpf/choke.c` | cgroup v2 root | Gates every IPv4 TCP/UDP `connect()` for the calling PID. Reads the `choke_pids` hash: `SEVER`/`QUARANTINE` → deny outright; `THROTTLE`/`TARPIT` → lazy-refill token bucket, deny when empty. This is what makes throttling *actually* rate-limit exfil rather than just log it. |
| 2 | `choke_connect6` — `SEC("cgroup/connect6")` | `choke.c` | cgroup v2 root | Same decision for IPv6 — without it an attacker escapes the choke by dialing over v6. |
| 3 | `choke_sendmsg4` — `SEC("cgroup/sendmsg4")` | `choke.c` | cgroup v2 root | Covers **unconnected** IPv4 UDP `sendmsg`, which never calls `connect()` — closes the DNS-tunnelling / connectionless-exfil gap. |
| 4 | `choke_sendmsg6` — `SEC("cgroup/sendmsg6")` | `choke.c` | cgroup v2 root | IPv6 counterpart of #3. |
| **B. Hand-written — network/device choke data plane (`devchoke.o`)** | | | | |
| 5 | `devchoke_ingress` — `SEC("tc")` | `engine/internal/enforce/devbpf/bpf/devchoke.c` | `tc` clsact **ingress** on the bridge iface | Keys on `eth->h_source` (the LAN device's MAC) to shape LAN→WAN frames. The cgroup hooks only see the *host's own* sockets and are blind to forwarded traffic — this is the only way to choke an IoT device or laptop from an inline bridge. Also runs `observe()` (passive device discovery) and `record_flow()` (per-device destination flows: "what is this device talking to?"). |
| 6 | `devchoke_egress` — `SEC("tc")` | `devchoke.c` | `tc` clsact **egress** | Keys on `eth->h_dest` to shape WAN→LAN. Attaching *both* directions is what makes `sever` cut a device off completely instead of only choking its uploads. Quarantine deliberately still passes DHCP/DNS (`is_infra()`) so a device can re-lease and recover — the distinction between quarantine and sever. |
| **C. Tetragon-loaded — detection policies (`policies/`)** | | | | |
| 7 | kprobe `__x64_sys_setuid` + `__x64_sys_setreuid` (2 programs) | `policies/privilege-escalation.yaml` | syscall kprobe | Fires only when the target uid argument is `0` — catches privilege escalation to root while filtering out routine uid drops in-kernel. |
| 8 | kretprobe `security_file_permission` | `policies/sensitive-files.yaml` | LSM hook kprobe | Detect-only read/write watch on `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/root/.ssh/` and the honeypot dir. Placed at the LSM hook rather than `open()` so it can't be bypassed by an alternate syscall path. |
| 9 | kprobe `tcp_connect` | `policies/network-watch.yaml` | kernel-function kprobe | Records outbound connections but *only* from shells and netcat-family binaries (`bash`/`sh`/`zsh`/`dash`/`nc`/`ncat`/`socat`) — the reverse-shell / C2-beacon signal, without the noise of every socket on the box. |
| 10 | kretprobe `security_file_permission` | `policies/override-credential-read.yaml` | LSM hook kprobe | Detect-only watch on credential paths (`~/.ssh/`, `~/.aws/`, `~/.gnupg/`, …) read by non-allowlisted binaries. Enforcement for this signal lives in the engine's choke gateway, not here — the policy header records why, and why `Override`/EACCES was unavailable on the deployed kernels. |

There is no separate enforcement tier. `policies/enforce/` used to exist and no
longer does: everything in it either moved up (the credential watch, now
detect-only) or was deleted (`sever-pipe-to-shell`, which shipped `Sigkill` and
**never fired** — at `execve` the calling process is the shell, not `curl`, so
`matchBinaries In [curl,wget]` could not match, and `| sh` is a shell construct
absent from curl's argv). The engine scores that pattern from the exec chain
instead, which works for exactly the reason the selector could not.

All four remaining policies declare `policy-mode: monitor`, so Tetragon
suppresses enforcing actions in-kernel regardless of their selectors while
leaving `Post` untouched — the second enforcement authority is disarmed by
declaration, reported on the agent heartbeat, and asserted by
[`host-posture.sh`](../../scripts/e2e/host-posture.sh). See
[threat-model](../plan/threat-model.md) EN-1c/EN-1d/EN-3.

### Supporting BPF maps

| Map | Type / size | Purpose |
| --- | --- | --- |
| `choke_pids` | `HASH`, 65 536 entries | `u32 pid` → 24-byte `pid_bucket` (flags + token bucket). Written by userspace, read by programs 1–4. |
| `choke_devs` | `HASH`, 4 096 entries | `dev_key{mac[6]+pad}` → 24-byte `dev_bucket`. Written by userspace, read by programs 5–6. |
| `choke_devs_seen` | `LRU_HASH`, 4 096 entries | Passive device discovery — last-seen timestamp, packet count, sampled source IPv4. |
| `choke_flows` | `LRU_HASH`, 8 192 entries | Per-device destination flows (`mac`, `daddr`, `dport`, `proto` → packets/bytes/last-seen). Powers the "what is this device talking to?" view an operator checks before choking. |

The 24-byte bucket layout is byte-for-byte identical across `choke.c`,
`devchoke.c`, and the Go structs (`bpfmap.PIDBucket` / `devbpf.DeviceBucket`) —
`last_ns` is declared first so `u64` alignment introduces no padding that Go's
`encoding/binary` would not emit.

### Two things worth flagging

- The three files in `policies/choke/` (`shell-egress-throttle`,
  `network-tools-tarpit`, `agent-loop-cap`) are **not** eBPF programs. They are
  userspace `ChokePolicy` YAML that the engine reads to decide *what values* to
  write into the `choke_pids` map.
- The `Makefile` only has a build rule for `devchoke.o` (`make devbpf`).
  `choke.o` is expected at `$(REMOTE_DIR)/bpf/choke.o` on the target host, but
  no target compiles it.
