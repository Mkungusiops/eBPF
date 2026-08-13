# Deploy the full platform across five AWS hosts

The reference **multi-host** deployment: a control plane, a single-tenant
engine, one real agent per tenant, and a disposable device to contain. Both
choke gateways run for real — process enforcement is a genuine `SIGKILL`, device
enforcement is a genuine `tc` drop rule — and the whole thing is verified by
[`scripts/e2e/all.sh`](../../scripts/e2e/all.sh).

This is the topology the local [OrbStack mirror](orbstack-local-mirror.md)
cannot reproduce: its VMs are L2-isolated from each other, so there is never a
legitimate, non-critical device to sever. On separate cloud instances in one
subnet there is.

---

## 1. Why five hosts

| Host | Runs | Why it is separate |
|------|------|--------------------|
| control plane | Postgres (RLS), Keycloak, control plane, nginx | No kernel hooks; it is the only host browsers reach |
| single-tenant engine | engine + Tetragon + nginx | Its own kernel — this is the standalone product |
| tenant A agent | agent + Tetragon + tc device plane | **Own kernel per tenant** |
| tenant B agent | agent + Tetragon + tc device plane | Second tenant proves isolation is real |
| victim device | nothing (a target) | Something safe to actually contain |

**One kernel per tenant is the whole point.** Tetragon attaches BPF to a kernel,
so tenants sharing one (containers on a single host, for instance) would observe
each other's process events and the isolation would be cosmetic. Agents must be
VMs or separate machines — not LXC/containers on a shared host.

The victim exists because a device gateway with nothing safe to choke cannot be
demonstrated. On a flat subnet the only neighbours an agent sees are usually its
own gateway and the control plane, and both are — correctly — refused by the
protect list.

## 2. Sizing

Measured on an idle-to-light rig with real telemetry flowing:

| Component | RSS |
|-----------|-----|
| Keycloak (JVM) | ~630 MiB |
| Postgres | ~590 MiB |
| Tetragon | ~110 MiB |
| nginx / engine / control plane | ~35 / ~25 / ~20 MiB |
| **control-plane host total** | **~2.3 GiB** |
| **agent host total** | **~1.9 GiB** |

`2 vCPU / 4 GiB` per host is comfortable; load average sits near zero. This
workload is **memory and kernel-hook bound, not CPU bound** — do not buy cores.

Disk is the number that grows: roughly **130 MiB/day** of telemetry per busy
host. 20–40 GiB per host is fine for a test rig.

Guests need **BTF** (`/sys/kernel/btf/vmlinux`) or Tetragon cannot attach.
Ubuntu 22.04+ / Debian 12+ are fine.

## 3. Networking

Give every host a DNS name you control, and **allocate Elastic/static IPs for
anything DNS points at** — an auto-assigned public IP changes on stop/start and
silently breaks both the console and its OIDC issuer.

Minimum inbound rules (each instance may have its own security group — check,
because a self-referencing rule does nothing if they differ):

| Host | Port | Source | Purpose |
|------|------|--------|---------|
| control plane | 80 | `0.0.0.0/0` | console + ACME HTTP-01 |
| control plane | 443 | `0.0.0.0/0` | console over TLS |
| control plane | 9443 | VPC CIDR | agent enrolment, telemetry, heartbeat, commands |
| engine | 80, 443 | `0.0.0.0/0` | engine UI + ACME |
| victim | 8000 | VPC CIDR | traffic for the device-drop proof |
| all | 22 | your IP | management |

`:80` must be open to **`0.0.0.0/0`**, not your IP — Let's Encrypt validates
from arbitrary addresses.

**Do not expose Keycloak's port.** It is proxied on the console origin (§4).
Postgres and the control plane's HTTP API bind `127.0.0.1` and must stay there.

## 4. Deploy

### Control plane

```bash
TLS=1 DATA_MODE=none \
SSH_HOST=control-plane TARGET_HOST=console.example.com TLS_EMAIL=you@example.com \
  ./scripts/deploy/multi-tenant-ubuntu.sh
```

- `TLS=1` obtains a certificate **before** provisioning, then serves `:443` and
  redirects `:80`. The OIDC issuer, redirect URI and `Secure` session cookies all
  follow the scheme automatically.
- `DATA_MODE=none` provisions no sim-agents. Use it whenever real agents are
  managed separately — otherwise every redeploy resurrects the simulators
  alongside the real agents, the tenant ends up with two, and enforcement can be
  dispatched to a simulator that acks success for a process it never touched.

Keycloak is proxied at `/realms`, `/resources`, `/admin`, `/js` on the console
origin rather than published on its own port. That is not only tidier: the
control plane resolves OIDC discovery by dialling the issuer URL, which on a
cloud host is a hairpin to its own public IP, and that only works on a port the
security group admits. One open port instead of two.

### Single-tenant engine

```bash
TLS=1 SSH_HOST=single-tenant-engine TARGET_HOST=engine.example.com \
TLS_EMAIL=you@example.com \
  ./scripts/deploy/single-tenant-ubuntu.sh
```

When `TARGET_HOST` is a DNS name the engine is fronted by nginx, so it is
reached on a clean origin instead of `host:8090` and its own port never needs
opening. `DEVCHOKE=1` additionally compiles and attaches the tc device plane.

### Agents — one per tenant

```bash
# trust material, from the control plane
ssh control-plane 'sudo cat /var/lib/ebpf-soc/ca.pem'   > .deploy-build/trust/ca.pem
ssh control-plane 'sudo cat /var/lib/ebpf-soc/fleet.pub' > .deploy-build/trust/fleet.pub

CP_SSH=control-plane ./scripts/deploy/provision-agent-ssh.sh \
  tenant-a-id  tenant-a-host  <cp-private-ip>  <cp-admin-token> \
  .deploy-build/trust/ca.pem .deploy-build/trust/fleet.pub \
  .deploy-build/agent  engine/internal/enforce/devbpf/bpf/devchoke.o
```

The admin token is `CP_ADMIN_TOKEN` in `/etc/ebpf-soc/controlplane.env`.
`devchoke.o` must be compiled on a Linux host (`make devchoke`, or `clang -O2 -g
-target bpf`); the object is portable across same-architecture hosts.

The provisioner **resolves the protect list itself** — the default gateway and
the control plane, plus the agent's own NIC. This is a safety control, not a
nicety: on a flat subnet those are the only devices an agent can see, so without
it the first device an operator could sever is the box's route to the fleet.

### Victim

Nothing of ours to install — it only needs a service the agent can reach, so
there is a real flow to interrupt. Make it durable, because
[`device-drop-proof.sh`](../../scripts/e2e/device-drop-proof.sh) asserts the
agent can reach it *before* enforcement; an ad-hoc process that dies makes the
proof fail at its baseline rather than at the thing under test:

```bash
ssh victim-host 'sudo tee /etc/systemd/system/victim-http.service >/dev/null <<UNIT
[Unit]
Description=victim device HTTP service (device-choke drop target)
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 -m http.server 8000 --bind 0.0.0.0
Restart=always

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl enable --now victim-http'
```

## 5. Verify

```bash
./scripts/e2e/all.sh          # reads .deploy-build/e2e.env
```

Five suites: host enforcement posture, the single-tenant engine, both tenants
multi-tenant, and the kernel drop proof. It exits non-zero on failure, so it
drops straight into CI.

Posture runs **first**. The other suites all assert that enforcement happens
when an operator asks for it; none of them would notice a Tetragon policy
killing processes with no operator involved at all. If the declared posture is
a lie, the rest of the results describe the wrong system.

The console reports the same thing live, so this is not only a test-time check.
`/api/choke/state` carries a `kernel` block — `diverged` is true when the engine
is detect-only while some agent has a kernel policy armed, and `diverged_agents`
names them. It is fed by the agent asking Tetragon directly on each heartbeat,
never by reading policy files, because a file edited but not reloaded still runs
its old version and a policy deleted at runtime returns on the next restart.
`agents_reporting` vs `agents_total` matters: an agent that reports nothing is
not a clean agent, it is an unknown one.

The proof that matters is
[`device-drop-proof.sh`](../../scripts/e2e/device-drop-proof.sh): an operator
severs a device from the console, and a request from the agent that worked a
second earlier stops — with nothing changed on the victim, only a drop rule in
the agent's kernel. Then release, and it resumes.

## 6. Traps

**Package management vs. enforcement.** Tetragon's `matchBinaries` matches the
*executable*, so for a `#!/usr/bin/perl` script the executable is `/usr/bin/perl`
— listing the script's own path in an allow-list has **no effect**. Package
maintainer scripts run through `debconf` (a perl script), so an enforcing
credential-read policy SIGKILLs them mid-configure, leaving packages in `iF`/`iU`
and blocking all further `apt`. Driven by `unattended-upgrades` on a timer, it
degrades a fleet silently over days. This is why
`policies/override-credential-read.yaml` reports rather than kills, and
why enforcement for that signal belongs to the engine's choke gateway (which
matches the process it scored and honours its own critical-binary list).

**`followChildren` does not rescue it.** The obvious repair — exempt anything
descended from `dpkg`/`apt` instead of naming interpreters — was measured on
Tetragon v1.6.1 and does not work: with `NotIn` a descendant of a listed binary
was still killed, and with `In` a descendant was not matched. The policy loads
reporting `added` with **no warning**, so the flag is a silent no-op, which
reads as a working control. It is also structurally wrong for this policy even
where supported: the allow-list contains `systemd` (PID 1 — every process is
its descendant, so nothing would match) and `sshd` (which would exempt every
interactive session). There is no correct kernel-level formulation here.

**`policy-mode: monitor` is the control that makes this safe.** Every policy in
`policies/` declares it, and under it Tetragon suppresses enforcing actions
(`Sigkill`, `Override`, `Signal`) in the kernel regardless of what the selectors
say, while leaving `Post` untouched — verified both halves on v1.6.1: a `Sigkill`
policy returned exit 0 with the option and 137 without; `Post` delivery was
identical either way. Prefer it to `tetra tracingpolicy set-mode`, which is
imperative and silently reverts on restart. Tetragon reports the mode in
`tracingpolicy list` and over gRPC, which is what makes host posture reportable
rather than assumed.

**A policy in `enforce/` is not evidence that it enforces.**
`sever-pipe-to-shell.yaml` shipped `Sigkill` for `curl|sh`, was loaded on every
host, and never fired: at `execve` the calling process is the shell, not curl,
so `matchBinaries In [curl,wget]` cannot match — and `| sh` is a shell
construct that never appears in curl's argv. It was removed rather than fixed,
because the engine already scores the pattern from the exec chain
(`/bin/bash → /usr/bin/curl`, score 26) — which works for exactly the reason the
selector cannot: it sees the parent's argv. Posture is now asserted by
[`host-posture.sh`](../../scripts/e2e/host-posture.sh) rather than assumed.

**Deleting a policy from Tetragon does not remove it.** `tetra tracingpolicy
delete` unloads the running copy, but anything left in a source directory
(`/opt/ebpf-soc/policies/`, `/var/lib/ebpf-engine/policies/`, or the container's
`/etc/tetragon/tetragon.tp.d/`) loads again on the next restart. Purge all of
them, then restart Tetragon and re-list to confirm — and give the daemon time
to finish loading before reading the list, or a mid-load snapshot looks like
policies went missing.

**`tetra tracingpolicy add` is create-only.** A policy whose *content* changed
keeps running the version loaded when Tetragon started. The provisioners delete
before adding for exactly this reason; anything hand-rolled must do the same or
policy changes deploy and do nothing.

**Changing `TARGET_HOST` requires a redeploy**, not just a DNS change. The OIDC
issuer and the Keycloak client's redirect URIs are baked at provision time. The
provisioner re-asserts them on every run; a console that serves fine but answers
the login page with `400 Invalid parameter: redirect_uri` is a stale client
registration.

**Device and process planes arm independently.** Arming one must never arm the
other — a device `sever` is a reversible drop rule, a process `sever` is a
`SIGKILL`.

**Device state reaches the console only on the agent heartbeat (~30 s).** Any
check asserting a device state change must clear a full interval, or a real
change reads as a miss.

## 7. Credentials

Written to `.deploy-build/credentials-<TARGET_HOST>.txt` on every deploy
(gitignored) and reused across redeploys — the provisioner reads back existing
passwords rather than minting new ones, so redeploying does not invalidate what
an operator wrote down.

| Surface | URL |
|---------|-----|
| Console (per-tenant analysts, cross-tenant `msoc`) | `https://<console-host>/` |
| Platform admin (Keycloak: realms, users, roles) | `https://<console-host>/admin/` |
| Single-tenant engine | `https://<engine-host>/` |

Rotate by deleting the user's line from `/etc/ebpf-soc/console-users.env` (or
`/etc/ebpf-engine/engine.yaml` for the engine) and redeploying.
