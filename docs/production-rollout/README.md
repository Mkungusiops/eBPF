# Production Rollout for Device Choke Gateways

This runbook fills the gap between the single-gateway deployment guides in
[`docs/deployment/`](../deployment/) and a production rollout across many
sites or gateway boxes.

Use it with:

- [`deployment/network-choke-gateway.md`](../deployment/network-choke-gateway.md)
  for the inline 2-NIC device choke install.
- [`deployment/ubuntu-server.md`](../deployment/ubuntu-server.md) for the
  systemd/nginx/TLS server deployment path.
- [`reference/chokectl.md`](../reference/chokectl.md) for fleet CLI operations.

The current fleet implementation supports many gateways by listing peers in a
`fleet_hosts` file and fanning out server-side API calls. This guide adds the
missing operational pieces: hardware standards, provisioning, enrollment,
secrets, monitoring, rollout gates, rollback, and day-2 ownership.

## Folder Name Options

Suggested names considered for this section:

| Folder | Fit |
|---|---|
| `production-rollout` | Recommended. Covers provisioning, deployment, security, and operations. |
| `mass-deployment` | Clear, but narrower and more install-focused. |
| `fleet-rollout` | Good for multi-gateway control, less clear for site install work. |
| `gateway-operations` | Good for day-2 operations, less clear for first rollout. |
| `deployment-at-scale` | Accurate, but longer than needed. |

## Rollout Model

Mass use means deploying a standard inline gateway at each controlled network
edge, then enrolling each gateway into the fleet control plane.

The expected production shape is:

1. Build or select a supported hardware SKU.
2. Install a standard Ubuntu/Debian image with kernel support for TCX.
3. Provision the engine, `devchoke.o`, systemd unit, config, TLS, and admin
   access.
4. Place the gateway inline between the upstream router and the downstream
   managed-device switch.
5. Start in detect-only or device `dry_run`.
6. Verify topology, device discovery, protected MACs, and audit behavior.
7. Enroll the gateway into fleet.
8. Move from pilot to staged enforcement.
9. Monitor, upgrade, rotate secrets, and maintain audit retention.

## Hardware Standard

Do not roll out arbitrary machines. Standardize one or more approved gateway
SKUs and certify them before field deployment.

Minimum hardware criteria:

| Item | Requirement |
|---|---|
| CPU | x86_64 or arm64 Linux-compatible CPU with enough headroom for bridge forwarding and BPF map operations. |
| RAM | 2 GB minimum for small sites; 4 GB or more recommended for production gateways. |
| Disk | 16 GB minimum; 32 GB or more recommended if local audit retention is enabled. |
| NICs | Two physical NICs minimum: one uplink, one downstream LAN. Avoid USB NICs for production. |
| Kernel | Linux kernel 6.6 or newer for TCX attach support. |
| Firmware | Secure boot policy documented; BIOS/UEFI access controlled. |
| Power | UPS-backed where the inline gateway is a critical network path. |

Recommended certification gates for a hardware SKU:

- `make netns-smoke` passes on the target kernel.
- `devchoke.o` compiles against the installed kernel headers.
- `tc filter show dev <iface> ingress` shows the attached program on both
  bridge slave ports.
- `/api/choke/device-state` reports `plane=tc`, `links_attached > 0`, and
  increasing `frames_seen`.
- A test device can be throttled, severed, and thawed without affecting a
  bystander device.
- Sustained site traffic does not exceed CPU, memory, disk, or NIC headroom.
- Re-cabling bypass procedure restores connectivity without software changes.

## Site Survey

Complete a site survey before shipping hardware.

Required fields:

| Field | Example |
|---|---|
| Site ID | `nbo-branch-01` |
| Gateway ID | `gw-nbo-branch-01-a` |
| Upstream handoff | ISP router LAN port 1 |
| Downstream handoff | Managed switch uplink port 48 |
| VLANs | `untagged`, `10`, `20`, or `none` |
| DHCP/DNS location | ISP router, firewall, Windows DC, or local resolver |
| Expected managed devices | Count by type: laptops, cameras, POS, printers, IoT |
| Bypass plan | Direct cable from downstream switch to ISP router |
| Maintenance window | Approved install window and rollback deadline |
| Critical MACs | Router, DHCP/DNS, operator laptop, monitoring probe, printers |

Topology validation checklist:

- Managed devices must sit behind the downstream switch connected through the
  gateway.
- Devices on the ISP router's own WiFi or switch ports bypass the gateway and
  cannot be choked by MAC.
- If devices sit behind another router, the gateway may only see that router's
  MAC, not each client device.
- Bridge slave interfaces, not the bridge master, must be listed in
  `devchoke_ifaces`.
- VLAN handling must be tested before enforcement. Do not assume every site has
  the same tagging behavior.

## Golden Image and Provisioning

Use repeatable provisioning. Avoid hand-built gateways.

Recommended image contents:

- Ubuntu 22.04/24.04 LTS or approved Debian release.
- Kernel 6.6 or newer.
- `git`, `curl`, `make`, `jq`, `build-essential`, `clang`, `llvm`,
  `libbpf-dev`, matching `linux-headers`, `iproute2`, `bpftool`.
- `ebpf-engine` binary installed at `/opt/ebpf-engine/engine`.
- `devchoke.o` installed at `/opt/ebpf-engine/bpf/devchoke.o`.
- Systemd unit installed and disabled by default until site config is present.
- Host firewall rules for management access.
- Log rotation for engine logs.
- Time sync enabled.
- SSH locked down to approved keys or certificate auth.

Provisioning should be one of:

- cloud-init for VM or appliance images.
- Ansible for bare-metal gateways.
- PXE or image flashing for repeated field installs.
- A signed tarball plus a small bootstrap script for constrained environments.

Minimum provisioning flow:

```text
1. Install OS and baseline packages.
2. Set hostname to the gateway ID.
3. Install the engine binary and BPF object.
4. Write `/etc/ebpf-engine/engine.yaml` from a site template.
5. Install TLS material or join the gateway to the management plane.
6. Install the systemd unit.
7. Start in dry-run or detect-only.
8. Run local acceptance tests.
9. Register the gateway in fleet.
10. Mark the site ready for enforcement approval.
```

## Configuration Management

Treat gateway configuration as inventory-driven data.

Maintain an inventory record per gateway:

```yaml
gateway_id: gw-nbo-branch-01-a
site_id: nbo-branch-01
mgmt_url: https://gw-nbo-branch-01.example.net
role: device-choke-gateway
engine_version: 2026.06.29-1
kernel_required: ">=6.6"
uplink_iface: eth0
lan_iface: eth1
bridge: br0
devchoke_ifaces: "eth0,eth1"
initial_dry_run: true
fleet_group: east-africa-branches
protected_macs:
  - mac: "aa:bb:cc:11:22:33"
    label: "ISP router"
  - mac: "aa:bb:cc:44:55:66"
    label: "DHCP/DNS"
  - mac: "aa:bb:cc:77:88:99"
    label: "operator laptop"
```

Template these keys into `/etc/ebpf-engine/engine.yaml`:

```yaml
http: "127.0.0.1:8080"
db: "/var/lib/ebpf-engine/events.db"
devchoke_obj: "/opt/ebpf-engine/bpf/devchoke.o"
devchoke_ifaces: "eth0,eth1"
devchoke_protect: "aa:bb:cc:11:22:33,aa:bb:cc:44:55:66,aa:bb:cc:77:88:99"
dry_run: true
user: "admin"
pass: "CHANGE_ME"
```

Rules:

- `devchoke_protect` must be populated before enabling enforcement.
- `dry_run` should default to `true` for first boot.
- Configuration changes should be reviewed and auditable.
- Avoid editing production gateway config manually except during break-glass
  recovery.

## Fleet Enrollment

Each gateway must be enrolled into the fleet control plane before it is treated
as production-ready.

Enrollment steps:

1. Confirm the gateway has a stable management URL.
2. Confirm login works and `/api/whoami` returns the expected host identity.
3. Confirm `/api/choke/device-state` reports the expected data plane state.
4. Add the gateway to the fleet hosts source of truth.
5. Sync or reload the `fleet_hosts` file on the controller.
6. Verify `/api/fleet/hosts` lists the new gateway.
7. Verify `/api/fleet/devices` returns the gateway's device inventory.
8. Run a no-op or dry-run action before any enforcing action.

Example `fleet.hosts`:

```text
# one "<name> <url>" per line
nbo-branch-01 https://gw-nbo-branch-01.example.net
nbo-branch-02 https://gw-nbo-branch-02.example.net
msa-branch-01 https://gw-msa-branch-01.example.net
```

Current implementation note: fleet fan-out uses the configured admin
credential to log into peers. For production, use unique per-environment
credentials at minimum, rotate them regularly, and plan a move to stronger
machine-to-machine auth before broad external exposure.

## Secrets and Access

Do not reuse demo credentials in production.

Required secret handling:

- Unique admin password per environment, and preferably per gateway.
- SSH access via named keys or SSH certificates, not shared passwords.
- TLS certificates from an internal CA or public CA depending on exposure.
- Secrets stored in a vault or password manager, not in git.
- Rotation schedule for gateway admin credentials and SSH keys.
- Emergency break-glass account with documented approval and audit.

Access controls:

- Restrict dashboard access to operator networks, VPN, or a bastion.
- Avoid exposing gateway management URLs directly to the public internet.
- Use nginx/TLS in front of the engine for browser access.
- Keep `/api/*` behind the same auth and network boundary as the UI.
- Log operator actions and retain audit history.

## Rollout Stages

Use staged rollout. Do not enable enforcement fleet-wide on first install.

| Stage | Scope | Exit criteria |
|---|---|---|
| Lab | Netns and bench hardware | `make netns-smoke`, bridge attach, local API tests pass. |
| Pilot | 1 site, non-critical devices | Device inventory stable, protected MACs verified, no bypass surprises. |
| Limited production | 3-5 sites | Monitoring active, rollback rehearsed, operator runbook tested. |
| Regional rollout | One region or business unit | Upgrade/rollback automation proven; support team trained. |
| General availability | All approved sites | SLOs met, audit retention/backup live, security review complete. |

Default enforcement posture by stage:

| Stage | Device posture |
|---|---|
| Lab | Enforcing allowed on test devices only. |
| Pilot | Start `dry_run: true`; enable enforcement only for controlled tests. |
| Limited production | Enforcing allowed after site acceptance. |
| Regional rollout | Enforcing by default only for approved device classes or incidents. |
| General availability | Enforcing based on policy and operator approval. |

## Site Acceptance Test

Run this checklist before marking a gateway production-ready.

Install validation:

- Hostname matches gateway inventory.
- Kernel version is 6.6 or newer.
- Engine service is enabled and running.
- `/api/version` reports the expected build.
- `/api/choke/device-state` is reachable after login.
- `plane=tc`, `links_attached > 0`, and `frames_seen` increases under traffic.
- `/devices` loads and shows discovered devices.
- Protected MACs are present in config and refused for destructive actions.

Network validation:

- Managed test device appears in `/api/choke/devices`.
- Test device flow expansion shows active destinations.
- `throttle` changes behavior without disconnecting critical services.
- `sever` blocks the test device only.
- `device-thaw` restores the test device.
- Bystander device remains unaffected.
- Physical bypass restores site connectivity.

Fleet validation:

- Gateway appears in `/api/fleet/hosts`.
- Gateway contributes rows to `/api/fleet/devices`.
- Fleet health page shows expected mode and reachability.
- A dry-run or low-risk fleet action returns a successful per-host response.

Approval:

- Site owner signs off.
- Network owner signs off.
- Security/operator owner signs off.
- Rollback deadline and contacts are recorded.

## Monitoring and Alerts

At minimum, collect these signals per gateway:

| Signal | Alert condition |
|---|---|
| Engine service | Service down or restart loop. |
| Gateway reachability | Management URL unreachable. |
| Data plane | `plane=noop` on an enforcing gateway. |
| Attach count | `links_attached=0` or unexpected drop from previous value. |
| Forwarded frames | `frames_seen=0` while links are attached and site traffic exists. |
| Kill-switch | `kill_switched=true` outside approved maintenance. |
| Mode | Unexpected transition between detect-only and enforcing. |
| Device inventory | Sudden large drop or spike in known devices. |
| Audit chain | `/api/verify-chain` reports failure. |
| Disk | Database or logs approach capacity. |
| CPU/memory | Sustained high utilization. |
| Time sync | Clock drift affects audit ordering. |

Fleet-level views should include:

- gateways online/offline.
- gateways in dry-run vs enforcing.
- gateways with `plane=noop`.
- active chokes by action.
- recent device decisions.
- sites missing recent check-ins.

## Upgrade and Rollback

Upgrades must be staged.

Upgrade flow:

```text
1. Build and sign or checksum the release artifact.
2. Deploy to lab gateway.
3. Run netns and bridge smoke tests.
4. Deploy to one pilot gateway.
5. Confirm version, service health, data plane, and device discovery.
6. Deploy to limited production batch.
7. Watch monitoring for one maintenance window.
8. Continue batch rollout.
```

Rollback requirements:

- Keep the previous `ebpf-engine` binary on disk.
- Keep the previous `devchoke.o` on disk.
- Keep the previous `engine.yaml`.
- Know whether rollback needs a service restart or full gateway reboot.
- Confirm `device-kill-switch {"on":true}` works before high-risk changes.
- Rehearse rollback before regional rollout.

Example artifact layout:

```text
/opt/ebpf-engine/releases/2026.06.29-1/engine
/opt/ebpf-engine/releases/2026.06.29-1/devchoke.o
/opt/ebpf-engine/current -> /opt/ebpf-engine/releases/2026.06.29-1
```

## Emergency Controls

Emergency stop order:

1. Engage fleet or gateway kill-switch.
2. Verify `/api/choke/device-state` shows `kill_switched=true`.
3. Thaw affected MACs if needed.
4. Confirm critical devices recover.
5. If the site is still impaired, physically bypass the gateway.
6. Open an incident record and preserve logs.

Do not clear the kill-switch until:

- root cause is identified.
- protected MAC list is corrected if relevant.
- affected devices are confirmed reachable.
- site owner approves re-enforcement.

## Device Inventory

MAC-only identity is enough for enforcement, but not enough for operations.

Maintain a device inventory that maps:

| Field | Purpose |
|---|---|
| MAC | Enforcement key. |
| Hostname | Operator-friendly identity. |
| Owner | Accountability and contact. |
| Site/location | Dispatch and impact analysis. |
| Device type | Laptop, printer, camera, POS, IoT, infrastructure. |
| Criticality | Whether quarantine/sever needs extra approval. |
| Protected | Whether MAC belongs in `devchoke_protect`. |
| Last seen | Staleness and asset drift. |
| Notes | Known exceptions or maintenance windows. |

Unknown devices should default to observation until classified unless there is
an active incident.

## Audit Retention and Backup

Define retention before rollout.

Minimum policy:

- Keep local audit data for enough time to cover incident response needs.
- Back up gateway databases or forward audit records centrally.
- Monitor database size.
- Periodically run `/api/verify-chain`.
- Document who may access device flow and decision history.
- Define deletion and export procedure for site decommissioning.

If SQLite is used locally, treat it as an edge cache for production scale. For
long retention or cross-site reporting, forward audit events to a central store.

## Privacy and Compliance

The device gateway can expose device flow metadata: destination IP, port,
protocol, packet counts, and byte counts. This is operationally useful but can
be sensitive.

Production deployments should document:

- what data is collected.
- who can view it.
- how long it is retained.
- whether it leaves the site.
- how operator actions are audited.
- what approvals are needed to quarantine or sever a device.

## Operator Runbook

Daily checks:

- Review fleet reachability.
- Review gateways not in expected mode.
- Review gateways with `plane=noop`, `links=0`, or stale `frames_seen`.
- Review active chokes and scheduled reverts.
- Review audit chain health.

Before choking a device:

1. Confirm the MAC maps to the intended asset.
2. Expand device flows and review current destinations.
3. Check whether the device is protected or critical.
4. Choose the least disruptive action: `throttle`, `tarpit`, `quarantine`,
   then `sever`.
5. Enter a concrete reason.
6. Use `revert_after_seconds` for temporary containment.
7. Verify impact and recovery path.

After choking:

- Confirm the decision appears in audit history.
- Watch for collateral impact.
- Notify the owner or incident channel.
- Thaw when containment is no longer required.

## Support Workflow

When a site reports an issue, collect:

- gateway ID and site ID.
- current `/api/choke/device-state`.
- service status and recent logs.
- `tc filter show dev <uplink> ingress` and `<lan> ingress`.
- current `engine.yaml` minus secrets.
- affected MAC/IP/hostname.
- whether physical bypass resolves the issue.
- last upgrade or config change.

Common fixes:

| Symptom | Likely cause |
|---|---|
| `/devices` shows `plane=noop` | Missing `devchoke_obj`, missing `devchoke_ifaces`, failed BPF attach, or single-NIC host. |
| `links_attached=0` | Wrong interface names or attaching to bridge master instead of slaves. |
| `frames_seen=0` | Traffic bypasses gateway, wrong bridge placement, or no site traffic. |
| Critical device blocked | Missing protected MAC or accidental fleet action. Engage kill-switch and thaw. |
| Devices absent | Gateway not inline, neighbor discovery quiet, DHCP traffic not visible, or downstream router hides client MACs. |
| Fleet action partial failure | Peer unreachable, auth mismatch, TLS failure, or stale `fleet_hosts`. |

## Packaging Backlog

For a mature mass rollout, add these project artifacts:

- `.deb` or `.rpm` package for `ebpf-engine`.
- Versioned package for `devchoke.o` tied to supported kernels.
- Ansible role for gateway provisioning.
- cloud-init template for first boot.
- inventory schema and validation script.
- fleet enrollment command.
- central metrics exporter or documented scrape endpoint.
- backup/restore command for local audit data.
- release promotion checklist.

