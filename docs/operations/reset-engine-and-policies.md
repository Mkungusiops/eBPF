# Reset engine and policies

Wipe the events database, bring the engine back up cleanly, and mute the noisy
MOTD policies while you prep. Useful before a live demo, so you start from a
single clean chain instead of a flood of Ubuntu-login noise.

## Pick your host

Every command below runs **on the engine host**. Set a prefix once and paste the
rest verbatim:

```bash
# OrbStack (the local estate — `make deploy-local`)
run() { orb -m ebpf-engine sudo bash -c "$*"; }

# A remote server
run() { ssh user@host sudo bash -c "$*"; }

# Multipass (legacy local VMs)
run() { multipass exec ebpf -- sudo bash -c "$*"; }
```

## Wipe the DB and restart (clean slate)

The normal case. A provisioned host already has a permanent `ebpf-engine` unit
with its config at `/etc/ebpf-engine/engine.yaml`, so the service keeps its
settings across the wipe.

```bash
run 'systemctl stop ebpf-engine'
run 'rm -f /var/lib/ebpf-engine/events.db'
run 'systemctl start ebpf-engine'
```

`events.db` is recreated empty on boot. This also clears the hash-chained
`decisions` audit table — expected for a fresh demo, but **never do it on a host
whose audit trail matters**.

To reset the host entirely instead, re-run the provisioner: `./scripts/deploy/
single-tenant-orbstack.sh` locally, or `SSH_HOST=user@host ./scripts/deploy/
single-tenant-ubuntu.sh` for a server.

## Disable / re-enable noisy policies

`sensitive-file-access` fires on every Ubuntu MOTD invocation, so each `exec`
into the VM generates a flood of alerts and can push the sshd chain up the choke
ladder. This acts on **Tetragon**, independently of the engine's mode — which is
the same independence that makes [enforcement-traps.md](enforcement-traps.md)
trap 2 possible.

```bash
# Disable
run 'docker exec tetragon tetra tracingpolicy disable sensitive-file-access'
run 'docker exec tetragon tetra tracingpolicy disable privilege-escalation'

# Re-enable
run 'docker exec tetragon tetra tracingpolicy enable sensitive-file-access'
run 'docker exec tetragon tetra tracingpolicy enable privilege-escalation'
```

## Recommended demo-prep sequence

```bash
# 1. Mute noisy policies while we set up
run 'docker exec tetragon tetra tracingpolicy disable sensitive-file-access'
run 'docker exec tetragon tetra tracingpolicy disable privilege-escalation'

# 2. Wipe DB and restart engine
run 'systemctl stop ebpf-engine'
run 'rm -f /var/lib/ebpf-engine/events.db'
run 'systemctl start ebpf-engine'

# 3. (browser) hard-refresh the dashboard — should show 0 critical/high/medium

# 4. Re-enable policies right before the demo
run 'docker exec tetragon tetra tracingpolicy enable sensitive-file-access'
run 'docker exec tetragon tetra tracingpolicy enable privilege-escalation'

# 5. Fire an attack to populate live alerts
run 'bash /var/lib/ebpf-engine/attacks/02-credential-theft.sh'
```

> **Demo in detect-only.** A provisioned engine starts detect-only unless it was
> given `-enforce`; decisions are audited but nothing is choked. Turning
> enforcement on for a demo will sever `sudo` on that host — read
> [enforcement-traps.md](enforcement-traps.md) first.

## Status & log inspection

```bash
run 'systemctl is-active ebpf-engine'
run 'systemctl status ebpf-engine --no-pager'
run 'ss -tlnp | grep 8090'          # 8080 for a hand-run engine
run 'journalctl -u ebpf-engine -n 50 --no-pager'
```

## Related

- [enforcement-traps.md](enforcement-traps.md) — before you enable enforcement
- [backup-and-restore.md](backup-and-restore.md) — when you need the data back rather than gone
- [../deployment/orbstack-local-mirror.md](../deployment/orbstack-local-mirror.md) — the local estate (`make deploy-local`)
- [../deployment/ubuntu-server.md](../deployment/ubuntu-server.md) — the engine's flag set and a permanent install
