# Reset engine and policies

Procedure to wipe the events database and bring the engine back up cleanly,
plus how to mute the noisy MOTD policies while you prep — useful before a
live demo so you start from a single clean chain instead of a flood of
Ubuntu-login noise.

All commands target the Multipass `ebpf` VM; adapt the host/paths for a
real server.

## Hardened start (systemd-run) — use this for demos

`nohup ... & disown` works most of the time but races with the SSH session
that `multipass exec` opens — occasionally the new process gets SIGHUP'd as
the session closes. Run the engine as a **transient systemd unit** so it's
fully detached from the spawning shell and auto-restarts on crash. The first
three lines make the block idempotent (clear any prior/failed unit).

```bash
# Set a console password first. There is deliberately no default: the previously
# published one (admin/ebpf-soc-demo) has been removed from every deploy path,
# because following this runbook verbatim used to stand up a console on a
# credential printed in this repository.
export ENGINE_PASS="$(openssl rand -base64 24)"

multipass exec ebpf -- sudo systemctl stop ebpf-engine 2>/dev/null || true
multipass exec ebpf -- sudo systemctl reset-failed ebpf-engine 2>/dev/null || true
multipass exec ebpf -- sudo pkill -f engine-linux-amd64 || true
sleep 2
multipass exec ebpf -- sudo systemd-run \
  --unit=ebpf-engine \
  --description="eBPF Choke Gateway (transient)" \
  --property=Restart=always \
  --property=RestartSec=2 \
  --property=StandardOutput=append:/var/log/ebpf-engine.log \
  --property=StandardError=append:/var/log/ebpf-engine.log \
  --property=WorkingDirectory=/home/ubuntu/ebpf-poc \
  /home/ubuntu/ebpf-poc/engine-linux-amd64 \
    -tetragon       unix:///var/run/tetragon/tetragon.sock \
    -db             /var/lib/ebpf-engine/events.db \
    -http           :8080 \
    -user           admin -pass "$ENGINE_PASS" \
    -policies       /home/ubuntu/ebpf-poc/policies \
    -choke-policies /home/ubuntu/ebpf-poc/policies/choke \
    -attacks        /home/ubuntu/ebpf-poc/attacks \
    -honeypots      /var/lib/ebpf-engine/honey
```

> Omit `-enforce` (as above) to run **detect-only** — decisions are audited
> but nothing is choked. Add `-enforce -cgroup-root /sys/fs/cgroup` to
> actually throttle/freeze/SIGKILL. See the engine's `--help` or
> [../deployment/ubuntu-server.md](../deployment/ubuntu-server.md) for the flags.

Verify:

```bash
multipass exec ebpf -- sudo systemctl is-active ebpf-engine     # → active
multipass exec ebpf -- sudo systemctl status ebpf-engine --no-pager
multipass exec ebpf -- sudo ss -tlnp | grep 8080
```

Manage:

```bash
multipass exec ebpf -- sudo systemctl restart ebpf-engine       # restart
multipass exec ebpf -- sudo systemctl stop    ebpf-engine       # stop
multipass exec ebpf -- sudo journalctl -u ebpf-engine -f        # live logs
```

> Transient = no `/etc/systemd` files written; the unit vanishes on VM
> reboot. Fine for demos. For a permanent install use `deploy/install.sh`,
> which lays down a real unit under `/etc/systemd/system/` — see
> [../deployment/ubuntu-server.md](../deployment/ubuntu-server.md).

## Wipe the DB and restart (clean slate)

Use this just before a demo to start from zero alerts. The systemd unit
retains its config — no need to re-run the long `systemd-run` command.

```bash
multipass exec ebpf -- sudo systemctl stop ebpf-engine
multipass exec ebpf -- sudo rm -f /var/lib/ebpf-engine/events.db
multipass exec ebpf -- sudo systemctl start ebpf-engine
```

The `events.db` is recreated empty on boot. This also clears the
hash-chained `decisions` audit table — expected for a fresh demo, but never
do it on a host whose audit trail matters.

## Disable / re-enable noisy policies

`sensitive-file-access` fires on every Ubuntu MOTD invocation, so each
`multipass exec` call generates a flood of alerts (and can push the sshd
chain up the choke ladder). Disable while preparing, re-enable when ready.
This acts on **Tetragon**, independent of the engine:

```bash
# Disable
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy disable sensitive-file-access
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy disable privilege-escalation

# Re-enable
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy enable sensitive-file-access
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy enable privilege-escalation
```

## Recommended demo-prep sequence

```bash
# 1. Mute noisy policies while we set up
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy disable sensitive-file-access
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy disable privilege-escalation

# 2. Wipe DB and restart engine
multipass exec ebpf -- sudo systemctl stop ebpf-engine
multipass exec ebpf -- sudo rm -f /var/lib/ebpf-engine/events.db
multipass exec ebpf -- sudo systemctl start ebpf-engine

# 3. (browser) hard-refresh the dashboard — should show 0 critical/high/medium

# 4. Re-enable policies right before the demo
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy enable sensitive-file-access
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy enable privilege-escalation

# 5. Fire an attack to populate live alerts
multipass exec ebpf -- sudo bash /home/ubuntu/ebpf-poc/attacks/02-credential-theft.sh
```

## Status & log inspection

```bash
multipass exec ebpf -- sudo systemctl is-active ebpf-engine
multipass exec ebpf -- sudo ss -tlnp | grep 8080
multipass exec ebpf -- sudo tail -30 /var/log/ebpf-engine.log
multipass exec ebpf -- sudo journalctl -u ebpf-engine -n 50 --no-pager
```

## Related

- [../deployment/ubuntu-server.md](../deployment/ubuntu-server.md) —
  permanent systemd install + the choke-gateway flag set.
- [../deployment/orbstack-local-mirror.md](../deployment/orbstack-local-mirror.md)
  — the local OrbStack dev stack.
</content>
