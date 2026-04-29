# Reset Engine and Policies

Procedure to stop policy scoring on MOTD reads, wipe the events database, and restart the engine cleanly. Useful when you want a single, clean MOTD chain in the database.

## 1. Disable the policies

Disabling stops Tetragon from scoring MOTD reads (or any other matching events). Alternatively, stop Tetragon entirely.

```bash
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy disable sensitive-file-access
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy disable privilege-escalation
```

## 2. Wipe DB and restart the engine

One shot — produces only a single MOTD chain.

```bash
multipass exec ebpf -- sudo bash -c '
  pkill -f engine-linux-amd64
  rm -f /var/lib/ebpf-engine/events.db
  cd /home/ubuntu/ebpf-poc && nohup ./engine/engine-linux-amd64 \
    -tetragon  unix:///var/run/tetragon/tetragon.sock \
    -db        /var/lib/ebpf-engine/events.db \
    -http      :8080 \
    -user      admin -pass ebpf-soc-demo \
    -policies  /home/ubuntu/ebpf-poc/policies \
    -attacks   /home/ubuntu/ebpf-poc/attacks \
    -honeypots /var/lib/ebpf-engine/honey \
    > /var/log/ebpf-engine.log 2>&1 & disown
'
```

## 3. Re-enable the policies when ready

```bash
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy enable sensitive-file-access
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy enable privilege-escalation
```

## 4. Clean restart

```bash
multipass exec ebpf -- sudo bash -c 'cd /home/ubuntu/ebpf-poc && nohup ./engine/engine-linux-amd64 \
  -tetragon  unix:///var/run/tetragon/tetragon.sock \
  -db        /var/lib/ebpf-engine/events.db \
  -http      :8080 \
  -user      admin -pass ebpf-soc-demo \
  -policies  /home/ubuntu/ebpf-poc/policies \
  -attacks   /home/ubuntu/ebpf-poc/attacks \
  -honeypots /var/lib/ebpf-engine/honey \
  > /var/log/ebpf-engine.log 2>&1 & disown'
sleep 4
multipass exec ebpf -- pgrep -af engine-linux-amd64 | tail -1
multipass exec ebpf -- sudo ss -tlnp 2>/dev/null | grep 8080
```
## 5. Check engine status and tail log

```bash
multipass exec ebpf -- pgrep -af engine-linux-amd64; echo "---LISTEN---"; multipass exec ebpf -- sudo ss -tlnp 2>/dev/null | grep 8080 || echo "(nothing on 8080)"; echo "---LOG---"; multipass exec ebpf -- sudo tail -30 /var/log/ebpf-engine.log 2>&1
```
# Reset engine and policies

Procedure to wipe the events database and bring the engine back up cleanly,
plus a hardened start mode for live demos.

## Hardened start (systemd-run) — use this for board demos

`nohup ... & disown` works most of the time but has a race with the SSH
session that `multipass exec` opens — occasionally the new process gets
SIGHUP'd as the session closes. For demos, run the engine as a **transient
systemd unit** so it's fully detached from the shell that spawned it and
gets auto-restarted on crash.

```bash
multipass exec ebpf -- sudo systemctl stop ebpf-engine 2>/dev/null || true
multipass exec ebpf -- sudo systemctl reset-failed ebpf-engine 2>/dev/null || true
multipass exec ebpf -- sudo pkill -f engine-linux-amd64 || true
sleep 2
multipass exec ebpf -- sudo systemd-run \
  --unit=ebpf-engine \
  --description="eBPF SOC engine (transient, board demo)" \
  --property=Restart=always \
  --property=RestartSec=2 \
  --property=StandardOutput=append:/var/log/ebpf-engine.log \
  --property=StandardError=append:/var/log/ebpf-engine.log \
  --property=WorkingDirectory=/home/ubuntu/ebpf-poc \
  /home/ubuntu/ebpf-poc/engine/engine-linux-amd64 \
    -tetragon  unix:///var/run/tetragon/tetragon.sock \
    -db        /var/lib/ebpf-engine/events.db \
    -http      :8080 \
    -user      admin -pass ebpf-soc-demo \
    -policies  /home/ubuntu/ebpf-poc/policies \
    -attacks   /home/ubuntu/ebpf-poc/attacks \
    -honeypots /var/lib/ebpf-engine/honey
```

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

> Transient = no `/etc/systemd` files written; the unit vanishes when the
> VM reboots. Fine for demos; for permanent install, write a real unit
> file under `/etc/systemd/system/`.

## Wipe the DB and restart (clean slate)

Use this just before a demo to start from zero alerts.

```bash
multipass exec ebpf -- sudo systemctl stop ebpf-engine
multipass exec ebpf -- sudo rm -f /var/lib/ebpf-engine/events.db
multipass exec ebpf -- sudo systemctl start ebpf-engine
```

The systemd unit retains its config — no need to re-run the long
`systemd-run` command.

## Disable / re-enable noisy policies

`sensitive-file-access` fires on every Ubuntu MOTD invocation, which means
each `multipass exec` call generates a flood of alerts. Disable while
preparing the demo, re-enable when ready:

```bash
# Disable
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy disable sensitive-file-access
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy disable privilege-escalation

# Re-enable
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy enable sensitive-file-access
multipass exec ebpf -- sudo docker exec tetragon tetra tracingpolicy enable privilege-escalation
```

## Recommended demo prep sequence

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
multipass exec ebpf -- pgrep -af engine-linux-amd64
multipass exec ebpf -- sudo ss -tlnp | grep 8080
multipass exec ebpf -- sudo tail -30 /var/log/ebpf-engine.log
multipass exec ebpf -- sudo journalctl -u ebpf-engine -n 50 --no-pager
```

## Legacy `nohup` start (don't use for demos)

Kept for reference — works for one-off ops where you'll re-check
manually:

```bash
multipass exec ebpf -- sudo bash -c 'cd /home/ubuntu/ebpf-poc && nohup ./engine/engine-linux-amd64 \
  -tetragon  unix:///var/run/tetragon/tetragon.sock \
  -db        /var/lib/ebpf-engine/events.db \
  -http      :8080 \
  -user      admin -pass ebpf-soc-demo \
  -policies  /home/ubuntu/ebpf-poc/policies \
  -attacks   /home/ubuntu/ebpf-poc/attacks \
  -honeypots /var/lib/ebpf-engine/honey \
  > /var/log/ebpf-engine.log 2>&1 & disown'
```
