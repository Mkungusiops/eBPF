# chokectl — fleet CLI for the eBPF Choke Gateway

`scripts/chokectl` is a terminal tool for driving N hosts (each running
the engine + Tetragon) over HTTP. It reads a hosts file, fans the same
operation out in parallel to every host, and merges results into a
single table or download tree. Read-only commands are safe; write
commands hit every host unless `--host=NAME` restricts the scope.

The per-host web UIs at `http://<host>:8080/` and `/choke` are
unchanged — `chokectl` is the way to operate the **fleet** as a unit
without juggling 7 browser tabs.

> Tier 1 in [docs/architecture.md](architecture.md) — terminal only,
> no central web UI. Tier 2 (a fleet aggregator with a single SOC
> dashboard) is documented but not yet built.

---

## Quick start

```bash
# 1. populate the hosts file (one "name url" per line; # comments allowed)
cat > chokectl.hosts <<EOF
ebpf-1   http://10.0.1.11:8080
ebpf-2   http://10.0.1.12:8080
ebpf-3   http://10.0.1.13:8080
ebpf-4   http://10.0.1.14:8080
ebpf-5   http://10.0.1.15:8080
ebpf-6   http://10.0.1.16:8080
ebpf-7   http://10.0.1.17:8080
EOF

# 2. health check across the fleet
./scripts/chokectl status

# 3. ongoing ops — see the cookbook below
```

---

## Configuration

### Hosts file

`chokectl` reads `./chokectl.hosts` by default. Override with the
`--hosts=PATH` flag or the `CHOKECTL_HOSTS` env var. See
[`chokectl.hosts.example`](../chokectl.hosts.example) for the format.

```
# chokectl hosts file — one entry per line, # comments allowed.
# Format:  <name>  <base-url>
ebpf-1   http://192.168.252.3:8080
ebpf-2   http://10.0.1.12:8080  # optional trailing comment
```

### Auth

All hosts must accept the same admin credentials. Set via env vars:

```bash
export CHOKE_USER=admin
export CHOKE_PASS='your-strong-password-here'
```

Defaults are `admin` / `ebpf-soc-demo` (the development credentials).
**Change these in production.**

`chokectl` caches the session cookie per-host in `/tmp/chokectl-cookies-<name>`
and re-uses it across invocations. The engine has a 10/min per-IP rate
limit on `/api/login`, and sessions live 24h server-side, so caching
keeps you under the limit even when running `chokectl` in tight loops.

### Flags

```
--hosts=PATH       override the hosts file
--host=NAME        restrict to a single host (writes only)
--timeout=SECS     per-request timeout (default 5)
-h | --help        show help
```

### Exit codes

```
0   all hosts succeeded
1   one or more hosts unreachable / errored (others may still be ok)
3   bad usage / bad config / no hosts matched
```

---

## Subcommand reference

### Read-only

| Command | What it does |
|---|---|
| `status`            | One-row-per-host table of mode, kill-switch, thresholds, tracked-process count, state-counts, audit-chain status |
| `cgroups`           | Per-host count of PIDs in each `choke-throttled / choke-tarpit / choke-quarantined` kernel cgroup |
| `decisions [N]`     | Last `N` (default 50) decisions merged across all hosts, newest first |
| `alerts [N]`        | Last `N` (default 20) alerts merged across all hosts, newest first |
| `snapshot [DIR]`    | Download `/api/choke/forensic-snapshot` from each host into `DIR/<host>.json` (default `./snapshots/<utc-stamp>/`) |

### Control plane (writes)

> Write commands hit every host in the file unless `--host=NAME` is set.
> Each write is recorded as a hash-chained audit row on every target
> host, with `actor=admin` (or `$CHOKE_USER`).

| Command | What it does |
|---|---|
| `preset <name>`               | Apply a named posture: `containment` / `forensic` / `maintenance` / `default` |
| `thresholds T/Tp/Q/S`         | Set the four circuit thresholds (e.g. `20/50/120/200`) |
| `kill-switch on \| off`       | Toggle global enforcement bypass |
| `thaw`                        | Release the quarantined cgroup (un-freeze every paused process) |
| `jail HOST PID ACTION REASON` | Manual override on **one specific host**. Action: `throttle` / `tarpit` / `quarantine` / `sever` |

---

## Cookbook

### Daily operations

**Morning health check across all 7 hosts.**

```bash
./scripts/chokectl status
```

```
HOST         MODE           KILL   THRESHOLDS                 TRACKED COUNTS                     AUDIT
------------ -------------- ------ -------------------------- ------- -------------------------- ------
ebpf-1       enforcing      off    20/50/120/200              9       qua=5 tar=3 thr=1          ok·996
ebpf-2       enforcing      off    20/50/120/200              4       qua=2 tar=2                ok·412
ebpf-3       kill-switched  on     20/50/120/200              0                                  ok·150
…
```

**See what's been firing across the fleet in the last hour.**

```bash
./scripts/chokectl decisions 200
```

The output is a tab-separated table; pipe to `column -t -s$'\t'` for
fixed-width display, or to `grep` to focus on specific actions /
hosts / binaries.

```bash
./scripts/chokectl decisions 500 | grep sever
./scripts/chokectl decisions 500 | grep ebpf-3
./scripts/chokectl decisions 500 | grep /usr/bin/curl
```

**Merge alerts across the fleet for a SOC standup.**

```bash
./scripts/chokectl alerts 100 | head -30
```

### Incident response

**An incident just opened — switch the entire fleet into Containment
posture.**

```bash
./scripts/chokectl preset containment
```

This drops every host's thresholds to `1/3/8/60` so any chain crossing
the noise floor immediately gets choked. Each host records an audit row
linking the change to your operator account.

**Capture a forensic baseline before doing anything else.**

```bash
./scripts/chokectl snapshot ./incidents/$(date -u +%Y%m%dT%H%M%SZ)/
```

Each host dumps its full state — circuits, decisions (last 2000),
cgroups, BPF-map mirror, audit-chain verification, annotations, pending
reverts — into `./incidents/<stamp>/<host>.json`. Snapshots are
single-shot, can be diffed with `jq`, and are SIEM-friendly.

**One specific host is compromised — kill a known-bad PID.**

```bash
./scripts/chokectl jail ebpf-3 1574 sever "incident #2026-04-30 — compromised process"
```

**Wind down: restore safe defaults across the fleet.**

```bash
./scripts/chokectl preset default                          # thresholds 10/30/60/100, kill-switch off
./scripts/chokectl thresholds 20/50/120/200                # tune to fleet-specific safe values
```

### Maintenance windows

**Planned maintenance on all 7 — pause enforcement.**

```bash
./scripts/chokectl preset maintenance
```

This flips kill-switch on **and** raises every threshold above any
plausible chain score, so the gateway records what it sees but never
chokes anything. After maintenance:

```bash
./scripts/chokectl preset default
```

**Single-host pause for a planned upgrade.**

```bash
./scripts/chokectl --host=ebpf-3 kill-switch on
# … upgrade ebpf-3 …
./scripts/chokectl --host=ebpf-3 kill-switch off
```

### Tuning

**Roll new thresholds across the fleet, with rollback if anything goes
wrong.**

```bash
# capture pre-change state
./scripts/chokectl status > /tmp/before.txt

# apply
./scripts/chokectl thresholds 25/60/140/220

# verify each host accepted the change
./scripts/chokectl status

# if something looks wrong, roll back
./scripts/chokectl thresholds 20/50/120/200
```

The thresholds API validates strict ascending order (`throttle <
tarpit < quarantine < sever`) and rejects malformed values per host —
you'll see a red error line for any host that refused.

**Try a posture on one host first, then promote fleet-wide.**

```bash
./scripts/chokectl --host=ebpf-1 thresholds 30/70/150/240   # canary
# watch ebpf-1 for an hour
./scripts/chokectl --host=ebpf-1 status
./scripts/chokectl --host=ebpf-1 decisions 100
# happy → roll out
./scripts/chokectl thresholds 30/70/150/240
```

### Auditing

**Verify the audit chain on every host hasn't been tampered with.**

```bash
./scripts/chokectl status
```

The right-most column is `ok·N` (chain intact, N decisions) or
`BROKEN at id <X>` (silent tamper detected). Investigate any `BROKEN`
host immediately — the chain hash is computed from the prior row's
hash, so a missing or modified row breaks the link.

**Compare two snapshots to see what changed.**

```bash
./scripts/chokectl snapshot ./snap-a/
sleep 3600
./scripts/chokectl snapshot ./snap-b/

for h in ebpf-1 ebpf-2 ebpf-3; do
  echo "=== $h ==="
  diff <(jq -S '.counts, .thresholds, .kill_switch' snap-a/$h.json) \
       <(jq -S '.counts, .thresholds, .kill_switch' snap-b/$h.json)
done
```

**Pull the audit chain from one host for a compliance review.**

```bash
./scripts/chokectl --host=ebpf-2 snapshot ./compliance/2026-04/
jq '.decisions[]' compliance/2026-04/ebpf-2.json | head -100
```

### Targeted investigations

**Inspect what's currently being choked on every host.**

```bash
./scripts/chokectl cgroups
```

```
HOST          CGROUP_TIER_INHABITANTS
ebpf-1        throttled=0  tarpit=3  quarantined=5
ebpf-2        throttled=0  tarpit=0  quarantined=0
…
```

**Find every host that has a process in `quarantined` right now.**

```bash
./scripts/chokectl cgroups | awk '$0 ~ /quarantined=[1-9]/'
```

**Use the snapshot output to trace a chain across hosts.**

```bash
./scripts/chokectl snapshot ./trace/
jq -r '.circuits[] | select(.state=="quarantined") | "\(.exec_id) \(.binary)"' trace/*.json
```

---

## Makefile shortcuts

The Makefile wraps the most common chokectl operations and adds
multipass-aware deploy / attack targets that operate on a `VMS` list:

```bash
# multipass-side fanout (uses VMS env var)
make deploy-all VMS="ebpf-1 ebpf-2 ebpf-3 ebpf-4 ebpf-5 ebpf-6 ebpf-7"
make redeploy-all VMS="ebpf-1 ebpf-2"
make vm-status-all                                # one-line status per VM
make vm-attack-all SCRIPT=03-reverse-shell.sh     # fire same attack on all VMs

# chokectl wrappers (read from chokectl.hosts)
make fleet-status
make fleet-decisions N=100
make fleet-alerts N=50
make fleet-snapshot
```

`VMS` defaults to `$(VM)` so existing single-host targets like
`make deploy` keep working unchanged.

---

## Implementation notes

- **Parallel fanout.** Each subcommand forks one subshell per host,
  waits for all to finish, and prints results in stable hosts-file
  order regardless of completion order.
- **Cookie caching.** `/tmp/chokectl-cookies-<name>` per host. Re-used
  across invocations until invalidated by a `/api/whoami` 401 probe.
- **Robust quoting.** JSON bodies are passed to embedded Python via env
  vars, not heredocs, to avoid shell-redirection precedence bugs.
- **No third-party deps.** Just `bash`, `curl`, `python3` (which the
  rest of the engine's deploy scripts already require). Works on macOS
  and Linux.

---

## Troubleshooting

### `429 Too Many Requests` on login

The engine's anti-brute-force limiter caps `/api/login` at 10/minute
per IP. `chokectl` caches cookies to avoid this, but if you see 429:

```bash
# wait the limiter window out
sleep 70
# clear stale cookies and retry
rm -f /tmp/chokectl-cookies-*
./scripts/chokectl status
```

### `BROKEN at id N` in the audit column

The hash chain has a break. Pull the snapshot and inspect:

```bash
./scripts/chokectl --host=ebpf-3 snapshot ./broken/
jq '.audit_chain' broken/ebpf-3.json
# {"total": 1247, "ok": false, "bad_at": 412, "bad_field": "hash"}
```

Possible causes: someone wrote to the `decisions` SQLite table directly,
the database file was restored from a partial backup, or — in the worst
case — someone tried to silently delete an audit row. Treat as a
security-incident-of-the-incident.

### Host shows `unreachable`

- The engine isn't running (`systemctl status ebpf-engine` on the VM).
- The HTTP port is firewalled (the engine listens on `:8080`; check
  your security group / iptables).
- Wrong URL in the hosts file.
- The `--timeout=N` is too short — try `--timeout=10` if the host is
  far away.

### `unknown subcommand: …`

You're on an older `chokectl`. The script self-documents:

```bash
./scripts/chokectl --help
```

---

## Related

- [Architecture overview](architecture.md) — where the gateway fits in
  the engine
- [State ladder](state-ladder.md) — what each transition action means
- [Multipass deploy](run-on-multipass-vm.md) — single-host setup that
  the fleet is built on
- [`scripts/chokectl`](../scripts/chokectl) — the script itself
- [`chokectl.hosts.example`](../chokectl.hosts.example) — sample config
