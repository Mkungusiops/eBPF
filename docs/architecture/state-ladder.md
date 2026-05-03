# The State Ladder

The State Ladder is the visual representation of the Choke Gateway's
per-process state machine. Every process Tetragon observes climbs (or
stays at the bottom of) a five-rung ladder based on how suspicious its
behavior chain looks. Each rung is a stronger level of enforcement —
from "ignore" all the way to "SIGKILL".

The ladder appears in the left column of the Choke Gateway Console at
[`/choke`](http://localhost:8080/choke). Bars are width-normalized to
the busiest rung, so an empty system shows nothing and a fleet under
attack shows the danger rungs lit up.

## The five rungs

| Rung            | Default threshold | Kernel effect                                                               | Reversible? | Purpose                                                                                                |
|-----------------|-------------------|-----------------------------------------------------------------------------|-------------|--------------------------------------------------------------------------------------------------------|
| **pristine**    | < 20              | Nothing                                                                     | n/a         | Default — process behaves normally, no choke applied                                                   |
| **throttled**   | ≥ 20              | Moved to `choke-throttled` cgroup: 5% CPU, 200 max pids, low IO weight       | yes         | Gentle nudge — process still runs but its bandwidth to do harm is capped                               |
| **tarpit**      | ≥ 50              | Moved to `choke-tarpit` cgroup: 1% CPU, 50 max pids, lowest IO weight        | yes         | Severely degraded — useful for letting attackers reveal more of their playbook before pulling the plug |
| **quarantined** | ≥ 120             | Moved to `choke-quarantined` cgroup + `cgroup.freeze = 1`                    | yes (Thaw)  | Frozen mid-syscall — forensics-friendly: state is preserved, but the attacker can't progress           |
| **severed**     | ≥ 200             | `kill(pid, SIGKILL)` from userspace + bpfmap entry cleared                   | no          | Terminal — process is gone. PID-reuse safe                                                             |

> Defaults are baked into the systemd unit via the Makefile vars
> `THROTTLE_AT / TARPIT_AT / QUARANTINE_AT / SEVER_AT`. They are tuned
> so Ubuntu's sshd MOTD churn (which scores ~84) only reaches **tarpit**
> — never quarantine or sever. Override per-deploy with e.g.
> `make deploy SEVER_AT=60`.

The thresholds are also tunable at runtime — drag a handle in the
**Thresholds** panel of the console. The **Blast radius** preview shows
which currently-tracked processes would re-bucket under the proposed
thresholds before you commit.

## Two design principles you can read off the ladder

### 1. Monotonic

Once a process reaches a rung, it never slides back down automatically.
A brief score spike from a transient false positive doesn't get
auto-reversed; the audit trail captures "this process was suspicious,
here's what we did, here's what an operator changed."

The only ways back down are:

- **Operator override** in the Tracked Processes table or alert drill-in
  panel (records the actor + a mandatory reason in the audit chain).
- **Auto-revert** scheduled at choke time (e.g. "tarpit for 5 minutes
  then put back").
- **Forget** — drops the process from the gateway's live state machine
  entirely. The decision history in the audit chain is preserved.
- **Thaw** — a special operator action that clears `cgroup.freeze` on
  the entire `choke-quarantined` tier.

### 2. Graduated response, not binary block/allow

Most security tools are "allow or kill" — that's brittle (kills
legitimate noisy processes) and information-poor (kills the attacker
before you learn anything). The ladder lets each tier match the *cost*
of being wrong:

- **throttle** is reversible and cheap — even a false positive is
  recoverable in seconds.
- **sever** is unrecoverable — used only when the chain score is
  unambiguous.

The thresholds form a "speed bump → roadblock → freeze → kill" gradient.
You buy time at the lower tiers and pay a one-way ticket only at the top.

## Why the bars look the way they do

Bar widths are normalized — the longest bar = whichever rung has the
most processes right now. So if pristine has 412 and severed has 4, the
pristine bar is full-width and severed is a thin sliver. It's a
relative-density view, not a percent-of-total — operationally you
usually want to know "where are most of my processes?" and "is
anything in the danger rungs at all?", and the bar widths surface both
at a glance.

Colors match every other state badge in the console:

- **pristine** — slate (no event)
- **throttled** — blue
- **tarpit** — yellow
- **quarantined** — orange
- **severed** — red, with a pulsing glow

A process you find in the Tracked Processes table, the Decision Tape,
or an alert detail panel ties visually back to where it sits on the
ladder.

## The end-to-end flow

```
Tetragon kprobe fires
  → engine adds score to process tree node
  → checkAlert computes chain score (sum across ancestors, up to 10 hops)
  → dispatchGateway calls circuit.Evaluate(execID, pid, binary, score)
  → if score crossed a threshold, transition to that rung
  → enforcer chain runs:
       cgroupv2.Backend  → moves PID to the matching cgroup
                            (and cgroup.freeze=1 on quarantine)
       severerBackend    → SIGKILL on severed
  → audit row written to hash-chained decisions table
  → SSE broadcasts the decision to every connected console
  → State Ladder counts update in real time
```

When you see a count tick up by one, that's a real process whose chain
just crossed a threshold, got moved into the matching cgroup
(`/sys/fs/cgroup/choke-<tier>/cgroup.procs`), and is now subject to the
kernel's CPU/IO/pids caps — all in under a millisecond from the kprobe
firing.

## Operator surface

The ladder is the read side. The write side is everywhere:

| Surface                                  | What it does                                                              |
|------------------------------------------|---------------------------------------------------------------------------|
| **Tracked Processes** table (per-row)    | Hover → ↓ throttle, ≋ tarpit, ⌖ quarantine, ✕ sever                       |
| **Tracked Processes** bulk-action bar    | Multi-select → same actions across many processes in one round-trip       |
| **Alert drill-in** → 🔒 **Choke** button | Acts on the alert's leaf process. Auto-targeted, no PID copy-paste needed |
| 🔒 **Jail Process** button (top bar)     | Pick *any* live PID from `/proc`, even ones the gateway hasn't seen yet   |
| **Incident Response presets**            | Atomic posture switch: Containment / Forensic / Maintenance / Default     |
| **Manual override** modal                | Optional auto-revert (5 / 15 / 60 min) so "tarpit while I investigate" doesn't get forgotten |

Every write goes through `gateway.Manual()` (or `gateway.OnEvent()` for
score-driven transitions), which appends a hash-chained row to the
`decisions` table. `GET /api/verify-chain` re-walks the chain and
detects any tampering — including silent deletion of a row, since each
row's hash incorporates the prior row's hash.

## Related

- [`internal/choke/circuit/circuit.go`](../../engine/internal/choke/circuit/circuit.go)
  — the state machine itself (`Evaluate`, `Force`, `Snapshot`,
  thresholds).
- [`internal/choke/gateway.go`](../../engine/internal/choke/gateway.go)
  — wires circuit + enforcer + store + broadcast.
- [`internal/enforce/cgroupv2/`](../../engine/internal/enforce/cgroupv2/)
  — the cgroup v2 backend that physically moves PIDs and freezes them.
- [`internal/enforce/severer.go`](../../engine/internal/enforce/severer.go)
  — the SIGKILL actuator.
- [`internal/store/decisions.go`](../../engine/internal/store/decisions.go)
  — the hash-chained audit log.
- [`docs/architecture/overview.md`](overview.md)
  — broader system overview (where the gateway fits in the engine).
- [`docs/operations/run-on-multipass-vm.md`](../operations/run-on-multipass-vm.md)
  — deploy guide with the gateway flags spelled out.
