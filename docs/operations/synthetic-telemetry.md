# Synthetic telemetry and `DATA_MODE`

Where this platform's fake data comes from, how to switch it off, and the
production incident that made that switch matter.

> **If a console shows a "critical" posture that never changes, read this
> first.** A dial that reads the same on a quiet Sunday as during a breach is
> not measuring the estate.

---

## The incident (2026-08-19)

The multi-tenant console reported a security posture of **93–97 / 100
"critical"**, continuously, on both tenants. It had done so for as long as
anyone had looked.

The number was arithmetically correct. What produced it:

| | alerts in 30 min | weighted rate/hr | posture |
| --- | --- | --- | --- |
| `acme-corp` (multi-tenant) | 241 critical / 193 high / 270 medium | 5,554 | **97** |
| `adanian-internal` (multi-tenant) | 116 / 98 / 132 | 2,708 | **93** |
| single-tenant engine, same hour | 24 / 12 / 13 | 482 | 71 |
| single-tenant engine, idle | ~3 alerts per **hour** | ~48 | ~11 |

The multi-tenant estate had produced a dead-flat **~2,000 alerts/hour for 25
consecutive hours** — 1,975 to 2,172 every single hour. That is a metronome, not
an estate.

**The cause was `ebpf-activity.service`**, installed on every agent by
[`scripts/deploy/provision-agent-ssh.sh`](../../scripts/deploy/provision-agent-ssh.sh).
It runs `/opt/ebpf-soc/activity.sh`: a `while true` loop that every 20–45
seconds picks a random script from the attack catalogue, runs
`bash -c 'cat /etc/shadow; id'`, and opens connections to five hardcoded
"threat actor" IPs. It is a demo aid, and it is extremely good at its job.

The single-tenant engine has no such generator, which is the entire reason the
two deployments disagreed by a factor of several hundred. **Both consoles run
identical posture maths.**

## The deploy-contract bug underneath it

`DATA_MODE=none` is the documented switch for "no synthetic data", and
[`estate.sh`](../../scripts/deploy/estate.sh) had passed it faithfully to the
control plane on every deploy. It governed only the control plane's
**sim-agents** ([`lib.sh`](../../scripts/deploy/lib.sh)). The agent provisioner
never read it, and installed and started the activity generator
**unconditionally**.

So the estate's "no fake data" flag did not cover the estate's largest source of
fake data. Worse, `scripts/ci/verify-deploy.sh` asserted
*"no sim-agents running (DATA_MODE=none)"* — and **passed**, on every deploy,
while three synthetic attack generators ran beside the real agents.

That is the shape worth remembering: the check was real, the flag was real, and
the gap between what they covered and what an operator assumed they covered was
invisible from either side.

### The result, measured

Same estate, same posture maths, generator removed:

| Hour (UTC), 2026-08-19 | Alerts | State |
| --- | ---: | --- |
| 07:00 | 2,005 | generator running |
| 08:00 | 2,084 | generator running |
| 09:00 | 2,026 | generator running |
| 10:00 | 2,102 | generator running |
| 11:00 | 2,213 | generator removed at 11:17, plus a full `e2e/all.sh` run |
| 12:00 | 782 | four back-to-back redeploys |

**Be careful how you read the last row.** In the first quiet stretch after the
change — before the redeploys resumed — the estate produced **47 alerts in
fifteen minutes and zero in a ten-minute window.** The 782 that the 12:00 hour
finished on is the agents correctly observing four consecutive deployments:
`apt`, `docker`, `tar`, `systemctl`, service restarts. That is real activity, and
the sensors are supposed to see it.

So the honest claim is: **the flat ~2,000/hour floor is gone**, and what remains
tracks what is actually happening on the boxes. A settled baseline number needs a
genuinely quiet hour to measure, which this estate has not had since the change.

The telemetry pipeline was confirmed alive throughout — 509 events and 22 alerts
in the ten minutes after the change, newest timestamps seconds old. That check
matters: on this dial, "quiet" and "broken" produce the same number, and the
console cannot tell them apart for you.

### What changed

- `DATA_MODE` is now read by **both** agent provisioners (`-ssh`, `-orbstack`).
- `DATA_MODE=none` **actively removes** the generator — stop, disable, delete
  the unit *and* the script. Merely declining to install it would have left
  every already-provisioned host exactly as noisy, since the unit was enabled.
- `estate.sh` passes `DATA_MODE=none` to the agents as well as the control plane.
- `verify-deploy.sh` asserts per agent that `ebpf-activity` is **not** running,
  and fails the deploy with an explicit message if it is.

## Using it

```bash
# Real estate: every number on the console is a measurement.
DATA_MODE=none ./scripts/deploy/estate.sh          # the default for this estate

# Demo or screenshot estate: populate the console with plausible activity.
DATA_MODE=sim  make deploy-agent TENANT=… AGENT_HOST=…
```

| `DATA_MODE` | Control plane | Agents |
| --- | --- | --- |
| `none` | no sim-agents; disables leftovers | **no activity generator; removes leftovers** |
| `sim` (default) | one sim-agent per tenant | activity generator installed and started |
| `real` | real agent VMs per tenant | activity generator installed and started |

The agent provisioner prints a warning naming the consequence whenever it
installs the generator, because the cost of it is not obvious from the unit name
(`continuous real activity for the agent to observe`) and was not obvious to
anyone for months.

## The separate problem: dynamic range

Switching the generator off fixes *this* estate's reading. It does not fix the
underlying property, which is worth stating plainly.

[`web/src/features/soc/risk.ts`](../../web/src/features/soc/risk.ts) maps a
weighted alert rate onto 0–100 with a soft knee, `r / (r + 200)`. The half-scale
is **200 weighted alerts/hour**. This estate's *floor*, with the generator
running, was 5,554/hr — twenty-seven times half-scale. The curve is asymptotic
so nothing technically pegs, but at that rate the dial parks at 96–97 and a real
incident on top of it moves the needle by less than a point.

The 2026-08-05 fix removed a hard `min(100, …)` clamp that saturated at thirteen
criticals. It was the right fix and it did not, and could not, address a
sustained baseline: **a posture dial measures a rate against a chosen scale, and
any estate whose noise floor sits far above that scale will read "critical"
forever, honestly.**

The console does say so — `riskSaturated` fires at ten times half-scale and the
band prints *"sustained extreme alert rate · check for a noisy source"*. That
disclosure was correct and permanently on, which an operator reads the same way
as never.

**The durable answer is not a bigger constant.** It is to score against the
estate's own recent baseline, so the question becomes "is this worse than normal
here" rather than "is this worse than a number chosen in 2026". That is not
built; it is recorded here as the known limitation, and it is why the first
thing to check on a pinned dial is whether the estate is generating its own
alerts.

## Diagnosing it on a live estate

```bash
# Is a generator running?
ssh <agent-host> 'systemctl is-active ebpf-activity'

# What is the real alert rate, per hour, on the control plane?
ssh control-plane "sudo -u postgres psql -d ebpf_soc -c \"
  SELECT date_trunc('hour', to_timestamp(at/1e9)) AS hr, count(*)
  FROM telemetry WHERE kind='alert' AND at >= (extract(epoch from now())-86400)*1e9
  GROUP BY 1 ORDER BY 1 DESC LIMIT 25;\""
```

**A flat hourly count is the tell.** Real estates are bursty — they follow
working hours, deploys and attacks. A count that varies by less than 10% across
24 hours is a machine, and the machine is usually ours.

## Related

- [`../plan/threat-model.md`](../plan/threat-model.md)
- [`enforcement-traps.md`](enforcement-traps.md) — the other way this platform surprises its operator
- [`../../scripts/deploy/README.md`](../../scripts/deploy/README.md) — the deploy variables in full
