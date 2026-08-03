# Pre-deployment checklist

What to run before putting this platform in front of a customer, what it proves,
and — as importantly — **what it does not cover**. Green suites are evidence, not
a guarantee, and the gaps below are the ones that would matter first.

---

## 1. The full gate

```bash
REBOOT_TEST=1 ./scripts/e2e/all.sh      # ~15 min, reboots one agent
```

Exits non-zero on any failure. Without `REBOOT_TEST=1` it skips the reboot suite
and takes ~8 minutes — that is the right call for an ordinary pre-commit run, and
the wrong one before a deployment.

| Suite | Assertions | What it actually proves |
|---|---|---|
| host-posture | 15 | No host has a kernel-level kill armed, loaded **or staged on disk**, and none omits the OpenSSH split-process path |
| single-tenant | 51 | The engine's full choke ladder, guardrails, audit chain, and a real `SIGKILL` |
| detection | 15 | Six live attacks produce scored, severity-rated, pivotable alerts |
| kill-switch | 16 | The emergency stop genuinely halts enforcement — and still audits what it suppressed |
| multi-tenant ×2 | 50 | Tenant isolation asserted from **both** sides; cross-tenant read and write denied |
| device-drop | 8 | An operator severs a device and real traffic stops in the kernel, then resumes |
| posture-divergence | 6 | If a second enforcement authority appears, the console **notices and names the agent** |
| reboot-resilience | 9 | An agent host reboots and the whole stack returns unattended |

**161 assertions, all passing** as of the last run against the five-host rig.

## 2. Why several of these exist

Each of the following passed a weaker version of its check for a long time while
being broken. That is the failure mode to design against:

- **A control that cannot fail is not a control.** `sever-pipe-to-shell.yaml`
  shipped `action: Sigkill`, was loaded on every host, and never fired once — the
  selector could not match at `execve`. It looked like coverage on every audit.
- **Asserting the safe state is not testing the mechanism.** The kill-switch was
  only ever asserted *disengaged*; a switch wired to nothing passes that forever.
  The suite now proves enforcement kills, then that the switch stops it, then
  that lifting it restores enforcement.
- **A precondition that fails silently turns a test green.** The kill-switch
  suite once "passed" its central assertion because a bad CSRF header meant
  nothing was ever armed. It now aborts rather than reporting a vacuous pass.
- **Counting is weaker than naming.** Policy checks assert the expected policies
  **by name**; a count passes just as happily when a detection has vanished and
  something unrelated replaced it.
- **Silence is not safety.** `agents_reporting` is compared against
  `agents_total`; an agent that never answered is *unknown*, not clean.

## 3. Deploying a new host

Order matters — the control plane first, agents second, because they enrol
against it.

```bash
SSH_HOST=<cp> TARGET_HOST=<console-fqdn> TLS=1 DATA_MODE=none make deploy-console
TENANT=<id> AGENT_HOST=<host> CP_SSH=<cp> CP_IP=<cp-private-ip> make deploy-agent
```

Then re-run the gate. Specifically confirm:

- `host-posture` still passes on the **new** host (it is included automatically
  once its `*_RSH` is in `e2e.env`)
- the agent appears with `agents_reporting` incrementing, not merely a host row —
  registration persists forever and is not liveness
- `links_attached >= 1` if you expect device containment to work; without it the
  console will accept a device sever that silently does nothing

**`DATA_MODE=none` is not optional when real agents exist.** Otherwise every
redeploy resurrects the simulators alongside them, the tenant ends up with two
agents, and enforcement can be dispatched to a simulator that acks success for a
process it never touched.

## 4. Known gaps — read before you promise anything

**Alert severity saturates.** On a rig with six attack simulations run once,
**91 of 100 alerts were `critical`** (score range 16–179 against a critical
threshold of 40). Scores are cumulative per process chain and only grow, so once
a chain crosses 40 every subsequent event on it is critical too. Detection is
correct and the severity matches the documented bands — but as a triage signal
the field carries almost no information, and a SOC analyst will notice in the
first hour. Either score per-event, decay the chain score over time, or raise the
bands. This is a product decision, not a bug, and it is not fixed.

**Fresh-host enrolment is not covered by any suite.** The rig's agents were
enrolled by hand and the suites only exercise hosts that are *already* enrolled.
Enrolling a brand-new host is precisely what a customer deployment does, and it
is the least-tested path in the system. Testing it needs a sixth host, or a
decision to consume the victim (which would break `device-drop-proof`, since that
suite requires a clean, non-agent neighbour to contain).

**Also untested:** policy bundle distribution and signature verification (EN-4),
agent behaviour when the control plane is unreachable for an extended period,
Postgres backup and restore, TLS certificate renewal under `certbot`, and
anything at scale — the largest fleet ever exercised is two agents.

## 5. Operational traps that cost real time

- **`tetra tracingpolicy add` is create-only.** An edited policy keeps running
  the version loaded at start. Delete first, keyed on `metadata.name`, which is
  **not** the filename (`network-watch.yaml` declares `outbound-connections`).
- **Deleting a policy at runtime does not remove it.** Anything left in
  `/opt/ebpf-soc/policies/`, `/var/lib/ebpf-engine/policies/`, or the container's
  `/etc/tetragon/tetragon.tp.d/` returns on the next restart.
- **nginx serves the console from `/var/www/console` on disk**, not from the
  control plane's `go:embed` bundle. Shipping a UI change means staging
  `web/dist`; deploying the binary alone changes nothing and looks like it worked.
- **Device state only reaches the console on the ~30 s heartbeat.** Any check
  asserting a device change must clear a full interval.
- **The engine rate-limits `/api/login` to 5/min.** Repeated runs trip it, and
  `HTTP 429` reads exactly like a bad password.
- **Never `cat >` over a running binary** — `ETXTBSY`, silently swallowed by
  `&&`. Write-then-rename.
