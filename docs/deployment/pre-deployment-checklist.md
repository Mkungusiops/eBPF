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
| agent-autonomy | 12 | The agent keeps detecting with the control plane stopped, and re-converges alone |

Run against a **six-host** rig: control plane, single-tenant engine, three agents
(two of them in one tenant) and a victim device.

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

## 4. Closed since the first pass

**Alert severity saturation — FIXED.** Six attack simulations produced 100
alerts, 91% of them `critical`, from only 5 distinct descriptions. Chain scores
are cumulative and never fall, so once a chain crossed 40 every later event on it
was critical too. Alerts now fire on an *escalation in severity* or on a *finding
the chain has not reported before*, rather than on every event above the
threshold. Same six simulations now produce **20 alerts with 12 distinct
findings** and a severity spread.

Two traps, both hit and both worth knowing: deduplicating on severity band alone
silenced three of the six simulations outright, because an early file-read pushed
the chain to critical and the event that actually identified the reverse shell
had no band left to climb. And the agent carries its own copy of `checkAlert`, so
fixing only the engine would have left every multi-tenant console saturated.

**Cloud credential theft was invisible — FIXED.** `override-credential-read` had
no case in `scoreKprobe`, so every event it produced scored 0 and never raised an
alert. It watches paths `sensitive-file-access` does not: `/etc/gshadow` and the
user's `~/.ssh`, `~/.aws`, `~/.kube`, `~/.gnupg`, `~/.netrc`. Verified on the rig
— a read of `~/.aws/credentials` produced **zero** alerts in the same command
where `/etc/shadow` produced four. It now scores 18 and reports
`Credential store read: <path>`.

**Fresh-host enrolment — TESTED.** A clean Ubuntu 26.04 host went from nothing to
an enrolled, reporting agent in **166 seconds**: 4 policies applied durably, the
tc device plane attached, the protect list resolved to gateway + control plane,
mTLS identity persisted, services running. This is the path a customer deployment
takes and it had never been exercised.

**Agent autonomy — TESTED** (`agent-autonomy.sh`, 12 assertions). With the
control plane stopped outright, the agent kept its service, Tetragon and all four
policies, **detected and recorded a live attack**, and re-registered on its own
once the console returned. The invariant that a missed heartbeat never stops
enforcement now has evidence behind it.

**Backup and restore — TESTED.** `pg_dump -Fc` → restore into a scratch database
reproduced all **1,884,606** rows with RLS still enabled and its policy intact.
Production was never the restore target.

**Fleet response actions — FIXED.** `/api/fleet/{kill-switch,thresholds,preset,
thaw}` returned HTTP 501 while the identical fleet-wide operations worked under
`/api/choke/*`. An operator on the Fleet page got "not yet enabled" for the
**fleet-wide emergency stop** that worked one screen across. They are now aliases
of the same handlers, dispatcher and RBAC grant.

## 5. Known gaps — read before you promise anything

**Severity bands — MEASURED, and they are fine.** This was previously listed as
"untuned" on the strength of 65% of alerts being critical during an attack run.
That was the wrong baseline: a host running six back-to-back intrusion
simulations *should* look critical. The number that decides whether severity is
informative is what a normal host produces, and over four minutes of ordinary
operation the engine emitted **zero alerts**. A detector that is silent at rest
and loud under attack is behaving correctly, so the bands stay as they are.

Still worth revisiting after a week of real customer traffic — four minutes on a
test rig is evidence, not proof — but there is no reason to change them now, and
changing scoring thresholds on the eve of a deployment would be the riskier act.

**Policy DRIFT is now visible; policy DISTRIBUTION is still manual.** The wire
contract has always carried `applied_policy_version`, the console has always
displayed it, and no agent ever set it — so every host reported an empty string
and a host running a different policy set from its neighbours was invisible.

Agents now fingerprint the policy set the kernel is *actually* running (name +
mode + enabled, sorted then hashed) and report it every heartbeat. Derived from
the loaded set rather than files on disk, deliberately: `tetra tracingpolicy add`
is create-only and a deleted policy returns from a stale file on restart, so what
is on disk is what someone *intended* and the entire bug class is the two
disagreeing. Proven on the rig — two agents in one tenant agreed on
`00b71db0107eb563`, removing one policy from a single host moved it to
`15ffbf59d932fcfb`, and restoring brought them back into agreement.

What is still *not* built is signed bundle distribution: there is no mechanism
for the control plane to ship a policy set to agents. Policies reach hosts
through the provisioner (`make deploy-agent`), over SSH, applied durably to
`tetragon.tp.d`. That is a working distribution channel with real authentication
— it is simply not the one EN-4 describes.

**This was deliberately not built before the deployment.** A brand-new path that
fetches remote content and applies it to the kernel is exactly the wrong thing to
introduce two days before a customer install, with no soak time. Drift detection
gives the operational safety (you find out when a host diverges) without adding
that risk. Note the other half of EN-4 *is* already enforced: local guardrails —
the protected-binary list and the kill-switch — apply regardless of what any
command says, and `TestProtectedListGuardrail` pins it.

**Scale is proven to three agents, not thirty.** Two agents in one tenant
aggregate correctly (`links_attached=4` across both). Nothing has been exercised
at fleet scale.

**`/api/fleet/kill-switch` accepts `{}` with HTTP 200** where sibling endpoints
reject a missing reason with 400. It defaults to disengaged so it is not
dangerous, but it is inconsistent with the audit discipline everywhere else.

**Still untested:** certbot renewal end-to-end (certs are valid to 2026-10-28 and
the timers are active, but a full `--dry-run` was not completed),
`/api/choke/policy/preview` and `/api/choke/forensic-snapshot` remain 501 by
design — hide those controls rather than letting a customer click them.

## 6. Operational traps that cost real time

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
