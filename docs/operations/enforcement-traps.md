# Enforcement traps

The two ways this platform locks you out of your own host, and how to get back
in. Both are real incidents from the first production deployment, not
hypotheticals — they are recorded here because the platform can `SIGKILL`
processes and sever devices, and that authority is the product *and* the largest
self-inflicted risk.

This document is host-agnostic. The runbook for the specific box these were
learned on has been retired along with the box.

> Referenced normatively by [`plan/threat-model.md`](../plan/threat-model.md)
> §5.1 as the canonical containment failure.

---

## Trap 1 — enforcing mode severs `sudo`

In **ENFORCING** mode the process choke scores `/usr/bin/sudo` at ~120+ and
severs it. Every `sudo`, and any deploy step needing root, is **`SIGKILL`'d
(exit 137)**. The host is not broken; it is doing exactly what it was told, to
you.

Two properties compound it:

**Boot mode comes only from the `-enforce` flag.** It is not restored from the
store — see `Config.Enforcing` in
[`engine/internal/choke/gateway.go`](../../engine/internal/choke/gateway.go),
which wires the real enforcer chain at boot when set and a logger stand-in when
not. The console's ENFORCING / DETECT-ONLY toggle is **runtime-only and does not
survive a restart**, so a restart can silently re-arm severing on a host an
operator believes they left in detect-only.

**The engine exempts a system-critical set**, `sudo` among the paths it will not
auto-sever, but that exemption governs the *automatic* ladder. An operator-driven
sever still applies.

### Recovery

Flip to **DETECT-ONLY** in the console, or restart the engine without
`-enforce`. If `sudo` itself is severed, you need a session that already holds
root, or console access to the host.

### The operating rule

**Deploy and operate in detect-only.** Flip to enforcing from the console when
you specifically want live severing, knowing it will cut `sudo` again. The
deploy scripts follow this: `provision_engine` in
[`scripts/deploy/lib.sh`](../../scripts/deploy/lib.sh) does not pass `-enforce`
unless asked.

---

## Trap 2 — Tetragon policies enforce independently of the engine

> **Disarmed, not gone.** Every policy in `policies/` now declares
> `policy-mode: monitor`, so this cannot fire on a currently-provisioned host.
> It stays on record because the independence itself is unchanged — it is only
> suppressed — and because any host provisioned before that change still carries
> the old policy set.

The `tetragon` container loads its own TracingPolicies. A `Sigkill` action in one
fires **whatever the engine's mode says**, with no audit row, no reversal and no
kill-switch. Switching the *engine* to detect-only does not disable them. The
engine's mode and the kernel's behaviour are two different things.

### What it did: silently broke `apt` across a fleet

`override-credential-read` `SIGKILL`ed any non-allowlisted process reading a
credential path. Package maintainer scripts run through `debconf`, which is a
`#!/usr/bin/perl` script — and `matchBinaries` matches the **executable**, so
allow-listing the script's own path had no effect. Maintainer scripts were killed
mid-configure, leaving packages **half-configured (`iF` / `iU`)** and blocking
all further `apt`.

Driven by `unattended-upgrades` on a timer, this degrades a fleet over days with
no operator action. The same policy also `SIGKILL`ed the OpenSSH login path and
locked an operator out of a host.

### Why `policy-mode: monitor` is the fix

Under it Tetragon suppresses enforcing actions **in the kernel** while leaving
`Post` (the event delivery the engine scores on) untouched. Verified on
Tetragon v1.6.1: a `Sigkill` policy returned exit 0 with the option and 137
without, with identical `Post` delivery.

It is **declarative**, so it survives a restart. `tetra tracingpolicy set-mode`
does not, which is why the mode lives in the policy file rather than in a runtime
command. Enforcement belongs to the engine's choke gateway, which is mode-aware,
reversible and audited.

### Verify

```bash
sudo docker exec tetragon tetra tracingpolicy list
# every row should read MODE=monitor and NENFORCE=0
```

`scripts/ci/check-policy-posture.sh` asserts this statically on every push, and
`scripts/e2e/host-posture.sh` asserts it against a live host.

### Repair a host still carrying the old policy set

```bash
# 1. finish the half-configured packages, with the killer disabled
sudo docker exec tetragon tetra tracingpolicy disable override-credential-read
sudo DEBIAN_FRONTEND=noninteractive dpkg --configure -a
sudo docker exec tetragon tetra tracingpolicy enable  override-credential-read

# 2. redeploy the policies so they carry the monitor declaration
make policies-apply
```

Order matters. Re-enabling before `dpkg --configure -a` completes puts you back
where you started.

---

## Detecting divergence before it bites

The condition that matters is the console reporting detect-only while some agent
is actually enforcing. The control plane surfaces it on `/api/choke/state` as
`diverged` and `diverged_agents` — see `engine/internal/controlplane/choke.go`.
`scripts/e2e/posture-divergence.sh` exercises it.

A fleet where those disagree is a fleet where an operator's understanding of what
is armed is wrong, which is the precondition for both traps above.

---

## Related

- [`plan/threat-model.md`](../plan/threat-model.md) — EN-1 and EN-2, the risks these traps instantiate
- [`architecture/state-ladder.md`](../architecture/state-ladder.md) — what scoring severs, and when
- [`operations/reset-engine-and-policies.md`](reset-engine-and-policies.md) — clean slate after an incident
- [`deployment/pre-deployment-checklist.md`](../deployment/pre-deployment-checklist.md) — the gate that should catch this before a customer does
