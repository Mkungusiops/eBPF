# Behavioural baselines and threat-intelligence enrichment

Two detection layers added on top of the static chain scorer, closing the "no
baseline learning" and "no reputation data" gaps.

Both are **additive**. `internal/score` is untouched: the same rules produce the
same points they always did, and enrichment adjusts the chain around them. A
deployment that configures neither behaves exactly as it did before.

---

## 1. Why the static scorer was not enough

`internal/score` is a rule table. `curl … | sh` scores 25 on every host, forever
— whether that host runs it ten thousand times a day in a build pipeline or has
never run it once. That cuts both ways:

- A host whose *normal work* resembles the rules alerts constantly, so its
  operators learn to ignore it.
- Behaviour that is obviously novel *for this host* — a web server that has
  never spawned a shell in six weeks suddenly spawning one — scores **zero**,
  because no rule can express "this has never happened here".

The second is the expensive one. The single most discriminating fact in process
telemetry is not what a binary is called; it is whether **this parent has ever
launched this child on this machine before**.

---

## 2. The behavioural baseline (`internal/baseline`)

### What it learns

Four decayed frequency facets:

| Facet | Key | Why |
|---|---|---|
| `edge` | `parent>child` | Highest value. Expresses what no rule can. |
| `binary` | executable path | First-ever execution on this host. |
| `userbin` | `uid:binary` | `www-data` running `apt` is not `root` running `apt`. |
| `hour` | hour of day | Activity at 03:00 on a 09:00–18:00 host. |

Counts decay with a **14-day half-life**, so a host that changes role stops
being alarming within a fortnight rather than forever.

### Three properties that keep it honest

**Assess before observe.** If an event is folded into the profile before it is
judged, it has already made itself normal — every assessment returns "routine",
and the feature appears to work while reporting nothing, forever. Pinned by
`TestAssessBeforeObserveIsTheCallersContract`.

**It never scores before it is ready.** A fresh profile thinks everything is
novel, which on day one means every process on the box is an anomaly — the
classic UEBA failure that teaches operators the feature is noise. `Assess`
returns zero points until both an observation count *and* a wall-clock span are
met, and `/api/baseline` reports **progress toward readiness** so "still
learning" is visible rather than looking like "nothing found".

**It only ever adds.** Points are additive and bounded, never negative. A
negative contribution would let an attacker pad a chain with routine activity to
drag it back under the containment threshold. When behaviour is strongly typical
the assessment reports `Routine`, which carries no points — it is an annotation
for the analyst, and the fastest false-positive dismissal there is.

### Bounds

| Bound | Value | Reason |
|---|---|---|
| Per event | 12 points | Sits above medium (10), below high (20). |
| Per chain | 25 points | Above high, **below critical (40)**. |
| Keys per facet | 20,000 | A build farm must not grow the map without limit. |

The per-chain ceiling is the important one: a chain can reach *high* on novelty
alone, but reaching **critical** — the band that drives the harshest containment
— always requires a rule hit or an indicator match. A host in the middle of a
package upgrade legitimately execs hundreds of never-seen binaries and must not
be able to contain its own package manager.

### Restart and priming

The profile is persisted to the host's own database and restored at startup.
Without that, every restart would blind the sensor for its whole warm-up window
— "deploy the new build" and "switch anomaly detection off fleet-wide" would be
the same action.

On a first run with no saved profile, it **primes from stored history**: the
`events` table is replayed oldest-first, with original timestamps so decay
applies as if observed live. An established host is therefore warm the moment
the process starts, rather than blind for a day.

Restore is tried *before* priming. A restored profile already contains every
previous start's priming; priming on top would replay the same executions again
on each restart, inflating every weight until nothing was ever novel again.

### Per-host vs per-tenant

An agent **never knows its own tenant** — tenant identity is derived from the
mTLS client certificate at the collector (`tenant-isolation-invariant.md` R1),
and that is deliberate: an agent that could name its tenant could name someone
else's. So there are two profiles:

- **Per-host**, on each sensor, feeding the chain scorer in real time.
- **Per-tenant**, on the control plane, assembled from the ingest stream on the
  far side of the certificate boundary. It answers what no single host can:
  *"this is normal on the box it ran on, but no other host in this tenant has
  ever done it."*

The tenant profile is fed **from ingest**, never by querying `telemetry`. That
is a hard constraint, not an optimisation: an aggregate over a tenant's history
is exactly the query shape that took the control plane down on 2026-08-05.

The tenant profile **persists** across control-plane restarts, in its own
RLS-protected tables (`baseline_tenant_counts`, `baseline_tenant_meta`),
snapshotted every five minutes and once on shutdown.

This does not reintroduce the 2026-08-05 query. Nothing here reads `telemetry`.
The profile is still fed entirely from the ingest stream; persistence only
writes out the resulting **bounded key set** — a few thousand rows per tenant —
and reads it back once at startup. Restore happens in `New`, before the gRPC
server accepts a record, so an early arrival cannot create an empty profile that
the restore then overwrites.

A behavioural profile is a precise description of what a tenant's estate does
all day, so it is tenant-partitioned like every other such table: RLS enabled,
RLS **forced**, every statement running as a non-superuser with `app.tenant_id`
set. Postgres only — there is no SQLite equivalent for RLS, so that deployment
keeps profiles in memory rather than persisting them with weaker isolation than
everything around them. That is the same reasoning `openChatStore` already
applies to conversations.

Note also that **readiness has two gates** and either can be the outstanding
one. A profile can hold thousands of observations and still be too *young*.
Reporting only "needs more data" when the real constraint is age is a small
inaccuracy that reads as a bigger one, so `Status` reports progress against both
and the assistant's tool description says to check which is outstanding.

---

## 3. Threat-intelligence enrichment (`internal/intel`)

### Matching is local — always

Feeds are pulled **in** as files and evaluated in process. An observed address is
**never sent out** to be checked.

This is a product requirement, not an efficiency choice. A query-time reputation
API turns every outbound connection this platform observes into a disclosure to
a third party of who the customer talks to — a SOC tool that leaks its customer's
traffic graph to a vendor is a breach with a support contract. It would also put
someone else's uptime and rate limit inside the detection path, which the
autonomy contract forbids.

### What is matched, and where

| Source | Observable | Strength |
|---|---|---|
| `outbound-connections` kprobe | destination IP (`daddr:dport`) | **Full** — a connection that happened |
| Command-line args | URLs, hosts, bare IPs | **Half** — an intention, not a fact |
| Binary content | SHA-256 | Full — gated on baseline novelty |

Hashing is gated on the baseline flagging a binary as **novel**. A binary this
host has run ten thousand times does not need its digest recomputed on run ten
thousand and one, and reading files on the event path is the one cost this
package cannot absorb casually.

### Scoring

High 30 · medium 18 · low 8; halved for a command-line mention.

A high-confidence hit on a real connection can carry a chain to critical on its
own. That is deliberate: an indicator match is **external corroboration** rather
than inference, and if a process is talking to a known C2 address the analyst
should not have to wait for it to also read `/etc/shadow`.

### False-positive resistance

A bad match can sever a production host, so three exclusions are structural
rather than configurable:

- **Private, loopback, link-local, CGNAT and multicast addresses never match.**
  Public feeds contain RFC1918 space more often than you would think, and one
  entry for `172.31.0.0/16` would mark every agent's uplink to the control plane
  as C2 traffic.
- **`allow.txt` is checked first** and is never overwritten by a deploy once it
  exists on a box — it is the operator's veto list.
- **Bare public suffixes are rejected at load.** A feed with a stray `com` line
  is not hypothetical; truncated downloads and mis-parsed CSVs produce exactly
  that, and the failure is catastrophic and silent.

Rejections are reported in `/api/intel` under `errors`, so a broken feed looks
broken rather than clean.

### Refreshing

Optional and **off by default** — a security product must not acquire an
outbound dependency because someone upgraded it. A failed fetch leaves the
previous file in place: degrading to an empty indicator set is the worst
possible failure here, because it is indistinguishable from a clean estate.

See `deploy/intel/README.md` for the file format.

---

## 4. The three-way distinction the UI must preserve

An empty findings list means one of three things, with opposite operational
consequences:

| State | Means | Must not read as |
|---|---|---|
| Enrichment off | Not running here | "nothing found" |
| Baseline not ready | Still learning | "nothing unusual" |
| Zero indicators loaded | Nothing to match against | "estate is clean" |

`/api/baseline` reports `enabled` and readiness progress; `/api/intel` reports
`loaded` and indicator counts. The **Behaviour & Intel** console panel states
both *above* the findings, and every empty list carries the reason it is empty.
This is the same distinction `/api/system-health` already draws between a quiet
telemetry feed and a broken one.

---

## 5. API

All reads. There is deliberately **no** route that adds an indicator, edits the
allowlist, or resets a profile: feeds are files an operator owns, and a console
that can rewrite detection content is a console whose detection content can be
rewritten by whoever obtains a session.

| Route | Returns |
|---|---|
| `GET /api/baseline` | Learned profile + readiness progress |
| `GET /api/baseline/anomalies` | Recent behavioural findings |
| `GET /api/intel` | Feeds loaded, counts, refresh state, parse errors |
| `GET /api/intel/matches` | Recent indicator hits |
| `GET /api/intel/lookup?q=` | Is this indicator known? |
| `GET /api/platform-doc` | Product glossary (see `analyst-assistant.md`) |

On the control plane every one is tenant-scoped from the **session**, never from
a query parameter.

The assistant reads all of them through `baseline_profile`,
`behavioural_anomalies`, `threat_intel_status`, `threat_intel_matches` and
`lookup_indicator`.
