# Changelog

All notable changes to the eBPF Threat Choke Gateway.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The running version is reported by `GET /api/version` on both the engine and the
control plane (readable without a session only from the host itself — see
`internal/edge`). A `dirty` flag there means the binary was built from an
uncommitted tree and **cannot be reproduced from a tag**; a release build must
never report it.

---

## [Unreleased] — Behavioural baselines, threat intel, and a conversational assistant

Three additions, all layered on the existing chain scorer rather than replacing
it. A deployment that configures none of them behaves exactly as it did before.

### Added — behavioural baselines (`internal/baseline`)

Per-deployment learning of what is normal: which executables run here, which
parent launches which child, which user runs what, and when the host is active.
Counts decay with a 14-day half-life. The lineage facet is the one that matters
— it expresses "nginx has never launched a shell on this host", which no static
rule can.

- **Assess before observe.** Judging an event after folding it into the profile
  makes it normal by definition; the feature would appear to work and report
  nothing forever. Pinned by a test.
- **No scoring before ready.** A fresh profile thinks everything is novel, which
  on day one flags every process on the box. Readiness gates scoring, and the
  API reports *progress* so "still learning" is distinguishable from "nothing
  found" — the same distinction `/api/system-health` draws for telemetry.
- **Primes from stored history** and **persists across restarts**, so an
  established host is warm at startup rather than blind for its warm-up window.
  Without persistence, every deploy would disable anomaly detection fleet-wide.
- **Only ever adds points**, capped at 12 per event and 25 per chain. Novelty
  can reach *high* alone but never *critical*: a package upgrade legitimately
  execs hundreds of never-seen binaries and must not contain its own package
  manager. Negative scoring was rejected outright — it would let an attacker pad
  a chain with routine activity to drop below the containment threshold.

The control plane keeps a **per-tenant** profile alongside the sensors'
per-host ones, assembled from the ingest stream. Agents cannot do this: an agent
never knows its own tenant, by design. Fed from ingest rather than by querying
`telemetry`, because that aggregate is the query shape that caused the
2026-08-05 outage.

### Added — threat-intelligence enrichment (`internal/intel`)

IP, CIDR, domain and SHA-256 matching against feed files, at detection on the
sensors and at ingest on the control plane.

- **Matching is local.** Feeds are pulled in; an observed address is never sent
  out. A query-time reputation API would disclose the customer's traffic graph
  to a vendor and put a third party in the detection path.
- **Connections outrank command lines.** A socket argument scores full weight; the
  same address named in `argv` scores half — an argument is an intention, a
  socket is a fact.
- **Binary hashing is gated on baseline novelty**, so digests are computed for
  the interesting set rather than on every exec.
- **False-positive resistance is structural**: private/loopback/link-local/CGNAT
  addresses never match, bare public suffixes (`com`, `co.uk`) are rejected at
  load, over-broad CIDRs are rejected, and `allow.txt` is checked first and is
  never overwritten by a deploy.
- Feed refresh is **optional and off by default**; a failed fetch keeps the last
  good copy, because degrading to zero indicators is indistinguishable from a
  clean estate.

### Added — assistant conversation memory

`Run` built every request from the system prompt and the newest question alone.
Prior turns were **persisted, rendered, and never sent to the model** — so "what
about that host?" had no referent and every message was the analyst's first.

The control plane now replays the thread from its own chat store (authoritative,
and scope-checked by the same ownership rule that guards the write); the
single-tenant engine, which has no chat store, accepts a bounded client-supplied
thread. Both are sanitised identically: only `user`/`assistant` roles survive, so
a forged `system` turn cannot rewrite the evidence rules, and tool-call
structures are dropped so a fabricated tool result cannot be laundered into the
transcript.

### Added — assistant capability

- Five enrichment tools (`baseline_profile`, `behavioural_anomalies`,
  `threat_intel_status`, `threat_intel_matches`, `lookup_indicator`).
- `explain_platform`, backed by `internal/platformdoc` and `/api/platform-doc`:
  the product's own vocabulary, so "what is a tarpit" is answered from this
  codebase rather than from the model's general knowledge of security products.
- Server-applied filters on `list_alerts` and `list_events` (severity, host,
  exec id, binary, policy, free text), replacing pull-200-rows-and-read.

### Added — console

**Behaviour & Intel** panel. Readiness and feed counts are stated *above* the
findings, because an empty list means three different things — enrichment off,
baseline still learning, or zero indicators loaded — and only the band can tell
them apart.

---

## [1.0.0] — 2026-08-12 — Enterprise handover

First release cut for handover. The theme of this release is **honest
reporting**: the platform's enforcement was already correct, but several
surfaces described it inaccurately, and four of those inaccuracies appeared in
artefacts a customer would keep.

### Fixed — false statements in the console

Each of these was verified against the live estate, not inferred.

- **Exported decisions were all marked successful.** No backend sends a boolean
  `ok` on a decision — they send `outcome`, free text. The report export computed
  `ok: d.ok !== false`, so `undefined` became `true` for **100% of rows**,
  including ones whose outcome read `"skipped: system-critical chain
  (auto-only; manual override allowed)"` — decisions that deliberately did
  nothing. Both the JSON report and the CSV now carry the engine's own wording,
  and an absent outcome renders `unknown`, never `ok`.
- **The audit chain was reported BROKEN on the control plane**, in four places:
  the assurance pill, the audit popover, the fleet KPI tile, and the downloadable
  board report (in alarm-red). The control plane does not hash-chain centrally —
  each agent chains its own decisions — and answers `{ok: false, supported:
  false}`. All four now distinguish *not maintained here* from *broken*.
  `FleetKpis` gained `auditBroken`/`auditUnsupported`, and `AuditState` gained
  the `supported` field it previously had no way to express.
- **The device plane reported itself active when it cannot drop a packet.** Two
  contradictory predicates existed for `data_plane: "noop"`; the one treating it
  as healthy drove the header readout and the exported evidence bundle. Measured
  live: the single-tenant engine runs `data_plane=noop links=0`. Collapsed to one
  predicate, and the bundle now also carries the raw reported value.
- **ATT&CK coverage printed 0% when coverage is unmeasurable.** Coverage derives
  from policies carrying a technique tag; a fleet running policy names this build
  has never seen maps nothing, and the percentage computes to zero. "0%" asserts
  an estate detects nothing. Now `n/a · no ATT&CK mapping published`, via a single
  `coverageLabel()` used by all six export sites.
- **"Operations: Healthy"** derived purely from `hostOk && streamState ===
  "live"`. It measures the telemetry feed, not the security posture — an estate
  with thousands of open criticals still read Healthy. Relabelled **Telemetry**.
- **Fleet "Healthy" counted reachable hosts.** A reachable host can be
  kill-switched, drifted, or holding a broken chain. Relabelled **Reachable**,
  matching the detail line that already said so.

### Fixed — enforcement and storage

- **Quarantine tier stayed frozen after the last process left.** `cgroup.freeze`
  is tier-wide but the ladder is per-process, so releasing a process moved it out
  of the cgroup and never cleared the flag. Observed on all three enforcement
  hosts: `freeze=1` with zero pids. Harmless in itself, but it made the next
  quarantine's freeze write unfalsifiable — landing on an already-frozen tier, a
  failed write is indistinguishable from a successful one, which silently
  disarms the 0.1%-CPU fallback that exists for exactly that failure.
  `reconcileQuarantineFreeze()` now runs after any release and at `Setup()`, so
  existing residue heals on restart.
- **Containment is routed, not broadcast** (threat model EN-2/CH-5). A sever
  aimed at one host previously landed on every agent in the tenant.
  `STATUS_NOT_TARGET` plus a `TargetMatch` discriminator lets an agent answer
  "that target is not mine", and `Enqueue` mints a distinct command id per agent
  so acks cannot be misattributed.
- **Telemetry retention.** Nothing was ever deleted. Measured: 268 MB/day against
  19 GB free — a disk-full deadline roughly 73 days out, and a full disk stops
  Postgres accepting writes, not merely the console rendering. Events are kept 30
  days, alerts 90, **decisions never** — deleting the record of what the platform
  did to a host is not a disk-space decision. Retention below twice the largest
  console window is refused, because every KPI renders a delta against the prior
  window and a shorter horizon makes that delta quietly wrong rather than absent.
- **Seven-day window returns an exact count.** Severity moved to an indexed
  column with SQL-side bucketing and a batched, idempotent backfill; the previous
  Go-side tally was bounded by a 200k scan limit while a 7-day view scans 935,600
  alert rows, so every window past a day was a floor.
- **Correlation graph shows containment.** Nodes carry a rung ring — severed
  drawn as a broken ring, since terminal must not read as merely held. Previously
  the rung was legible only after clicking into a node's process list.
- **Graph legend was invisible.** Every swatch set `fill:` on an HTML `<i>`, which
  is SVG-only and inert; seven colour keys rendered as blank gaps.

### Security

- **`/api/version` no longer public on the control plane.** It was ungated on an
  internet-facing multi-tenant console, publishing revision, dirty flag and build
  time — a free answer to "is this host behind on patches?". Build identity is
  now readable without a session only from the host itself. The test is
  deliberately negative so it fails closed: nginx stamps `X-Forwarded-*` on
  everything it proxies and a caller cannot strip what the proxy adds, so their
  absence from a loopback peer is the only accepted evidence. A loopback peer
  alone proves nothing, because nginx itself proxies from loopback.
- **Keycloak error pages had no way back.** The client set `rootUrl` but not
  `baseUrl`, and the error template renders its recovery link only when `baseUrl`
  has content — so "Cookie not found", which any reload of the one-shot
  authenticate URL produces, was a dead end.

### Operations

- **Database backups now exist.** The nightly job produced 1,572-byte PKI+config
  tarballs and no database dump at all; a 3.5 GB / 5.24M-row store including the
  audit chain had never been backed up.
- `manifest.webmanifest` served as `application/octet-stream` by nginx (no
  `.webmanifest` in stock `mime.types`), so a strict client discarded the file
  carrying `theme_color` and the whole icon list.
- `/favicon.ico` answered with the SPA catch-all on the console (HTML, discarded
  by the browser) and with SVG bytes under an SVG content type on the engine.
  Both now serve a real multi-resolution ICO, revalidated by ETag because that
  path cannot carry a cache-busting query.

### Removed

- **983,910 bytes of unreachable HTML.** Five standalone consoles were embedded
  in the engine binary with no route reaching any of them; `/login` has been
  served from the Vite bundle since that migration, and the only consumer of the
  legacy login page was never called. They were being maintained by mistake — an
  earlier favicon fix carefully updated icon links in all five, to no effect.

### Verified

Against the live AWS estate, not a local mirror: **9 e2e suites, 171 assertions,
zero failures** — host posture, single-tenant, detection, kill-switch,
multi-tenant (both tenants, isolation from both sides), multi-agent containment
routing, kernel device-drop proof, posture divergence. Includes `SEVER ACTUALLY
KILLED THE PROCESS (kernel effect)` and a hash-chain verification after the
ladder ran. Unit tests: 152 web, 40 Go packages.

---

## Earlier work

Releases before 1.0.0 were not tagged. The commit history on
`feat/production-readiness` and `main` carries them; notable prior fixes include
the control-plane outage caused by a missing `telemetry(tenant_id, at)` index
(2.8M-row sorts exhausting the connection pool), dashboard metric corrections,
and the multi-tenant device-gateway routing rebuild.

[1.0.0]: https://github.com/jeffmk/ebpf-soc/releases/tag/v1.0.0
