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
