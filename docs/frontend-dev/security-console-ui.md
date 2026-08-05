# Security Console UI Contracts

> Last updated: 2026-06-28

This note records the current user-facing contracts for the SOC dashboard
and Choke Gateway screens. Keep it in sync when changing executive summary,
briefing, tracked-process, or drilldown behavior.

## SOC Executive Summary And Briefing

The SOC dashboard opens with the executive summary band. It must answer the
first operational read without requiring a drilldown:

- current security posture and change over the selected time window
- number of alerts that still need containment
- number of response decisions that are blocked or pending
- top MITRE technique by observed activity
- event throughput and host/process health

Briefing mode expands inline from that same band. It is role-neutral: a CEO,
CTO, SOC lead, analyst, or incident commander should be able to read it and
understand what is happening, why it matters, what is affected, what has
already been done, and what should happen next.

Long host, process, and exec identifiers must be shortened, wrapped, or
ellipsized so the "what is affected" and "what has been done" columns never
overlap. The briefing copy should prefer plain operational language over raw
implementation terms unless a technical identifier is the actual evidence.

Focused regression:

```bash
PLAYWRIGHT_START_WEB_SERVER=1 npm run e2e -- --project=chromium soc.spec.ts
```

## Choke Tracked Processes

The tracked-process table is optimized for triage while hundreds of processes
are present. Preserve this column order:

1. select
2. status
3. process id
4. binary
5. origin
6. exec id
7. risk
8. actions

The table header is rendered inside the same virtual scroll viewport as the
rows through `VirtualList.before`. It is intentionally not sticky. This keeps
the labels moving with the row content during horizontal and vertical scroll,
which avoids stale headers implying the wrong column mapping.

Selection controls live above the scroll viewport and stay outside the grid:
`Select all visible`, `Clear selection`, and the selected count. Row-level
actions stay in the final column and use short command labels.

Focused regression:

```bash
PLAYWRIGHT_START_WEB_SERVER=1 npm run e2e -- --project=chromium choke.spec.ts
```

## Shared Drilldown Timeline

SOC and Choke drill panels use the shared `EventReplay` component for event
progression. Route-specific panels can choose their own surrounding evidence,
but timeline rendering, scrubber behavior, and event density should stay
consistent.

## Release Gates

Run these local checks before rebuilding the embedded binary for these UI
surfaces:

```bash
npm run typecheck
npm run lint
PLAYWRIGHT_START_WEB_SERVER=1 npm run e2e -- --project=chromium soc.spec.ts choke.spec.ts
```

After a production deploy, verify the deployed routes with the production URL:

```bash
EBPF_WEB_BASE_URL=https://engine.adanianlabs.io \
EBPF_E2E_USER=admin \
EBPF_E2E_PASSWORD=... \
npm run e2e -- --project=chromium auth.spec.ts choke.spec.ts
```
