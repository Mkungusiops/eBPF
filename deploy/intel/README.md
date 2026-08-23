# Threat-intelligence feeds

Files here are loaded by the engine, every agent and the control plane, and
matched against observed IPs, domains and file hashes.

**Matching is local.** Feeds are pulled *in*; an observed address is never sent
*out* to be checked. A query-time reputation API would disclose the customer's
traffic graph to a vendor, and would put a third party's uptime in the detection
path. See `engine/internal/intel/doc.go`.

## Format

One indicator per line. `#` starts a comment. Optional tab-separated fields:

```
<indicator>\t<category>\t<confidence>
```

`<indicator>` is an IPv4/IPv6 address, a CIDR range, a domain, or a SHA-256 hex
digest — the type is detected, not declared.

## Filenames carry meaning

| Name | Meaning |
|---|---|
| `allow.txt` | Never match these, whatever a feed says. Checked first. |
| `<source>.txt` | Indicators attributed to `<source>`, medium confidence. |
| `<source>.high.txt` | ... at high confidence. |
| `<source>.low.txt` | ... at low confidence. |

Confidence sets the score: high 30, medium 18, low 8. A high-confidence hit on a
real connection can carry a chain to critical on its own — that is deliberate,
because an indicator match is external corroboration rather than inference.
An indicator merely *named on a command line* scores half, because an argument
is an intention and a socket is a fact.

## What is rejected at load

Silently matching everything is the worst failure this component has, so these
are dropped rather than trusted:

- Private, loopback, link-local, CGNAT and multicast addresses. Public feeds
  contain RFC1918 space more often than you would think, and one entry for
  `172.31.0.0/16` would mark every agent's uplink to the control plane as C2.
- Domains of one label, and bare public suffixes (`com`, `co.uk`). A truncated
  download produces exactly these.
- Prefixes shorter than /8 (IPv4) or /32 (IPv6).

Rejections are reported in `/api/intel` under `errors`, so a broken feed looks
broken rather than clean.

## Refreshing

Optional and **off by default** — a security product must not acquire an
outbound dependency because someone upgraded it. When enabled, a failed fetch
leaves the previous file in place: degrading to an empty indicator set would be
indistinguishable from a clean estate.
