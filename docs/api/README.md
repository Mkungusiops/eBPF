# Platform APIs

Start here. This directory is the contract between this platform and anything
that integrates with it.

Everything in it is **generated from the source and gated in CI**, so it cannot
quietly fall out of date. If you find a difference between these documents and
the running system, that is a bug in the platform, not a stale doc — please
report it rather than working around it.

| Document | What it covers | Generated from |
|---|---|---|
| [`openapi.yaml`](openapi.yaml) | Both HTTP surfaces — 136 routes | the `mux` registrations + handler doc comments |
| [`wire-contract.md`](wire-contract.md) | agent ↔ control-plane gRPC | `engine/proto/ebpfsoc/v1/*.proto` |
| [`integration-guide.md`](integration-guide.md) | How to authenticate and call the platform, with worked examples | hand-written |

## How to read these

**The two Markdown files render anywhere** — GitHub, your IDE, any Markdown
viewer. Start with this file, then `integration-guide.md`.

**For a browsable API reference**, build the rendered version:

```bash
make api-docs        # -> docs/api/dist/index.html
open docs/api/dist/index.html
```

That is **one self-contained HTML file**. It runs no server and makes **no
network requests** — you can open it offline, email it, or host it on an
internal share. The renderer is inlined rather than loaded from a CDN,
deliberately: opening the API documentation for a security product should not
fetch third-party JavaScript, and it must work in an airgapped review
environment.

Every CI run also publishes it as the **`api-reference`** build artefact, so a
team can download the current reference without checking out the repository or
installing anything.

> **Do not serve this from the production console.** It is a complete map of a
> security platform's API, containment and kill-switch endpoints included.
> Denials already return `404` specifically so the surface cannot be enumerated;
> publishing the spec would undo that.

## Regenerating

```bash
./scripts/ci/gen-openapi.py     # rewrites openapi.yaml
./scripts/ci/gen-protodoc.py    # rewrites wire-contract.md
make api-docs-check             # what CI runs
```

CI runs both with `--check` and **fails the build** if either has drifted.

---

## There are three API surfaces, not one

They are frequently confused, and confusing them is the most common integration
mistake. They are separate products with separate trust models.

```
                        ┌──────────────────────────────┐
   operator / browser   │  1. CONTROL PLANE  (HTTP)    │
   ────────────────────▶│     multi-tenant             │
   OIDC + PKCE          │     console.<domain>         │
                        └──────────────┬───────────────┘
                                       │ 3. WIRE CONTRACT (gRPC + mTLS)
                                       │    agent dials OUT and holds
                                       │    the stream; CP pushes signed
                                       │    commands down it
                        ┌──────────────▼───────────────┐
                        │  agents (one kernel/tenant)  │
                        └──────────────────────────────┘

                        ┌──────────────────────────────┐
   operator / browser   │  2. ENGINE  (HTTP)           │
   ────────────────────▶│     single-tenant, standalone│
   session cookie       │     engine.<domain>          │
                        └──────────────────────────────┘
```

### 1. Control plane — multi-tenant (`console.<domain>`)

The MSSP / MSOC surface. Every request is tenant-scoped, and authorisation is
evaluated per tenant on every call. This is what you integrate with if you
manage more than one customer.

### 2. Engine — single-tenant (`engine.<domain>`)

One host, its own console, no tenancy model at all. The standalone product.
Several paths look identical to the control plane's but **have no tenant
parameter and a different auth model** — do not assume a client written for one
works against the other.

### 3. Wire contract — agent ↔ control plane (gRPC)

Not HTTP, and not something you should implement against unless you are writing
an agent. Documented in [`wire-contract.md`](wire-contract.md).

---

## Five things that will surprise you

Read these before writing a client. Each one has caused a real integration bug.

**1. Denials return `404`, never `403`.** This is deliberate: error codes must
not let a caller discover which tenants or resources exist. Treat `404` as
*"no such thing, or not yours"* — the distinction is intentionally unavailable.
Do not build retry or escalation logic that assumes `403` means "exists but
forbidden".

**2. Tenant identity never travels in a request body.** On HTTP it is a query
parameter that is *authorised*, not trusted. On gRPC it comes from the verified
mTLS client certificate (`O=<tenant>`). A `tenant_id` in a payload could only
ever be tamper-detection telemetry, never an authorisation input — the wire
contract says so normatively.

**3. Unsafe methods need a CSRF header.** Any non-`GET`/`HEAD`/`OPTIONS` request
under `/api/` must send `X-CSRF-Token` echoing the `csrf_token` cookie.
Omitting it returns `403` with a JSON body — this is the one place a `403` is
meaningful, and it is about the request, not your permissions.

**4. Destructive actions may be *held*, not applied.** When dual control is
enabled, `quarantine` and `sever` return **`202`** with
`status: "APPROVAL_REQUIRED"` and `ok: false`. The action has **not** run. A
client that treats `2xx` as success will report containment that never happened.
Poll the returned approval id, or handle `approval_required` explicitly.

**5. `ok: true` means applied, not accepted.** The platform distinguishes
"dispatched" from "the agent confirmed it applied". An agent that does not own
the target acks `NOT_TARGET`, and that is **not** containment. Fields like
`applied`, `target_match` and `routing` exist so you can tell the difference —
use them.

---

## Authentication at a glance

| Surface | Mechanism | Notes |
|---|---|---|
| Control plane (human) | OIDC Authorization Code + **PKCE** via Keycloak → opaque `soc_session` cookie | The access token never reaches the browser — the BFF holds it |
| Control plane (machine) | `Authorization: Bearer <CP_ADMIN_TOKEN>` | Cross-tenant `msoc-admin`. Treat as a root credential |
| Engine | Signed, stateless `soc_session` cookie from `POST /api/login` | 24h TTL |
| Agent → CP | mutual TLS, client cert issued at enrolment | Tenant is the cert subject |

Full worked examples, including the CSRF dance and the approval flow, are in
[`integration-guide.md`](integration-guide.md).

---

## What is deliberately *not* in the OpenAPI file

Request and response **schemas are absent**, and that is a decision rather than
an omission.

This repository has been bitten by hand-synced duplication before — the
telemetry schema is authored in four places and has already drifted into a
duplicate index. Generating paths and descriptions from the code is safe because
they have a single source of truth. Inventing schemas would not be: it would
produce a confidently wrong document, and an integrating team would build
against it and discover the difference in production. A missing schema costs you
one question; a wrong one costs you an incident.

Bodies for the endpoints teams actually integrate against are documented by hand
— and verified against the real server — in
[`integration-guide.md`](integration-guide.md).

---

## Conventions for contributors

- **Adding a route?** Run `./scripts/ci/gen-openapi.py`. CI fails otherwise.
- **Write the handler doc comment.** It becomes the API description that another
  team reads. 72% of routes currently have one; the remainder show
  *"No handler documentation in source."* in the spec, which is a to-do list.
- **Changing the `.proto`?** Run `./scripts/ci/gen-protodoc.py`, and remember the
  comments are normative — they are the contract's rationale, not commentary.
- **Do not serve this spec from the production console.** A complete map of a
  security platform's API, including the containment and kill-switch endpoints,
  is reconnaissance. Publish it internally or behind the same auth as everything
  else — note that denials already return `404` specifically so the surface
  cannot be enumerated.
