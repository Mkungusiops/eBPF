# Integration guide

Worked examples for the endpoints teams actually build against. Every status
code and body shape below was **verified against a running control plane**, not
inferred from the code — where behaviour is surprising, the surprise is
documented rather than tidied away.

Read [`README.md`](README.md) first for the three-surface model and the five
things that commonly trip up new clients.

Conventions used here:

```bash
CP=https://console.example.com     # control plane (multi-tenant)
EN=https://engine.example.com      # engine (single-tenant)
TENANT=acme-corp
```

---

## 1. Authenticating

### Control plane, machine-to-machine

```bash
curl -sS -H "Authorization: Bearer $CP_ADMIN_TOKEN" \
  "$CP/api/approvals?tenant=$TENANT"
```

`CP_ADMIN_TOKEN` carries the `msoc-admin` role, which is **cross-tenant read +
respond**. Treat it as a root credential: it can contain processes in every
tenant. It lives in `/etc/ebpf-soc/controlplane.env` on the control-plane host.

### Control plane, as a human

Browser only. `GET /auth/login` starts an OIDC Authorization Code + PKCE flow
against Keycloak; `/auth/callback` completes it and sets an **opaque**
`soc_session` cookie. The access token stays server-side in the BFF and never
reaches the browser, so there is no bearer token for a browser client to leak.

### Engine (single-tenant)

```bash
curl -sS -c jar.txt -X POST "$EN/api/login" \
  --data-urlencode "user=$ENGINE_USER" \
  --data-urlencode "pass=$ENGINE_PASS"
```

Sets two cookies: `soc_session` (HttpOnly, signed, 24h) and `csrf_token`
(readable by JS, deliberately). Both carry `Secure` when the request arrives over
TLS.

> Sessions are stateless and signed. Logout clears the cookies but **cannot
> revoke** an already-issued one before it expires. If a session is believed
> compromised, rotate the signing secret on the host.

---

## 2. The CSRF dance

Every unsafe method (`POST`, `PUT`, `PATCH`, `DELETE`) under `/api/` must echo
the CSRF cookie in the `X-CSRF-Token` header. Omitting it returns `403` with a
JSON body:

```json
{ "error": "csrf token missing or invalid" }
```

This is the one place a `403` is meaningful — it is about the *request*, not
your permissions.

```bash
CSRF=$(grep csrf_token jar.txt | awk '{print $7}')

curl -sS -b jar.txt -X POST "$EN/api/choke/manual" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF" \
  -d '{"exec_id":"...","pid":4242,"action":"throttle","reason":"triage"}'
```

Safe methods must **not** send it.

---

## 3. Containing a process

```bash
curl -sS -H "Authorization: Bearer $CP_ADMIN_TOKEN" \
  -X POST "$CP/api/choke/manual?tenant=$TENANT" \
  -H "Content-Type: application/json" \
  -d '{
        "exec_id": "abc123",
        "pid": 4242,
        "action": "quarantine",
        "reason": "confirmed C2 beacon"
      }'
```

`action` is one rung of the ladder: `throttle`, `tarpit`, `quarantine`, `sever`,
or `thaw` to release.

### A reason is mandatory for `quarantine` and `sever`

Enforced server-side, so it cannot be skipped by calling the API directly:

```json
{ "ok": false, "error": "a reason is required to sever (this action is irreversible)" }
```
→ `400`. The reversible rungs stay frictionless on purpose.

### Read the response carefully — `2xx` is not success

| Field | Meaning |
|---|---|
| `ok` | The agent **confirmed it applied**. This is the only success signal. |
| `status` | `STATUS_APPLIED`, `NO_AGENT`, `AMBIGUOUS_TARGET`, `APPROVAL_REQUIRED` |
| `agent` | Which agent actually applied it |
| `routing` | How the target was resolved (evidence grade) |
| `routed_to` | Every agent the command was offered to |
| `applied_by` | Present when a reversible rung landed on more than one host |

An agent that does not own the target acks `NOT_TARGET`, and that **never**
counts as containment. A client that treats HTTP `200` as "contained" will
report containment that did not happen.

### `sever` refuses ambiguous targets

`sever` is a `SIGKILL` and cannot be undone, so if the control plane cannot pin
the process to exactly one host it refuses rather than broadcasting:

```json
{
  "ok": false,
  "status": "AMBIGUOUS_TARGET",
  "candidates": ["agent-a", "agent-b"],
  "error": "cannot determine which agent is running this process (pid-only); sever is irreversible — re-issue with agent_id set to one of: agent-a, agent-b"
}
```
→ `409`. Re-issue with `"agent_id"` naming one host. Reversible rungs still fan
out, because a throttle on the wrong host is undone by a thaw and a kill is not.

---

## 4. Dual control (change control)

When dual control is enabled, `quarantine` and `sever` are **held** for a second
operator. The request returns `202`:

```json
{
  "ok": false,
  "status": "APPROVAL_REQUIRED",
  "approval_required": true,
  "approval": { "id": "apr_...", "expires_at": "..." },
  "detail": "sever is a destructive action and needs a second operator to approve it (request apr_...). It has NOT been applied."
}
```

**Nothing has been dispatched.** Handle `approval_required` explicitly.

Bulk and device containment behave the same way and report how many targets were
held:

```json
{ "results": [...], "approval_required": true, "held": 3,
  "detail": "3 of 5 targets need a second operator to approve sever; those have NOT been applied." }
```

Approve — and note the approver may not be the requester:

```bash
curl -sS -H "Authorization: Bearer $CP_ADMIN_TOKEN" \
  -X POST "$CP/api/approvals/decide?tenant=$TENANT" \
  -H "Content-Type: application/json" \
  -d '{"id":"apr_...","approve":true,"note":"verified on host"}'
```

Self-approval returns `403` with `status: "SELF_APPROVAL_DENIED"` — that is the
control working, not a bug. On approval the action **executes immediately** and
the outcome is recorded on the same record, so "approved" and "applied" cannot
drift apart in the audit trail.

Check whether dual control is on before designing around it:

```bash
curl -sS -H "Authorization: Bearer $CP_ADMIN_TOKEN" "$CP/api/approvals/policy?tenant=$TENANT"
```
```json
{ "enabled": false, "requires_approval": [],
  "never_gated": ["thaw","throttle","tarpit","kill-switch","detect-only"],
  "ttl_seconds": 1800 }
```

`thaw`, the reversible rungs, the kill-switch and disarming are **never** gated.
An approval rule that can block you from stopping enforcement turns a safety
control into an outage.

---

## 5. Status codes you will actually see

Verified live against the control plane:

| Code | When | Notes |
|---|---|---|
| `200` | Success, **or** an authorised query that matched nothing | See the tenant note below |
| `202` | Held for approval — **not applied** | |
| `400` | Missing `tenant`, or a destructive action with no reason | |
| `401` | No/invalid credential | |
| `403` | CSRF only, or self-approval denied | Not used for authorisation |
| `404` | Not authorised for this tenant, **or** it does not exist | Deliberately indistinguishable |
| `409` | Ambiguous target for an irreversible action | |
| `501` | Feature unavailable on this backend | e.g. alert stats on ClickHouse |

### The tenant subtlety worth knowing

A **cross-tenant** principal (`msoc-admin`, `cross-tenant-responder`) is
authorised for *any* tenant string, so an unknown tenant returns `200` with an
empty result — **not** `404`:

```bash
curl -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $CP_ADMIN_TOKEN" \
  "$CP/api/approvals?tenant=does-not-exist"     # → 200, empty
```

A **tenant-scoped** principal asking for a tenant outside its scope gets `404`.
So `404` means "outside your scope, or absent", and `200` with an empty body
does **not** prove the tenant exists. Do not use either code to enumerate
tenants — that is precisely what the design prevents.

---

## 6. Fleet operations

Fleet endpoints fan out to every agent in the tenant and return per-host results:

```json
{ "hosts": [ { "name": "agent-...", "ok": true, "data": { ... } } ] }
```

A host that is unreachable appears with `ok: false` rather than being omitted —
a partial fan-out must be visible, not silently smaller.

**Read `audit` honestly.** The control plane does not hash-chain decisions
centrally, so it reports:

```json
{ "audit": { "ok": false, "supported": false, "total": 0 } }
```

`supported: false` is a third state meaning *unverifiable here* — not *broken*,
and specifically not *verified*. Do not render it as a passing check. The
per-host chain is verifiable on the agent itself.

---

## 7. Agents (gRPC)

Only relevant if you are writing an agent. See
[`wire-contract.md`](wire-contract.md). Two properties matter most:

- The agent **dials out** and holds the command stream, so it works through
  customer NAT with no inbound access.
- Tenant comes from the **verified mTLS client certificate**, never the payload.
  An agent cannot assign itself a tenant, and local guardrails override any
  command the control plane sends — a signed command cannot strip the
  protect-list that keeps sshd and sudo alive.
