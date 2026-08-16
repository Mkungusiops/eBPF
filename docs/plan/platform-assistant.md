# Platform Assistant — the menu-bar chat

Design for a persistent, cross-surface assistant reachable from the console nav,
with conversation history that spans a user's whole scope. Successor surface to
the per-panel `AssistantPanel` shipped in [`ai-and-console-reuse.md`](ai-and-console-reuse.md) §3.

Reference implementation studied: `/Users/jeff/Code/m` — a complete Next.js chat
product (streaming, history, search, projects, artifacts). What transfers and
what does not is in §3.

---

## 1. The invariant this design must not break

"Intelligence across the whole platform" collides directly with tenant
isolation ([`tenant-isolation-invariant.md`](tenant-isolation-invariant.md)).
Two things look alike and must be separated:

| | Scope | Why |
|---|---|---|
| **Chat history** | may span tenants | it is the *operator's* conversation, owned by them |
| **Answers inside it** | never widen | the tools read tenant-scoped endpoints as the caller |

The assistant's tools already forward the asking analyst's session cookie, so a
`tenant-analyst` sees their tenant and a `msoc-admin` legitimately sees more.
That property is what makes the assistant safe, and it is load-bearing.

**The rule: the menu-bar chat is a WIDER DOOR INTO THE SAME ROOM, never a bigger
room.**

The specific danger is not the design — it is a later optimisation. A global
chat surface *feels* like one pane of glass, which invites someone to give it a
service identity "so it can answer platform-wide questions". That single change
would silently defeat RLS and every isolation guard in
`internal/isolationguard`. It must be impossible to do by accident:

- No code path constructs an `assistant.Runner` without a caller `Cookie`.
- A test asserts a runner built with an empty cookie fails rather than falling
  back to a privileged identity — the ratchet idea from
  `internal/assistant/registry_test.go`.
- Every stored chat row carries `tenant_id` *and* the authoring user; reads
  filter by the caller's scope through `centralstore`, never a raw query.

## 2. What the user gets

One surface, reachable anywhere, that remembers. Concretely:

- Ask a question from any route without losing the route.
- Reopen yesterday's incident conversation and see what was concluded.
- Search across every past conversation by title *and* message content.
- For a `msoc-admin`: one history spanning the tenants they administer, with
  each answer still scoped to the tenant it was asked about.

## 3. What to take from `/Users/jeff/Code/m`

It is Next.js + Prisma + SQLite, single-tenant by design, with its own auth. Our
control plane is Go + Postgres with RLS and tenant-derived-from-session. So:
**copy the schema and the interaction model, re-implement the storage in Go.**

| From `m` | Take | Note |
|---|---|---|
| `Chat` / `Message` schema | **Yes — the shape** | see §4 |
| `compactedSummary` on Chat | **Yes** | the field people forget; long incident chats exceed context and need a summarisation path from day one, not retrofitted |
| Streaming, abortable mid-stream | **Yes — the behaviour** | non-negotiable for a 20s tool-calling answer in a sidebar |
| Search over titles AND content | **Yes** | title-only search makes history a graveyard |
| Projects (shared system prompt) | **Adapt** | maps onto per-incident or per-tenant grouping |
| Incognito (nothing persisted) | **Yes, and it matters more here** | an analyst may ask about a live breach before it is classified |
| Pinning | **Yes** | the incident you are working is the chat you reopen twenty times |
| Prisma/SQLite storage | **No** | Postgres + RLS |
| Its auth/session | **No** | we have OIDC + BFF sessions |
| Artifacts gallery, design mode | **No** | see `ai-and-console-reuse.md` §7a — the assistant does not render |

## 4. Data model

Postgres, tenant-partitioned, reached only through `centralstore`.

```
chat      id, tenant_id, user_id, title, mode, system_prompt,
          compacted_summary, pinned_at, created_at, updated_at
message   id, chat_id, role, content, model, tokens_in, tokens_out,
          steps_json, grounded, created_at
```

`steps_json` and `grounded` are stored per message, not recomputed. An answer's
provenance is part of the record: a post-incident review must be able to see
which endpoints an assisted conclusion was built from, and whether it was
grounded at all. Storing the text without them makes the history unusable as
evidence.

RLS on both tables, `ENABLE` **and** `FORCE`, matching every other
tenant-partitioned table.

## 5. UI/UX

The nav in the current console groups as OVERVIEW / RESPOND / DETECT &
INVESTIGATE / INTELLIGENCE / MANAGE / SETTINGS.

**Placement: top of INTELLIGENCE, above Watchlist.** Not a new group — it is an
intelligence surface, and inventing a group for one item makes the nav worse.
Use the `Sparkles` icon already carried by `AssistantPanel` so the two surfaces
read as one feature.

**It opens a right-hand panel; it does not navigate.** An analyst mid-triage
must not lose the alert queue. Same reasoning that put the assistant inside
drill panels rather than on a chat page. Persist width and open/closed state.

**Inside, top to bottom:**

- chat list + search (collapsible), pinned first
- the conversation, rendered by the existing `AnswerText` — one renderer, one
  place to get escaping right
- the same permanent **Read-only** badge and **N sources consulted** disclosure
  the drill assistant already carries
- composer with named starters, not a bare prompt

**Continuity with the drill assistant.** A conversation started from a drill
panel should be the same conversation, opened wider — carry the `exec_id` in as
context. Two assistants that look alike but do not share history is the worst
outcome: it teaches the operator that neither remembers.

**States, all three distinct and none of them red:** unconfigured (this
deployment has no model), unreachable (provider down), errored (this ask
failed). An optional feature that is switched off is not a fault.

## 6. Build order

1. **Schema + store access, with RLS tests.** ✅ `internal/chatstore`. Storage
   first, because getting tenant scoping wrong later means a migration under
   pressure.
2. **CRUD + search endpoints**, tenant-scoped. ✅
   `internal/controlplane/chat.go`.
3. **Streaming.** The current `/api/assistant/ask` is request/response; a
   sidebar conversation needs SSE and an abort path. ❌ **deferred — see below.**
4. **The panel shell** — list, search, conversation, composer. ✅
   `web/src/features/assistant/ChatSidebar.tsx`.
5. **Continuity** — drill panel hands its `exec_id` and conversation to the
   sidebar. ✅ `AssistantChatProvider`, mounted in `src/app/render.tsx`.

Steps 1–2 carry the security risk and deserve the review attention. 3–5 are
ordinary product work.

### Why 4–5 shipped before 3

Streaming was deferred, deliberately and with a cost. The sidebar is what makes
the store observable at all — without it, steps 1–2 are endpoints nobody calls
— so building it first bought end-to-end verification of the security-critical
half much sooner.

The interim cost is real: an analyst waits on a spinner for a tool-calling
answer instead of watching it work. It is bounded by the seam — every network
call goes through the injected `ChatApi` / `AssistantApi`, so SSE lands behind
those interfaces without touching a component. What it is NOT is free; §3 calls
abortable streaming non-negotiable and that judgement still stands.

### What step 1 was missing when it was first written

Worth recording, because none of it was visible in Go and all of it would have
failed on first contact with a database:

- **No `GRANT`s.** Both tables forced RLS and granted nothing to the app role
  `withScope` drops to — every statement would have failed permission denied.
- **A default role nobody creates.** `NewPGStore` defaulted to `ebpf_soc_app`;
  every migration creates `ebpf_app`. Now `centralstore.AppRole` is exported and
  is the single source of truth, and an empty role is a startup error.
- **An unbounded connection pool** — the exact root cause of a previous total
  control-plane outage. Chat now has its own small bounded pool rather than
  sharing centralstore's, so history load cannot starve telemetry reads.

The lesson generalises: unit tests that never touch Postgres cannot tell a
working store from one that is merely well-typed.

## 7. What not to do

- **Do not give the runner a service identity**, however convenient for
  "platform-wide" answers. §1.
- **Do not render model output as markup.** `ai-and-console-reuse.md` §7a.
- **Do not build a second answer renderer.** Reuse `AnswerText`.
- **Do not ship history without search.** Untitled, unsearchable chats are
  write-only.
- **Do not persist incognito conversations** anywhere, including logs.
