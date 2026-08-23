# The analyst assistant

An LLM with **read-only** access to the platform's own telemetry, so an analyst
can ask *"why did this score 117?"* and get an answer grounded in the actual
process chain instead of a guess.

**Status: shipped.** Backend in
[`engine/internal/assistant/`](../../engine/internal/assistant/), control-plane
routes in `engine/internal/controlplane/{assistant,chat}.go`, chat history in
`engine/internal/chatstore/`, console surfaces in `web/src/features/assistant/`.
Off by default. Streaming shipped 2026-08-19.

---

## The security decision

An LLM next to a containment console is a **security decision, not a feature
decision**. This platform can `SIGKILL` processes and sever devices from the
network. The [threat model](../plan/threat-model.md) already names the risk in
EN-2 — dual control exists to stop *one actor containing many hosts* — and an
agent holding containment tools is exactly that actor, minus the second pair of
eyes.

So: **the assistant gets queries, a human presses the button.**

That is not enforced by a prompt. A prompt is a request; a registry is a
constraint. Read-only is structural here, in three independent layers.

### Layer 1 — the unsafe state is unrepresentable

`Tool.method` is unexported and `NewReadTool` is the only constructor, hard-coding
`GET`. There is no `NewWriteTool` and no exported field that would let a caller
change the method afterwards. Code outside the package **cannot express** "a tool
that POSTs".

### Layer 2 — the registry refuses, loudly, at wiring time

`Registry.Register` rejects a non-GET method, a path on the containment
**denylist**, or a path outside the read **allowlist**. `MustRegister` panics, so
a mistake fails the process at startup rather than surfacing mid-incident.

Both lists exist because they fail differently. A denylist alone fails open: a
containment route added tomorrow under an unpredicted name would pass the check
and be reachable. The positive allowlist means a new endpoint is **invisible to
the assistant until someone deliberately adds it**.

Today the allowlist is `/api/alerts`, `/api/alert-stats`, `/api/events`,
`/api/decisions`, `/api/process/`, `/api/choke/processes`, `/api/choke/devices`,
`/api/choke/device-state`, `/api/choke/device-flows`, `/api/fleet/hosts`,
`/api/fleet/state`, `/api/policies`, `/api/policy-stats`, `/api/system-health`.

The device and fleet entries are the **reporting halves** of pairs whose acting
halves are on the denylist: read `device-state`, never `device-mode`; read
`fleet/state`, never `fleet/preset`.

`/api/mitre` used to be on this list and is gone. **No such route ever existed
on either server**, and no tool was ever registered for it — a phantom
capability, allowlisted and unreachable, while the shared prompt invited the
model to reason about ATT&CK coverage. `TestEveryAllowlistedPathIsServed` now
fails the build on any allowlist entry the API does not serve, and
`TestNoAllowlistEntryIsUnused` fails on any entry no tool reads.

### Layer 3 — the transport refuses regardless

The `http.RoundTripper` handed to tools rejects any non-GET request. A tool that
builds its own request still cannot mutate. This is the backstop for the case the
first two miss: someone editing this package later who did not read `doc.go`.

Layer 2 catches mistakes early and legibly. Layer 3 catches them absolutely. Both
exist because the cost of being wrong once is an LLM quarantining a production
host with no operator involved.

### The ratchet

`registry_test.go` enumerates every registered tool and fails the build if any
maps to a mutating method or a containment path. Critically, it also asserts the
**denylist still covers every containment endpoint the API actually serves** — so
adding a containment route without updating this package breaks the build rather
than silently widening what the assistant can reach.

That direction is the point. The danger is not a tool pointed at a known-bad
path; it is a *new* bad path appearing and nobody remembering this package
exists. The fleet-wide entries (`/api/fleet/preset`, `/api/fleet/thaw`,
`/api/fleet/thresholds`) were missed by the hand-written list and found by that
test — they are the most dangerous ones, since a fleet threshold change applies
to every host at once.

Same idea as [`internal/isolationguard`](../../engine/internal/isolationguard/),
which does this for tenant isolation.

---

## Authorization: the analyst's own session

`Runner.Cookie` carries the **asking analyst's session**, forwarded verbatim onto
every tool call. The assistant therefore sees **exactly what the person asking
can see** — same tenant, same scope, same denials.

This is a deliberate decision, not plumbing. Giving the assistant its own
privileged identity would build a *confused deputy*: an analyst could ask it to
summarise data their own session is refused. Tenant isolation is not re-derived
for the assistant; it inherits it.

---

## The tools

Thirteen, all `GET`, all named for what an analyst would ask:

| Tool | Reads | For |
| --- | --- | --- |
| `list_alerts` | `/api/alerts` | What happened and when |
| `alert_statistics` | `/api/alert-stats` | "How bad is it", trends |
| `list_events` | `/api/events` | Raw execve/open/connect when an alert isn't enough |
| `list_decisions` | `/api/decisions` | The tamper-evident enforcement audit chain |
| `process_tree` | `/api/process/{exec_id}` | The chain that led to a process — the primary tool for justifying a score |
| `list_choked_processes` | `/api/choke/processes` | What is currently throttled, tarpitted or quarantined |
| `list_devices` | `/api/choke/devices` | The device inventory — what is on the network |
| `device_plane_state` | `/api/choke/device-state` | Whether the device data plane is **armed or audit-only** |
| `device_flows` | `/api/choke/device-flows` | Which device talked to which |
| `list_fleet_hosts` | `/api/fleet/hosts` | Which hosts report in, and whether a sensor went quiet |
| `fleet_state` | `/api/fleet/state` | Per-host enforcement posture |
| `list_policies` | `/api/policies` | Detection coverage, including ATT&CK mapping |
| `policy_stats` | `/api/policy-stats` | Which rules actually fire — a noisy rule is not a busy estate |
| `system_health` | `/api/system-health` | Whether the telemetry can be trusted at all |

### Why it grew from six

Six covered alerts, events, decisions and one process tree. That was the right
start and the wrong end state, because the console mounts this assistant on
**eight** surfaces and three of them — Choke Assurance, Devices, Devices
Assurance — are about the device plane and the fleet, which none of those six
could see. The panel rendered *"Investigating the device fleet"* above an
assistant with no way to read a device.

An assistant that cannot see its own subject does not decline. It answers from
the nearest data it has.

### The `alert_statistics` parameter that was never read

`alert_statistics` advertised a `span` argument (`"24h"`, `"7d"`) and put it on
the query string verbatim. **Neither server has ever read `span`** — both read
`window_min`, in minutes. So every trend answer was computed over the server's
default **30-minute** window while the model believed it had asked for a day,
and narrated it as a day.

The trace looked right. The citation looked right. The window was wrong. No
prompt can fix that, which is why the translation now happens in the tool's
builder and `TestAlertStatisticsAsksTheWindowTheServerActuallyReads` pins it. An
unparseable span is an **error handed back to the model**, never a silent
fallback — quietly substituting a different window is how the original defect
produced confident answers about the wrong day.

`Registry.List()` sorts by name so the prompt is stable. An unstable tool order
changes the prompt, which changes the model's output for an unchanged question —
and an assistant whose answer drifts with map iteration order cannot be reasoned
about during an incident.

Path construction keeps the fixed path and the variable part separate, and
`Call` re-checks the joined suffix for `..` and `/` at the one place they meet.

---

## Grounding

`Answer.Grounded` is a field, not a hope. The prompt asks the model to ground its
answer in tool output; that field is what records whether it did. An assistant
that guesses a severity is worse than no assistant, because an analyst acts on
it. Refusal behaviour is part of the product.

The loop is bounded by `MaxCalls` (default 6). A model that keeps asking for data
will keep asking forever, and an incident console cannot wait — better a
truncated answer that says so than an open-ended request holding a browser tab.

### What grounding does NOT catch

Measured on the live rig, 2026-08-19. Asked *"How many critical alerts in the
last 24 hours?"*, `gpt-oss:120b` replied:

> "5828 critical alerts in the last 24h … **policy_stats shows no single rule
> dominates**, so it reflects a genuinely busy estate rather than one noisy
> policy."

It had called **exactly one tool: `alert_statistics`.** It never ran
`policy_stats`.

`Answer.Grounded` was `true`, and correctly so — the answer *was* built on a real
read. Grounding asks "did the model read anything at all", which catches the
model that answers from imagination under urgent framing. It cannot catch the
model that reads one thing and attributes a *second* claim to a source it never
opened.

That second failure is the more dangerous one on a SOC console, because it
arrives **wearing a citation**. The analyst sees a named source and a plausible
conclusion, and the only way to know it is unfounded is to expand the trace and
count.

Two things now guard it, because a prompt alone is a request:

- `sharedRules` carries an explicit clause — *never cite a tool you did not
  call*, and *call the tool before the claim* — pinned by
  `TestEveryAgentCarriesTheCitationRule` so it cannot be shortened away.
- [`scripts/e2e/assistant.sh`](../../scripts/e2e/assistant.sh) extracts every
  tool name mentioned in the answer prose and fails if any is absent from the
  trace. That check runs against a live model, which is the only place this
  behaviour exists.

The general lesson: **"grounded" is a floor, not a guarantee.** It says an
answer touched the data. It does not say every sentence in it did.

### When grounding ate the greeting

Two rules in this package were mutually exclusive, and both were right.

`f451eb1` taught the `ask` agent to greet a greeting like a colleague would — a
few words, no numbers, no wall of alert statistics. Answering "Hello" correctly
therefore requires calling **no tools**. But a tool-free answer was treated as
ungrounded and *replaced* with the refusal text. So, measured live, typing
"Hello" returned:

> "The assistant could not ground an answer in this engine's data … Nothing is
> reported because an unverified answer is not evidence."

The operator is scolded for saying hello, by something that looks broken.

The resolution is not to weaken grounding. It is to notice what grounding
protects against: **unverified claims.** A reply that claims nothing has nothing
to verify. *"Hi — quiet right now, what do you need?"* cannot mislead an analyst
about the estate, because it says nothing about the estate.

`assertsNothing` is deliberately conservative, because the cost of being wrong is
a fabricated incident summary getting through:

| Condition | Why |
| --- | --- |
| under 60 words | a greeting is short by instruction; anything long is an answer |
| **no digits at all** | every fact this assistant could invent — a count, a score, a PID, a timestamp, a technique id — contains one |
| conversational agents only | a task agent must never return a chat reply instead of doing its job |

`Answer.Grounded` still reports `false`. The flag stays honest; only the
replacement is skipped. `TestAnUngroundedCLAIMIsStillRefused` covers the half
that matters more — a single digit disqualifies a tool-free reply.

---

## Provider and configuration

The provider is **OpenAI-compatible** and takes its base URL from configuration,
which is why a self-hosted endpoint needs no new code path. The API key is read
from the environment **server-side and never crosses to the browser**: the
console talks to the engine, the engine talks to the model.

The assistant is **off unless configured**:

```bash
ebpf-engine -assistant-url https://your-endpoint/v1 -assistant-model <model-id>
```

The key comes from the environment (`assistant.Config.APIKeyEnv`), never a flag —
flags land in `/proc` and in `ps` output.

For deployments, set `ASSISTANT_URL` and `OPEN_WEIGHT_API_KEY` and the
provisioner wires it up, writing the key to a `0600` env file read by systemd:

```bash
ASSISTANT_URL=https://your-endpoint/v1 \
OPEN_WEIGHT_API_KEY=sk-... \
  ./scripts/deploy/single-tenant-ubuntu.sh
```

Setting `ASSISTANT_URL` without a key is a **warning, not a failure** — the
engine reports the assistant unavailable and the console says so, which is a
working deployment minus one optional feature.

---

## Surfaces: the assistant knows which panel it is on

The console mounts the assistant on eight panels. Until 2026-08-19 all eight sent
an identical request — an agent id, a question, sometimes an exec id — so the
model could not tell a device inventory from a process tree from a KPI tile.
`KpiDrillBody` passed nothing at all.

`Surface` ([`surface.go`](../../engine/internal/assistant/surface.go)) closes
that. Each mount names itself, and the server uses it for two things:

1. **Which task buttons to offer.** `GET /api/assistant?surface=devices` returns
   the agents that can be answered there. "Explain this process chain" is the
   right button over a process tree and a nonsense one over a device inventory,
   and an operator offered a button that cannot apply learns to distrust the row.
2. **A short briefing folded into the system prompt** — what the analyst is
   looking at and which tools answer questions asked from here.

| Surface | Panel | Task agents offered |
| --- | --- | --- |
| `alert-drill` | SOC drill-down slide-over | explain-chain, summarise-incident |
| `process-action` | Process action modal | explain-chain, summarise-incident |
| `graph` | Correlation graph selection | explain-chain, summarise-incident |
| `kpi-drill` | KPI drill | summarise-incident |
| `choke-process` | Choke Gateway process drill | explain-chain, summarise-incident, assess-containment |
| `choke-assurance` | Choke Assurance | assess-containment |
| `devices` | Devices | assess-device-exposure |
| `devices-assurance` | Devices Assurance | assess-device-exposure |

### Briefings describe; agents instruct

Each briefing says exactly two things: **what the analyst is looking at**, and
**which tools read that subject**. None of them says how to answer.

That restraint was learned by breaking it, and the failure is worth recording
because the obvious fix did not work.

The first version carried imperatives — *"lead with the arming state"*,
*"start from process_tree"* — reasonable-sounding, and duplicated from the task
agents that already say so. The effect, measured live: **"Hello" on the Devices
Assurance panel returned a device-plane posture report.** The briefing's
imperative outranked the `ask` agent's explicit greeting clause. That is the
defect `f451eb1` fixed, reintroduced through a different door, and it was
invisible to every unit test because the prompt was still perfectly well-formed.

**Moving the briefing earlier in the prompt did not fix it.** That is the whole
lesson. The problem was never ordering — an instruction competes with an
instruction wherever you put it. Prompt-position tuning is the tempting fix and
it buys nothing here.

The durable improvement is to split by **kind**, not position:

| | Says | Example |
| --- | --- | --- |
| **Surface** | where you are, what you can read here | "This panel is about whether DEVICE containment would work. Tools that read this subject: `device_plane_state`, `list_devices`, `device_flows`." |
| **Agent** | what to do, and when not to do it | "Lead with the plane's arming state in the first sentence." |

A task agent that wants *"lead with X"* states it in its own instructions, where
it applies to that task and nothing else.

**Be honest about what this did and did not achieve.** It removed the duplicated
directives and it is the right structure. It did **not** restore greeting
behaviour on a panel: asked "Hello" on Devices Assurance, the model still reads
"this panel is about whether device containment would work", calls the device
tools, and replies with a short device status.

That residual behaviour was left alone, deliberately, because it is not the
`f451eb1` failure. That bug returned an *irrelevant* process-chain analysis to
someone saying hello. This returns a brief, accurate line about the thing the
analyst is currently looking at — which on a drill panel is defensible product
behaviour, not a defect. The place greetings actually happen is the sidebar
opened from the nav, which carries **no surface at all**, and there the greeting
path is clean.

The lesson worth carrying: a model weighing strong context against a
conditional instruction will often choose the context, and no amount of prompt
rearrangement reliably changes that. Decide which outcome you actually want per
surface, rather than fighting the prompt.

`TestSurfaceBriefingsDescribeRatherThanInstruct` fails the build on imperative
phrasing in a briefing, and `TestAgentInstructionsOutrankTheSurfaceBriefing`
keeps the ordering right as a second line of defence. `Runner.systemPrompt` is a
named method rather than three lines inside `Run`, so the assembly has one
definition and the test can assert the real one — a test that reassembles the
prompt itself proves only that the test agrees with the test.

**A surface is framing, not authorization.** It changes what the model is *told*,
never what it may *read* — the registry and the caller's session remain the only
things that decide that. A forged surface string mis-frames an answer for the
person who forged it and does nothing else. An unknown surface degrades to a
generic briefing rather than failing, because the console and the engine deploy
separately and will skew.

The conversational `ask` agent is offered on **every** surface, asserted by
`TestEverySurfaceOffersTheConversationalAgent`. Whatever else a panel shows, the
analyst must always be able to just ask.

### The free-text routing defect

`AssistantPanel` hard-coded `summarise-incident` for typed questions, on all
eight panels. Ask *"is this host compromised?"* and receive a shift handover.

This is the **same defect** that was found and fixed in the sidebar — which had
hard-coded a *different* agent, and was fixed alone. The `Conversational` flag
exists precisely for this and the panel already read it, to filter buttons; it
simply did not use it to route. Both surfaces now derive the agent from one
place (`useAssistant.conversationalAgent`), and
`AssistantPanel.test.tsx` fails against the old behaviour.

---

## Streaming

`POST /api/assistant/stream` returns `text/event-stream`:

```
event: step     one completed tool call
event: answer   the finished Answer; always last on success
event: error    the run failed; always last on failure
```

**It streams the investigation, not the prose.** The latency in an answer is not
token generation — it is up to six reads against the engine's own API before the
model has a word to say. `AssistantPanel`'s design notes say progress must be
named rather than spun; until `Runner.OnStep` existed there was nothing to name
it with, and the panel showed a fixed "Reading telemetry…" that was true of every
run and informative about none. It now names the last completed read and the
count so far.

Three details that are load-bearing:

- **`X-Accel-Buffering: no`.** Both deployments sit behind nginx, which
  otherwise buffers the whole response — a stream that works on loopback and not
  in production is the default outcome.
- **Frames are blank-line terminated**, or the browser holds each event until
  the next arrives and progress is permanently one step stale.
- **A stream that ends without `answer` or `error` is a failure.** Silence must
  never be read as success; the panel would render an empty answer as though the
  assistant had found nothing to say.

`askStream` is **optional** on the `AssistantApi` interface and callers fall back
to `ask`. An assistant that only works over SSE stops working the first time it
meets a buffering proxy.

## Authentication

Both control-plane endpoints now require a principal. This gate was missing:
because the tools forward the caller's cookie and every read endpoint checks the
tenant, an unauthenticated caller could never obtain data — the tool calls failed
and the run returned the ungrounded refusal. But it could still **start a run**,
driving a full tool-calling loop against a paid inference endpoint.
Confidentiality was intact; cost and availability were not.

"It fails safe downstream" is not a reason to leave the front door open, and the
answer to *who may ask this assistant anything* should not be an emergent
property of six other handlers.

## Conversation memory

Until this existed, **`Run` built its message list from exactly two things: the
system prompt and the question just asked.** Prior turns were never passed to
the model.

The effect was specific and was visible in the product. The control plane was
faithfully persisting every exchange to Postgres, the console was rendering the
thread, and the model saw none of it — so every message was the analyst's first.
"What about that host?" had no referent. "Are you sure?" was answered as a fresh
question about certainty. The tools were fine; the *conversation* did not exist.

Where the thread comes from differs by deployment, and the difference matters:

| Deployment | Source | Why |
|---|---|---|
| Control plane | The **chat store**, by `chat_id` | Authoritative — it is what was actually said, and `ListMessages` takes the caller's `Scope`, so another operator's chat id returns nothing rather than their conversation. |
| Single-tenant engine | The **request body** | It has no chat store at all (see `handleAssistantChatsUnavailable`). |

`SanitiseHistory` bounds and strips both paths identically:

- **Only `user` and `assistant` roles survive.** A forged `system` turn would
  otherwise let a request body rewrite the operating instructions — including
  the evidence rules — from a field the console never sets.
- **Tool-call structures are dropped.** Replaying a tool result the server did
  not produce is how a fabricated *"policy_stats shows…"* gets laundered into the
  transcript as though a tool had returned it — the exact failure the shared
  rules spend a paragraph forbidding.
- **Bounded in turns (20) and bytes (16KB), oldest dropped first.** An unbounded
  thread on a paid inference endpoint is a cost incident, and a long enough one
  pushes the system prompt out of the model's effective attention, silently
  disabling the grounding discipline.

Ordering is system prompt → history → new question. History sits *between* them
rather than being folded into the question, because the model has to tell what
is being asked **now** from what was asked ten minutes ago; flattening a thread
into one user turn produces answers to the wrong message in it.

Nothing here widens what may be **read**: tool authorization comes from the
session cookie, which none of this touches. What a caller can do on the engine
is mislead the model about their own earlier conversation, which misleads only
themselves.

---

## Knowing the product, not just the estate

Every other tool answers *"what is happening on the estate"*. None answered
*"what does this word mean here"* — and an analyst asks that constantly: what is
the difference between throttle and tarpit, what is severity derived from.

The assistant had two ways to handle those and both were bad. It could refuse —
*"I cannot ground an answer in this engine's data"* — which is technically true
and reads as a malfunction, because the question never needed telemetry. Or it
could answer from the model's general knowledge of security products, producing
confident, plausible, generic prose about what a tarpit *usually* is, in a
console where "tarpit" is a specific thing with specific thresholds. The second
is worse: it is indistinguishable from a correct answer, and it teaches the
analyst something false about the tool they are about to press a button in.

`internal/platformdoc` writes the product's own vocabulary down and serves it at
`/api/platform-doc`, grounded exactly like every other fact. The numbers in it
are the numbers in the code; when a threshold changes, it changes with it — a
glossary that drifts from the implementation is a confident liar, and worse than
nothing because the assistant will cite it.

---

## Filters, not eyeballing

`list_alerts` used to take only `limit` and `since`, so answering *"any critical
alerts on this host in the last hour"* meant pulling 200 rows and reading them —
which the model did, badly, and which silently truncated the moment the answer
lay outside the newest 200. Both `list_alerts` and `list_events` now take server
-applied filters (severity, host, exec id, binary, policy, free text).

A filter the server applies is cheaper **and honest**; a filter the model applies
by reading is neither. An invalid enum value is an error handed back to the
model, never a silent drop — that silent-drop behaviour is exactly how the
`alert_statistics` `span` bug produced confident answers about the wrong day.

---

## What is not built

- **Cross-tenant (MSOC) scope.** The assistant is bounded by the caller's session,
  so an MSOC-role query spanning tenants is not a distinct capability yet.
- **Token-level streaming.** The stream carries tool steps and one final answer,
  not a token feed. Steps are where the wait actually is.
- **Conversation compaction.** `chat.compacted_summary` exists in the schema and
  nothing writes it. History is bounded by truncation rather than summarised, so
  a long incident conversation loses its oldest turns rather than exceeding
  context.

---

## Verifying it on a live deployment

[`scripts/e2e/assistant.sh`](../../scripts/e2e/assistant.sh) (part of
`./scripts/e2e/all.sh`) runs against a **deployed** console with a real session,
because all three defects above were invisible to unit tests: each produced a
confident, well-formed, wrong answer rather than an error. It asserts the
anonymous refusal, the per-surface agent lists, that a stream emits tool steps
before exactly one answer event, and that the answer comes back grounded.

It skips cleanly when the assistant is not configured — an opt-in feature that
is switched off is not a failure.

## Related

- [`engine/internal/assistant/doc.go`](../../engine/internal/assistant/doc.go) — the rationale, in the source
- [`../plan/platform-assistant.md`](../plan/platform-assistant.md) — the menu-bar chat design and its history
- [`behaviour-and-intel.md`](behaviour-and-intel.md) — the two enrichment layers the newest tools read
- [`../plan/ai-and-console-reuse.md`](../plan/ai-and-console-reuse.md) — the work plan this came out of
- [`../plan/threat-model.md`](../plan/threat-model.md) — EN-2, the risk this design answers to
- [`../plan/tenant-isolation-invariant.md`](../plan/tenant-isolation-invariant.md) — the isolation the assistant inherits
