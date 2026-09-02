import {
  assistantStreamBody,
  assistantStreamError,
  installMockApi,
  mockData,
  RequestLog
} from "./support/mock-api";
import { attachBrowserDiagnostics, expect, expectNoReleaseBlockingBrowserErrors, socNavItem, test } from "./support/test";

/**
 * The Analyst Assistant, in the browser.
 *
 * WHAT THESE PIN, in order of how expensive the bug was:
 *
 *  1. DISABLED IS THE COMMON CASE. The assistant is opt-in and ships off, so
 *     the unconfigured deployment is what most operators see. It must render a
 *     calm "not configured" note — not an error, and above all not a crash.
 *     It crashed: `useAssistant` dereferenced `capability.agents` without a
 *     guard, and a 200 whose body omitted that key took the entire SOC route
 *     down through the error boundary.
 *  2. THE READ-ONLY GUARANTEE IS A UI PROPERTY. Three layers in the engine make
 *     containment impossible for the model. None of that is worth anything to
 *     an analyst who cannot see it, so the badge is load-bearing and is tested
 *     like a feature.
 *  3. THE WORK IS SHOWN. Every answer carries the reads that produced it. An
 *     answer an analyst cannot verify anchors judgement during an incident,
 *     which is worse than no answer.
 *  4. FREE TEXT GOES TO THE CONVERSATIONAL AGENT. It was hard-coded to
 *     `summarise-incident`, so "is this host compromised?" returned a handover
 *     report. The fix routes by the server's `conversational` flag; this
 *     asserts the routing over the wire rather than trusting the flag.
 *
 * WHY IT IS HERE AND NOT IN UNIT TESTS: AssistantPanel.test.tsx already drives
 * the component with an injected client. What jsdom cannot show is the panel
 * mounted inside the real drill slide-over, on the real route, talking to the
 * real fetch path — which is where every one of these failures actually
 * happened.
 */

const AGENTS = [
  { id: "ask", title: "Ask a question", conversational: true },
  { id: "explain-chain", title: "Explain this process chain" },
  { id: "summarise-incident", title: "Summarise this incident" }
];

const enabledAssistant = {
  "/api/assistant": { enabled: true, model: "gpt-oss:120b", agents: AGENTS }
};

/** Opens the SOC alert drill, which is where the panel is embedded. */
async function openDrill(page: import("@playwright/test").Page) {
  await page.addInitScript(() => {
    // The drill is reached from an alert, and the fixture alert carries a fixed
    // timestamp. Widen the window so it falls inside the default range.
    window.localStorage.setItem("soc.prefDefaultRange", "525600");
  });
  await page.goto("/");
  await page.getByRole("button", { name: /Credential file read/i }).click();
  const drill = page.locator('[data-panel="drill-down-slide-over"]');
  // NOT toBeVisible(): SlideOver renders its <aside> unconditionally and the
  // closed state is `transform: translateX(102%)`, which Playwright still
  // counts as visible. Probed: toBeVisible() here passes without ever clicking
  // the alert, so it could not have caught a drill that failed to open.
  await expect(drill).toHaveClass(/is-open/);
  return drill;
}

test.describe("Analyst Assistant — unconfigured deployment", () => {
  test("says it is not configured, and does not take the drill panel down", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    await installMockApi(page);

    const drill = await openDrill(page);
    const assistant = drill.getByRole("region", { name: "Analyst assistant" });

    await expect(assistant).toBeVisible();
    await expect(assistant).toContainText("Not configured on this deployment");
    await expect(assistant).toContainText("no model configured");
    // Off is not broken. An optional feature that is switched off must not be
    // coloured like a fault, or operators learn to ignore the colour that
    // means an incident.
    await expect(assistant.getByRole("alert")).toHaveCount(0);
    // And the rest of the drill still works.
    await expect(drill.locator(".soc-drill-hero")).toContainText("Credential file read");

    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });

  test("offers Behaviour & Intel in the nav, because nothing else can reach it", async ({ page }) => {
    await installMockApi(page);
    await page.goto("/");

    // Enrichment is on by default and the assistant is off by default, so this
    // is the common deployment, not the edge one: without this fallback the
    // behavioural baseline and the intel feed status would be unreachable.
    const behaviour = socNavItem(page, "Behaviour & Intel");
    await expect(behaviour).toBeVisible();
    await behaviour.click();
    await expect(page.locator('[data-panel="behaviour-modal"]')).toBeVisible();
  });
});

test.describe("Analyst Assistant — configured deployment", () => {
  test("shows the read-only guarantee and one button per task agent", async ({ page }) => {
    await installMockApi(page, { routes: enabledAssistant });

    const drill = await openDrill(page);
    const assistant = drill.getByRole("region", { name: "Analyst assistant" });

    await expect(assistant).toContainText("Read-only");
    // Task agents get buttons; the conversational agent does not — it has no
    // fixed job, so a one-click button would promise an action it cannot do.
    await expect(assistant.getByRole("button", { name: "Explain this process chain" })).toBeVisible();
    await expect(assistant.getByRole("button", { name: "Summarise this incident" })).toBeVisible();
    await expect(assistant.getByRole("button", { name: "Ask a question" })).toHaveCount(0);
    await expect(assistant.getByLabel("Ask the analyst assistant a question")).toBeVisible();
  });

  test("routes typed questions to the conversational agent, not to a task agent", async ({ page }) => {
    const recorder = new RequestLog();
    await installMockApi(page, {
      recorder,
      routes: {
        ...enabledAssistant,
        "/api/assistant/stream": assistantStreamBody({
          agent: "ask",
          content: "A shell started cat against /etc/shadow.",
          steps: [{ tool: "events", path: "/api/events", args: "{}", bytes: 812, duration: "120ms" }],
          model: "gpt-oss:120b",
          duration: "3.1s",
          grounded: true
        })
      }
    });

    const drill = await openDrill(page);
    const assistant = drill.getByRole("region", { name: "Analyst assistant" });

    await assistant.getByLabel("Ask the analyst assistant a question").fill("is this host compromised?");
    await assistant.getByRole("button", { name: "Send question" }).click();

    await expect(assistant).toContainText("A shell started cat against /etc/shadow.");

    const asks = recorder.matching(/^\/api\/assistant\/stream$/);
    expect(asks.length, "the question never reached the server").toBeGreaterThan(0);
    const sent = JSON.parse(asks[asks.length - 1].body ?? "{}") as { agent?: string; question?: string };
    expect(
      sent.agent,
      "free text must go to the agent the SERVER flagged conversational; a hard-coded task agent answers a different question than the one asked"
    ).toBe("ask");
    expect(sent.question).toBe("is this host compromised?");
  });

  test("shows the reads behind an answer, expandable", async ({ page }) => {
    await installMockApi(page, {
      routes: {
        ...enabledAssistant,
        "/api/assistant/stream": assistantStreamBody({
          agent: "explain-chain",
          content: "cat was started by bash.",
          steps: [
            { tool: "events", path: "/api/events", args: '{"exec_id":"exec-fixture-1"}', bytes: 812, duration: "120ms" },
            { tool: "process", path: "/api/process/exec-fixture-1", args: "{}", bytes: 233, duration: "40ms" }
          ],
          model: "gpt-oss:120b",
          duration: "3.1s",
          grounded: true
        })
      }
    });

    const drill = await openDrill(page);
    const assistant = drill.getByRole("region", { name: "Analyst assistant" });

    await assistant.getByRole("button", { name: "Explain this process chain" }).click();
    await expect(assistant).toContainText("cat was started by bash.");

    const trace = assistant.getByRole("button", { name: /2 sources consulted/ });
    await expect(trace).toBeVisible();
    await expect(trace).toHaveAttribute("aria-expanded", "false");
    await trace.click();
    await expect(trace).toHaveAttribute("aria-expanded", "true");
    // The endpoint and the cost, verbatim — that is what makes an answer
    // checkable rather than merely plausible.
    await expect(assistant).toContainText("/api/events");
    await expect(assistant).toContainText("/api/process/exec-fixture-1");
    await expect(assistant).toContainText("812 B");
    // Provenance: which model produced it, and how long it took.
    await expect(assistant.locator(".asst__meta")).toContainText("gpt-oss:120b");
  });

  test("labels an answer the model did not ground in telemetry", async ({ page }) => {
    await installMockApi(page, {
      routes: {
        ...enabledAssistant,
        "/api/assistant/stream": assistantStreamBody({
          agent: "summarise-incident",
          content: "This looks like credential theft.",
          steps: [],
          model: "gpt-oss:120b",
          duration: "0.9s",
          grounded: false
        })
      }
    });

    const drill = await openDrill(page);
    const assistant = drill.getByRole("region", { name: "Analyst assistant" });

    await assistant.getByRole("button", { name: "Summarise this incident" }).click();

    // Unmistakable, and an ARIA alert: an ungrounded answer that reads like a
    // grounded one is the worst output this feature can produce.
    const warning = assistant.getByRole("alert");
    await expect(warning).toContainText("Not grounded in telemetry");
    await expect(warning).toContainText("unverified");
  });

  test("surfaces a failed ask as an error, without losing the drill", async ({ page }) => {
    await installMockApi(page, {
      routes: {
        ...enabledAssistant,
        "/api/assistant/stream": { status: 503, body: { error: "model unreachable" } },
        "/api/assistant/ask": { status: 503, body: { error: "model unreachable" } }
      }
    });

    const drill = await openDrill(page);
    const assistant = drill.getByRole("region", { name: "Analyst assistant" });

    await assistant.getByRole("button", { name: "Summarise this incident" }).click();

    await expect(assistant.getByRole("alert")).toBeVisible();
    // The investigation around it survives — the assistant is an aid, and an
    // aid that takes the evidence with it when it fails is a liability.
    await expect(drill.locator(".soc-drill-hero")).toContainText("Credential file read");
    await expect(page.getByRole("heading", { name: /stopped rendering/i })).toHaveCount(0);
  });

  /**
   * THE UPSTREAM FAILURE MODES, AND WHY THEY ARE MOCKED RATHER THAN PROBED.
   *
   * On 2026-08-27 the assistant answered "the assistant could not complete this
   * request" on both live deployments. The cause was upstream: the model
   * gateway (a proxy to Ollama Cloud, no local GPU) shares ONE account across
   * thirteen tenant keys, and a neighbouring key ran 4,790 requests in 24h with
   * 3,309 of them 429'd. During its bursts our completions went from ~1s to
   * 52-129s. Every console failure sat inside that window.
   *
   * None of the live probes could have caught it: they deliberately never send
   * a question, because each one spends a real completion against a production
   * key on a provider that is already rate-limiting. That was the right call
   * for a live probe and it left the whole failure PATH untested. It costs
   * nothing here — the stream is stubbed, so these run in the mocked suite with
   * no provider, no key and no quota.
   *
   * WHAT THE SERVER SENDS: one sentence per condition, chosen from a fixed set
   * by assistant.OperatorMessage and never interpolated from the upstream
   * error. Both halves matter and they pull against each other — the sentence
   * has to distinguish "retry in a moment" from "this is broken", because those
   * are different operator actions, while still echoing no provider string, URL
   * or key to a browser. Every case below asserts both.
   *
   * This used to be one generic sentence for all four, pinned here with
   * test.fail; the classification landed in provider.go (status read BEFORE the
   * body is decoded, so a 429 is a 429 even when its `error` field is a bare
   * string) and the markers came off.
   */
  const UPSTREAM_CONDITIONS = [
    {
      key: "rate-limited",
      // Ollama Cloud's real 429 body is a bare string. That used to break the
      // Go decoder outright — `error` was typed as an object, so the whole body
      // failed to decode and a rate limit reached the operator as "provider
      // returned unreadable JSON". Now classified on status before the decode.
      serverSays:
        "the assistant is rate limited right now — too many requests are in flight. Try again in a moment.",
      // A CONCURRENCY limit, not a per-minute one — measured, the upstream body
      // reads "too many concurrent requests". "Wait a minute" is wrong advice,
      // so the wording deliberately says in flight rather than naming a delay.
      wants: /rate limit|too many|in flight|concurrent/i,
      why: "a rate limit clears when the other callers finish; the operator should retry, not escalate"
    },
    {
      key: "overloaded",
      serverSays: "the assistant's model service is busy right now. Try again in a moment.",
      wants: /busy|overloaded|capacity/i,
      why: "upstream accepted the request but cannot serve it; retrying shortly is the right action"
    },
    {
      key: "slow",
      serverSays: "the assistant ran out of time on this question. Try a narrower question, or ask again.",
      wants: /slow|timed out|took too long|ran out of time/i,
      why: "a timeout means the model is alive but slow; a narrower question or a quieter minute may succeed"
    },
    {
      key: "unreachable",
      serverSays: "the assistant could not complete this request",
      // The one condition for which the generic sentence is correct.
      wants: /could not complete|unavailable|unreachable/i,
      why: "genuinely broken is the one case the generic message already fits"
    }
  ] as const;

  for (const condition of UPSTREAM_CONDITIONS) {
    test(`an upstream ${condition.key} failure is reported to the operator without losing the drill`, async ({
      page
    }) => {
      await installMockApi(page, {
        routes: {
          ...enabledAssistant,
          "/api/assistant/stream": assistantStreamError(condition.serverSays)
        }
      });

      const drill = await openDrill(page);
      const assistant = drill.getByRole("region", { name: "Analyst assistant" });
      await assistant.getByRole("button", { name: "Summarise this incident" }).click();

      // 1. The operator is TOLD. A failure that renders as an empty answer, or
      //    as a spinner that stops, is the worst outcome — the analyst waits.
      const alert = assistant.getByRole("alert");
      await expect(alert, `an upstream ${condition.key} failure told the operator nothing`).toBeVisible();

      // 2. It says WHICH condition this is. Retry-in-a-moment, ask-something-
      //    smaller and this-is-broken are three different operator actions, and
      //    they all read as the third when they share one sentence.
      await expect(
        alert,
        `${condition.why} — the message must say which condition this is, not one sentence for all of them`
      ).toContainText(condition.wants);

      // 3. The evidence survives. The assistant is an aid; one that takes the
      //    investigation down with it is a liability.
      await expect(drill.locator(".soc-drill-hero")).toContainText("Credential file read");
      await expect(page.getByRole("heading", { name: /stopped rendering/i })).toHaveCount(0);

      // 4. NOTHING LEAKS. This is the constraint that made the message generic
      //    in the first place, and it has to survive the change that made the
      //    conditions distinguishable. Asserted on the whole panel, not just the
      //    alert, because a trace or a footer could carry it too.
      const shown = await assistant.innerText();
      for (const secret of ["openweights", "ollama", "api_key", "Bearer", "/v1/chat/completions"]) {
        expect(
          shown.toLowerCase(),
          `the assistant panel echoed "${secret}" to the browser on an upstream failure`
        ).not.toContain(secret.toLowerCase());
      }
    });
  }
});

test.describe("Assistant sidebar", () => {
  test("opens beside the dashboard rather than replacing it", async ({ page }) => {
    await installMockApi(page, { routes: enabledAssistant });
    await page.goto("/");

    await socNavItem(page, "Assistant").click();

    const sidebar = page.getByRole("complementary", { name: "Platform assistant" });
    await expect(sidebar).toBeVisible();
    // §5 of the assistant design: the sidebar is NOT one of the mutually
    // exclusive tool overlays. Routing it through them would close whatever
    // the analyst was reading in order to ask a question about it.
    await expect(page.locator('[data-panel="kpi-row"]')).toBeVisible();
    await expect(page.locator('[data-panel="live-event-stream"]')).toBeVisible();

    await sidebar.getByRole("button", { name: "Close assistant" }).click();
    await expect(sidebar).toBeHidden();
  });

  test("lists prior conversations and searches them on the server", async ({ page }) => {
    const recorder = new RequestLog();
    await installMockApi(page, {
      recorder,
      routes: {
        ...enabledAssistant,
        // Search is SERVER-side: the sidebar sends ?q= and renders whatever
        // comes back. Answering it from a fixed list here would have the test
        // pass while proving only that a client-side filter it does not have
        // works.
        "/api/assistant/chats": (request: { search: string }) => {
          const query = new URLSearchParams(request.search).get("q") ?? "";
          const chats = mockData.assistantChats.chats.filter((chat) =>
            chat.title.toLowerCase().includes(query.toLowerCase())
          );
          return { chats };
        }
      }
    });
    await page.goto("/");
    await socNavItem(page, "Assistant").click();

    const sidebar = page.getByRole("complementary", { name: "Platform assistant" });
    await expect(sidebar).toContainText("Why did cat read /etc/shadow?");

    const search = sidebar.getByLabel("Search conversations");
    await expect(search).toBeVisible();
    await search.fill("nothing-matches-this");
    await expect(sidebar).not.toContainText("Why did cat read /etc/shadow?");
    expect(
      recorder.matching(/^\/api\/assistant\/chats$/).some((r) => r.search.includes("nothing-matches-this")),
      "the search term must reach the server; a purely local filter cannot see message bodies"
    ).toBe(true);

    await search.fill("");
    await expect(sidebar).toContainText("Why did cat read /etc/shadow?");
  });
});
