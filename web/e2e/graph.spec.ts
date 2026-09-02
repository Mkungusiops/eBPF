import type { Locator, Page } from "@playwright/test";

import { RequestLog, installMockApi, type MockApiOptions } from "./support/mock-api";
import { expect, socNavItem, test } from "./support/test";

/**
 * The correlation graph past "it opens".
 *
 * WHAT THESE PIN: the graph is the only surface where an operator picks a
 * containment target out of a picture rather than a list, so three things have
 * to be true at once and none of them is checked by rendering the canvas:
 *
 *   · the rail describes the node that was CLICKED — subject, kind, and the
 *     concrete processes behind it. A rail that lags the selection by one click
 *     hands the operator the wrong exec_id, and the modal will happily SIGKILL
 *     it;
 *   · a context node (policy/file/peer/device) is EVIDENCE, not a target. It
 *     resolves its processes through its edges, and when the records behind it
 *     carry no exec_id it has to say so — "nothing to enforce against" and "your
 *     filter hid them" are the same empty box otherwise;
 *   · the ladder's two safety interlocks — a reason before a destructive rung,
 *     a second press before the irreversible one — survive being rendered
 *     inside this modal, and Escape dismisses the modal WITHOUT dismissing the
 *     graph underneath it.
 *
 * WHY HERE AND NOT IN UNIT TESTS: buildCorrelationGraph is pure and unit
 * tested; nothing below re-tests it. What jsdom cannot observe is the part
 * under test here — an imperative D3 island that owns the contents of a real
 * <svg>, with layout, a running force simulation, hit-testing on a <g>, and a
 * zoom transform between the click and the datum. The selection round-trip
 * (SVG click → D3 restyle → React setState → rail → modal) only exists in a
 * browser, and the modal's Escape interlock is a capture-phase window listener
 * racing another window listener — a real event loop or nothing.
 *
 * FIXTURES: /api/alerts and /api/events are replaced wholesale (the default
 * single-alert fixture yields one process, one policy and one file — no
 * lineage, one kind of context node, and nothing to distinguish a peer from a
 * device). The replacement is built from what graphModel.ts actually reads:
 * exec_id → binary label, parent_pid on process_exec → lineage edges,
 * policy_name → policy node, path → file node, dest_ip → peer or device by
 * RFC1918. It yields 4 process nodes, 2 policy, 2 file, 1 peer, 1 device and
 * 8 edges. The default stream frames are suppressed because they inject one
 * more alert/event pair (exec-fake-1, "cat") that would add a node and an edge
 * these tests do not describe.
 */

const at = "2026-06-25T09:00:00Z";

/**
 * Two scored processes (attack + threat) plus their lineage. `process` is an
 * absolute path deliberately: processChainFromAlert returns it as a one-element
 * chain, which is what a host whose ancestors pre-date the engine really sends.
 */
const graphAlerts = [
  {
    id: "alert-cat",
    timestamp: at,
    severity: "critical",
    title: "Credential file read",
    description: "cat read the shadow file",
    policy_name: "override-credential-read",
    process: "/usr/bin/cat",
    exec_id: "exec-cat",
    pid: 4242,
    score: 44,
    agent: "alpha-edge",
    mitre_id: "T1003",
    tactic: "Credential Access"
  },
  {
    id: "alert-curl",
    timestamp: at,
    severity: "medium",
    title: "Outbound connection to a flagged host",
    description: "curl reached a public address",
    policy_name: "outbound-connections",
    process: "/usr/bin/curl",
    exec_id: "exec-curl",
    pid: 4310,
    score: 18,
    agent: "alpha-edge"
  }
];

const graphEvents = [
  // The lineage root. parent_pid 1 is never observed in this window, so the
  // model must draw no edge for it.
  {
    id: "ev-bash",
    timestamp: at,
    event_type: "process_exec",
    process: "/bin/bash",
    exec_id: "exec-bash",
    pid: 4100,
    parent_pid: 1,
    agent: "alpha-edge"
  },
  {
    id: "ev-cat-exec",
    timestamp: at,
    event_type: "process_exec",
    process: "/usr/bin/cat",
    exec_id: "exec-cat",
    pid: 4242,
    parent_pid: 4100,
    agent: "alpha-edge"
  },
  {
    id: "ev-cat-open",
    timestamp: at,
    event_type: "file_open",
    process: "/usr/bin/cat",
    exec_id: "exec-cat",
    pid: 4242,
    parent_pid: 4100,
    policy_name: "override-credential-read",
    severity: "critical",
    path: "/etc/shadow",
    agent: "alpha-edge"
  },
  {
    id: "ev-curl-exec",
    timestamp: at,
    event_type: "process_exec",
    process: "/usr/bin/curl",
    exec_id: "exec-curl",
    pid: 4310,
    parent_pid: 4100,
    agent: "alpha-edge"
  },
  // Public destination → a peer node.
  {
    id: "ev-curl-public",
    timestamp: at,
    event_type: "network_connect",
    process: "/usr/bin/curl",
    exec_id: "exec-curl",
    pid: 4310,
    policy_name: "outbound-connections",
    dest_ip: "203.0.113.10",
    dest_port: 443,
    agent: "alpha-edge"
  },
  // RFC1918 destination → a DEVICE node, not a peer.
  {
    id: "ev-curl-lan",
    timestamp: at,
    event_type: "network_connect",
    process: "/usr/bin/curl",
    exec_id: "exec-curl",
    pid: 4310,
    policy_name: "outbound-connections",
    dest_ip: "10.0.0.25",
    dest_port: 8443,
    agent: "alpha-edge"
  },
  // No exec_id: a real shape on this wire, and the one that makes a node
  // un-actionable. The file it touched is still evidence and still drawn.
  {
    id: "ev-head-open",
    timestamp: at,
    event_type: "file_open",
    process: "/usr/bin/head",
    pid: 4390,
    path: "/etc/passwd",
    agent: "alpha-edge"
  }
];

/**
 * The health check that is the host talking to itself — see isLoopbackPeer.
 *
 * It runs its OWN binary rather than riding on curl, and that is load-bearing.
 * Attached to curl the event contributes NOTHING observable when it is handled
 * correctly: curl's process node and the outbound-connections policy node both
 * already exist from other events, so delivering this event and dropping it on
 * the floor produce byte-identical DOM — "the canvas refused to draw loopback
 * as a destination" and "the route override never reached the page" become the
 * same green. With its own binary the event's ARRIVAL is visible as a fifth
 * process node while its DESTINATION is still refused, so the two claims fail
 * separately and each test below carries a positive control.
 */
const loopbackEvent = {
  id: "ev-healthcheck-loopback",
  timestamp: at,
  event_type: "network_connect",
  process: "/usr/bin/healthcheck",
  exec_id: "exec-healthcheck",
  pid: 4501,
  policy_name: "outbound-connections",
  dest_ip: "127.0.0.1",
  dest_port: 8090,
  agent: "alpha-edge"
};

async function openGraph(page: Page, options: MockApiOptions = {}): Promise<Locator> {
  await installMockApi(page, {
    ...options,
    streamFrames: [],
    routes: { "/api/alerts": graphAlerts, "/api/events": graphEvents, ...options.routes }
  });
  // The graph builds from range-filtered data and the fixtures carry a fixed
  // timestamp, so the window has to be wide enough to contain them.
  await page.addInitScript(() => {
    window.localStorage.setItem("soc.prefDefaultRange", "525600");
  });
  await page.goto("/");
  await socNavItem(page, "Correlation Graph").click();

  const surface = page.locator('[data-panel="process-correlation-graph-modal"]');
  await expect(surface, "the correlation graph surface did not open").toBeVisible();
  // Wait for the simulation to have painted, so a click lands on a node rather
  // than on empty canvas.
  await expect(
    surface.locator("svg.soc-correlation-graph g.soc-graph-node"),
    "no nodes were drawn, nothing under test"
  ).not.toHaveCount(0);
  return surface;
}

/** A node on the canvas, addressed by the full label the renderer publishes. */
function graphNode(surface: Locator, fullLabel: string): Locator {
  return surface.locator(`svg.soc-correlation-graph g.soc-graph-node[aria-label="${fullLabel}"]`);
}

/** One `dt`/`dd` pair out of the selection rail's identity list. */
function railField(page: Page, surface: Locator, label: string): Locator {
  return surface
    .locator(".soc-graph-detail dl > div")
    .filter({ has: page.getByText(label, { exact: true }) })
    .locator("dd");
}

/**
 * Click a node and wait for the rail to describe it.
 *
 * `force` is not laziness. Clicking a node starts a d3 drag gesture, which
 * re-heats the force simulation, and the simulation never comes back to a full
 * stop: measured here, a node still drifts ~0.002px per second thirty seconds
 * after the click. That is invisible to an operator but it is motion, so
 * Playwright's stability check (two identical bounding boxes in consecutive
 * frames) can never pass and every click after the first one would time out.
 * The drift is far smaller than a node, so the click still lands where the
 * assertion below proves it landed.
 */
async function selectNode(surface: Locator, fullLabel: string): Promise<void> {
  const node = graphNode(surface, fullLabel);
  await expect(node, `no node labelled ${fullLabel} was drawn`).toHaveCount(1);
  await node.click({ force: true });
  await expect(
    surface.locator(".soc-graph-detail strong"),
    `clicking ${fullLabel} did not put it in the selection rail`
  ).toHaveText(fullLabel);
}

test.describe("correlation graph", () => {
  test.use({ viewport: { width: 1600, height: 1000 } });

  /**
   * WHAT THIS PINS: the rail is the bridge between a dot on a canvas and an
   * exec_id an operator can SIGKILL. It must describe the node that was
   * clicked — its kind, its classification, how many things it touches, and the
   * concrete processes behind it with their pids — and it must follow a second
   * click rather than latching on the first.
   */
  test("selecting a process node describes that node and the processes behind it", async ({ page }) => {
    const surface = await openGraph(page);

    await selectNode(surface, "/usr/bin/cat");

    await expect(railField(page, surface, "kind"), "a process node reported the wrong kind").toHaveText("process");
    await expect(
      railField(page, surface, "classification"),
      "score 44 must classify as attack (>= 25)"
    ).toHaveText("attack");
    await expect(railField(page, surface, "max score"), "the alert's score 44 is the node's max").toHaveText("44");
    // policy + file + its parent /bin/bash.
    await expect(
      railField(page, surface, "connections"),
      "cat touches a policy, a file and its parent shell — three edges"
    ).toHaveText("3");

    const procs = surface.locator("button.soc-graph-proc");
    await expect(procs, "the one exec_id behind /usr/bin/cat is missing from the rail").toHaveCount(1);
    await expect(procs.first(), "the process row must carry the pid enforcement will target").toContainText("pid 4242");
    await expect(procs.first(), "the process row must carry the score that justifies acting").toContainText("44");

    // The rail follows the selection. A second click must re-describe, not
    // append to or keep the first subject.
    await selectNode(surface, "/usr/bin/curl");
    await expect(railField(page, surface, "classification"), "score 18 must classify as threat (10..24)").toHaveText(
      "threat"
    );
    await expect(railField(page, surface, "max score"), "the rail kept the previous node's score").toHaveText("18");
    await expect(
      railField(page, surface, "connections"),
      "curl touches a policy, a peer, a device and its parent shell — four edges"
    ).toHaveText("4");
  });

  /**
   * WHAT THIS PINS: the four node kinds are the graph's whole vocabulary — a
   * file a process opened and a host it phoned are different facts, and the
   * legend claims you can tell them apart. They are distinguished only by a
   * class the D3 join writes, so nothing but a browser can check it. Includes
   * the RFC1918 split that decides peer (reached out to the internet) from
   * device (talked to something on our network), and the loopback rule that
   * refuses to draw a health check as a destination at all.
   *
   * The loopback half carries its own positive control — see loopbackEvent:
   * the event runs a binary nothing else in the fixture runs, so "the canvas
   * refused to draw the destination" is a separate, separately-failing claim
   * from "the event was delivered".
   */
  test("each node kind is drawn as its own kind, and loopback is not a destination", async ({ page }) => {
    const surface = await openGraph(page, {
      routes: { "/api/events": [...graphEvents, loopbackEvent] }
    });
    const svg = surface.locator("svg.soc-correlation-graph");

    // POSITIVE CONTROL, and the reason the loopback event runs its own binary:
    // it proves the override reached the page. Without it every count below is
    // equally satisfied by "the canvas filtered the destination" and by "the
    // loopback event was never delivered at all".
    await expect(
      graphNode(surface, "/usr/bin/healthcheck"),
      "the loopback event never reached the canvas — the loopback assertion below would pass vacuously"
    ).toHaveCount(1);

    await expect(
      svg.locator("g.soc-graph-node.node-process"),
      "expected bash, cat, curl, head and the health checker as process nodes"
    ).toHaveCount(5);
    await expect(
      svg.locator("g.soc-graph-node.node-policy"),
      "expected the two policies that fired to be their own nodes"
    ).toHaveCount(2);
    await expect(svg.locator("g.soc-graph-node.node-file"), "expected /etc/shadow and /etc/passwd").toHaveCount(2);
    await expect(
      svg.locator("g.soc-graph-node.node-peer"),
      "203.0.113.10 is public — exactly one peer node, and the LAN address must not be one"
    ).toHaveCount(1);
    await expect(
      svg.locator("g.soc-graph-node.node-device"),
      "10.0.0.25 is RFC1918 — it belongs on the graph as a device, not a peer"
    ).toHaveCount(1);
    await expect(
      svg.locator('g.soc-graph-node[aria-label*="127.0.0.1"]'),
      "a loopback health check must never be drawn as a destination this process reached"
    ).toHaveCount(0);
    // The process that made the loopback call is on the canvas (above), so it
    // is on the canvas with no destination hanging off it: the only edge it
    // owns is to the policy it tripped.
    await expect(
      svg.locator("g.soc-graph-node.node-peer, g.soc-graph-node.node-device"),
      "the loopback destination was drawn as a peer or a device"
    ).toHaveCount(2);

    // Classification colours ride on process nodes only; context nodes are
    // neutral evidence and must not be tinted as if the scorer had judged them.
    await expect(
      svg.locator("g.soc-graph-node.score-attack"),
      "only cat scored into the attack band"
    ).toHaveCount(1);
    await expect(
      svg.locator("g.soc-graph-node:not(.node-process)[class*='score-']"),
      "a policy/file/peer/device node must carry no score class"
    ).toHaveCount(0);
  });

  /**
   * WHAT THIS PINS: a context node is evidence. Clicking one has to answer the
   * same question every node answers — "which processes are behind this?" —
   * by walking its edges, and it has to LABEL the answer as indirect ("via this
   * node") so nobody reads a file's process list as the file itself. It also
   * pins the two empty states apart: a node whose records carry no exec_id has
   * nothing to enforce against, which is a different sentence from "no process
   * matches this filter" and a different sentence again from the evidence node
   * that leads to it. All three were once the same blank box.
   */
  test("an evidence node resolves its processes through its edges, and says when it cannot", async ({ page }) => {
    const surface = await openGraph(page);

    await selectNode(surface, "override-credential-read");
    await expect(railField(page, surface, "kind"), "a policy node reported the wrong kind").toHaveText("policy");
    await expect(
      surface.locator(".soc-graph-detail dl"),
      "classification is a judgement about a process; a policy node must not claim one"
    ).not.toContainText("classification");
    // The claim is that the list is labelled INDIRECT, and that the one
    // process behind the policy is in it. Asserted on the distinguishing
    // fragment plus the list itself rather than on the whole "Processes (1) ·
    // via this node" string, which also welds in the "(n of m)" count format a
    // copy edit may legitimately change.
    const viaPolicy = surface.locator(".soc-graph-procs .soc-stat-label");
    await expect(
      viaPolicy,
      "the policy's processes must be marked as reached via the node, not as the node itself"
    ).toContainText("via this node");
    await expect(
      surface.locator("button.soc-graph-proc"),
      "the policy's one process must be reachable through its edges"
    ).toHaveCount(1);
    await expect(
      surface.locator("button.soc-graph-proc").first(),
      "the process behind the policy is the cat that tripped it"
    ).toContainText("pid 4242");

    // /etc/passwd was touched by a record with no exec_id, so the process it
    // leads to is not actionable — and the rail must say that rather than show
    // an empty list.
    await selectNode(surface, "/etc/passwd");
    await expect(railField(page, surface, "kind"), "a file node reported the wrong kind").toHaveText("file");
    await expect(surface.locator("button.soc-graph-proc"), "nothing behind this file is enforceable").toHaveCount(0);
    // The contract is that the three empty states are DIFFERENT sentences, not
    // that this one is word-perfect: assert the fragment that distinguishes it,
    // and that neither of the other two reasons is what got rendered.
    const emptyState = surface.locator(".soc-graph-selection-empty");
    await expect(
      emptyState,
      "an evidence node with nothing actionable must say so, not show a blank box"
    ).toContainText("This node is evidence");
    await expect(
      emptyState,
      "an evidence node must not be explained as an un-enforceable process"
    ).not.toContainText("no exec_id");
    await expect(
      emptyState,
      "an evidence node with no filter applied must not blame a filter"
    ).not.toContainText("filter");

    // The process itself gives the OTHER reason: it exists, but the records
    // behind it carry nothing to enforce against.
    await selectNode(surface, "/usr/bin/head");
    await expect(railField(page, surface, "kind"), "head is a process node").toHaveText("process");
    await expect(
      surface.locator(".soc-graph-selection-empty"),
      "a process with no exec_id must explain why it cannot be acted on"
    ).toContainText("no exec_id");
    await expect(
      surface.locator(".soc-graph-selection-empty"),
      "a process is not evidence — it must not be given the context node's sentence"
    ).not.toContainText("This node is evidence");
  });

  /**
   * WHAT THIS PINS: the brief's job is to size the picture before anyone clicks
   * it, so its numbers have to be the picture's numbers. Both halves of this
   * have already been wrong in production — the fabric card is the only place
   * the process/edge count is stated in words, and the indicator count read
   * `event.path` alone and printed "0 indicators observed" over a canvas
   * drawing six of them. Counting what was actually RENDERED is the only check
   * that cannot drift with the derivation.
   */
  test("the brief counts what the canvas drew", async ({ page }) => {
    const surface = await openGraph(page);
    const svg = surface.locator("svg.soc-correlation-graph");

    const processes = await svg.locator("g.soc-graph-node.node-process").count();
    const edges = await svg.locator("line").count();
    const evidence = await svg
      .locator("g.soc-graph-node.node-file, g.soc-graph-node.node-peer, g.soc-graph-node.node-device")
      .count();
    expect(processes, "no process nodes drawn, nothing under test").toBeGreaterThan(0);
    expect(edges, "no edges drawn — the fixture failed to correlate anything").toBeGreaterThan(0);
    expect(evidence, "no evidence nodes drawn, nothing under test").toBeGreaterThan(0);

    const fabric = surface.locator(".soc-graph-brief-card", { hasText: "Signal fabric" });
    await expect(
      fabric.locator("strong"),
      `the fabric card must state the ${processes} processes and ${edges} edges on the canvas`
    ).toHaveText(`${processes}/${edges}`);
    await expect(
      surface.locator(".soc-graph-counts"),
      `the control bar disagreed with the ${processes} processes / ${edges} edges drawn`
    ).toHaveText(`${processes} processes · ${edges} edges`);
    await expect(
      fabric.locator(".soc-graph-card-detail em"),
      `the canvas drew ${evidence} indicators (files, peers, devices)`
    ).toHaveText(`${evidence} indicators observed`);
  });

  /**
   * KNOWN DEFECT — the indicator count includes destinations the canvas
   * deliberately refuses to draw.
   *
   * CAUSE: GraphBrief.tsx derives indicators as
   * `event.path || extractFilePath(args) || peerFromEvent(event)` and says in
   * its own comment that it counts them "the SAME way the canvas draws them
   * (graphModel.ts)". It does not: graphModel filters peers through
   * `!isLoopbackPeer(p)` before adding a node, and GraphBrief does not filter
   * at all. A host's own health checks therefore inflate the count.
   *
   * WHY IT MATTERS HERE: this is the same failure the loopback rule was
   * introduced to fix. Measured on the engine's ten-day store, 397 of 559
   * IPv4-carrying events are `curl 127.0.0.1:8090` — so on a real window this
   * card claims hundreds of "indicators observed" that are the box talking to
   * itself, two inches from a canvas that correctly draws none of them.
   *
   * FIX: filter the derived peer through isLoopbackPeer in GraphBrief's
   * indicatorCount, exactly as graphModel.ts does.
   */
  test("the indicator count excludes loopback, like the canvas does", async ({ page }) => {
    test.fail(true, "known defect: GraphBrief counts loopback peers the graph refuses to draw");

    const surface = await openGraph(page, {
      routes: { "/api/events": [...graphEvents, loopbackEvent] }
    });
    const svg = surface.locator("svg.soc-correlation-graph");

    const evidence = await svg
      .locator("g.soc-graph-node.node-file, g.soc-graph-node.node-peer, g.soc-graph-node.node-device")
      .count();
    expect(evidence, "no evidence nodes drawn, nothing under test").toBeGreaterThan(0);
    await expect(
      graphNode(surface, "/usr/bin/healthcheck"),
      "precondition: the loopback event must have reached the page at all"
    ).toHaveCount(1);
    await expect(
      svg.locator('g.soc-graph-node[aria-label*="127.0.0.1"]'),
      "precondition: the canvas must be refusing to draw the loopback destination"
    ).toHaveCount(0);

    await expect(
      surface.locator(".soc-graph-brief-card", { hasText: "Signal fabric" }).locator(".soc-graph-card-detail em"),
      `the canvas drew ${evidence} indicators; the loopback health check is not one of them`
    ).toHaveText(`${evidence} indicators observed`);
  });

  /**
   * WHAT THIS PINS: the two interlocks standing between a click on a dot and a
   * SIGKILL. The ladder is shared with Choke Gateway and Devices, but it is
   * only in this modal that the target was chosen by pointing at a picture, so
   * this is where a mis-wired `apply` would send the wrong exec_id. The
   * assertion that matters is on what the page SENT: the request body is the
   * contract, and "the button looked disabled" is not evidence that nothing
   * was dispatched.
   *
   * And a third property, one rung down from the interlocks: a 2xx from
   * /api/choke/manual is an ACCEPTANCE. The control plane only learns the new
   * rung from the agent's heartbeat, so the ladder must sit on "dispatched —
   * awaiting confirmation…" until a read reports it, and never announce a
   * SIGKILL that has not happened. The fixture below withholds the new rung on
   * purpose so that intermediate state is actually observed.
   */
  test("the ladder gates a destructive rung behind a reason and the irreversible one behind a second press", async ({
    page
  }) => {
    const recorder = new RequestLog();
    // The mock's function form, with a Node-side flag: the fixture has to
    // answer /api/choke/circuits DIFFERENTLY after the write, or the ladder's
    // dispatched → confirmed transition (a 2xx is an acceptance, not a state
    // change) cannot be observed at all.
    //
    // The flip is deliberately NOT wired to the POST handler. A fixture that
    // severs synchronously inside /api/choke/manual has already changed the
    // rung by the time the response lands, so an implementation that read the
    // state once, immediately, and never waited would satisfy every assertion
    // below — which is exactly the behaviour this test exists to forbid. The
    // agent here reports the new rung only when the test releases it, after
    // the intermediate "awaiting confirmation" state has been observed.
    let severedByAgent = false;
    const severedRow = {
      exec_id: "exec-cat",
      pid: 4242,
      binary: "/usr/bin/cat",
      state: "severed",
      score: 44,
      last_seen: at
    };
    const surface = await openGraph(page, {
      recorder,
      routes: {
        "/api/choke/manual": () => ({ ok: true, detail: "sever applied" }),
        "/api/choke/circuits": () => (severedByAgent ? [severedRow] : [])
      }
    });

    await selectNode(surface, "/usr/bin/cat");
    await surface.locator("button.soc-graph-proc").first().click();

    const modal = page.locator('[data-panel="process-action-modal"]');
    await expect(modal, "picking a process must open the action modal").toBeVisible();
    await expect(modal, "the modal must name the exec_id it will act on").toContainText("exec-cat");
    await expect(modal, "the modal must name the pid it will act on").toContainText("4242");

    const ladder = modal.locator('[data-panel="enforcement-ladder"]');
    await expect(ladder, "the modal must carry the shared enforcement ladder").toBeVisible();
    await expect(ladder.locator(".enf-ladder-rungs li"), "the ladder must draw all five rungs").toHaveCount(5);
    await expect(ladder.locator(".enf-ladder-rung.is-current"), "an untouched process sits at pristine").toHaveText(
      "pristine"
    );

    const quarantine = ladder.getByRole("button", { name: "Quarantine" });
    const sever = ladder.locator(".enf-ladder-btn.is-terminal");
    // Precondition: the ladder is live, so a disabled destructive rung means
    // the reason gate and not a wholesale-dead ladder.
    await expect(ladder.getByRole("button", { name: "Throttle" }), "the ladder is not live").toBeEnabled();
    await expect(quarantine, "quarantine must be gated until a reason is given").toBeDisabled();
    // The claim is that the dead button explains itself, not the exact
    // rendering of `A reason is required to ${ACTION_FOR_RUNG[rung]}`.
    await expect(quarantine, "a gated rung must say WHY it is dead").toHaveAttribute(
      "title",
      /A reason is required/
    );
    await expect(sever, "sever must be gated until a reason is given").toBeDisabled();

    await ladder.getByLabel("Reason for this enforcement action").fill("e2e: credential theft, containing");
    await expect(quarantine, "a typed reason must open the gate").toBeEnabled();
    await expect(sever, "a typed reason must open the gate for sever too").toBeEnabled();

    // First press arms; it must not dispatch.
    await sever.click();
    await expect(sever, "the first press must turn the button into a confirmation").toHaveText("Confirm");
    await expect(ladder.locator(".enf-ladder-warn"), "the armed state must spell out that it cannot be undone").toContainText(
      "cannot be undone"
    );
    expect(
      recorder.matching(/\/api\/choke\/(manual|thaw)/).map((request) => request.body),
      "the first press of sever dispatched an enforcement action"
    ).toEqual([]);

    await sever.click();
    await expect
      .poll(
        () => recorder.matching(/\/api\/choke\/manual/).length,
        { message: "the confirmed press did not dispatch exactly one enforcement action" }
      )
      .toBe(1);
    const sent = recorder.matching(/\/api\/choke\/manual/)[0];
    expect(sent.method, `sever was sent as ${sent.method}`).toBe("POST");
    expect(
      JSON.parse(sent.body ?? "{}"),
      `the dispatched body must name the graph's target and carry the reason: ${sent.body}`
    ).toMatchObject({
      exec_id: "exec-cat",
      pid: 4242,
      action: "sever",
      reason: "e2e: credential theft, containing"
    });

    // A 2xx is an acceptance. The ladder must wait for the rung to actually
    // change before it claims the process was severed — so while the agent is
    // still reporting the process as pristine, the only honest thing it can
    // say is that it is waiting.
    const result = ladder.locator(".enf-ladder-result");
    await expect(result, "the ladder must report the dispatch it is still waiting on").toContainText(
      "sever dispatched — awaiting confirmation"
    );
    await expect(
      result,
      "the ladder claimed the sever landed on the strength of the 2xx, before any read reported it"
    ).not.toContainText("confirmed — now");
    await expect(
      ladder.locator(".enf-ladder-rung.is-current"),
      "the rung advanced on the acceptance alone, before the agent reported it"
    ).toHaveText("pristine");

    // Now the agent reports the new rung, and only now may the ladder claim it.
    severedByAgent = true;
    await expect(
      result,
      "the ladder claimed nothing after the agent reported the new rung"
    ).toContainText("sever confirmed — now severed", { timeout: 15_000 });
    await expect(
      ladder.locator(".enf-ladder-warn"),
      "a severed process is terminal — the ladder must say so"
    ).toContainText("Terminal state");
    await expect(
      ladder.locator(".enf-ladder-actions button:not([disabled])"),
      "nothing can be applied to a SIGKILLed process, including release"
    ).toHaveCount(0);
  });

  /**
   * WHAT THIS PINS: the graph is itself an Escape-closable surface, and the
   * modal is layered on top of it. One Escape that closed both would throw an
   * operator out of the investigation they are in the middle of — the exact
   * reason ProcessActionModal listens in the capture phase and calls
   * stopImmediatePropagation. Two window listeners racing on the real event
   * loop; jsdom's synthetic dispatch is not the thing that broke.
   */
  test("Escape closes the action modal without closing the graph under it", async ({ page }) => {
    const surface = await openGraph(page);

    await selectNode(surface, "/usr/bin/cat");
    await surface.locator("button.soc-graph-proc").first().click();

    const modal = page.locator('[data-panel="process-action-modal"]');
    await expect(modal, "no modal open, nothing under test").toBeVisible();

    await page.keyboard.press("Escape");
    await expect(modal, "Escape must dismiss the action modal").toBeHidden();
    await expect(surface, "Escape must not take the graph down with the modal").toBeVisible();
    await expect(
      surface.locator(".soc-graph-detail strong"),
      "the selection must survive closing the modal, so the operator returns to the list"
    ).toHaveText("/usr/bin/cat");

    // And Escape still works on the graph itself — proving the modal consumed
    // the first one rather than the graph having no listener at all.
    await page.keyboard.press("Escape");
    await expect(surface, "Escape must still close the graph once the modal is gone").toBeHidden();
  });
});
