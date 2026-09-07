import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { recordResponseAuthority } from "../features/soc/api";
import { SensorHealthBody } from "../features/soc/SensorHealthBody";

/**
 * One panel, two deployments that measure different things.
 *
 * The renderer was written against the CONTROL PLANE's payload, which learns
 * backlog, evidence loss and freshness from agent heartbeats. The single-tenant
 * engine has no heartbeat and no evidence-loss counter, and deliberately OMITS
 * those fields rather than sending zeros — because a zero on this surface
 * asserts "no evidence has been lost", which is the reassurance the whole
 * panel exists to avoid fabricating.
 *
 * The renderer then called `.toLocaleString()` on them unguarded, so the honest
 * payload threw the panel into the error boundary. The API was verified with
 * curl and the screen was never opened; these are the tests that would have
 * caught it.
 */

// This panel's write controls are withheld until the server has said what the
// account may do, and the shared authority store starts at "loading" — so a
// test that renders and immediately presses a button is testing the gate, not
// the payload. These tests are about the BODY the server decodes, so they put
// the session where a real one is: whoami answered. `null` is the answer the
// single-tenant engine gives (it publishes no can_respond), which is the
// deployment every payload below was captured from.
beforeEach(() => {
  act(() => recordResponseAuthority(null));
});

// Captured verbatim from https://engine.adanianlabs.io on 2026-08-22. Using the
// real payload rather than a fixture is the point: a hand-built one would have
// been written from the same wrong assumption as the renderer.
const ENGINE_PAYLOAD = {
  agents: [{
    agent_id: "ip-172-31-33-137",
    issues: [],
    kernel_observable: true,
    kernel_read_via: "grpc",
    last_seen: "2026-08-22T19:09:23.688273859Z",
    missing_policies: [],
    policies_enforce: 0,
    policies_loaded: 4,
    process_links: 0,
    process_plane: "noop",
    status: "ok",
    tetragon: true
  }],
  agents_fresh: 1,
  agents_losing: 0,
  agents_total: 1,
  coverage_caveat:
    "this console reads ONE host — its own. It says nothing about any other machine, and a host with no engine on it is invisible here.",
  evidence_loss_known: false,
  expected_policies: [
    "outbound-connections", "override-credential-read", "privilege-escalation", "sensitive-file-access"
  ],
  generated_at: "2026-08-22T19:09:23.688273859Z"
};

const CP_PAYLOAD = {
  agents: [{
    agent_id: "agent-f8c7", status: "ok", issues: [],
    last_seen_age_seconds: 3, fresh: true,
    policies_loaded: 4, policies_enforce: 0, missing_policies: [], kernel_observable: true,
    process_plane: "noop", process_links: 0, device_plane: "tc", device_links: 2,
    buffer_depth: 223, dropped_records: 0, dropped_broadcast: 0
  }],
  agents_total: 1, agents_fresh: 1, agents_losing: 0,
  dropped_records: 0,
  expected_policies: ["sensitive-file-access"],
  coverage_caveat: "counts enrolled agents only",
  policy_versions: { "00b71db0107e": 1 },
  policy_drift: false
};

function mockFetch(payload: unknown) {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(payload), {
    status: 200, headers: { "Content-Type": "application/json" }
  })));
}

afterEach(() => vi.unstubAllGlobals());

describe("the panel renders the engine's payload without crashing", () => {
  it("survives absent backlog and evidence-loss counters", async () => {
    mockFetch(ENGINE_PAYLOAD);
    render(<SensorHealthBody policyStats={[]} open />);
    await waitFor(() => expect(screen.getByText("ip-172-31-33-137")).toBeTruthy());
    // If this renders at all, `.toLocaleString()` did not throw.
    expect(screen.getByText(/4 loaded/)).toBeTruthy();
  });

  it("says 'not measured', never 0, where the engine cannot count", async () => {
    // The whole reason the field is absent. A zero here would be the exact
    // fabricated reassurance the API refuses to send.
    mockFetch(ENGINE_PAYLOAD);
    render(<SensorHealthBody policyStats={[]} open />);
    await waitFor(() => expect(screen.getByText("ip-172-31-33-137")).toBeTruthy());
    expect(screen.getAllByText("not measured").length).toBeGreaterThan(0);
  });

  it("does not claim zero drift from a fleet of one", async () => {
    // "Detection set agrees across all reporting hosts" is meaningless with a
    // single host and reads as an estate-wide assurance.
    mockFetch(ENGINE_PAYLOAD);
    render(<SensorHealthBody policyStats={[]} open />);
    await waitFor(() => expect(screen.getByText("ip-172-31-33-137")).toBeTruthy());
    expect(screen.queryByText(/Detection set agrees/)).toBeNull();
  });
});

describe("the control plane's payload still renders every measurement", () => {
  it("shows real counts where they were actually measured", async () => {
    mockFetch(CP_PAYLOAD);
    render(<SensorHealthBody policyStats={[]} open />);
    await waitFor(() => expect(screen.getByText("agent-f8c7")).toBeTruthy());
    expect(screen.getByText("223")).toBeTruthy();          // backlog, measured
    expect(screen.queryAllByText("not measured").length).toBe(0);
    expect(screen.getByText(/Detection set agrees/)).toBeTruthy();
  });
});

// A finding with no next step is a dead end. This panel stated problems behind
// a READ-ONLY badge and left the operator to work out, unaided, that the fix
// lives on a different surface.
describe("every finding carries what to do about it", () => {
  const withIssues = {
    ...ENGINE_PAYLOAD,
    agents: [{
      ...ENGINE_PAYLOAD.agents[0],
      status: "degraded",
      missing_policies: ["sensitive-file-access"],
      issues: [
        { code: "policies-missing", detail: "expected detections not loaded: sensitive-file-access" },
        { code: "no-tetragon", detail: "no Tetragon connection — this host is not receiving kernel events" }
      ]
    }]
  };

  it("offers a route to the fix where the platform can actually fix it", async () => {
    const onOpen = vi.fn();
    mockFetch(withIssues);
    render(<SensorHealthBody policyStats={[]} open onOpenDetections={onOpen} />);
    await waitFor(() => expect(screen.getByText(/expected detections not loaded/)).toBeTruthy());

    const btn = screen.getByRole("button", { name: /fix in detections/i });
    btn.click();
    expect(onOpen).toHaveBeenCalled();
  });

  it("gives an instruction, not a button, where it cannot", async () => {
    // Tetragon being down is not something this console can repair. A control
    // that did nothing would be worse than a sentence saying where to go.
    mockFetch(withIssues);
    render(<SensorHealthBody policyStats={[]} open onOpenDetections={() => {}} />);
    await waitFor(() => expect(screen.getByText(/no Tetragon connection/)).toBeTruthy());

    expect(screen.getByText(/restart the tetragon container on the host/i)).toBeTruthy();
    // Exactly one actionable issue in this payload, so exactly one button.
    expect(screen.getAllByRole("button", { name: /fix in detections/i })).toHaveLength(1);
  });

  it("renders an unrecognised code's detail rather than dropping it", async () => {
    // A server newer than the console must not lose findings silently.
    mockFetch({
      ...ENGINE_PAYLOAD,
      agents: [{ ...ENGINE_PAYLOAD.agents[0], status: "degraded",
        issues: [{ code: "something-this-build-has-never-heard-of", detail: "a brand new finding" }] }]
    });
    render(<SensorHealthBody policyStats={[]} open />);
    await waitFor(() => expect(screen.getByText("a brand new finding")).toBeTruthy());
  });
});

// The customer's complaint, in one line: "I don't see any difference — the
// sensor health still remains as-is." The panel looked identical whether a
// host could contain anything or not, because its verdict was computed from
// detection facts alone and it rendered enforcement as two backend names.
describe("the panel states containment capability, healthy case included", () => {
  const withContainment = (verdict: string, summary: string, extra: Record<string, unknown> = {}) => ({
    ...ENGINE_PAYLOAD,
    agents: [{
      ...ENGINE_PAYLOAD.agents[0],
      containment: {
        verdict, summary, kill: "yes", freeze: "yes", resource_caps: "yes",
        net_process: "no", net_device: "no", auto: "detect-only", manual_lands: true
      },
      ...extra
    }]
  });

  it("says what the host can do even when nothing is wrong", async () => {
    mockFetch(withContainment("partial",
      "Kill, freeze and resource caps are live and an action you press lands immediately."));
    render(<SensorHealthBody policyStats={[]} open />);
    await waitFor(() => expect(screen.getByText(/Containment: partial/)).toBeTruthy());
    expect(screen.getByText(/an action you press lands immediately/)).toBeTruthy();
  });

  it("never claims a pressed action is dead when it is not", async () => {
    // The most damaging possible message, and one an earlier draft was going
    // to ship: telling a SOC their emergency stop does nothing when it works.
    mockFetch(withContainment("partial", "an action you press lands immediately"));
    render(<SensorHealthBody policyStats={[]} open />);
    await waitFor(() => expect(screen.getByText(/Containment: partial/)).toBeTruthy());
    expect(screen.queryByText(/Containment: NONE/)).toBeNull();
  });

  it("renders notes without counting them as attention", async () => {
    // A mechanism absent by deployment is stated, not alarmed on.
    mockFetch({
      ...withContainment("partial", "network containment is not deployed here"),
      agents: [{
        ...withContainment("partial", "x").agents[0],
        notes: [{ code: "no-kernel-network-choke", detail: "per-PID network containment is not deployed on this host" }]
      }]
    });
    render(<SensorHealthBody policyStats={[]} open />);
    await waitFor(() => expect(screen.getByText(/per-PID network containment is not deployed/)).toBeTruthy());
    // Notes must not appear as findings needing attention.
    expect(screen.queryByRole("button", { name: /fix in detections/i })).toBeNull();
  });

  it("shows — not 0 — for 'cannot contain' when a posture is unreadable", async () => {
    // Same discipline as the evidence tile: an unmeasured zero is the most
    // reassuring lie available.
    mockFetch(withContainment("partial-unknown", "some mechanisms could not be read"));
    render(<SensorHealthBody policyStats={[]} open />);
    await waitFor(() => expect(screen.getByText(/Cannot contain/)).toBeTruthy());
    const tile = screen.getByText("Cannot contain").parentElement!;
    expect(tile.textContent).toContain("—");
  });

  it("counts a host that cannot contain at all", async () => {
    mockFetch({
      ...ENGINE_PAYLOAD,
      agents: [{
        ...ENGINE_PAYLOAD.agents[0],
        containment: {
          verdict: "none", summary: "Nothing this console does reaches the kernel.",
          kill: "no", freeze: "yes", resource_caps: "yes", net_process: "no",
          net_device: "no", auto: "detect-only", manual_lands: false
        }
      }]
    });
    render(<SensorHealthBody policyStats={[]} open />);
    await waitFor(() => expect(screen.getByText(/Containment: NONE/)).toBeTruthy());
    const tile = screen.getByText("Cannot contain").parentElement!;
    expect(tile.textContent).toContain("1");
  });
});

// Every code the SERVER can emit must have a remedy in the UI.
//
// This is the gap that shipped: five enforcement codes were added server-side
// and their client half was never written, so the one finding actually firing
// on the estate rendered as a bare sentence with nothing under it. A test that
// hand-picks codes cannot catch that — this one enumerates the contract.
describe("every emitted finding tells the operator what to do", () => {
  const EMITTED = [
    "kernel-unreadable", "policies-missing", "no-tetragon", "policy-enforcing",
    "stale-heartbeat", "evidence-lost",
    "enforcement-degraded", "no-process-containment", "device-plane-detached",
    "containment-shadowed", "kill-switched"
  ];

  for (const code of EMITTED) {
    it(`has a remedy for ${code}`, async () => {
      mockFetch({
        ...ENGINE_PAYLOAD,
        agents: [{ ...ENGINE_PAYLOAD.agents[0], status: "degraded",
          issues: [{ code, detail: `finding: ${code}` }] }]
      });
      render(<SensorHealthBody policyStats={[]} open onOpenDetections={() => {}} />);
      await waitFor(() => expect(screen.getByText(`finding: ${code}`)).toBeTruthy());

      // The detail alone is not a remedy. There must be guidance beneath it.
      const li = screen.getByText(`finding: ${code}`).closest("li")!;
      expect(li.textContent!.length, `${code} renders only its detail, no remedy`)
        .toBeGreaterThan(`finding: ${code}`.length + 40);
    });
  }
});

// Four rounds of added prose produced four rounds of "I don't see a change".
// The finding that fires on this estate had a remedy and nothing to press.
describe("the panel can change the mode it reports, in both directions", () => {
  // First built as an action on the detect-only FINDING. Arming resolved the
  // finding, so the control deleted itself and the only way back was another
  // page. Demoting it to a link over-corrected: it left the panel that tells
  // you the ladder is off unable to turn it on.
  //
  // The fault was hanging a two-way control on a one-way signal. Findings only
  // exist while something is wrong; the containment block renders always, so
  // both directions fit.
  const withAuto = (auto: string) => ({
    ...ENGINE_PAYLOAD,
    agents: [{
      ...ENGINE_PAYLOAD.agents[0],
      containment: {
        verdict: "partial", summary: "Kill, freeze and resource caps are live.",
        kill: "yes", freeze: "yes", resource_caps: "yes",
        net_process: "no", net_device: "no", auto, manual_lands: true
      }
    }]
  });

  it("offers to arm when the ladder is off", async () => {
    mockFetch(withAuto("detect-only"));
    render(<SensorHealthBody policyStats={[]} open />);
    await waitFor(() => expect(screen.getByText(/Containment: partial/)).toBeTruthy());
    expect(screen.getByRole("button", { name: /arm automatic containment/i })).toBeTruthy();
  });

  it("offers to DISARM when it is on — the control does not vanish", async () => {
    // The regression this replaces: arming removed its own control and the way
    // back lived on a page that never mentioned it.
    mockFetch(withAuto("enforcing"));
    render(<SensorHealthBody policyStats={[]} open />);
    await waitFor(() => expect(screen.getByText(/Containment: partial/)).toBeTruthy());
    expect(screen.getByRole("button", { name: /return to detect-only/i })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /arm automatic containment/i })).toBeNull();
  });

  it("arms with {enforcing:true} — the key the server actually decodes", async () => {
    const user = userEvent.setup();
    const calls: Array<{ url: string; body: unknown }> = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        calls.push({ url: String(url), body: JSON.parse(String(init.body)) });
        return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify(withAuto("detect-only")), {
        status: 200, headers: { "Content-Type": "application/json" } });
    }));

    render(<SensorHealthBody policyStats={[]} open />);
    await waitFor(() => expect(screen.getByText(/Containment: partial/)).toBeTruthy());
    await user.click(screen.getByRole("button", { name: /arm automatic containment/i }));
    await user.type(screen.getByPlaceholderText(/CAB-1234/), "maintenance window");

    const panel = screen.getByText(/contain processes on its own/i).closest("div")!;
    const confirm = Array.from(panel.querySelectorAll("button"))
      .find((b) => /arm automatic containment/i.test(b.textContent || ""))!;
    await user.click(confirm);

    await waitFor(() => expect(calls.length).toBe(1));
    expect(calls[0].url).toContain("/api/choke/mode");
    expect(calls[0].body).toMatchObject({ enforcing: true });
    // {mode:"enforcing"} was silently ignored by the server and set the opposite.
    expect(calls[0].body).not.toHaveProperty("mode");
  });

  it("offers no control for a fault the console cannot fix", async () => {
    mockFetch({
      ...ENGINE_PAYLOAD,
      agents: [{ ...ENGINE_PAYLOAD.agents[0], status: "degraded",
        issues: [{ code: "enforcement-degraded", detail: "the kernel refused 1 configured containment limit" }] }]
    });
    render(<SensorHealthBody policyStats={[]} open />);
    await waitFor(() => expect(screen.getByText(/kernel refused/)).toBeTruthy());
    expect(screen.getByText(/Raise it with engineering/i)).toBeTruthy();
  });
});

describe("the remaining action posts the body the server actually decodes", () => {
  it("releases the kill-switch with {on:false}, matching `On bool `json:\"on\"``", async () => {
    const user = userEvent.setup();
    const calls: Array<{ url: string; body: unknown }> = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        calls.push({ url: String(url), body: JSON.parse(String(init.body)) });
        return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({
        ...ENGINE_PAYLOAD,
        agents: [{ ...ENGINE_PAYLOAD.agents[0], status: "degraded",
          issues: [{ code: "kill-switched", detail: "the enforcement kill-switch is engaged" }] }]
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }));

    render(<SensorHealthBody policyStats={[]} open />);
    await waitFor(() => expect(screen.getByText(/kill-switch is engaged/)).toBeTruthy());
    await user.click(screen.getByRole("button", { name: /release the kill-switch/i }));
    await user.type(screen.getByPlaceholderText(/CAB-1234/), "incident closed");

    const panel = screen.getByText(/re-enables all containment/i).closest("div")!;
    const confirm = Array.from(panel.querySelectorAll("button"))
      .find((b) => /release the kill-switch/i.test(b.textContent || ""))!;
    await user.click(confirm);

    await waitFor(() => expect(calls.length).toBe(1));
    expect(calls[0].url).toContain("/api/choke/kill-switch");
    expect(calls[0].body).toMatchObject({ on: false });
  });
});
