import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ResponseControls, type Thresholds } from "../features/soc/SettingsResponse";
import { SensorHealthBody } from "../features/soc/SensorHealthBody";
import { DetectionsBody } from "../features/soc/DetectionsBody";
import { recordResponseAuthority } from "../features/soc/api";
import type { SocPolicy } from "../features/soc/types";

/**
 * The three widest write controls on the platform, and the panel that names
 * why a control is withheld.
 *
 * The first permission sweep gated the alert drill, the process modal and the
 * graph rail — and left the kill-switch, the enforcement-mode toggle and the
 * score ladder armed on the SAME SOC page, on two surfaces. A read-only
 * operator could press "Engage the kill-switch": the server refused it, the
 * console said nothing, and the operator had no way to tell a refused write
 * from a platform that had quietly stopped enforcing. That is worse than the
 * defect the sweep fixed, because these three decide whether the platform acts
 * at all.
 *
 * Three rules, all of them checked on both surfaces:
 *
 *  1. A control the server will refuse is disabled, not hidden. A kill-switch
 *     that vanishes reads as a deployment that has none.
 *  2. It says why ON THE CONTROL, in the language of PERMISSION. An operator
 *     must not have to press a button to discover it is not theirs, and must
 *     not be sent to debug an estate that is healthy.
 *  3. `null` — the single-tenant engine, which never publishes `can_respond` —
 *     changes nothing. Absence of the field is not a refusal.
 */
const THRESHOLDS: Thresholds = { throttle_at: 10, tarpit_at: 20, quarantine_at: 30, sever_at: 40 };

const PERMISSION = /ask an administrator for responder access/i;

function renderResponseControls(killSwitched: boolean | null = false, mode = "detect-only") {
  render(
    <ResponseControls thresholds={THRESHOLDS} mode={mode} killSwitched={killSwitched} onChanged={() => {}} />
  );
}

/**
 * A host that reports both mode and a kill-switch finding, so the two write
 * controls this panel offers are on screen at once.
 */
const SENSOR_PAYLOAD = {
  agents: [
    {
      agent_id: "ip-172-31-33-137",
      status: "degraded",
      issues: [{ code: "kill-switched", detail: "enforcement is globally disengaged" }],
      policies_loaded: 4,
      policies_enforce: 0,
      kernel_observable: true,
      process_plane: "cgroup",
      process_links: 2,
      containment: {
        verdict: "partial",
        summary: "This host can kill and freeze a process.",
        kill: "SIGKILL",
        freeze: "cgroup freezer",
        resource_caps: "cpu quota",
        net_process: "not available",
        net_device: "tc",
        auto: "detect-only",
        manual_lands: true
      }
    }
  ],
  agents_total: 1,
  agents_fresh: 1,
  agents_losing: 0,
  expected_policies: ["sensitive-file-access"],
  coverage_caveat: "this console reads ONE host — its own."
};

function mockSensorHealth() {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(JSON.stringify(SENSOR_PAYLOAD), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        })
    )
  );
}

async function renderSensorHealth() {
  mockSensorHealth();
  render(<SensorHealthBody policyStats={[]} open />);
  await waitFor(() => expect(screen.getByText("ip-172-31-33-137")).toBeTruthy());
}

/**
 * The authority store is module state shared by every surface, so each test
 * sets it explicitly and hands it back. Wrapped in act() because a mounted
 * component subscribes to it: an unwrapped write is a React state update from
 * outside the renderer.
 */
function setAuthority(value: boolean | null) {
  act(() => recordResponseAuthority(value));
}

beforeEach(() => setAuthority(null));
afterEach(() => {
  setAuthority(null);
  vi.unstubAllGlobals();
});

describe("Settings › Response withholds the ladder, the mode and the kill-switch", () => {
  it("disables all three for a read-only account and names the permission on each", () => {
    setAuthority(false);
    renderResponseControls();

    const killSwitch = screen.getByRole("button", { name: /engage the kill-switch/i });
    const mode = screen.getByRole("button", { name: /arm automatic containment/i });
    const thresholds = screen.getByRole("button", { name: /apply thresholds/i });

    expect(killSwitch).toBeDisabled();
    expect(mode).toBeDisabled();
    expect(thresholds).toBeDisabled();

    // On the control itself: the operator learns it is not theirs without
    // pressing it, and without reading the panel top to bottom.
    for (const control of [killSwitch, mode, thresholds]) {
      expect(control.getAttribute("title")).toMatch(/read-only/i);
    }

    // And once, in prose, in the language of permission — never as an outage.
    expect(screen.getByText(PERMISSION)).toBeTruthy();
    expect(screen.queryByText(/no Tetragon connection|not configured|unavailable/i)).toBeNull();
  });

  it("does not let a read-only account reach the kill-switch confirm at all", async () => {
    setAuthority(false);
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    renderResponseControls();

    await userEvent.click(screen.getByRole("button", { name: /engage the kill-switch/i }));

    // No confirm panel, and above all no write: the disabled attribute is the
    // affordance, the guard in run() is the enforcement.
    expect(screen.queryByText(/ALL containment stops/i)).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("also withholds the reason box and the ladder inputs, not just the buttons", () => {
    setAuthority(false);
    renderResponseControls();
    expect(screen.getByPlaceholderText(/tuning for the billing estate/i)).toBeDisabled();
    expect(screen.getByRole("spinbutton", { name: /throttle/i })).toBeDisabled();
  });

  it("leaves the single-tenant console exactly as it was when whoami never said", () => {
    // can_respond null. The engine has no notion of a principal who may not
    // respond, and reading its silence as a refusal would strip its console of
    // the controls it legitimately owns.
    renderResponseControls(true, "enforcing");
    expect(screen.getByRole("button", { name: /release the kill-switch/i })).toBeEnabled();
    expect(screen.getByRole("button", { name: /return to detect-only/i })).toBeEnabled();
    expect(screen.getByPlaceholderText(/tuning for the billing estate/i)).toBeEnabled();
    expect(screen.queryByText(PERMISSION)).toBeNull();
  });
});

describe("Sensor Health offers the same two writes, and withholds them the same way", () => {
  it("disables arm/disarm and the kill-switch release for a read-only account", async () => {
    setAuthority(false);
    await renderSensorHealth();

    const mode = screen.getByRole("button", { name: /arm automatic containment/i });
    const release = screen.getByRole("button", { name: /release the kill-switch/i });

    expect(mode).toBeDisabled();
    expect(release).toBeDisabled();
    for (const control of [mode, release]) {
      expect(control.getAttribute("title")).toMatch(/read-only/i);
    }
    expect(screen.getAllByText(PERMISSION).length).toBeGreaterThan(0);
  });

  it("keeps the readings it withholds the controls for", async () => {
    // Only the controls are withheld. What the host can DO is a reading, and a
    // read-only operator keeps every reading — that is the whole job of this
    // panel.
    setAuthority(false);
    await renderSensorHealth();
    expect(screen.getByText(/This host can kill and freeze a process/i)).toBeTruthy();
    expect(screen.getByText(/enforcement is globally disengaged/i)).toBeTruthy();
  });

  it("arms both again for a whoami that never published the field", async () => {
    await renderSensorHealth();
    expect(screen.getByRole("button", { name: /arm automatic containment/i })).toBeEnabled();
    expect(screen.getByRole("button", { name: /release the kill-switch/i })).toBeEnabled();
    expect(screen.queryByText(PERMISSION)).toBeNull();
  });
});

describe("Detections does not name a cause before the server has given it one", () => {
  const loaded = [
    {
      name: "sensitive-file-access",
      description: "Watches credential paths",
      mitre: "T1552",
      loadedAgents: 3,
      kernelStateKnown: true,
      expected: true
    } as SocPolicy
  ];

  it("says it does not know yet while whoami is unanswered", () => {
    // `canPush: false` here is a DEFAULT, not a statement: it is read off the
    // same whoami payload that has not landed. Announcing an outage from it
    // sends the first operator of the session to Sensor Health to investigate
    // an agent nobody reported a fault on.
    render(
      <DetectionsBody
        policies={loaded}
        open
        onRefresh={() => {}}
        canPush={false}
        identityAnswered={false}
        scope="fleet"
      />
    );
    expect(screen.queryByText(/no Tetragon connection/i)).toBeNull();
    expect(screen.queryByText(PERMISSION)).toBeNull();
    expect(screen.getByText(/has not been told yet/i)).toBeTruthy();
    // Still no control — the capability is unknown, which is not permission to
    // offer one.
    expect(screen.queryByRole("button", { name: /write or upload a detection/i })).toBeNull();
  });

  it("refuses the operator even where the deployment says it can push", () => {
    // can_push_policy and can_respond are two different refusals off one
    // payload. The control plane happens to report both false for a read-only
    // account today, so `canPush` alone was enough by coincidence — but every
    // control here dispatches a signed command, and a coincidence is not what
    // should be standing between a refused account and one.
    setAuthority(false);
    render(<DetectionsBody policies={loaded} open onRefresh={() => {}} canPush scope="fleet" />);
    expect(screen.queryByRole("button", { name: /write or upload a detection/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /remove from/i })).toBeNull();
    expect(screen.getByText(PERMISSION)).toBeTruthy();
    expect(screen.queryByText(/no Tetragon connection/i)).toBeNull();
  });

  it("names the deployment once whoami has actually answered", () => {
    render(
      <DetectionsBody
        policies={loaded}
        open
        onRefresh={() => {}}
        canPush={false}
        identityAnswered
        scope="host"
      />
    );
    expect(screen.getByText(/no Tetragon connection/i)).toBeTruthy();
    expect(screen.queryByText(/has not been told yet/i)).toBeNull();
  });
});
