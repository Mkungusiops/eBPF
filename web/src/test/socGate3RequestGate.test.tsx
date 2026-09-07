import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ResponseControls, type Thresholds } from "../features/soc/SettingsResponse";
import { SensorHealthBody } from "../features/soc/SensorHealthBody";
import { SettingsBody } from "../features/soc/SettingsBody";
import { DetectionsBody } from "../features/soc/DetectionsBody";
import { AUTHORITY_PENDING_REASON, READ_ONLY_ACCOUNT_REASON, recordResponseAuthority } from "../features/soc/api";
import type { SocPolicy } from "../features/soc/types";

/**
 * THE GATE ON THE REQUEST, NOT ON THE BUTTON.
 *
 * api.ts already refuses a containment call while the authority answer is in
 * flight — but only inside `jailSocAlert` and `applyChokeAction`, the two calls
 * it makes itself. Every other write on the SOC page goes straight from a
 * component to `postJSON`: the score ladder, the enforcement mode, the
 * kill-switch, the kill-switch RELEASE on Sensor Health, a policy removal, and
 * the suppression list. For all of those, the button's `disabled` was the only
 * thing between a read-only account and the endpoint — which is how the drill's
 * sever came back refused while "Engage the kill-switch" posted successfully in
 * the same second, for the same account, on a control plane whose /api/whoami
 * was failing.
 *
 * A test cannot demonstrate that by clicking correctly-disabled controls:
 * React refuses to dispatch a click to an element it rendered `disabled`, so
 * such a test passes whether or not the request gate exists. So this file
 * reproduces THE CODE THAT SHIPPED instead — `useResponseAuthority` is mocked
 * to the pre-fix answer, in which `readOnlyAccount` is false whenever the server
 * has not said no, and "loading" therefore reads as permitted. Every control
 * comes up armed, exactly as it did in production, and the assertion is that
 * pressing it still sends nothing.
 *
 * The store underneath is NOT mocked, so `responseWithheldNow` sees the real
 * "loading", which is the state the whole defect lives in.
 */
vi.mock("../features/soc/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../features/soc/api")>();
  return {
    ...actual,
    useResponseAuthority: () => ({
      canRespond: actual.responseAuthorityNow(),
      // The four fields as the shipped code computed them: `canRespond === false`
      // is false while loading, so nothing was withheld and nothing said why.
      readOnlyAccount: false,
      pending: false,
      withheld: false,
      reason: null,
      withheldReason: null
    })
  };
});

const THRESHOLDS: Thresholds = { throttle_at: 10, tarpit_at: 20, quarantine_at: 30, sever_at: 40 };

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

const SUPPRESSIONS_PAYLOAD = {
  suppressions: [
    { id: 7, binary: "/opt/backup/agent", policy: "sensitive-file-access", reason: "nightly backup", hits: 12 }
  ],
  candidates: [],
  window: "7d",
  hits_known: true,
  effect: "stops adding to a score"
};

const POLICIES: SocPolicy[] = [
  {
    name: "sensitive-file-access",
    expected: true,
    kernelStateKnown: true,
    loadedAgents: 1,
    kernelMode: "monitor",
    yaml: "apiVersion: cilium.io/v1alpha1\n"
  } as unknown as SocPolicy
];

type Sent = { url: string; method: string };
let sent: Sent[] = [];

function mockFetch(bodyFor: (url: string) => unknown) {
  sent = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      sent.push({ url, method: (init?.method ?? "GET").toUpperCase() });
      return new Response(JSON.stringify(bodyFor(url)), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    })
  );
}

/** Only the calls that CHANGE something — these panels legitimately GET on mount. */
function writes(): Sent[] {
  return sent.filter((r) => r.method !== "GET" && r.method !== "HEAD");
}

function type(input: HTMLElement, value: string) {
  fireEvent.change(input, { target: { value } });
}

/**
 * The button INSIDE the confirmation, found by container rather than by
 * position. Both panels render a confirm block whose action repeats the label
 * of the control that opened it, and the two are not in a fixed DOM order —
 * Sensor Health draws its confirmation above the findings list, Settings ›
 * Response below its controls — so "the last match" silently re-presses the
 * opener on one of them and asserts nothing.
 */
function confirmAction(name: RegExp): HTMLElement {
  const panel = document.querySelector(".soc-sensor-confirm");
  if (!panel) throw new Error("no confirmation panel is open");
  return within(panel as HTMLElement).getByRole("button", { name });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ------ the whoami outage: the store never leaves "loading" for these tests ---- */

describe("an armed control cannot post while the authority answer is in flight", () => {
  it("Settings › Response refuses the kill-switch and says it is still checking", async () => {
    mockFetch(() => ({ ok: true }));
    render(<ResponseControls thresholds={THRESHOLDS} mode="detect-only" killSwitched={false} onChanged={() => {}} />);

    // Armed, because this is the shipped permission read.
    const engage = screen.getByRole("button", { name: /engage the kill-switch/i });
    expect(engage).not.toBeDisabled();
    fireEvent.click(engage);

    // The confirm panel is the window that matters most: it outlives the render
    // that opened it, so a gate held only in that render is already stale by the
    // time the operator presses through.
    type(await screen.findByPlaceholderText(/arming for the maintenance window/i), "CAB-1234: break glass");
    fireEvent.click(confirmAction(/engage the kill-switch/i));

    await waitFor(() => expect(screen.getByText(AUTHORITY_PENDING_REASON)).toBeTruthy());
    expect(writes()).toEqual([]);
  });

  it("Settings › Response refuses the threshold ladder too", async () => {
    mockFetch(() => ({ ok: true }));
    render(<ResponseControls thresholds={THRESHOLDS} mode="detect-only" killSwitched={false} onChanged={() => {}} />);

    // The throttle rung, changed to a value the ladder still accepts — an
    // invalid ladder disables the commit for a reason that has nothing to do
    // with permission, which would make this test pass on the wrong grounds.
    type(screen.getByLabelText("throttle"), "5");
    type(screen.getByPlaceholderText(/tuning for the billing estate/i), "CAB-1234: tightening");
    fireEvent.click(screen.getByRole("button", { name: /apply thresholds/i }));

    await waitFor(() => expect(screen.getByText(AUTHORITY_PENDING_REASON)).toBeTruthy());
    expect(writes()).toEqual([]);
  });

  it("Sensor Health refuses arming the ladder from the containment block", async () => {
    mockFetch(() => SENSOR_PAYLOAD);
    render(<SensorHealthBody policyStats={[]} open />);
    await waitFor(() => expect(screen.getByText("ip-172-31-33-137")).toBeTruthy());

    fireEvent.click(screen.getByRole("button", { name: /arm automatic containment/i }));
    type(await screen.findByPlaceholderText(/arming for the maintenance window/i), "CAB-1234: window");
    fireEvent.click(confirmAction(/arm automatic containment/i));

    await waitFor(() => expect(screen.getByText(AUTHORITY_PENDING_REASON)).toBeTruthy());
    expect(writes()).toEqual([]);
  });

  it("Sensor Health refuses the kill-switch RELEASE offered on a finding", async () => {
    mockFetch(() => SENSOR_PAYLOAD);
    render(<SensorHealthBody policyStats={[]} open />);
    await waitFor(() => expect(screen.getByText("ip-172-31-33-137")).toBeTruthy());

    fireEvent.click(screen.getByRole("button", { name: /release the kill-switch/i }));
    type(await screen.findByPlaceholderText(/arming for the maintenance window/i), "CAB-1234: passed");
    fireEvent.click(confirmAction(/release the kill-switch/i));

    await waitFor(() => expect(screen.getByText(AUTHORITY_PENDING_REASON)).toBeTruthy());
    expect(writes()).toEqual([]);
  });

  it("Settings › Expected behaviour refuses both the add and the delete", async () => {
    mockFetch((url) => (url.includes("suppressions") ? SUPPRESSIONS_PAYLOAD : {}));
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText("/opt/backup/agent")).toBeTruthy());

    type(screen.getByPlaceholderText("/opt/backup/agent"), "/usr/bin/curl");
    type(screen.getByPlaceholderText(/our backup agent reads credential paths nightly/i), "CAB-1: expected here");
    fireEvent.click(screen.getByRole("button", { name: /add suppression/i }));
    await waitFor(() => expect(screen.getByText(AUTHORITY_PENDING_REASON)).toBeTruthy());
    expect(writes()).toEqual([]);

    // DELETE is on the same page and was missed by the same sweep. It resumes
    // detection, which is the safe direction — but it is still a tenant
    // configuration change signed with this operator's name.
    fireEvent.click(screen.getByRole("button", { name: /remove/i }));
    await waitFor(() => expect(screen.getByText(AUTHORITY_PENDING_REASON)).toBeTruthy());
    expect(writes()).toEqual([]);
  });

  it("Detections refuses a policy removal, which had no request guard at all", async () => {
    mockFetch(() => ({ ok: true }));
    render(<DetectionsBody policies={POLICIES} open onRefresh={() => {}} canPush scope="host" />);

    fireEvent.click(screen.getByRole("button", { name: /remove from this host/i }));
    type(await screen.findByPlaceholderText(/too noisy on the billing estate/i), "CAB-1234: too broad");
    fireEvent.click(screen.getByRole("button", { name: /^Remove sensitive-file-access from this host$/ }));

    // Unloading a detection is a signed command to every host that has it. It
    // must not leave while the console still does not know who is asking.
    await waitFor(() => expect(writes()).toEqual([]));
  });
});

/* --------------------------- and once the server has actually refused --------- */

describe("an armed control cannot post after the server has refused the account", () => {
  it("reports the permission, not the pending sentence", async () => {
    act(() => recordResponseAuthority(false));
    mockFetch(() => ({ ok: true }));
    render(<ResponseControls thresholds={THRESHOLDS} mode="detect-only" killSwitched={false} onChanged={() => {}} />);

    fireEvent.click(screen.getByRole("button", { name: /engage the kill-switch/i }));
    type(await screen.findByPlaceholderText(/arming for the maintenance window/i), "CAB-1234: break glass");
    fireEvent.click(confirmAction(/engage the kill-switch/i));

    await waitFor(() => expect(screen.getByText(READ_ONLY_ACCOUNT_REASON)).toBeTruthy());
    expect(writes()).toEqual([]);
  });
});
