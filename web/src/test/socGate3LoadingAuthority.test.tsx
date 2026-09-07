import { act, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ResponseControls, responseWithheldNow, type Thresholds } from "../features/soc/SettingsResponse";
import { SensorHealthBody } from "../features/soc/SensorHealthBody";
import { SettingsBody } from "../features/soc/SettingsBody";
import { DetectionsBody } from "../features/soc/DetectionsBody";
import {
  AUTHORITY_PENDING_REASON,
  READ_ONLY_ACCOUNT_REASON,
  recordResponseAuthority,
  responseAuthorityNow
} from "../features/soc/api";
import type { SocPolicy } from "../features/soc/types";

/**
 * LOADING IS NOT PERMISSION — on the SOC page's own write surfaces.
 *
 * The device and process choke planes learned this already (see
 * chokeGate2FirstPaintArming): the shared authority store starts at "loading",
 * `readOnlyAccount` is `canRespond === false`, and false is NOT what "loading"
 * is — so any control whose `disabled` reads `readOnlyAccount` arms itself
 * while the answer is in flight. Three SOC surfaces still did exactly that, and
 * between them they carry the two widest blast radii the product has:
 *
 *   • Settings › Response — the score ladder, the enforcement mode and the
 *     kill-switch.
 *   • Sensor Health — arm/disarm and the kill-switch RELEASE.
 *   • Settings › Expected behaviour — the suppression list, which decides what
 *     this platform stops scoring at all.
 *
 * This is not only a first-paint flicker. `recordResponseAuthority` leaves
 * "loading" only on a whoami that ANSWERED, so on a control plane whose
 * /api/whoami is failing — a documented outage of this system — the store sits
 * at "loading" for the whole session. In that session the alert drill's sever
 * was refused by api.ts's own request gate while "Engage the kill-switch"
 * posted successfully, for the same account, in the same second.
 *
 * Two rules, and BOTH are checked on every surface, because the previous two
 * passes fixed the first and stopped there:
 *
 *   1. THE CONTROL is disabled, and says which refusal it is — never
 *      "read-only" while the console is still asking.
 *   2. THE REQUEST is refused independently of the control. Every write in
 *      these files goes straight to postJSON from a component, so a surface
 *      that gates on the wrong flag is one forgotten `disabled` away from
 *      firing. That half lives in socGate3RequestGate, which renders these same
 *      surfaces with the pre-fix permission read so the controls come up ARMED
 *      and the request has to refuse itself. React will not dispatch a click to
 *      a control it rendered `disabled`, so it cannot be checked from here.
 *
 * ORDERING MATTERS IN THIS FILE. The store starts at "loading" and only
 * `recordResponseAuthority` moves it off — there is no way back. Every test
 * needing the in-flight state therefore runs before any test that lets a whoami
 * answer, and the first expectation pins that precondition rather than assuming
 * it. This is also why `permGate2WriteControls` never caught the defect: its
 * `beforeEach` calls `setAuthority(null)`, normalising the loading state away
 * before a single case runs.
 */

const THRESHOLDS: Thresholds = { throttle_at: 10, tarpit_at: 20, quarantine_at: 30, sever_at: 40 };

/** A host reporting both of Sensor Health's write controls at once. */
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

const SUPPRESSIONS_PAYLOAD = {
  suppressions: [
    { id: 7, binary: "/opt/backup/agent", policy: "sensitive-file-access", reason: "nightly backup", hits: 12 }
  ],
  candidates: [{ binary: "/usr/bin/curl", policy: "network-activity", events: 940, suppressed: false }],
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
    kernelMode: "monitor"
  } as unknown as SocPolicy
];

/**
 * Every request this suite sees, so an assertion can say "no WRITE left" rather
 * than "no fetch happened" — these panels legitimately GET on mount.
 */
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

function writes(): Sent[] {
  return sent.filter((r) => r.method !== "GET" && r.method !== "HEAD");
}

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ------------------------------------------------------------------ loading */

describe("nothing on the SOC page is armed while whoami is in flight", () => {
  it("starts at loading — the precondition every assertion in this file rests on", () => {
    expect(responseAuthorityNow()).toBe("loading");
  });

  it("Settings › Response draws the ladder, the mode and the kill-switch inert, and says it is still checking", () => {
    mockFetch(() => ({}));
    render(<ResponseControls thresholds={THRESHOLDS} mode="detect-only" killSwitched={false} onChanged={() => {}} />);

    const killSwitch = screen.getByRole("button", { name: /engage the kill-switch/i });
    const mode = screen.getByRole("button", { name: /arm automatic containment/i });
    const thresholds = screen.getByRole("button", { name: /apply thresholds/i });
    for (const control of [killSwitch, mode, thresholds]) expect(control).toBeDisabled();

    // The ladder inputs too: an operator who can type a sever threshold into a
    // form they may not submit has been invited to compose a change and then
    // told it was never theirs.
    for (const label of ["throttle", "tarpit", "quarantine", "sever"]) {
      expect(screen.getByLabelText(label)).toBeDisabled();
    }

    // WHICH refusal, in the language of what the console actually knows.
    expect(screen.getByText(new RegExp(AUTHORITY_PENDING_REASON.slice(0, 40), "i"))).toBeTruthy();
    // And never the other sentence: telling a responder their account is
    // read-only for the length of a whoami outage is a lie of its own. The
    // whole document, so moving the copy cannot hide it.
    expect(document.body.textContent).not.toMatch(/read-only/i);
  });

  it("Sensor Health draws arm/disarm and the kill-switch release inert", async () => {
    mockFetch(() => SENSOR_PAYLOAD);
    render(<SensorHealthBody policyStats={[]} open />);
    await waitFor(() => expect(screen.getByText("ip-172-31-33-137")).toBeTruthy());

    const arm = screen.getByRole("button", { name: /arm automatic containment/i });
    const release = screen.getByRole("button", { name: /release the kill-switch/i });
    expect(arm).toBeDisabled();
    expect(release).toBeDisabled();
    expect(arm.getAttribute("title")).toBe(AUTHORITY_PENDING_REASON);
    // The withheld note names the state as pending, not as a permission.
    expect(document.querySelector('[data-withheld="pending"]')).toBeTruthy();
    expect(document.querySelector('[data-withheld="permission"]')).toBeNull();
    expect(document.body.textContent).not.toMatch(/read-only/i);
    expect(writes()).toEqual([]);
  });

  it("Settings › Expected behaviour draws both suppression writes inert and keeps the list readable", async () => {
    mockFetch((url) => (url.includes("suppressions") ? SUPPRESSIONS_PAYLOAD : {}));
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText("/opt/backup/agent")).toBeTruthy());

    const add = screen.getByRole("button", { name: /add suppression/i });
    const remove = screen.getByRole("button", { name: /remove/i });
    expect(add).toBeDisabled();
    expect(remove).toBeDisabled();
    // The fields are NOT withheld, on purpose: composing a suppression is the
    // reader's, and the same rule keeps the choke plane's threshold simulator
    // live for an account that may not commit it. Only the two writes go inert.
    expect(screen.getByPlaceholderText("/opt/backup/agent")).not.toBeDisabled();

    // The list itself is a READING and stays legible: an analyst triaging a
    // binary that has gone quiet needs to see why, whether or not they may
    // change it.
    expect(screen.getByText("nightly backup")).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/read-only/i);
    // The panel names the state as still-checking rather than as a permission.
    expect(screen.getByText(new RegExp(AUTHORITY_PENDING_REASON.slice(0, 40), "i"))).toBeTruthy();
    expect(writes()).toEqual([]);
  });

  it("Detections does not claim the deployment has no Tetragon connection before whoami answers", async () => {
    mockFetch(() => ({}));
    // canPush=false is exactly what SocModals passes before whoami lands:
    // `snapshot.whoami.canPushPolicy` is undefined on the placeholder, so
    // `=== true` is false. It is a DEFAULT, not a statement about the
    // deployment — and the panel used to read it as one and announce an outage.
    render(<DetectionsBody policies={POLICIES} open onRefresh={() => {}} canPush={false} scope="host" />);

    expect(screen.queryByText(/no Tetragon connection/i)).toBeNull();
    expect(screen.queryByRole("button", { name: /write or upload a detection/i })).toBeNull();
    // The third sentence: it does not know yet, and says so — naming neither a
    // fault nor the account.
    expect(document.querySelector('[data-withheld="unknown"]')).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/read-only/i);
    expect(writes()).toEqual([]);
  });
});

/* ------------------------------------------------- the server said no (false) */

describe("a whoami that refuses this account is told in the language of permission", () => {
  beforeEach(() => act(() => recordResponseAuthority(false)));

  it("keeps every Settings › Response control inert and names the permission on it", () => {
    mockFetch(() => ({}));
    render(<ResponseControls thresholds={THRESHOLDS} mode="detect-only" killSwitched={false} onChanged={() => {}} />);

    const killSwitch = screen.getByRole("button", { name: /engage the kill-switch/i });
    expect(killSwitch).toBeDisabled();
    expect(killSwitch.getAttribute("title")).toBe(READ_ONLY_ACCOUNT_REASON);
    expect(screen.getByText(/ask an administrator for responder access/i)).toBeTruthy();
    // Not the pending sentence: the server HAS answered.
    expect(document.body.textContent).not.toMatch(/Checking what this account may do/i);
  });

  it("withholds the suppression writes as a permission, and never as an outage", async () => {
    mockFetch((url) => (url.includes("suppressions") ? SUPPRESSIONS_PAYLOAD : {}));
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText("/opt/backup/agent")).toBeTruthy());

    const add = screen.getByRole("button", { name: /add suppression/i });
    expect(add).toBeDisabled();
    expect(add.getAttribute("title")).toBe(READ_ONLY_ACCOUNT_REASON);
    expect(screen.getByRole("button", { name: /remove/i })).toBeDisabled();
    expect(writes()).toEqual([]);
    // Suppressions are an analyst's own surface, so the temptation to explain
    // the refusal as "settings could not be read" is real. It is a permission.
    expect(document.body.textContent).not.toMatch(/no Tetragon connection|not configured|unavailable/i);
  });

  it("blames the permission on Detections rather than the deployment", () => {
    mockFetch(() => ({}));
    render(<DetectionsBody policies={POLICIES} open onRefresh={() => {}} canPush scope="host" />);

    expect(document.querySelector('[data-withheld="permission"]')).toBeTruthy();
    expect(screen.queryByText(/no Tetragon connection/i)).toBeNull();
  });

  it("reports the same refusal from the shared request gate every write in these files calls", () => {
    expect(responseWithheldNow()).toBe(READ_ONLY_ACCOUNT_REASON);
  });
});

/* -------------------------------------- a whoami that answered without the field */

describe("a server that answered and never mentioned can_respond changes nothing", () => {
  beforeEach(() => act(() => recordResponseAuthority(null)));

  it("arms the ladder, the mode and the kill-switch again", () => {
    mockFetch(() => ({}));
    render(<ResponseControls thresholds={THRESHOLDS} mode="detect-only" killSwitched={false} onChanged={() => {}} />);

    expect(screen.getByRole("button", { name: /engage the kill-switch/i })).not.toBeDisabled();
    expect(screen.getByRole("button", { name: /arm automatic containment/i })).not.toBeDisabled();
    expect(screen.getByLabelText("sever")).not.toBeDisabled();
    // No refusal copy at all: the single-tenant engine has no concept of an
    // operator who may not contain, and inventing one takes a working console's
    // controls away.
    expect(document.body.textContent).not.toMatch(/read-only|Checking what this account may do/i);
  });

  it("arms the suppression list again", async () => {
    mockFetch((url) => (url.includes("suppressions") ? SUPPRESSIONS_PAYLOAD : {}));
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText("/opt/backup/agent")).toBeTruthy());

    expect(screen.getByRole("button", { name: /remove/i })).not.toBeDisabled();
    expect(screen.getByRole("button", { name: /add suppression/i })).toBeDisabled(); // empty form, not permission
  });

  it("lets Detections author again, and still never mentions a Tetragon outage", () => {
    mockFetch(() => ({}));
    render(<DetectionsBody policies={POLICIES} open onRefresh={() => {}} canPush scope="host" />);

    expect(screen.getByRole("button", { name: /write or upload a detection/i })).toBeTruthy();
    expect(screen.queryByText(/no Tetragon connection/i)).toBeNull();
  });

  it("lets the shared request gate through", () => {
    expect(responseWithheldNow()).toBeNull();
  });
});
