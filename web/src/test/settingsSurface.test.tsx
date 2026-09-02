import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SettingsBody } from "../features/soc/SettingsBody";

/**
 * A settings surface's characteristic failure is saving something and not
 * applying it — or claiming an effect it does not have. These pin the claims.
 */
function mockGet(payload: unknown, status = 200, byPath: Record<string, unknown> = {}) {
  // URL-aware: the settings surface reads three endpoints, and a stub that
  // answers all of them with the suppressions body is how a panel passes its
  // test against a shape the server never sends.
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    for (const [frag, body] of Object.entries(byPath)) {
      if (url.includes(frag)) {
        return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
      }
    }
    return new Response(JSON.stringify(payload), { status, headers: { "Content-Type": "application/json" } });
  }));
}

/** The control plane's change-control posture, four-eyes currently off. */
const CHANGE_CONTROL = {
  enabled: false,
  mandated: false,
  can_disable: false,
  gated: ["quarantine", "sever", "fleet arming"],
  never_gated: ["thaw", "throttle", "tarpit", "kill-switch", "detect-only"],
  available: true
};

/** What the engine and the control plane both return for the protect-lists. */
const PROTECTED = {
  floor: ["/usr/bin/sudo", "/usr/sbin/sshd"],
  binaries: ["/opt/monitoring/agent"],
  macs: ["0a:1b:2c:3d:4e:5f"],
  process_plane: true,
  device_plane: true,
  macs_are_add_only: true,
  desired_only: false
};

afterEach(() => vi.unstubAllGlobals());

const EMPTY = { suppressions: [], hits_known: true, effect: "score only" };

describe("the settings surface states what a suppression does not do", () => {
  it("says the event is still recorded and the binary still containable", async () => {
    // The claim moved from a paragraph into the settings model's row help,
    // where it sits next to the control it qualifies.
    // An operator reasonably reads "suppress" as "stop watching this". It is
    // not: only the score is withheld, and the score is what drives automatic
    // containment. Getting this wrong means someone suppresses a binary
    // believing they have stopped monitoring it.
    mockGet(EMPTY);
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText(/Expected behaviour/)).toBeTruthy());
    expect(screen.getByText(/still recorded/)).toBeTruthy();
    expect(screen.getByText(/contained by hand/)).toBeTruthy();
  });

  it("says matching is exact, on the field where it matters", async () => {
    mockGet(EMPTY);
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText(/matched exactly/)).toBeTruthy());
  });

  it("states the lifecycle and scope of every row it shows", async () => {
    // The point of the restructure: an operator must see at a glance whether a
    // value is live, needs a restart, or is owned by the deploy. A settings
    // page that renders them all as editable fields is how someone changes
    // something and believes it took.
    mockGet(EMPTY);
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText(/Expected behaviour/)).toBeTruthy());
    expect(screen.getAllByText(/Live|Needs restart|Set by deploy|Not available yet/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/per-tenant|platform-wide|this-host/).length).toBeGreaterThan(0);
  });

  it("does not offer a control for a row the platform cannot change", async () => {
    // Platform is rewritten wholesale by the deploy on every run, so a control
    // there would be silently reverted. A disabled input would invite someone
    // to keep clicking it.
    const user = userEvent.setup();
    mockGet(EMPTY);
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText(/Expected behaviour/)).toBeTruthy());
    await user.click(screen.getByRole("button", { name: /^Platform/i }));
    expect(screen.getByText(/silently reverted/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /add suppression/i })).toBeNull();
  });

  it("still defers identity to Keycloak, next to a row it can change", async () => {
    // Access holds both: RBAC belongs in Keycloak and says so, while change
    // control is a real switch. The section has to make that split obvious
    // rather than reading as half-broken.
    const user = userEvent.setup();
    mockGet(EMPTY, 200, { "/api/settings/change-control": CHANGE_CONTROL });
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText(/Expected behaviour/)).toBeTruthy());
    await user.click(screen.getByRole("button", { name: /^Access/i }));
    expect(screen.getByText(/Change it there, not here/)).toBeTruthy();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /Require a second operator/i })).toBeTruthy());
  });
});

describe("change control is a live switch, with a floor it cannot cross", () => {
  async function openAccess(payload: unknown) {
    const user = userEvent.setup();
    mockGet(EMPTY, 200, { "/api/settings/change-control": payload });
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText(/Expected behaviour/)).toBeTruthy());
    await user.click(screen.getByRole("button", { name: /^Access/i }));
    return user;
  }

  it("names what is never held, whatever the setting is", async () => {
    // A safety property, not an omission: the way out of a bad state must not
    // wait for a quorum. An operator has to be able to read that here.
    await openAccess(CHANGE_CONTROL);
    await waitFor(() => expect(screen.getByText(/must not wait for a quorum/)).toBeTruthy());
    expect(screen.getByText(/kill-switch/)).toBeTruthy();
  });

  it("locks the control when the platform mandates four-eyes", async () => {
    // Rendered locked, not discovered from a 409 after the operator commits.
    await openAccess({ ...CHANGE_CONTROL, enabled: true, mandated: true, can_disable: false });
    await waitFor(() => expect(screen.getByText(/This platform mandates change control/)).toBeTruthy());
    expect(screen.queryByRole("button", { name: /Switch change control off/i })).toBeNull();
  });

  it("will not switch off without a reason", async () => {
    const user = await openAccess({ ...CHANGE_CONTROL, enabled: true, can_disable: true });
    await user.click(await screen.findByRole("button", { name: /Switch change control off/i }));
    const commit = screen.getByRole("button", { name: /Switch change control off/i });
    expect((commit as HTMLButtonElement).disabled).toBe(true);
    // And it warns that the queue is not released.
    expect(screen.getByText(/switching this off does not approve it/)).toBeTruthy();
  });

  it("says four-eyes is not applicable on a single-host engine", async () => {
    // The engine does not serve this route. That is different from the read
    // failing, and warning about it on every engine console is crying wolf.
    const user = userEvent.setup();
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
      if (url.includes("/api/settings/change-control")) return new Response("404 page not found", { status: 404 });
      return new Response(JSON.stringify(EMPTY), { status: 200, headers: { "Content-Type": "application/json" } });
    }));
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText(/Expected behaviour/)).toBeTruthy());
    await user.click(screen.getByRole("button", { name: /^Access/i }));
    await waitFor(() => expect(screen.getByText(/no second operator for a request to wait on/)).toBeTruthy());
  });
});

describe("guardrails are editable, and say what cannot be edited", () => {
  async function openGuardrails() {
    const user = userEvent.setup();
    mockGet(EMPTY, 200, { "/api/settings/protected": PROTECTED });
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText(/Expected behaviour/)).toBeTruthy());
    await user.click(screen.getByRole("button", { name: /^Guardrails/i }));
    await waitFor(() => expect(screen.getByText("/opt/monitoring/agent")).toBeTruthy());
    return user;
  }

  it("shows the compiled-in floor without a way to remove it", async () => {
    // The floor is what stops a containment mistake locking every operator
    // out. Rendering it as a removable chip would offer a control that
    // silently restores its own value on the next apply.
    await openGuardrails();
    expect(screen.getByText("/usr/sbin/sshd")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Remove /usr/sbin/sshd" })).toBeNull();
    // The operator's own addition IS removable.
    expect(screen.getByRole("button", { name: "Remove /opt/monitoring/agent" })).toBeTruthy();
  });

  it("refuses a bare binary name, which would protect nothing", async () => {
    const user = await openGuardrails();
    await user.type(screen.getByLabelText(/Binary to protect/i), "monitoring-agent");
    expect(screen.getByText(/would protect nothing while looking protected/)).toBeTruthy();
  });

  it("refuses an address the agent could not parse", async () => {
    const user = await openGuardrails();
    await user.type(screen.getByLabelText(/Address to protect/i), "not-a-mac");
    expect(screen.getByText(/silently not protected/)).toBeTruthy();
  });

  it("will not apply without a reason, and not without a change", async () => {
    const user = await openGuardrails();
    const apply = screen.getByRole("button", { name: /Apply guardrails/i });
    expect((apply as HTMLButtonElement).disabled).toBe(true);
    // A reason alone is not enough — there is nothing to apply yet.
    await user.type(screen.getByLabelText(/Reason/i), "protect the jump hosts");
    expect((apply as HTMLButtonElement).disabled).toBe(true);
    await user.type(screen.getByLabelText(/Binary to protect/i), "/opt/jump/agent");
    await user.click(screen.getByRole("button", { name: /Add protected binary/i }));
    await waitFor(() => expect((apply as HTMLButtonElement).disabled).toBe(false));
  });

  it("warns that removing an address does not un-protect a running agent", async () => {
    // SetProtectedMACs is add-only in the agent on purpose. Saying "removed"
    // flatly would be the comfortable copy and the false one.
    const user = await openGuardrails();
    await user.click(screen.getByRole("button", { name: "Remove 0a:1b:2c:3d:4e:5f" }));
    expect(screen.getByText(/add-only while it is running/)).toBeTruthy();
  });

  it("says the control plane is reporting intent, not any agent's live list", async () => {
    const user = userEvent.setup();
    mockGet(EMPTY, 200, { "/api/settings/protected": { ...PROTECTED, desired_only: true } });
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText(/Expected behaviour/)).toBeTruthy());
    await user.click(screen.getByRole("button", { name: /^Guardrails/i }));
    await waitFor(() =>
      expect(screen.getByText(/cannot confirm what any single host holds/)).toBeTruthy());
  });

  it("does not render an unreadable protect-list as an unprotected one", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
      if (url.includes("/api/settings/protected")) return new Response("nope", { status: 500 });
      return new Response(JSON.stringify(EMPTY), { status: 200, headers: { "Content-Type": "application/json" } });
    }));
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText(/Expected behaviour/)).toBeTruthy());
    await user.click(screen.getByRole("button", { name: /^Guardrails/i }));
    await waitFor(() => expect(screen.getByText(/not the same as nothing being protected/)).toBeTruthy());
  });

  it("survives a deployment that omits fields this panel expects", async () => {
    // The Sensor Health panel crashed on exactly this: .map on a field the
    // server simply did not send.
    const user = userEvent.setup();
    mockGet(EMPTY, 200, { "/api/settings/protected": { floor: null, binaries: undefined } });
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText(/Expected behaviour/)).toBeTruthy());
    await user.click(screen.getByRole("button", { name: /^Guardrails/i }));
    await waitFor(() =>
      expect(screen.getByText(/did not report its fixed list/)).toBeTruthy());
  });
});

describe("the form refuses rules that cannot work", () => {
  it("will not submit a bare binary name", async () => {
    // Matching is on absolute paths, so "curl" would never fire and would sit
    // in the list looking like a working rule.
    const user = userEvent.setup();
    mockGet(EMPTY);
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByPlaceholderText("/opt/backup/agent")).toBeTruthy());

    await user.type(screen.getByPlaceholderText("/opt/backup/agent"), "curl");
    await user.type(screen.getByPlaceholderText(/backup agent reads/), "a reason");
    expect((screen.getByRole("button", { name: /add suppression/i }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("will not submit without a reason", async () => {
    const user = userEvent.setup();
    mockGet(EMPTY);
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByPlaceholderText("/opt/backup/agent")).toBeTruthy());

    await user.type(screen.getByPlaceholderText("/opt/backup/agent"), "/opt/backup/agent");
    expect((screen.getByRole("button", { name: /add suppression/i }) as HTMLButtonElement).disabled).toBe(true);
  });
});

describe("a dead rule is visible, and an unknown count is not a zero", () => {
  it("says a rule has never fired rather than showing 0", async () => {
    // "0" reads as "this rule does nothing" and invites deleting it. "never
    // fired — check the path" says the actionable thing: it is probably a typo.
    mockGet({
      suppressions: [{ id: 1, binary: "/opt/typo/agnt", reason: "typo'd path", hits: 0 }],
      hits_known: true, effect: "score only"
    });
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText("/opt/typo/agnt")).toBeTruthy());
    expect(screen.getByText(/never fired — check the path/)).toBeTruthy();
  });

  it("says the count is unreported when the deployment cannot measure it", async () => {
    mockGet({
      suppressions: [{ id: 1, binary: "/opt/backup/agent", reason: "expected" }],
      hits_known: false, effect: "score only"
    });
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText("/opt/backup/agent")).toBeTruthy());
    expect(screen.getByText(/count not reported/)).toBeTruthy();
    expect(screen.queryByText(/never fired/)).toBeNull();
  });
});

describe("an unreadable settings surface does not claim there are no rules", () => {
  it("distinguishes 'could not read' from 'none configured'", async () => {
    // Rendering "No suppressions" on a failed read invites an operator to add
    // one that already exists.
    vi.stubGlobal("fetch", vi.fn(async () => new Response("nope", { status: 500 })));
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText(/Settings could not be read/)).toBeTruthy());
    expect(screen.getByText(/not the same as having no suppressions/)).toBeTruthy();
  });
});

// The page opened on an empty text field asking for an absolute binary path.
// An analyst arrives knowing something is NOISY, not knowing which path to
// type — so the surface has to lead with a question they can answer.
describe("settings leads with what is actually noisy on this host", () => {
  const withCandidates = {
    suppressions: [],
    candidates: [
      { binary: "/opt/backup/agent", policy: "sensitive-file-access", events: 4120, suppressed: false },
      { binary: "/usr/bin/cfgmgr", policy: "privilege-escalation", events: 300, suppressed: false }
    ],
    window: "7d", hits_known: true, effect: "score only"
  };

  it("offers the binaries producing the findings, with their volume", async () => {
    mockGet(withCandidates);
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText("/opt/backup/agent")).toBeTruthy());
    expect(screen.getByText(/4,120 events/)).toBeTruthy();
    expect(screen.getAllByRole("button", { name: /expected here/i }).length).toBe(2);
  });

  it("fills the form from a candidate instead of making the operator type a path", async () => {
    // Typing an absolute path from memory is how a rule ends up never firing.
    const user = userEvent.setup();
    mockGet(withCandidates);
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText("/opt/backup/agent")).toBeTruthy());

    await user.click(screen.getAllByRole("button", { name: /expected here/i })[0]);
    expect((screen.getByPlaceholderText("/opt/backup/agent") as HTMLInputElement).value).toBe("/opt/backup/agent");
    expect(screen.getByText(/Suppress \/opt\/backup\/agent\?/)).toBeTruthy();
  });

  it("does not re-offer something already suppressed", async () => {
    // Re-offering a handled binary makes the list look like nothing happened.
    mockGet({
      suppressions: [{ id: 1, binary: "/opt/backup/agent", reason: "expected", hits: 5 }],
      candidates: [{ binary: "/opt/backup/agent", events: 10, suppressed: true }],
      window: "7d", hits_known: true, effect: "score only"
    });
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText(/fired 5×/)).toBeTruthy());
    expect(screen.queryByRole("button", { name: /expected here/i })).toBeNull();
  });
});
