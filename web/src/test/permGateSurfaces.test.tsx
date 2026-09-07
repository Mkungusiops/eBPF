import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DetectionsBody } from "../features/soc/DetectionsBody";
import { DrillPanel } from "../features/soc/DrillPanel";
import { ProcessActionModal } from "../features/soc/ProcessActionModal";
import { GraphSelectionRail } from "../features/soc/GraphSelectionRail";
import { recordResponseAuthority } from "../features/soc/api";
import type { ProcessInstance } from "../features/soc/graphModel";
import type { SocAlert, SocPolicy } from "../features/soc/types";

/**
 * What a principal the server refuses must SEE.
 *
 * Two rules run through every assertion here, and both come from the live
 * persona probes:
 *
 *  1. A control the server will refuse is never offered. The read-only
 *     operator who presses sever and watches nothing happen believes
 *     enforcement was bypassed.
 *  2. The withholding is stated in the language of PERMISSION. "No Tetragon
 *     connection" told an operator the platform was broken when they were
 *     merely not allowed, and pointed them at Sensor Health to investigate an
 *     outage that was not happening.
 *
 * And the third rule, which is what makes this a gate rather than a mute
 * button: `null` — a server that never published `can_respond`, i.e. the
 * single-tenant engine — changes nothing.
 */
const alert: SocAlert = {
  id: "a1",
  title: "curl piped to shell",
  severity: "high",
  score: 140,
  timestamp: "2026-09-02T09:00:00Z",
  execId: "ZXhlYy0x",
  pid: 4242,
  process: "/usr/bin/curl",
  description: "d"
} as SocAlert;

const drill: ProcessInstance = {
  execId: "ZXhlYy0x",
  pid: 4242,
  binary: "/usr/bin/curl",
  score: 40,
  agent: "web-01",
  policies: ["sever-pipe-to-shell"],
  lastSeen: "2026-09-02T09:00:00Z"
};

const loadedPolicy = [
  {
    name: "sensitive-file-access",
    description: "Watches credential paths",
    mitre: "T1552",
    loadedAgents: 3,
    kernelStateKnown: true,
    expected: true
  } as SocPolicy
];

function renderDrill() {
  render(
    <DrillPanel
      alert={alert}
      ack="new"
      note=""
      processDetail={null}
      processDetailError=""
      onAck={() => {}}
      onNote={() => {}}
      onActionComplete={() => {}}
    />
  );
}

function renderProcessModal() {
  render(
    <ProcessActionModal
      drill={drill}
      state="pristine"
      nodeLabel="web-01"
      apply={async () => ({ ok: true, detail: "" })}
      readState={async () => "pristine"}
      onClose={() => {}}
    />
  );
}

beforeEach(() => recordResponseAuthority(null));
afterEach(() => recordResponseAuthority(null));

describe("can_respond=false withholds containment, and says whose decision it was", () => {
  it("disables the alert drill's choke response and names the permission", () => {
    recordResponseAuthority(false);
    renderDrill();
    expect(screen.getByRole("button", { name: /send quarantine/i })).toBeDisabled();
    expect(screen.getByPlaceholderText(/required for \/api\/choke\/jail/i)).toBeDisabled();
    expect(screen.getByText(/ask an administrator for responder access/i)).toBeTruthy();
    // Not an outage, and not a missing feature.
    expect(screen.queryByText(/unavailable|not configured|no .* connection/i)).toBeNull();
  });

  it("withholds the process ladder rather than drawing rungs the server 404s", () => {
    recordResponseAuthority(false);
    renderProcessModal();
    for (const rung of [/^Throttle$/, /^Tarpit$/, /^Quarantine$/, /^Sever$/]) {
      expect(screen.queryByRole("button", { name: rung })).toBeNull();
    }
    expect(screen.getByText(/ask an administrator for responder access/i)).toBeTruthy();
    // The rung the process is ON is a reading, and a read-only operator keeps
    // every reading. Only the controls that move it are withheld.
    expect(screen.getByText("pristine")).toBeTruthy();
  });

  it("does not promise the graph rail's operator an action they cannot take", () => {
    recordResponseAuthority(false);
    render(
      <GraphSelectionRail
        selected={null}
        neighbours={[]}
        nodeProcesses={[]}
        visibleProcesses={[]}
        procFilter=""
        onProcFilterChange={() => {}}
        containedOnly={false}
        onToggleContainedOnly={() => {}}
        circuits={new Map()}
        onPickProcess={() => {}}
        onSelectNode={() => {}}
      />
    );
    expect(screen.getByText(/read-only/i)).toBeTruthy();
    expect(screen.queryByText(/inspect and act/i)).toBeNull();
  });
});

describe("can_respond=null leaves the single-tenant console exactly as it was", () => {
  it("keeps the alert drill's choke response usable", () => {
    renderDrill();
    // Disabled only by its own rule — a reason under three characters — which
    // is the state this form has always started in.
    expect(screen.queryByText(/read-only/i)).toBeNull();
    expect(screen.getByPlaceholderText(/required for \/api\/choke\/jail/i)).toBeEnabled();
    expect(screen.getByRole("button", { name: /send quarantine/i })).toBeInTheDocument();
  });

  it("keeps the process ladder drawn", () => {
    renderProcessModal();
    expect(screen.getByRole("button", { name: /^Sever$/ })).toBeTruthy();
    expect(screen.queryByText(/read-only/i)).toBeNull();
  });
});

describe("a withheld detection push names the reason it is actually withheld for", () => {
  it("blames the permission when the operator is the one refused", () => {
    recordResponseAuthority(false);
    render(<DetectionsBody policies={loadedPolicy} open onRefresh={() => {}} canPush={false} scope="fleet" />);
    // The deployment dispatches policy for a responding analyst on this very
    // estate, so naming an outage here sends the operator to debug a healthy
    // agent.
    expect(screen.queryByText(/no Tetragon connection/i)).toBeNull();
    expect(screen.getByText(/read-only/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /write or upload a detection/i })).toBeNull();
  });

  it("still blames the deployment when the deployment is what cannot push", () => {
    // can_respond null: nobody has been refused, so a missing push capability
    // is the fake/dev engine with no Tetragon connection — the original copy,
    // which must survive.
    render(<DetectionsBody policies={loadedPolicy} open onRefresh={() => {}} canPush={false} scope="host" />);
    expect(screen.getByText(/no Tetragon connection/i)).toBeTruthy();
    expect(screen.queryByText(/read-only/i)).toBeNull();
  });
});
