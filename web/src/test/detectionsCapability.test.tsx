import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { DetectionsBody } from "../features/soc/DetectionsBody";
import type { SocPolicy } from "../features/soc/types";

/**
 * The Detections surface is ONE component serving two deployments, and only one
 * of them can dispatch a policy: /api/policies/push is registered on the
 * control plane, and not on the single-tenant engine, which runs on the
 * monitored host, has no agents, and is provisioned by file.
 *
 * Rendered ungated, the engine's console offered a "push to the fleet" button
 * that 404s, and a "Remove from fleet" on every loaded policy that did the
 * same. That is the defect class this codebase keeps producing — a surface
 * asserting a capability the deployment behind it does not have — so the gate
 * is pinned rather than left to the next reader to notice.
 */
const loaded: SocPolicy[] = [
  {
    name: "sensitive-file-access",
    description: "Watches credential paths",
    mitre: "T1552",
    loadedAgents: 3,
    kernelStateKnown: true,
    expected: true
  } as SocPolicy
];

describe("the push affordance follows the deployment, not the layout", () => {
  it("offers authoring where a fleet exists", () => {
    render(<DetectionsBody policies={loaded} open onRefresh={() => {}} canPush scope="fleet" />);
    expect(screen.getByRole("button", { name: /write or upload a detection/i })).toBeTruthy();
    expect(screen.getByRole("button", { name: /remove from the fleet|remove from fleet/i })).toBeTruthy();
  });

  it("offers neither where there is no fleet, and says why", () => {
    render(<DetectionsBody policies={loaded} open onRefresh={() => {}} canPush={false} scope="host" />);
    expect(screen.queryByRole("button", { name: /write or upload a detection/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /remove from/i })).toBeNull();
    // Silence would read as a missing feature. The reason is the point.
    expect(screen.getByText(/no Tetragon connection/i)).toBeTruthy();
  });

  it("never offers to remove a policy the kernel does not have", () => {
    // Removal of an absent policy dispatches a command that changes nothing
    // and acks successfully — the operator is told it worked.
    const absent = [{ ...loaded[0], loadedAgents: 0 }] as SocPolicy[];
    render(<DetectionsBody policies={absent} open onRefresh={() => {}} canPush scope="fleet" />);
    expect(screen.queryByRole("button", { name: /remove from/i })).toBeNull();
  });

  it("never offers to remove a policy whose load state is unknown", () => {
    const unknown = [{ ...loaded[0], kernelStateKnown: false, loadedAgents: undefined }] as SocPolicy[];
    render(<DetectionsBody policies={unknown} open onRefresh={() => {}} canPush scope="fleet" />);
    expect(screen.queryByRole("button", { name: /remove from/i })).toBeNull();
  });
});

describe("the wording follows the scope, because the promise differs", () => {
  it("says 'this host' on a single-host deployment", () => {
    // A single-tenant engine applies to its own kernel. Calling that a fleet
    // push would promise a reach it does not have — and, worse, imply the
    // operator should go looking for other hosts that did not get it.
    render(<DetectionsBody policies={loaded} open onRefresh={() => {}} canPush scope="host" />);
    expect(screen.getByRole("button", { name: /remove from this host/i })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /remove from the fleet/i })).toBeNull();
  });

  it("says 'fleet' on the control plane", () => {
    render(<DetectionsBody policies={loaded} open onRefresh={() => {}} canPush scope="fleet" />);
    expect(screen.getByRole("button", { name: /remove from fleet/i })).toBeTruthy();
  });

  it("offers authoring on a single host — the capability is not the plane", () => {
    // The regression this guards: the engine could read kernel state but not
    // change it, so the surface was hidden entirely and a single-host customer
    // had no way to write a detection except SSH.
    render(<DetectionsBody policies={loaded} open onRefresh={() => {}} canPush scope="host" />);
    expect(screen.getByRole("button", { name: /write or upload a detection/i })).toBeTruthy();
  });
});

describe("policies are editable, not just create-and-delete", () => {
  const withBody = [{ ...loaded[0], yaml: 'metadata:\n  name: "sensitive-file-access"\n' }] as SocPolicy[];

  it("offers Edit on a policy whose body it has", async () => {
    // Update was the one letter of CRUD missing. Without it, changing a noisy
    // detection meant retyping its exact metadata.name from memory — and the
    // only control that looked like editing (Copy) renames away from the
    // original on purpose.
    render(<DetectionsBody policies={withBody} open onRefresh={() => {}} canPush scope="host" />);
    expect(screen.getByRole("button", { name: /^edit$/i })).toBeTruthy();
  });

  it("edits under the policy's own name, and says it replaces the running one", async () => {
    const user = userEvent.setup();
    render(<DetectionsBody policies={withBody} open onRefresh={() => {}} canPush scope="host" />);
    await user.click(screen.getByRole("button", { name: /^edit$/i }));

    // The warning is the point: a replace is delete-then-add, so an operator
    // has to know this is not an additive action.
    expect(screen.getByText(/REPLACES the detection that is running now/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: /replace sensitive-file-access/i })).toBeTruthy();
  });

  it("does not offer Edit when it has no body to edit", () => {
    render(<DetectionsBody policies={loaded} open onRefresh={() => {}} canPush scope="host" />);
    expect(screen.queryByRole("button", { name: /^edit$/i })).toBeNull();
  });
});

describe("a named coverage gap can be closed from where it is named", () => {
  const missing = [{
    ...loaded[0], loadedAgents: 0, expected: true,
    yaml: 'metadata:\n  name: "sensitive-file-access"\n'
  }] as SocPolicy[];

  it("offers to restore an expected detection the kernel does not have", () => {
    render(<DetectionsBody policies={missing} open onRefresh={() => {}} canPush scope="host" />);
    expect(screen.getByRole("button", { name: /restore this detection/i })).toBeTruthy();
  });

  it("does not offer to restore a policy the platform never shipped", () => {
    // Restoring something that was never expected is not a restore.
    const custom = [{ ...missing[0], expected: false }] as SocPolicy[];
    render(<DetectionsBody policies={custom} open onRefresh={() => {}} canPush scope="host" />);
    expect(screen.queryByRole("button", { name: /restore this detection/i })).toBeNull();
  });

  it("does not offer to restore when the load state is unknown", () => {
    // Unknown is not absent. Offering a fix implies a diagnosis nobody made.
    const unsure = [{ ...missing[0], kernelStateKnown: false }] as SocPolicy[];
    render(<DetectionsBody policies={unsure} open onRefresh={() => {}} canPush scope="host" />);
    expect(screen.queryByRole("button", { name: /restore this detection/i })).toBeNull();
  });
});

describe("scope comes from the server, not from guessing", () => {
  // The derivation used to be `Array.isArray(whoami.tenants) ? "fleet" : "host"`.
  // Measured on the live control plane, a cross-tenant MSOC admin's whoami is
  // {"cross_tenant":true,"tenants":null,...} — so the console would have told
  // the one operator most likely to push to a fleet that their change reached
  // "this host". Scope is now stated by the server.
  const scopeOf = (whoami: Record<string, unknown>) =>
    (whoami.policy_scope ?? whoami.policyScope) === "fleet" ? "fleet" : "host";

  it("says fleet when the control plane says fleet", () => {
    expect(scopeOf({ policy_scope: "fleet", tenants: null, cross_tenant: true })).toBe("fleet");
  });

  it("no longer depends on the tenants array", () => {
    // The exact live payload that broke the old derivation.
    expect(scopeOf({ policy_scope: "fleet", tenants: null })).toBe("fleet");
  });

  it("defaults to host when the server says nothing", () => {
    // An engine, or an older control plane. The narrower promise is the safe
    // default: claiming fleet reach you do not have is the worse error.
    expect(scopeOf({ user: "admin", hostname: "box" })).toBe("host");
  });
});
