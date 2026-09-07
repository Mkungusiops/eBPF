import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RuntimePanel, SettingsBody, runtimeGroups } from "../features/soc/SettingsBody";
import { RetentionControls } from "../features/soc/SettingsRetention";
import { isRouteNotServed } from "../features/soc/settingsModel";
import { ApiError } from "../lib/api";

/**
 * Two claims the Platform and Evidence sections make about a deployment.
 *
 * PLATFORM promised a value it never rendered: the row is captioned "The
 * deployed shape of this installation" and its caveat says "Shown as the
 * effective value", while SettingsBody rendered a control for every other row
 * and nothing at all for `runtime`. The section a platform engineer opens to
 * ask "where does this run, and against what?" showed the question, the caveat
 * about the value, and no value.
 *
 * EVIDENCE reported a route this deployment deliberately does not serve as a
 * failed read. The single-tenant engine answers 404 for /api/settings/retention;
 * its two sibling panels both call that "not applicable to this deployment",
 * and RetentionControls raised an amber "Retention could not be read" on every
 * healthy engine console instead.
 */

/** What the single-tenant engine answers, field for field. */
const ENGINE_VERSION = {
  sha: "b8f21c4",
  version: "",
  revision: "9a1c07e",
  dirty: true,
  built_at: "2026-09-01T09:12:00Z",
  started_at: "2026-09-01T09:20:00Z",
  lab_mode: false
};

const ENGINE_HEALTH = {
  status: "healthy",
  uptime: "26h12m",
  store: { backend: "sqlite", target: "/var/lib/ebpf-engine/engine.db" },
  bpf: { backend: "cilium-ebpf", attached_links: 4, expected_links: 4, healthy: true },
  tetragon: { connected: true },
  observability: { otlp_endpoint: "", log_format: "json", log_level: "info", metrics_enabled: false },
  auth: { hash: "bcrypt", sessions: "hmac-signed cookie", csrf: "double-submit cookie", rate_limit: "5/min per IP" }
};

const ENGINE_WHOAMI = { user: "admin", hostname: "engine-01", can_push_policy: true };

/** And what the multi-tenant control plane answers instead. */
const CP_VERSION = {
  sha: "0.3.0-controlplane+9a1c07e",
  version: "v0.3.0",
  revision: "9a1c07e",
  dirty: false,
  lab_mode: false,
  product: "0.3.0-controlplane"
};

const CP_HEALTH = {
  status: "healthy",
  host: "acme-corp",
  agents: 3,
  agents_fresh: 2,
  kernel_sensor: "unknown: not observable from the control plane",
  store: { ok: true, error: "" },
  last_seen: "2026-09-02T07:40:00Z"
};

const CP_WHOAMI = {
  user: "msoc@example.com",
  subject: "msoc@example.com",
  role: "tenant-analyst",
  tenants: ["acme-corp"],
  cross_tenant: false,
  policy_scope: "fleet"
};

function labelled(groups: ReturnType<typeof runtimeGroups>, title: string, label: string) {
  const group = groups.find((g) => g.title === title);
  expect(group, `no ${title} group`).toBeTruthy();
  const field = group?.fields.find((f) => f.label === label);
  expect(field, `no ${label} field in ${title}`).toBeTruthy();
  return field!;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("the Platform section shows the effective values it says it shows", () => {
  it("reports the engine's store, kernel sensor, identity and telemetry from what it serves", () => {
    const groups = runtimeGroups(ENGINE_VERSION, ENGINE_HEALTH, ENGINE_WHOAMI, "https://engine-01.example.com");

    expect(labelled(groups, "Store", "Backend").value).toBe("sqlite");
    expect(labelled(groups, "Store", "Target").value).toBe("/var/lib/ebpf-engine/engine.db");
    expect(labelled(groups, "Telemetry", "Kernel sensor").value).toContain("cilium-ebpf");
    expect(labelled(groups, "Telemetry", "Kernel sensor").value).toContain("4/4");
    expect(labelled(groups, "Telemetry", "Logs").value).toBe("json at info");
    expect(labelled(groups, "Identity", "Operator credentials").value).toContain("bcrypt");
    expect(labelled(groups, "Listeners", "Console reached at").value).toBe("https://engine-01.example.com");
  });

  it("says a metrics exporter is disabled rather than leaving the field blank", () => {
    // A blank here reads as "could not be read". The honest answer is that no
    // OTLP endpoint is configured, which is a different operational fact.
    const groups = runtimeGroups(ENGINE_VERSION, ENGINE_HEALTH, ENGINE_WHOAMI, "https://engine-01.example.com");
    expect(labelled(groups, "Telemetry", "Metrics export").value).toMatch(/disabled/);
  });

  it("keeps a dirty, untagged build honest rather than inventing a version", () => {
    const groups = runtimeGroups(ENGINE_VERSION, ENGINE_HEALTH, ENGINE_WHOAMI, "https://engine-01.example.com");
    expect(labelled(groups, "Build", "Release").value).toBe("no release tag");
    expect(labelled(groups, "Build", "Source revision").value).toContain("9a1c07e");
    expect(labelled(groups, "Build", "Source revision").value).toMatch(/dirty tree/);
    // lab_mode is false on both boxes, and the section has to say which way.
    expect(labelled(groups, "Build", "Lab surfaces").value).toMatch(/hidden/);
  });

  it("does not claim the engine's fields on a control plane that never serves them", () => {
    // The two planes answer genuinely different questions. Carrying the
    // engine's store backend or OTLP endpoint over to the control plane would
    // be the console inventing configuration.
    const groups = runtimeGroups(CP_VERSION, CP_HEALTH, CP_WHOAMI, "https://soc.example.com");
    expect(labelled(groups, "Store", "Central store").value).toBe("readable");
    expect(labelled(groups, "Telemetry", "Agents reporting").value).toContain("2 of 3");
    expect(labelled(groups, "Telemetry", "Kernel sensor").value).toMatch(/not observable from the control plane/);
    expect(labelled(groups, "Identity", "Tenant scope").value).toContain("acme-corp");
    // And the fields it does NOT serve are named as unserved, not dropped.
    expect(labelled(groups, "Telemetry", "Metrics and logs").value).toBe("");
    expect(labelled(groups, "Identity", "Identity provider").value).toBe("");
    expect(labelled(groups, "Identity", "Identity provider").detail).toMatch(/does not serve/);
  });

  it("states that no deployment serves its listen address, rather than guessing one", () => {
    // The browser knows the origin it reached; it does not know what the server
    // binds, or whether TLS is terminated in front of it. Both planes are the
    // same here, and the promise is kept by saying so.
    for (const groups of [
      runtimeGroups(ENGINE_VERSION, ENGINE_HEALTH, ENGINE_WHOAMI, "https://engine-01.example.com"),
      runtimeGroups(CP_VERSION, CP_HEALTH, CP_WHOAMI, "https://soc.example.com")
    ]) {
      const listen = labelled(groups, "Listeners", "Listen address and TLS");
      expect(listen.value).toBe("");
      expect(listen.detail).toMatch(/neither server reports/i);
    }
  });

  it("survives a deployment that omits everything this panel reads", () => {
    // The recurring crash in this console is .map or a property read on a field
    // the server simply did not send. An older build must leave the section
    // rendering rather than throwing inside Settings.
    const groups = runtimeGroups({}, {}, null, "");
    expect(groups.length).toBeGreaterThan(0);
    expect(groups.every((g) => g.fields.length > 0)).toBe(true);
  });

  it("renders a value in the pane, not just the question and the caveat", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
        const body = url.includes("/api/version")
          ? ENGINE_VERSION
          : url.includes("/api/system-health")
            ? ENGINE_HEALTH
            : ENGINE_WHOAMI;
        return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
      })
    );
    render(<RuntimePanel />);
    await waitFor(() => expect(screen.getByText("/var/lib/ebpf-engine/engine.db")).toBeTruthy());
    expect(screen.getByText("Store")).toBeTruthy();
    expect(screen.getAllByText(/not served by this deployment/).length).toBeGreaterThan(0);
  });

  it("is reachable from the Platform section of the settings surface", async () => {
    const user = userEvent.setup();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
        if (url.includes("/api/version")) {
          return new Response(JSON.stringify(ENGINE_VERSION), { status: 200, headers: { "Content-Type": "application/json" } });
        }
        if (url.includes("/api/system-health")) {
          return new Response(JSON.stringify(ENGINE_HEALTH), { status: 200, headers: { "Content-Type": "application/json" } });
        }
        if (url.includes("/api/whoami")) {
          return new Response(JSON.stringify(ENGINE_WHOAMI), { status: 200, headers: { "Content-Type": "application/json" } });
        }
        return new Response(JSON.stringify({ suppressions: [], hits_known: true, effect: "score only" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      })
    );
    render(<SettingsBody open />);
    await waitFor(() => expect(screen.getByText(/Expected behaviour/)).toBeTruthy());
    await user.click(screen.getByRole("button", { name: /^Platform/i }));
    // The promise the section makes, and the value it now keeps.
    expect(screen.getByText(/Shown as the effective value/)).toBeTruthy();
    await waitFor(() => expect(screen.getByText("cilium-ebpf · 4/4 programs attached")).toBeTruthy());
  });

  it("says nothing about the deployment when neither read answered", async () => {
    // Absent is not "nothing is configured". A blank platform section would be
    // read as a deployment with no store and no telemetry.
    vi.stubGlobal("fetch", vi.fn(async () => new Response("nope", { status: 500 })));
    render(<RuntimePanel />);
    await waitFor(() => expect(screen.getByText(/could not be read/i)).toBeTruthy());
    expect(screen.getByText(/Nothing is being claimed/)).toBeTruthy();
  });
});

describe("a route this deployment does not serve is not a failed read", () => {
  it("treats a 404 as not applicable, the way its two siblings do", async () => {
    // The engine registers no per-tenant retention route. An amber warning here
    // fires on every healthy engine console, which is how a console teaches its
    // operators to ignore warnings.
    vi.stubGlobal("fetch", vi.fn(async () => new Response("404 page not found", { status: 404 })));
    render(<RetentionControls />);
    await waitFor(() => expect(screen.getByText(/Not applicable to this deployment/)).toBeTruthy());
    expect(screen.queryByText(/Retention could not be read/)).toBeNull();
    expect(screen.getByText(/Containment decisions are never pruned/)).toBeTruthy();
  });

  it("still reports a genuine failure as a failure", async () => {
    // The 404 branch must not swallow a 500. A store that cannot be read is a
    // fault, and rendering a blank control invites setting a horizon believing
    // none exists.
    vi.stubGlobal("fetch", vi.fn(async () => new Response("boom", { status: 500 })));
    render(<RetentionControls />);
    await waitFor(() => expect(screen.getByText(/Retention could not be read/)).toBeTruthy());
    expect(screen.queryByText(/Not applicable to this deployment/)).toBeNull();
  });

  it("shares one predicate rather than a third copy of the test", () => {
    expect(isRouteNotServed(new ApiError("not found", 404, null))).toBe(true);
    expect(isRouteNotServed(new ApiError("boom", 500, null))).toBe(false);
    // A plain Error is what the non-ApiError paths hand over; "404 page not
    // found" is all there is to go on there.
    expect(isRouteNotServed(new Error("404 page not found"))).toBe(true);
    expect(isRouteNotServed(new Error("NetworkError when attempting to fetch"))).toBe(false);
    expect(isRouteNotServed(null)).toBe(false);
  });
});
