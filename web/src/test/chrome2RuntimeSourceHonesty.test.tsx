import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RuntimePanel, runtimeGroups } from "../features/soc/SettingsBody";

/**
 * The Platform section over a PARTIAL read, and what `sha` means on each plane.
 *
 * The panel reads /api/version, /api/system-health and /api/whoami
 * independently, and any one of them can fail on its own. That is the dangerous
 * case, not the total outage: the pane still renders, and every health-backed
 * field used to fall through to its own default and print it as a measurement —
 * Tetragon "not connected", metrics export "disabled — nothing is exported".
 * Neither had been read from anything. A platform engineer reading this section
 * to answer "where does this run, and against what?" would open a ticket about
 * a sensor that is running.
 *
 * The second claim here is `sha`. Both planes serve it and the console watches
 * it for the reload prompt, but the engine serves a hash of its EMBEDDED
 * FRONTEND ASSETS (internal/api/http.go: versionSHA) while the control plane
 * serves its Go build identity (internal/controlplane/http.go: buildinfo
 * Info.String()). The section stated the engine's meaning on both, so on a
 * control plane it described a value that does not move when the UI does.
 */

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
  observability: { otlp_endpoint: "", log_format: "json", log_level: "info" },
  auth: { hash: "bcrypt", sessions: "hmac-signed cookie", csrf: "double-submit cookie", rate_limit: "5/min per IP" }
};

const ENGINE_WHOAMI = { user: "admin", role: "admin", hostname: "engine-01" };

const CP_VERSION = {
  sha: "v0.3.0",
  version: "v0.3.0",
  revision: "9a1c07e",
  dirty: false,
  lab_mode: false,
  product: "0.3.0-controlplane"
};

const CP_HEALTH = {
  status: "healthy",
  agents: 3,
  agents_fresh: 2,
  kernel_sensor: "unknown: not observable from the control plane",
  store: { ok: true, error: "" }
};

const CP_WHOAMI = { user: "msoc@example.com", role: "tenant-analyst", tenants: ["acme-corp"], policy_scope: "fleet" };

function field(groups: ReturnType<typeof runtimeGroups>, title: string, label: string) {
  const found = groups.find((g) => g.title === title)?.fields.find((f) => f.label === label);
  expect(found, `no ${label} field in ${title}`).toBeTruthy();
  return found!;
}

/** The paragraph the panel painted for one field, so a claim can be read in context. */
function renderedRow(label: string) {
  const strong = screen.getByText(label, { selector: "strong" });
  const row = strong.closest("p");
  expect(row, `${label} rendered outside a row`).toBeTruthy();
  return row!.textContent ?? "";
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("a source that did not answer is not a measurement", () => {
  it("refuses to report Tetragon or the metrics exporter when system-health stayed silent", () => {
    const groups = runtimeGroups(ENGINE_VERSION, null, ENGINE_WHOAMI, "https://engine-01.example.com");

    const tetragon = field(groups, "Telemetry", "Tetragon");
    expect(tetragon.value).toBe("");
    expect(tetragon.value).not.toMatch(/connected/);
    expect(tetragon.absence).toBe("unread");
    expect(tetragon.detail).toMatch(/\/api\/system-health did not answer/);

    const metrics = field(groups, "Telemetry", "Metrics export");
    expect(metrics.value).toBe("");
    expect(metrics.value).not.toMatch(/disabled/);
    expect(metrics.absence).toBe("unread");
    expect(metrics.detail).toMatch(/\/api\/system-health did not answer/);
  });

  it("keeps reporting them once system-health does answer", () => {
    // The guard must not swallow the real reading: a silent source is the only
    // thing that blanks these fields.
    const groups = runtimeGroups(ENGINE_VERSION, ENGINE_HEALTH, ENGINE_WHOAMI, "https://engine-01.example.com");
    expect(field(groups, "Telemetry", "Tetragon").value).toBe("connected");
    expect(field(groups, "Telemetry", "Metrics export").value).toMatch(/disabled/);
    expect(field(groups, "Telemetry", "Tetragon").absence).toBeUndefined();
  });

  it("does not decide the lab gate from a version read that failed", () => {
    // "hidden — production" is the one claim on this page an operator acts on
    // by NOT looking for the attack runner. It has to come off a real read.
    const groups = runtimeGroups(null, ENGINE_HEALTH, ENGINE_WHOAMI, "https://engine-01.example.com");
    const lab = field(groups, "Build", "Lab surfaces");
    expect(lab.value).toBe("");
    expect(lab.absence).toBe("unread");
    expect(lab.detail).toMatch(/\/api\/version did not answer/);
  });

  it("does not claim a single-host deployment when nothing said which plane this is", () => {
    const groups = runtimeGroups(ENGINE_VERSION, null, null, "https://unknown.example.com");
    const scope = field(groups, "Identity", "Tenant scope");
    expect(scope.value).toBe("");
    expect(scope.absence).toBe("unread");
  });

  it("still distinguishes a field no deployment serves from one that went unread", () => {
    // Conflating the two is the same defect in the other direction: the listen
    // address is genuinely not served by either plane, and saying "could not be
    // read" there would send someone hunting a failed request that never was.
    const groups = runtimeGroups(ENGINE_VERSION, null, ENGINE_WHOAMI, "https://engine-01.example.com");
    expect(field(groups, "Listeners", "Listen address and TLS").absence).toBe("not-served");
  });

  it("says on screen what it could not read, instead of painting a default", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
        if (url.includes("/api/system-health")) return new Response("boom", { status: 500 });
        const body = url.includes("/api/version") ? ENGINE_VERSION : ENGINE_WHOAMI;
        return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
      })
    );
    render(<RuntimePanel />);

    await waitFor(() => expect(screen.getByText("Tetragon", { selector: "strong" })).toBeTruthy());
    // The two fabricated operational facts, gone from the painted page.
    expect(screen.queryByText("not connected")).toBeNull();
    expect(screen.queryByText(/disabled — nothing is exported/)).toBeNull();

    const tetragon = renderedRow("Tetragon");
    expect(tetragon).toMatch(/could not be read/);
    // And not the other absence: this deployment does serve Tetragon state.
    expect(tetragon).not.toMatch(/not served by this deployment/);
    expect(renderedRow("Metrics export")).toMatch(/could not be read/);

    // The partial read is named at the top, so a reader knows how much of the
    // section was actually measured without auditing every row.
    const notice = screen.getByText(/Not every source answered/).closest("div");
    expect(notice?.textContent).toMatch(/\/api\/system-health did not answer/);
    expect(notice?.textContent).not.toMatch(/\/api\/version/);
  });
});

describe("the build signal says what THIS deployment reports", () => {
  it("describes the engine's sha as the embedded asset hash", () => {
    const assets = field(
      runtimeGroups(ENGINE_VERSION, ENGINE_HEALTH, ENGINE_WHOAMI, "https://engine-01.example.com"),
      "Build",
      "Console assets"
    );
    expect(assets.value).toBe("b8f21c4");
    expect(assets.detail).toMatch(/assets/i);
    expect(assets.detail).toMatch(/reload/);
  });

  it("does not call the control plane's sha a UI hash, because it is the build revision", () => {
    const groups = runtimeGroups(CP_VERSION, CP_HEALTH, CP_WHOAMI, "https://soc.example.com");
    // The engine's label states the engine's meaning; the control plane must
    // not borrow it — its `sha` is buildinfo's tag-or-revision, which does not
    // move when only the console assets are rebuilt from the same commit.
    expect(groups.find((g) => g.title === "Build")?.fields.some((f) => f.label === "Console assets")).toBe(false);
    const signal = field(groups, "Build", "Build identity");
    expect(signal.value).toBe("v0.3.0");
    expect(signal.detail).toMatch(/build identity/i);
    expect(signal.detail).toMatch(/not an asset hash/i);
    expect(signal.detail).not.toMatch(/hash of the shipped UI/);
  });

  it("names both meanings when nothing said which plane answered", () => {
    const signal = field(runtimeGroups(ENGINE_VERSION, null, null, "https://unknown.example.com"), "Build", "Build signal");
    expect(signal.value).toBe("b8f21c4");
    expect(signal.detail).toMatch(/engine/i);
    expect(signal.detail).toMatch(/control plane/i);
  });
});
