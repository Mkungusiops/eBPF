import { describe, expect, it } from "vitest";
import { buildMitreCoverageModel } from "../features/soc/panels";
import { buildEngineFacts } from "../features/choke/panels";

/**
 * Two panels claimed more than their data supported.
 */
describe("MITRE bars all mean the same thing", () => {
  const policies = [{ name: "sensitive-file-access", mitre: "T1003" }] as never;

  it("does not fold kernel probe posts into the hit count", () => {
    // The bug: a technique with no alerts inherited its probe-post count since
    // sensor start, so one bar meant "alerts in this window" and the next
    // meant "probe fired this often, mostly on activity that scored nothing".
    const model = buildMitreCoverageModel(
      [{ label: "T1003", value: 13580 }],
      [] as never,
      policies
    );
    expect(model.observed.get("T1003") ?? 0).toBe(0);
  });

  it("reads a live probe with no alerts as covered, not as a gap", () => {
    const model = buildMitreCoverageModel([{ label: "T1071", value: 42 }], [] as never, [] as never);
    expect(model.stateOf("T1071")).toBe("covered");
  });

  it("counts alerts in the window as observed", () => {
    const model = buildMitreCoverageModel(
      [],
      [{ mitreId: "T1003", title: "cred read" }] as never,
      policies
    );
    expect(model.observed.get("T1003")).toBe(1);
    expect(model.stateOf("T1003")).toBe("observed");
  });
});

describe("the stack panel reports what its plane can answer", () => {
  it("drops the kernel-sensor row on a plane that says it cannot see it", () => {
    // Four of seven rows read "Not reported", "—", "—" and "v?" on the control
    // plane. A panel that mostly answers "unknown" trains people to skip the
    // place where "is my platform healthy" belongs.
    const facts = buildEngineFacts({
      kernel_sensor: "unknown: not observable from the control plane",
      agents: 3,
      agents_fresh: 2,
      last_seen_age_seconds: 14,
      store: { ok: true }
    });
    const labels = facts.map((f) => f.label);
    expect(labels).not.toContain("Kernel sensor");
    expect(labels).not.toContain("Uptime");
    expect(labels).not.toContain("Build");
  });

  it("renders the facts the control plane does have", () => {
    const facts = buildEngineFacts({
      kernel_sensor: "unknown: not observable from the control plane",
      agents: 3,
      agents_fresh: 2,
      last_seen_age_seconds: 14,
      store: { ok: true }
    });
    const byLabel = Object.fromEntries(facts.map((f) => [f.label, f]));
    // A stale agent is not being protected, so this must not read as healthy.
    expect(byLabel["Agents"].value).toBe("2/3 reporting");
    expect(byLabel["Agents"].status).toBe("warn");
    expect(byLabel["Last heartbeat"].value).toBe("14s ago");
    // store.ok was in the payload while the panel rendered "—".
    expect(byLabel["Event store"].value).toBe("Reachable");
  });

  it("still reports the engine's own rows on the engine", () => {
    const facts = buildEngineFacts({
      tetragon: { connected: true },
      store: { backend: "sqlite", target: "/var/lib/x/events.db" },
      uptime: "1h4m45s",
      version: "v1.3.0-20-g0684bf2-dirty"
    });
    const byLabel = Object.fromEntries(facts.map((f) => [f.label, f]));
    expect(byLabel["Kernel sensor"].value).toBe("Connected");
    expect(byLabel["Event store"].value).toBe("SQLite");
    expect(byLabel["Build"].value).toBe("v1.3.0-20-g0684bf2-dirty");
  });
});

describe("every row in the stack panel can change and can be wrong", () => {
  it("carries no permanently-ok sign-in row", () => {
    // It rendered a hardcoded "bcrypt · CSRF · sessions" with status "ok",
    // forever. If authentication broke tomorrow it would still show a green
    // dot reading "hardened auth" — a reassurance label in the one panel an
    // operator scans to find out what is wrong.
    const facts = buildEngineFacts({
      tetragon: { connected: true },
      auth: { rate_limit: "5/min" },
      store: { backend: "sqlite" }
    });
    const labels = facts.map((f) => f.label);
    expect(labels).not.toContain("Sign-in security");
    expect(facts.some((f) => f.value === "bcrypt · CSRF · sessions")).toBe(false);
  });

  it("keeps the rate limit as configuration, not as a health status", () => {
    const facts = buildEngineFacts({
      tetragon: { connected: true },
      auth: { rate_limit: "5/min" },
      store: { backend: "sqlite" }
    });
    const row = facts.find((f) => f.label === "Sign-in rate limit");
    expect(row?.value).toBe("5/min");
    // Neutral: it must never contribute a colour to a panel scanned for trouble.
    expect(row?.status).toBe("neutral");
  });

  it("omits the rate limit entirely when the deployment does not report one", () => {
    const facts = buildEngineFacts({ tetragon: { connected: true }, store: { backend: "sqlite" } });
    expect(facts.map((f) => f.label)).not.toContain("Sign-in rate limit");
  });

  it("marks telemetry as configuration so it is not read as health", () => {
    const facts = buildEngineFacts({ tetragon: { connected: true }, store: { backend: "sqlite" } });
    const row = facts.find((f) => f.label === "Telemetry");
    expect(row?.status).toBe("neutral");
    expect(row?.hint).toMatch(/configuration, not health/);
  });
});
