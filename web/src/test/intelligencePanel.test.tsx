import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { IntelligenceBody } from "../features/soc/IntelligenceBody";

/**
 * The panel's whole job is to stop an empty list being read as good news.
 *
 * "No anomalies" means one of three things — the baseline is still learning,
 * no feeds are loaded, or it genuinely found nothing — and they have opposite
 * operational consequences. These tests pin that the panel says WHICH.
 */

function mockAPI(routes: Record<string, unknown>) {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      // LONGEST prefix wins. "/api/intel" is a prefix of "/api/intel/matches",
      // so first-match ordering silently serves the feed status where the
      // findings were expected — and the assertion then fails for a reason
      // that has nothing to do with the component.
      const key = Object.keys(routes)
        .filter((k) => url.startsWith(k))
        .sort((a, b) => b.length - a.length)[0];
      if (key === undefined) return Promise.resolve(new Response("{}", { status: 503 }));
      return Promise.resolve(new Response(JSON.stringify(routes[key]), { status: 200 }));
    })
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

const warmBaseline = {
  enabled: true,
  anomalies_total: 0,
  status: {
    ready: true,
    observations: 5000,
    need_observations: 500,
    span_seconds: 172800,
    need_span_seconds: 1800,
    half_life_hours: 336,
    facets: []
  }
};

describe("Behaviour & Reputation panel", () => {
  it("says the baseline is still learning rather than showing a clean empty list", async () => {
    mockAPI({
      "/api/baseline?top": {
        enabled: true,
        anomalies_total: 0,
        status: {
          ready: false,
          observations: 120,
          need_observations: 500,
          span_seconds: 300,
          need_span_seconds: 1800,
          half_life_hours: 336,
          facets: []
        }
      },
      "/api/baseline/anomalies": { findings: [] },
      "/api/intel/matches": { findings: [] },
      "/api/intel": { status: { loaded: true, indicators: 10, ips: 10, cidrs: 0, domains: 0, hashes: 0, allowlisted: 0, sources: [] }, refresh: { enabled: false, feeds: 0 }, matches_total: 0 }
    });

    render(<IntelligenceBody open />);

    await waitFor(() => expect(screen.getByText(/Still learning/i)).toBeTruthy());
    // The critical sentence: an empty anomaly list here is NOT "nothing unusual".
    expect(screen.getByText(/is not a finding of 'nothing unusual'/i)).toBeTruthy();
  });

  it("says no feeds are loaded rather than implying nothing matched", async () => {
    mockAPI({
      "/api/baseline?top": warmBaseline,
      "/api/baseline/anomalies": { findings: [] },
      "/api/intel/matches": { findings: [] },
      "/api/intel": {
        status: { loaded: false, indicators: 0, ips: 0, cidrs: 0, domains: 0, hashes: 0, allowlisted: 0, sources: [] },
        refresh: { enabled: false, feeds: 0 },
        matches_total: 0
      }
    });

    render(<IntelligenceBody open />);

    await waitFor(() => expect(screen.getByText(/No feeds loaded/i)).toBeTruthy());
    expect(screen.getByText(/No feeds are loaded, so nothing can match/i)).toBeTruthy();
  });

  it("reports a genuine clean result only when both layers are actually working", async () => {
    mockAPI({
      "/api/baseline?top": warmBaseline,
      "/api/baseline/anomalies": { findings: [] },
      "/api/intel/matches": { findings: [] },
      "/api/intel": {
        status: { loaded: true, indicators: 4200, ips: 4000, cidrs: 100, domains: 90, hashes: 10, allowlisted: 2, sources: [{ source: "c2", indicators: 4200 }] },
        refresh: { enabled: false, feeds: 0 },
        matches_total: 0
      }
    });

    render(<IntelligenceBody open />);

    await waitFor(() => expect(screen.getByText(/Ready/)).toBeTruthy());
    expect(screen.getByText(/Nothing has departed from this deployment's learned normal/i)).toBeTruthy();
    expect(screen.getByText(/No observed address, domain or hash has matched/i)).toBeTruthy();
  });

  it("renders an indicator match with its source and category", async () => {
    mockAPI({
      "/api/baseline?top": warmBaseline,
      "/api/baseline/anomalies": { findings: [] },
      "/api/intel": {
        status: { loaded: true, indicators: 1, ips: 1, cidrs: 0, domains: 0, hashes: 0, allowlisted: 0, sources: [] },
        refresh: { enabled: false, feeds: 0 },
        matches_total: 1
      },
      "/api/intel/matches": {
        findings: [
          {
            at: new Date().toISOString(),
            kind: "intel",
            exec_id: "e1",
            pid: 42,
            binary: "/usr/local/bin/report",
            points: 30,
            match: {
              value: "198.51.100.7",
              kind: "ip",
              source: "abuse-c2",
              category: "cobalt-strike",
              confidence: "high",
              observed: "198.51.100.7",
              points: 30
            }
          }
        ]
      }
    });

    render(<IntelligenceBody open />);

    await waitFor(() => expect(screen.getByText("198.51.100.7")).toBeTruthy());
    expect(screen.getByText("cobalt-strike")).toBeTruthy();
    expect(screen.getByText("abuse-c2")).toBeTruthy();
  });

  it("explains itself when enrichment is switched off entirely", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response("{}", { status: 503 }))));
    render(<IntelligenceBody open />);
    await waitFor(() => expect(screen.getByText(/Enrichment is not enabled/i)).toBeTruthy());
    // A configuration state, not a fault — the wording matters because a red
    // error trains operators to ignore red.
    expect(screen.getByText(/configuration state, not a fault/i)).toBeTruthy();
  });
});
