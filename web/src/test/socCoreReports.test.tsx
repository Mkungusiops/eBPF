import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { GraphBrief } from "../features/soc/GraphBrief";
import { KpiDrillBody } from "../features/soc/KpiDrillBody";
import { ExportStudioBody } from "../features/soc/exportStudio";
import { groupAlertList } from "../features/soc/analytics";
import { SOC_PANEL_INVENTORY, SOC_STORAGE_KEYS } from "../features/soc/panelInventory";
import type { SocAlert, SocEvent } from "../features/soc/types";

/**
 * Four panels that each stated something stronger than their arithmetic: a
 * "top ten" that never sorted, an export that counted groups as alerts, a
 * storage key advertised and never written, and an indicator count including
 * destinations the canvas beside it refuses to draw.
 */
function alert(id: string, score: number, overrides: Partial<SocAlert> = {}): SocAlert {
  return {
    id,
    title: `Alert ${id}`,
    description: "fixture",
    severity: "critical",
    score,
    timestamp: "2026-06-25T09:00:00Z",
    raw: undefined,
    ...overrides
  };
}

describe("'Top 10 by score' is the top ten by score", () => {
  /**
   * KpiDrillBody rendered `scopedAlerts.slice(0, 10)` over a list that arrives
   * in wire order. On any bucket holding more than ten alerts the table headed
   * "Top 10 by score" showed the first ten received — and the highest-scoring
   * alerts, the exact rows the drill exists to surface, were dropped with
   * nothing on screen saying so.
   */
  const SCORES = [12, 5, 98, 31, 7, 44, 3, 71, 19, 2, 60, 8];
  const alerts = SCORES.map((score, index) => alert(`alert-${index}`, score));

  function scoresOnScreen() {
    render(<KpiDrillBody drill={{ kind: "critical", title: "Critical" }} alerts={alerts} events={[]} ackStates={{}} now={Date.parse("2026-06-25T09:05:00Z")} />);
    const table = screen.getByRole("heading", { name: "Top 10 by score" }).parentElement?.querySelector(".soc-kpi-table");
    const rows = [...(table?.querySelectorAll("div") ?? [])].filter((row) => row.querySelector("strong"));
    return rows.map((row) => Number(row.querySelector("strong")?.textContent));
  }

  it("lists the ten highest, in descending order", () => {
    const scores = scoresOnScreen();
    expect(scores, "the fixture must overflow the table or 'top 10' is a table of everything").toHaveLength(10);
    expect(scores).toEqual([...SCORES].sort((a, b) => b - a).slice(0, 10));
    expect(scores[0], "the highest-scoring alert in the bucket is missing from the table it heads").toBe(98);
  });
});

describe("a grouped queue exports every alert it stands for", () => {
  /**
   * The queue groups by default, so `filteredAlerts` is a list of AlertGroups.
   * The export model was built straight off that list: one row per GROUP, and
   * the summary counted groups as alerts. On three identical criticals plus one
   * high the modal offered "On screen (2)" and the file carried two rows —
   * two critical alerts leaving the artefact with nothing saying they had been
   * collapsed.
   */
  const duplicate = (id: string, pid: number) =>
    alert(id, 44, { title: "Credential file read", policyName: "override-credential-read", process: "cat", execId: id, pid });
  const grouped = groupAlertList([
    duplicate("alert-dup-1", 5001),
    duplicate("alert-dup-2", 5002),
    duplicate("alert-dup-3", 5003),
    alert("alert-solo-1", 61, { severity: "high", title: "Reverse shell attempt", policyName: "override-reverse-shell", process: "bash" })
  ]);

  function renderStudio() {
    return render(
      <ExportStudioBody
        filteredAlerts={grouped}
        rangeAlerts={grouped.flatMap((group) => group.members)}
        events={[]}
        decisions={[]}
        policies={[]}
        mitreRows={[]}
        whoami={{ user: "analyst", host: "engine", policyScope: "host" }}
        version={{ sha: "test", labMode: false }}
      />
    );
  }

  it("collapses four alerts into two rows, or this test is about nothing", () => {
    expect(grouped).toHaveLength(2);
  });

  it("counts the alerts on screen, not the rows", () => {
    renderStudio();
    expect(screen.getByRole("button", { name: "On screen (4)" })).toBeTruthy();
  });

  it("previews every alert the filtered scope covers", () => {
    const { container } = renderStudio();
    const lines = [...container.querySelectorAll(".soc-export-preview-list li")].map((li) => li.textContent);
    expect(lines, "the preview promises what the file will carry").toContain("4 alerts");
  });

  it("counts the collapsed criticals in the section summary", () => {
    renderStudio();
    // The section row's own count and note: what the ALERTS block will hold and
    // how many of them are critical. Both counted groups before.
    const alertsSection = screen.getByRole("button", { name: /^Alerts/ });
    expect(alertsSection.textContent, "the section count is alerts, not groups").toContain("4");
    expect(alertsSection.textContent, "the collapsed criticals must be counted").toContain("3 critical");
  });
});

describe("the panel inventory advertises only storage this console writes", () => {
  /**
   * `soc.savedViews` was advertised by the triage queue and counted in the
   * account page's "N local preference keys" inventory, while nothing in src
   * ever read or wrote it: there was no control to save the current
   * query/sort/chip set and none to restore one. An operator told the panel
   * keeps views went looking for a control that does not exist, so the claim is
   * withdrawn rather than left standing over an unbuilt feature.
   */
  function consoleSource(): string {
    const files: string[] = [];
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir)) {
        const path = join(dir, entry);
        if (statSync(path).isDirectory()) {
          if (entry === "test") continue;
          walk(path);
        } else if (/\.tsx?$/.test(entry) && entry !== "panelInventory.ts") {
          files.push(path);
        }
      }
    };
    walk("src");
    return files.map((file) => readFileSync(file, "utf8")).join("\n");
  }

  const source = consoleSource();
  const queueKeys = SOC_PANEL_INVENTORY.find((panel) => panel.id === "alert-triage-queue")?.storage ?? [];

  it("advertises storage for the queue, or the assertion below is vacuous", () => {
    expect(queueKeys.length).toBeGreaterThan(0);
  });

  it("names no queue key the console never writes", () => {
    const missing = queueKeys.filter((key) => !source.includes(key));
    expect(missing, `the queue advertises storage it never writes: ${missing.join(", ")}`).toEqual([]);
  });

  it("has withdrawn the saved-views claim rather than half-building it", () => {
    expect(queueKeys).not.toContain("soc.savedViews");
    expect(SOC_STORAGE_KEYS, "the account page's key inventory counted it too").not.toContain("soc.savedViews");
    expect(source, "a saved-view control would have to write the key it advertises").not.toContain("soc.savedViews");
  });
});

describe("the graph brief counts what the canvas draws", () => {
  /**
   * GraphBrief said in its own comment that it counted indicators "the SAME way
   * the canvas draws them (graphModel.ts)". graphModel filters every peer
   * through `!isLoopbackPeer(p)` before adding a node and GraphBrief did not,
   * so a host's own health checks inflated the number sitting two inches from a
   * canvas correctly drawing none of them. Measured on the engine's ten-day
   * store: 397 of 559 IPv4-carrying events are `curl 127.0.0.1:8090`.
   */
  function event(id: string, overrides: Partial<SocEvent>): SocEvent {
    return { id, eventType: "connect", timestamp: "2026-06-25T09:00:00Z", raw: undefined, ...overrides };
  }

  const events = [
    event("e-external", { process: "/usr/bin/curl", destIp: "203.0.113.10", destPort: 443 }),
    event("e-loopback", { process: "/usr/bin/healthcheck", destIp: "127.0.0.1", destPort: 8090 }),
    event("e-loopback-v6", { process: "/usr/bin/healthcheck", destIp: "::1", destPort: 8090 })
  ];

  it("excludes loopback destinations the canvas refuses to draw", () => {
    render(<GraphBrief alerts={[]} events={events} topProcesses={[]} meta={{ processes: 2, edges: 1 }} live />);
    const fabric = screen.getByText("Signal fabric").closest(".soc-graph-brief-card");
    expect(within(fabric as HTMLElement).getByText("1 indicators observed")).toBeTruthy();
  });
});
