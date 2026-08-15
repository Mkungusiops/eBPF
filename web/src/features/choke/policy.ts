// Policy Workbench source documents. The workbench never installs anything —
// it dry-runs YAML against the live tracked snapshot — so both documents here
// exist purely to give the operator something real to evaluate.
import type { CircuitEntry } from "./types";
import { basename } from "./utils";

export const DEFAULT_POLICY = `apiVersion: chokegw/v1
kind: ChokePolicy
metadata:
  name: shells-throttle
match:
  binaries:
    - /bin/bash
    - /bin/sh
  states:
    - throttled
buckets:
  - dimension: egress.connect
    rate_per_sec: 5
    burst: 10
`;

// buildLivePolicy synthesises a ChokePolicy from the current tracked snapshot
// so "Preview matches" returns real hits. It targets the most common
// non-pristine binary and the exact states it is currently in — guaranteeing
// the dry-run demonstrates the workbench actually evaluates live data.
export function buildLivePolicy(circuits: CircuitEntry[]): string {
  const active = circuits.filter((c) => (c.state || "pristine") !== "pristine");
  if (active.length === 0) return DEFAULT_POLICY;

  const byBinary = new Map<string, number>();
  for (const c of active) {
    const b = c.binary || "";
    if (b) byBinary.set(b, (byBinary.get(b) || 0) + 1);
  }
  const topBinary = [...byBinary.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || active[0].binary || "/bin/sh";
  const states = [...new Set(active.filter((c) => c.binary === topBinary).map((c) => c.state || "pristine"))]
    .filter((s) => s !== "pristine");
  const stateLines = (states.length > 0 ? states : ["severed"]).map((s) => `    - ${s}`).join("\n");

  return `apiVersion: chokegw/v1
kind: ChokePolicy
metadata:
  name: live-${basename(topBinary).replace(/[^a-z0-9]+/gi, "-").toLowerCase() || "match"}
  description: Auto-generated from the live snapshot to target ${basename(topBinary)}
match:
  binaries:
    - ${topBinary}
  states:
${stateLines}
buckets:
  - dimension: egress.connect
    rate_per_sec: 5
    burst: 10
`;
}
