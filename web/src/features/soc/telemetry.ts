// Event-side maths: ingestion rate, indicators, outbound peers, and the
// event → policy → ATT&CK join.
//
// Alerts are what the engine decided; events are what it saw. The two need
// different derivations, so the alert-queue maths lives in analytics.ts and
// everything that reads the raw event feed lives here.
import type { SocAlert, SocEvent, SocSnapshot } from "./types";

export function eventsPerSecond(events: SocEvent[], now: number): number {
  const cutoff = now - 60_000;
  return events.filter((event) => Date.parse(event.timestamp) >= cutoff).length / 60;
}

export function eventSpark(events: SocEvent[], now: number): number[] {
  const buckets = Array.from({ length: 12 }, () => 0);
  const bucketMs = 5_000;
  for (const event of events) {
    const age = now - Date.parse(event.timestamp);
    if (age < 0 || age >= bucketMs * buckets.length) continue;
    const index = buckets.length - 1 - Math.floor(age / bucketMs);
    buckets[index] += 1;
  }
  return buckets;
}

export function aggregateEventProcesses(events: SocEvent[]) {
  const rows = new Map<string, number>();
  for (const event of events) {
    const label = event.process || event.policyName || "unknown";
    rows.set(label, (rows.get(label) || 0) + 1);
  }
  return [...rows.entries()].map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value);
}

export function aggregateEventTypes(events: SocEvent[]) {
  const wanted = ["process_exec", "process_kprobe", "process_exit"];
  const rows = wanted.map((label) => ({ label: label.replace("process_", ""), value: events.filter((event) => event.eventType === label).length }));
  const known = rows.reduce((sum, row) => sum + row.value, 0);
  return [...rows, { label: "other", value: Math.max(0, events.length - known) }];
}

// mitreCoverage builds the ATT&CK technique breakdown. Alerts don't carry a
// technique, but each event carries its triggering `policy_name`, and each
// policy maps to a MITRE technique — so we join event → policy → technique.
// Range-aware (counts techniques observed in the current event window). If no
// technique-bearing events are in range, we fall back to the cumulative
// per-policy post counts so the table still shows the full coverage map.
export function mitreCoverage(
  events: SocEvent[],
  policies: SocSnapshot["policies"],
  policyStats: SocSnapshot["policyStats"]
) {
  const mitreByPolicy = new Map<string, string>();
  for (const policy of policies) {
    if (policy.mitre) mitreByPolicy.set(policy.name, policy.mitre);
  }

  type Row = { label: string; value: number; meta?: string; id?: string };
  const rows = new Map<string, Row>();

  for (const event of events) {
    const mitre = event.policyName ? mitreByPolicy.get(event.policyName) : undefined;
    if (!mitre) continue;
    const row = rows.get(mitre) || { label: mitre, value: 0, meta: event.policyName, id: mitre };
    row.value += 1;
    rows.set(mitre, row);
  }

  if (rows.size === 0) {
    const postsByPolicy = new Map<string, number>();
    for (const stat of policyStats) postsByPolicy.set(stat.name, stat.posts);
    for (const policy of policies) {
      if (!policy.mitre) continue;
      const posts = postsByPolicy.get(policy.name) ?? 0;
      const existing = rows.get(policy.mitre);
      if (existing) existing.value += posts;
      else rows.set(policy.mitre, { label: policy.mitre, value: posts, meta: policy.name, id: policy.mitre });
    }
  }

  return [...rows.values()].sort((a, b) => b.value - a.value).slice(0, 12);
}

// The remote endpoint an event connected to, as "ip" or "ip:port".
//
// destIp/remoteIp are populated only on the synthetic (sim-agent) path. A REAL
// agent's tcp_connect event carries the destination in `args` — the engine now
// renders the sock daddr:dport there (see extractKprobeArgs). So fall back to the
// first IPv4 in args; without this, real outbound connections produce no peer
// node in the correlation graph.
const IPV4_ENDPOINT_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b/;
export function peerFromEvent(event: SocEvent): string | undefined {
  if (event.destIp) return event.destPort ? `${event.destIp}:${event.destPort}` : event.destIp;
  if (event.remoteIp) return event.remoteIp;
  const match = event.args?.match(IPV4_ENDPOINT_RE);
  return match ? match[0] : undefined;
}

// A private/LAN destination is a DEVICE (a host on the local network — the same
// entities the Devices page inventories), whereas a public IP is an external
// peer (a would-be C2). Rendering the two differently answers "did this process
// talk to something on our network, or reach out to the internet?" — and it is
// what wires devices into the correlation graph, which otherwise only knew about
// processes. RFC1918 ranges: 10/8, 172.16/12, 192.168/16.
export function isDevicePeer(peer: string): boolean {
  const ip = peer.split(":")[0];
  return /^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
}

export function extractIocs(alerts: SocAlert[], events: SocEvent[]) {
  const files = new Map<string, number>();
  const peers = new Map<string, number>();
  const add = (map: Map<string, number>, key?: string) => {
    if (!key) return;
    map.set(key, (map.get(key) || 0) + 1);
  };
  for (const event of events) {
    add(files, event.path);
    add(peers, peerFromEvent(event));
  }
  for (const alert of alerts) {
    for (const match of `${alert.description} ${alert.args || ""}`.matchAll(/(\/(?:[\w.-]+\/?){2,})/g)) add(files, match[1]);
    for (const match of `${alert.description} ${alert.args || ""}`.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) add(peers, match[0]);
  }
  return {
    files: [...files.entries()].sort((a, b) => b[1] - a[1]),
    peers: [...peers.entries()].sort((a, b) => b[1] - a[1])
  };
}

export function aggregateNetwork(events: SocEvent[]) {
  const rows = new Map<string, { peer: string; count: number; procs: Set<string> }>();
  for (const event of events) {
    const peer = peerFromEvent(event);
    if (!peer) continue;
    const row = rows.get(peer) || { peer, count: 0, procs: new Set<string>() };
    row.count += 1;
    if (event.process) row.procs.add(event.process);
    rows.set(peer, row);
  }
  return [...rows.values()]
    .map((row) => ({ peer: row.peer, count: row.count, procs: [...row.procs] }))
    .sort((a, b) => b.count - a.count);
}

// File-access events keep the accessed path in args ("/etc/passwd 4"); pull the
// first absolute-path token so it can become a shared "file" node.
export function extractFilePath(args: string | undefined): string | undefined {
  if (!args) return undefined;
  const match = args.match(/\/[^\s"']+/);
  return match ? match[0] : undefined;
}

export function filterEvents(events: SocEvent[], query: string, hideNoise: boolean) {
  const regex = query.trim() ? safeRegex(query.trim()) : null;
  return events.filter((event) => {
    const text = `${event.eventType} ${event.process || ""} ${event.args || ""} ${event.policyName || ""}`;
    if (hideNoise && /vite|node|chrome|browser|npm/.test(text.toLowerCase())) return false;
    return regex ? regex.test(text) : true;
  });
}

function safeRegex(source: string): RegExp | null {
  try {
    return new RegExp(source, "i");
  } catch {
    return null;
  }
}
