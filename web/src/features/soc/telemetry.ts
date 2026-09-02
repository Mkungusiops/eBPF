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
//
// # The fallback stays. Measured, 2026-08-25, on a production agent:
//
//   outbound-connections events in the store   3,032
//   ...carrying an IPv4 in args                3,032   (100%)
//   ...carrying dest_ip                            2   (0.07%)
//
// The engine populates dest_ip from the SAME sock argument it renders into
// args, so the two agree wherever both exist — but the code that fills dest_ip
// shipped long after the code that renders args, and only two events have
// flowed through since. Retiring the fallback today would blank the peer node
// for 3,030 of 3,032 historical connections: every peer the correlation graph
// can currently draw on this estate.
//
// Revisit when a fresh window (not the whole store) shows dest_ip on
// substantially every outbound-connections event. That is a measurement, not a
// guess — re-run it before deleting anything here.
const IPV4_ENDPOINT_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b/;

/**
 * Policies whose events describe an actual network connection.
 *
 * Deliberately a closed list that UNDER-claims: an unrecognised policy is
 * treated as "not a connection", so a new detection cannot start silently
 * inventing peers before anyone decides whether its arguments mean one.
 */
const NETWORK_POLICIES = new Set(["outbound-connections"]);

/** True when an IP in this event's arguments describes a real connection. */
export function isConnectionEvent(event: SocEvent): boolean {
  return !!event.policyName && NETWORK_POLICIES.has(event.policyName);
}

/**
 * The remote endpoint this event touched.
 *
 * # Measured first, and derived only where derivation means something
 *
 * destIp is what the sensor reported from the connection itself. Everything
 * else is recovered by pattern-matching the process arguments, and an IP in a
 * command line is an INTENT, not an observation.
 *
 * That fallback used to run on every event, and on this estate it produced
 * 1,614 peers from non-network events against 55 from real connection events —
 * twenty-nine invented for every one recovered. The invented ones were command
 * arguments: `nc -w1 185.220.101.1 4444` from the old attack simulator, drawn
 * onto the correlation graph as though a connection to a Tor exit had been
 * observed. `ping -c1 <ip>` produced a "TCP peer" for an ICMP probe, and
 * `awk -v gw=<ip>` produced one from a shell variable.
 *
 * So the fallback is now gated on the event actually being a connection event.
 * That also removes the need to backfill: a historical outbound-connections
 * event still resolves, because the sensor rendered daddr:dport into its
 * arguments long before there was a field to put it in.
 */
export function peerFromEvent(event: SocEvent): string | undefined {
  if (event.destIp) return event.destPort ? joinPeer(event.destIp, event.destPort) : event.destIp;
  if (event.remoteIp) return event.remoteIp;
  if (!isConnectionEvent(event)) return undefined;
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
  const ip = peerAddress(peer);
  return /^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
}

/**
 * A peer's address, without its port.
 *
 * `peer.split(":")[0]` was correct for IPv4 and silently wrong for everything
 * else: an IPv6 address is itself full of colons, so "::1:8090" split to the
 * EMPTY STRING. Empty matches neither the loopback test nor the RFC1918 test,
 * so localhost fell through to "external peer" — a health check against your
 * own machine, drawn on the correlation graph as an outbound connection.
 *
 * Producers now bracket IPv6 (see JoinHostPort and joinPeer), so the bracketed
 * form is the one to parse. Unbracketed IPv6 is genuinely ambiguous — "::1:80"
 * is a valid address on its own — so it is returned whole rather than guessed
 * at, which errs toward classifying it correctly as loopback instead of
 * inventing a port split.
 */
export function peerAddress(peer: string): string {
  const s = peer.trim();
  if (s.startsWith("[")) {
    const end = s.indexOf("]");
    return end > 0 ? s.slice(1, end) : s.slice(1);
  }
  const first = s.indexOf(":");
  if (first < 0) return s;
  // More than one colon means IPv6, and an unbracketed IPv6 endpoint cannot be
  // split reliably. Keep it whole.
  if (s.indexOf(":", first + 1) >= 0) return s;
  return s.slice(0, first);
}

/** Join an address and port, bracketing IPv6 so the result can be parsed back. */
export function joinPeer(ip: string, port: number): string {
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}

// Loopback is neither a device on our network nor an external peer — it is the
// host talking to itself.
//
// Measured on the engine's ten-day store: of 559 events carrying an IPv4, 397
// are `curl 127.0.0.1:8090` health checks. Each one was drawing a PEER node,
// which on a security console reads as "this process reached an external
// address" — inventing a destination that does not exist, in the panel whose
// whole job is showing who talked to whom.
export function isLoopbackPeer(peer: string): boolean {
  const ip = peerAddress(peer);
  // 127.0.0.0/8, IPv6 ::1, and the IPv4-mapped form ::ffff:127.0.0.1 that a
  // dual-stack socket reports. All three are the host talking to itself, and
  // curl entering the outbound-connections policy made the last two common.
  if (/^127\./.test(ip)) return true;
  if (ip === "::1" || ip === "::1:0" || /^\[?::1\]?$/.test(ip)) return true;
  if (/^::ffff:127\./i.test(ip)) return true;
  // Unbracketed IPv6 kept whole by peerAddress: "::1:8090" is loopback with a
  // port that could not be split off.
  return /^::1:\d+$/.test(ip);
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
