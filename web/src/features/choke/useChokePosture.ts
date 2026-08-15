// The route's read of the host's posture: which deployment this is, what the
// engine says its mode is, what the KERNEL says independently of the engine,
// and the CommandMetrics the shared Containment Command header renders from.
//
// It is one hook because these facts are only meaningful together. Enforcement
// mode alone is not posture — a host can read detect-only here while a
// Tetragon policy kills in the kernel — so the divergence counters are derived
// alongside the mode they contradict, never somewhere else.
import { useMemo } from "react";
import { LADDER } from "../common/enforcement";
import { computePosture, type CommandMetrics } from "../common/ContainmentCommand";
import type { ApprovalRequest } from "./api";
import type { ChokeState, CircuitEntry, Decision, HostPingResult, LoadState, Whoami } from "./types";
import type { StreamInfo } from "./constants";
import { countByState, normalizeThresholds } from "./utils";

export function useChokePosture({
  chokeState,
  circuits,
  approvals,
  whoami,
  hostPings,
  streamInfo,
  loadState,
  now,
  windowMin,
  currentWindowDecisions,
}: {
  chokeState: ChokeState | null;
  circuits: CircuitEntry[];
  approvals: ApprovalRequest[];
  whoami: Whoami | null;
  hostPings: HostPingResult[];
  streamInfo: StreamInfo;
  loadState: LoadState;
  now: number;
  windowMin: number;
  currentWindowDecisions: Decision[];
}) {
  const thresholds = normalizeThresholds(chokeState?.thresholds);
  const mode = chokeState?.kill_switched ? "kill-switched" : chokeState?.mode || "detect-only";

  // The mode above is only the ENGINE's half of a host's posture. Tetragon
  // policies enforce independently of it, so a host can be killing processes
  // while this page says detect-only. Surfacing that is the whole point of
  // reporting it — see docs/plan/threat-model.md EN-3.
  const kernel = chokeState?.kernel;
  // Only the control plane returns a `kernel` block; the single-tenant engine's
  // /api/choke/state has no such key. That makes it a reliable "am I the
  // multi-tenant console?" signal without inventing a capability flag.
  //
  // It matters because two actions here are engine-LOCAL: policy preview
  // evaluates YAML against one host's tracked processes, and a forensic
  // snapshot dumps one host's state. Neither has a fleet-wide meaning, so the
  // control plane answers both with 501. Offering an enabled button that always
  // fails is worse than not offering it — the operator cannot tell a missing
  // feature from a broken one, and finds out by clicking it in front of someone.
  const isFleetConsole = Boolean(kernel);
  const engineOnlyHint = "Engine-local action — open the single-tenant engine for this host. The fleet console has no host to evaluate it against.";
  const divergedAgents = kernel?.diverged_agents || [];
  const pendingApprovals = approvals.filter((req) => req.status === "pending");
  const kernelFired = kernel?.enforce_actions || 0;
  // Only meaningful once at least one agent has answered; before that the
  // absence of a divergence says nothing at all.
  const agentsReporting = kernel?.agents_reporting ?? 0;
  const agentsTotal = kernel?.agents_total ?? 0;
  const agentsSilent = Math.max(0, agentsTotal - agentsReporting);
  const stateCounts = chokeState?.counts || countByState(circuits, thresholds);

  const staleSeconds = streamInfo.lastMessageAt ? Math.floor((now - streamInfo.lastMessageAt) / 1000) : 0;
  const disabled = loadState.kind === "disabled";

  // ── Containment Command metrics (shared hero + ladder) ──────────────────
  // Contained = anything on a rung above pristine. Active threats = uncontained
  // processes already scoring at/over the first enforcement threshold — the
  // ones an operator should be acting on right now.
  const containedCount = LADDER.filter((r) => r !== "pristine").reduce((sum, r) => sum + (stateCounts[r] || 0), 0);
  const activeThreats = useMemo(
    () =>
      circuits.filter(
        (c) => (!c.state || c.state === "pristine") && (c.score || 0) >= (thresholds.throttle_at || 20)
      ).length,
    [circuits, thresholds.throttle_at]
  );
  const enforceMode: "detect-only" | "enforcing" = chokeState?.mode === "enforcing" ? "enforcing" : "detect-only";
  // Three states, not two. supported=false means this deployment cannot verify
  // the chain at all (the fleet control plane does not hash-chain centrally) —
  // rendering that as a green "intact · 0 rows" claimed tamper-evidence that
  // was never checked, and rendering it red would cry wolf.
  const auditSupported = chokeState?.audit?.supported !== false;
  const auditOk = auditSupported && chokeState?.audit?.ok !== false;
  const commandMetrics: CommandMetrics = {
    subject: "processes",
    mode: enforceMode,
    activeThreats,
    contained: containedCount,
    tracked: chokeState?.tracked || circuits.length,
    auditOk,
    auditSupported,
    auditRows: chokeState?.audit?.total || 0,
    killSwitched: Boolean(chokeState?.kill_switched),
    headline: `${(currentWindowDecisions.length / Math.max(1, windowMin)).toFixed(1)} /min`,
    headlineLabel: "Decision rate",
    posture: computePosture({
      mode: enforceMode,
      activeThreats,
      contained: containedCount,
      auditOk,
      killSwitched: Boolean(chokeState?.kill_switched)
    })
  };

  const userLabel = String(whoami?.username || whoami?.user || "operator");
  const hostState = hostPings[0]?.ok === false ? "down" : hostPings[0] && hostPings[0].rtt_ms > 800 ? "slow" : "ok";

  return {
    thresholds,
    mode,
    kernel,
    isFleetConsole,
    engineOnlyHint,
    divergedAgents,
    pendingApprovals,
    kernelFired,
    agentsTotal,
    agentsSilent,
    stateCounts,
    staleSeconds,
    disabled,
    enforceMode,
    commandMetrics,
    userLabel,
    hostState,
  };
}
