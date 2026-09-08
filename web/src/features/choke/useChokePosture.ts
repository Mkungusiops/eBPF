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
import { CHOKE_UNREACHABLE } from "./api";
import { readCanRespond, readOnlyReason } from "./canRespond";
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
  // It matters because the forensic snapshot is engine-LOCAL: it dumps one
  // host's state, which has no fleet-wide meaning, so the control plane answers
  // it with 501. commandItems.ts drops the palette entry entirely on a fleet
  // console rather than offering an enabled button that always fails — the
  // operator cannot tell a missing feature from a broken one, and finds out by
  // clicking it in front of someone.
  //
  // Policy preview used to be the second such action, and this hook carried an
  // `engineOnlyHint` string for the disabled-button tooltip on it. 30318a3
  // removed the whole policy workbench, so the hint had no reader and is gone.
  const isFleetConsole = Boolean(kernel);
  const divergedAgents = kernel?.diverged_agents || [];
  // Normalised to an array here rather than at each use: an older control plane
  // omits the key entirely, and a panel that maps over undefined throws instead
  // of rendering — the Sensor Health crash, on a field the server simply did
  // not send.
  const ladderCorrections = Array.isArray(chokeState?.ladder_corrections)
    ? chokeState.ladder_corrections
    : [];
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

  // `disabled` above is a fact about the DEPLOYMENT — whether the gateway is
  // serving at all. It is not a fact about the operator, and the two were being
  // conflated: every containment control on this page armed itself off
  // loadState alone, so a read-only account was shown a live sever/jail/
  // kill-switch surface and discovered the truth by pressing it on a real host.
  // The server answers 404 and the fan-out summary reports what it reached,
  // which is nothing — a silent failure at the moment of an incident.
  const canRespond = readCanRespond(whoami);
  const readOnlyAccount = canRespond === false;
  const containmentDisabled = disabled || readOnlyAccount;
  // Only the permission reason is named here. The deployment reason already has
  // its own banner (ChokeBanners' disabled-banner), and saying it twice in two
  // registers is how an operator ends up debugging the wrong thing.
  const containmentBlockedReason = readOnlyAccount ? readOnlyReason("this gateway") : "";

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
  // The host pill, over EVERY endpoint the probe touched rather than only the
  // first. hostPings[0] is /api/whoami (constants.HOST_ENDPOINTS), and identity
  // answering says nothing about the state and circuit endpoints the operator
  // is actually reading — under a half-open gateway that split is precisely
  // what kept the pill green. Any endpoint that did not answer, or answered an
  // error, is now a down host; slow is reserved for a host that answered all of
  // them, late.
  //
  // With no reading at all the route's own load state decides. The probe runs
  // on an eight-second interval, so there is a window at first paint where
  // nothing has been measured; claiming "ok" there while this route has already
  // failed to reach the gateway is the same confident green in miniature. An
  // unreachable gateway is the only error that counts as down — a gateway that
  // answered an error is still a host that is answering.
  const probeFailed = hostPings.some((ping) => !ping.ok);
  const probeSlow = hostPings.some((ping) => ping.rtt_ms > 800);
  const routeUnreachable = loadState.kind === "error" && loadState.message.includes(CHOKE_UNREACHABLE);
  const hostState = hostPings.length === 0
    ? routeUnreachable
      ? "down"
      : "ok"
    : probeFailed
      ? "down"
      : probeSlow
        ? "slow"
        : "ok";

  return {
    thresholds,
    mode,
    kernel,
    isFleetConsole,
    divergedAgents,
    ladderCorrections,
    pendingApprovals,
    kernelFired,
    agentsTotal,
    agentsSilent,
    stateCounts,
    staleSeconds,
    disabled,
    canRespond,
    readOnlyAccount,
    containmentDisabled,
    containmentBlockedReason,
    enforceMode,
    commandMetrics,
    userLabel,
    hostState,
  };
}
