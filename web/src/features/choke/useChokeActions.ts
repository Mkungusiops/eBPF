// Every consequential act on this page, in one place.
//
// The invariant this file exists to hold: nothing here calls an API directly.
// Each function stages a ConfirmRequest — title, blast radius, audit reason —
// and the API call happens inside onConfirm, after the operator has read what
// they are about to do. That is also why every result is inspected rather than
// assumed: "accepted" is not "applied", and a toast that says a process was
// contained when no agent applied it is the containment lie the whole routing
// contract exists to prevent.
import type { Dispatch, SetStateAction } from "react";
import {
  applyPreset as applyPresetApi,
  bulkManualAction,
  chokeApplied,
  copyToClipboard,
  decideApproval,
  forensicSnapshot,
  forgetCircuits,
  manualAction,
  setMode,
  thawQuarantine,
  toggleKillSwitch,
  verifyChain,
} from "./api";
import type { ApprovalRequest } from "./api";
import type { ChokeAction, ChokeState, CircuitEntry, ConfirmRequest, ToastMessage } from "./types";
import { PRESET_DESCRIPTIONS } from "./constants";
import { readOnlyReason } from "./canRespond";
import { approvalRadiusLabel, containedHosts, isContainedState, shortExec } from "./utils";

export function useChokeActions({
  chokeState,
  setChokeState,
  selectedEntries,
  selectedExecs,
  setSelectedExecs,
  setConfirm,
  pushToast,
  refreshAll,
  refreshState,
  refreshApprovals,
  canRespond = null,
  circuits = [],
  isFleetConsole = false,
}: {
  chokeState: ChokeState | null;
  setChokeState: Dispatch<SetStateAction<ChokeState | null>>;
  selectedEntries: CircuitEntry[];
  selectedExecs: Set<string>;
  setSelectedExecs: Dispatch<SetStateAction<Set<string>>>;
  setConfirm: Dispatch<SetStateAction<ConfirmRequest | null>>;
  pushToast: (message: string, kind?: ToastMessage["kind"]) => void;
  refreshAll: () => Promise<void>;
  refreshState: () => Promise<void>;
  refreshApprovals: () => Promise<void>;
  /**
   * whoami's `can_respond`, or `null` when the server did not publish one.
   *
   * Only `false` refuses anything — see readCanRespond in canRespond.ts.
   */
  canRespond?: boolean | null;
  /**
   * Every tracked circuit on screen — not the selection.
   *
   * The untargeted thaw is the only write here with no target of its own, so it
   * takes its blast radius from what the console is showing: the hosts holding
   * something releasable. Defaulted to empty so a caller that does not pass it
   * gets the widest, and therefore the loudest, confirm rather than a silently
   * mis-scoped one.
   */
  circuits?: CircuitEntry[];
  /**
   * True on the fleet control plane, false on the single-host engine.
   *
   * The same POST means two different things on the two deployments, and the
   * operator has to be told which one they are about to do — see
   * openThawConfirm.
   */
  isFleetConsole?: boolean;
}) {
  /**
   * The permission gate every write on this page passes through.
   *
   * It lives at the action layer rather than only on the buttons because the
   * buttons are not the only way in: the command palette, the Ctrl+Shift+K
   * hotkey and the profile menu all call these openers directly. A gate on the
   * controls alone would leave a read-only operator one keystroke away from
   * staging a kill-switch the server is going to refuse.
   *
   * It refuses loudly. A control that silently does nothing is indistinguishable
   * from a broken one, and the operator needs to know it is their grant — not
   * the estate — that stopped them.
   */
  function refusedAsReadOnly(): boolean {
    if (canRespond !== false) return false;
    pushToast(readOnlyReason("this gateway"), "warn");
    return true;
  }

  // Approving is itself a destructive act — it is what finally sends the kill —
  // so it goes through the same confirm dialog, with the requester and their
  // stated reason in front of the approver. An approver who has not read what
  // they are authorizing is a rubber stamp, which is worse than no control
  // because it manufactures an audit trail that implies review.
  async function decideOnApproval(req: ApprovalRequest, approve: boolean): Promise<void> {
    if (refusedAsReadOnly()) return;
    if (!approve) {
      try {
        await decideApproval(req.id, false);
        pushToast(`denied ${req.action} requested by ${req.requester}`, "ok");
      } catch (error) {
        pushToast((error as Error).message || "deny failed", "err");
      }
      await refreshApprovals();
      return;
    }
    // THE RADIUS IS THE REQUEST'S OWN, not the widest one it could have been.
    // This line used to read "the entire tenant" for every fleet-scoped
    // request, so the approver of an "agent-a only" containment was told, in
    // the one sentence they must click through, that they were arming the
    // whole estate. The server publishes `targets`/`radius` precisely so this
    // sentence can be true — see approvalRadiusLabel.
    setConfirm({
      title: `APPROVE ${req.action.toUpperCase()}`,
      body:
        `${req.requester} asked to ${req.action} ` +
        `${approvalRadiusLabel(req)}` +
        `${req.reason ? ` — “${req.reason}”` : ""}. Approving applies it now.`,
      danger: true,
      confirmLabel: "approve",
      reasonRequired: true,
      onConfirm: async ({ reason }) => {
        const result = await decideApproval(req.id, true, reason);
        if (chokeApplied(result)) {
          pushToast(`${req.action} approved and applied${result.agent ? ` on ${result.agent}` : ""}`, "ok");
        } else {
          pushToast(`approved, but NOT applied: ${result?.detail || result?.status || "no agent applied it"}`, "err");
        }
        await refreshAll();
      },
    });
  }

  function openManualConfirm(entry: CircuitEntry, action: ChokeAction): void {
    if (refusedAsReadOnly()) return;
    setConfirm({
      title: `${action.toUpperCase()} pid ${entry.pid || "-"}`,
      body: `${entry.binary || "(unknown)"} (${shortExec(entry.exec_id)})`,
      danger: action === "sever" || action === "quarantine",
      confirmLabel: action,
      reasonRequired: true,
      withRevert: action !== "sever",
      onConfirm: async ({ reason, revert_after_seconds }) => {
        const result = await manualAction({
          exec_id: entry.exec_id,
          pid: entry.pid,
          binary: entry.binary,
          // Route to the host the row came from. Without it the control plane
          // has to infer the owner, and on a fleet a PID alone can point at the
          // wrong machine.
          agent_id: entry.agent,
          action,
          reason,
          revert_after_seconds,
        });
        // Report what the fleet actually did. A blanket "applied" toast here
        // told the operator a process was contained even when every agent
        // reported it was not theirs — the containment lie this whole path
        // exists to prevent.
        if (result?.approval_required) {
          // Held for change-control (EN-2). Deliberately a "warn", not an "ok":
          // the operator must leave knowing the process is still running.
          pushToast(
            `${action} NOT applied — queued for a second operator to approve (${result.approval?.id || "pending"})`,
            "warn",
          );
        } else if (chokeApplied(result)) {
          const where = result?.agent ? ` on ${result.agent}` : "";
          pushToast(`${action} applied${where}`, "ok");
        } else {
          pushToast(`${action} NOT applied: ${result?.detail || result?.status || "no agent applied it"}`, "err");
        }
        await refreshAll();
      },
    });
  }

  function openBulkConfirm(action: ChokeAction): void {
    if (refusedAsReadOnly()) return;
    if (selectedEntries.length === 0) return;
    setConfirm({
      title: `${action.toUpperCase()} ${selectedEntries.length} process${selectedEntries.length === 1 ? "" : "es"}`,
      body: selectedEntries.map((entry) => entry.binary || shortExec(entry.exec_id)).join(", "),
      danger: action === "sever" || action === "quarantine",
      confirmLabel: action,
      reasonRequired: true,
      withRevert: action !== "sever",
      onConfirm: async ({ reason, revert_after_seconds }) => {
        const response = await bulkManualAction({
          targets: selectedEntries.map((entry) => ({
            exec_id: entry.exec_id,
            pid: entry.pid,
            binary: entry.binary,
            agent_id: entry.agent,
          })),
          action,
          reason,
          revert_after_seconds,
        });
        const results = response.results || [];
        const ok = results.filter((result) => result.ok).length;
        pushToast(`bulk ${action}: ${ok}/${results.length || selectedEntries.length} ok`, ok === results.length ? "ok" : "warn");
        setSelectedExecs(new Set());
        await refreshAll();
      },
    });
  }

  function openBulkForgetConfirm(): void {
    if (refusedAsReadOnly()) return;
    const execIds = Array.from(selectedExecs);
    if (execIds.length === 0) return;
    setConfirm({
      title: `Forget ${execIds.length} circuit${execIds.length === 1 ? "" : "s"}`,
      body: "Live state is removed; audit history remains hash-chained.",
      confirmLabel: "forget",
      onConfirm: async () => {
        await forgetCircuits(execIds);
        pushToast(`forgot ${execIds.length} circuits`, "ok");
        setSelectedExecs(new Set());
        await refreshAll();
      },
    });
  }

  function openKillSwitchConfirm(): void {
    if (refusedAsReadOnly()) return;
    // An unknown state has no safe toggle direction — see the note in
    // features/devices/useDeviceActions.ts. The control plane reports null
    // because no heartbeat field carries the agent's kill-switch, and `!null`
    // resolving to "engage" meant the bypass could never be released here.
    if (chokeState?.kill_switched === null || chokeState?.kill_switched === undefined) {
      pushToast(
        "kill-switch state is not reported by this deployment — use the agent's own console to change it",
        "warn"
      );
      return;
    }
    const target = !chokeState?.kill_switched;
    setConfirm({
      title: target ? "Engage kill-switch" : "Disengage kill-switch",
      body: target
        ? "Every enforcer is bypassed. Decisions still write to the audit chain."
        : "Future decisions can reach the active enforcer chain again.",
      danger: target,
      confirmLabel: target ? "engage" : "disengage",
      onConfirm: async () => {
        await toggleKillSwitch(target);
        pushToast(target ? "kill-switch engaged" : "kill-switch disengaged", target ? "warn" : "ok");
        await refreshState();
      },
    });
  }

  function openPresetConfirm(name: string): void {
    if (refusedAsReadOnly()) return;
    setConfirm({
      title: `Apply preset: ${name}`,
      body: PRESET_DESCRIPTIONS[name] || "Apply gateway posture preset.",
      danger: name === "containment" || name === "maintenance",
      confirmLabel: "apply",
      reasonRequired: true,
      onConfirm: async ({ reason }) => {
        await applyPresetApi(name, reason);
        pushToast(`preset ${name} applied`, "ok");
        await refreshState();
      },
    });
  }

  /**
   * Release containment with no process named — and SAY HOW FAR IT REACHES.
   *
   * This control wore single-host wording ("Thaw quarantined cgroup", "Frozen
   * processes resume") inherited from the agent-local engine, where a
   * reason-only thaw unfreezes that one host's quarantine tier. On the control
   * plane the identical POST is now a fleet release: it walks every agent's
   * heartbeat snapshot and sends a Thaw for every contained process in the
   * TENANT. It used to 400 there, so the radius is new and the wording never
   * caught up — and thaw is deliberately never approval-gated, so nothing else
   * stands between one click and un-containing the estate.
   *
   * Two defences, in order. Scope it: when the console can attribute
   * containment to hosts, those hosts are sent as `targets` and the release
   * touches nobody else. Then state it: the confirm names the hosts it will
   * reach, or says outright that it reaches every agent in the tenant when the
   * request cannot be narrowed.
   */
  function openThawConfirm(): void {
    if (refusedAsReadOnly()) return;
    const hosts = containedHosts(circuits);
    // Counted over the rows the release will actually reach, not over the whole
    // table: on the fleet console those are the rows that name a host, which are
    // exactly the rows the targets above were derived from. A count that
    // included rows no target covers would overstate what confirming achieves.
    const held = circuits.filter(
      (entry) => isContainedState(entry.state) && (!isFleetConsole || Boolean(entry.agent)),
    ).length;
    // Scoped only when this is the fleet console AND the rows on screen name
    // their hosts. On the single-host engine there is no `agent` to send and
    // `targets` would mean nothing; with no attributable host the request goes
    // out untargeted, which is a tenant-wide release and is confirmed as one.
    const scoped = isFleetConsole && hosts.length > 0;
    const tenantWide = isFleetConsole && !scoped;
    const heldPhrase = `${held} contained process${held === 1 ? "" : "es"} tracked on them right now`;
    const title = scoped
      ? `Thaw containment on ${hosts.length} host${hosts.length === 1 ? "" : "s"}`
      : tenantWide
        ? "Thaw containment across the whole tenant"
        : "Thaw this host's quarantine tier";
    const body = scoped
      ? `Releases EVERY contained process on ${hosts.join(", ")} — ${heldPhrase}. ` +
        "Frozen processes resume immediately. Thaw is never held for a second approver, " +
        "so confirming applies it now. Audited as a gateway decision."
      : tenantWide
        ? "Releases EVERY contained process on EVERY agent in this tenant. " +
          "The console cannot narrow it, because no contained process on screen names a host. " +
          "Frozen processes resume immediately. Thaw is never held for a second approver, " +
          "so confirming applies it now. Audited as a gateway decision."
        : "Releases this host's whole quarantine tier: every frozen process on this host resumes. " +
          "It unfreezes them where they are and moves nobody off the quarantine rung — " +
          "for that, open the process and set it back to pristine on its ladder. " +
          "Audited as a gateway decision.";
    setConfirm({
      title,
      // A tenant-wide release is a fleet-scale change of enforcement posture in
      // one click, with no second operator behind it. It gets the danger
      // treatment a fleet sever gets.
      danger: tenantWide,
      body,
      confirmLabel: "thaw",
      reasonRequired: true,
      onConfirm: async ({ reason }) => {
        const result = await thawQuarantine(reason, scoped ? hosts : undefined);
        // Report what the fleet actually released. "quarantine thawed" was
        // printed unconditionally, so a release that reached no agent — or left
        // one host still frozen — read exactly like one that worked.
        if (!chokeApplied(result)) {
          pushToast(`thaw NOT applied: ${result?.detail || result?.status || "no agent released anything"}`, "err");
        } else if (typeof result?.released === "number") {
          pushToast(
            `released ${result.released} of ${result.contained ?? result.released} contained process(es)` +
              ` across ${result.total ?? hosts.length} host(s)`,
            "ok",
          );
        } else {
          pushToast("quarantine thawed", "ok");
        }
        await refreshAll();
      },
    });
  }

  function openModeConfirm(enforcing: boolean): void {
    if (refusedAsReadOnly()) return;
    setConfirm({
      title: enforcing ? "Switch to enforcing" : "Switch to detect-only",
      body: enforcing
        ? "Real kernel calls will fire for future decisions."
        : "Decisions will be recorded without hitting kernel enforcers.",
      danger: enforcing,
      confirmLabel: enforcing ? "enforce" : "detect-only",
      reasonRequired: true,
      onConfirm: async ({ reason }) => {
        await setMode(enforcing, reason);
        pushToast(enforcing ? "mode set to enforcing" : "mode set to detect-only", "ok");
        await refreshState();
      },
    });
  }

  async function handleAuditVerify(): Promise<void> {
    try {
      const response = await verifyChain();
      setChokeState((prev) => ({ ...(prev || {}), audit: response as ChokeState["audit"] }));
      // Three outcomes, not two. The fleet control plane does not hash-chain
      // decisions centrally, and reporting an unrun check as "verified" is a
      // false assurance about tamper-evidence — the one claim an audit control
      // exists to make. It is equally wrong to shout "chain broken" at an
      // operator when nothing is broken, so unavailability is its own state.
      if (response.supported === false) {
        pushToast(
          String(response.detail || "audit chain verification is not available on this deployment"),
          "warn"
        );
      } else {
        pushToast(response.ok === false ? "audit chain broken" : "audit chain verified", response.ok === false ? "err" : "ok");
      }
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "audit verify failed", "err");
    }
  }

  async function copyAuditHead(): Promise<void> {
    const audit = chokeState?.audit;
    const value = String(audit?.head_hash || audit?.head || audit?.tip || audit?.total || "");
    if (!value) return;
    pushToast((await copyToClipboard(value)) ? "copied" : "copy failed", "ok");
  }

  async function downloadSnapshot(): Promise<void> {
    try {
      const blob = await forensicSnapshot();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `choke-forensic-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      pushToast("snapshot downloaded", "ok");
    } catch (error) {
      pushToast(error instanceof Error ? error.message : "snapshot failed", "err");
    }
  }

  return {
    decideOnApproval,
    openManualConfirm,
    openBulkConfirm,
    openBulkForgetConfirm,
    openKillSwitchConfirm,
    openPresetConfirm,
    openThawConfirm,
    openModeConfirm,
    handleAuditVerify,
    copyAuditHead,
    downloadSnapshot,
  };
}
