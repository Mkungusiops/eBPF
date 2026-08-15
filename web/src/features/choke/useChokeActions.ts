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
import { shortExec } from "./utils";

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
}) {
  // Approving is itself a destructive act — it is what finally sends the kill —
  // so it goes through the same confirm dialog, with the requester and their
  // stated reason in front of the approver. An approver who has not read what
  // they are authorizing is a rubber stamp, which is worse than no control
  // because it manufactures an audit trail that implies review.
  async function decideOnApproval(req: ApprovalRequest, approve: boolean): Promise<void> {
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
    setConfirm({
      title: `APPROVE ${req.action.toUpperCase()}`,
      body:
        `${req.requester} asked to ${req.action} ` +
        `${req.scope === "fleet" ? "the entire tenant" : `${shortExec(req.exec_id || "")}${req.pid ? ` (pid ${req.pid})` : ""}`}` +
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

  function openThawConfirm(): void {
    setConfirm({
      title: "Thaw quarantined cgroup",
      body: "Frozen processes resume. This is audited as a gateway decision.",
      confirmLabel: "thaw",
      reasonRequired: true,
      onConfirm: async ({ reason }) => {
        await thawQuarantine(reason);
        pushToast("quarantine thawed", "ok");
        await refreshAll();
      },
    });
  }

  function openModeConfirm(enforcing: boolean): void {
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
