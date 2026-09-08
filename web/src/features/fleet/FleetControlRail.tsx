/**
 * The write rail: everything on this page that changes the estate.
 *
 * It is one column on purpose. Targeting sits at the top and the destructive
 * controls at the bottom, so an operator reaching for "Containment" or the
 * kill-switch passes the "Apply Changes To" segment on the way — the answer to
 * "how many hosts is this about to hit?" is never off-screen from the button
 * that hits them. The target count is restated under Emergency Controls for the
 * same reason.
 */
import { Activity, Check, Power, Unlock } from "lucide-react";

import { ladderReading } from "./fleetLogic";
import { PanelTitle } from "./PanelTitle";
import type { ApplyMode, PresetName, Thresholds } from "./types";

const PRESETS: Array<{
  name: PresetName;
  label: string;
  eyebrow: string;
  description: string;
  tone: "good" | "danger" | "warn" | "muted";
}> = [
  {
    name: "default",
    label: "Default",
    eyebrow: "Everyday",
    description: "10/30/60/100, kill-switch off",
    tone: "good"
  },
  {
    name: "containment",
    label: "Containment",
    eyebrow: "Severe",
    description: "1/3/8/60, aggressive choke",
    tone: "danger"
  },
  {
    name: "forensic",
    label: "Forensic",
    eyebrow: "Observe",
    description: "Preserve evidence, enforce lightly",
    tone: "warn"
  },
  {
    name: "maintenance",
    label: "Maintenance",
    eyebrow: "Pause",
    description: "Kill-switch on, thresholds raised",
    tone: "muted"
  }
];

export function FleetControlRail({
  applyMode,
  onApplyMode,
  selectedCount,
  writesDisabled,
  writesDisabledReason,
  onPreset,
  thresholdDraft,
  thresholdDirty,
  majorityThresholds,
  reportingHosts,
  ladderNote = "",
  ladderTemporary = false,
  onThreshold,
  onApplyThresholds,
  targetCount,
  onKillSwitchOn,
  onKillSwitchOff,
  onThaw
}: {
  applyMode: ApplyMode;
  onApplyMode: (mode: ApplyMode) => void;
  selectedCount: number;
  writesDisabled: boolean;
  /** Why the rail is disabled, in the operator's terms; "" when it is armed. */
  writesDisabledReason: string;
  onPreset: (name: PresetName) => void;
  thresholdDraft: Thresholds;
  thresholdDirty: boolean;
  majorityThresholds: Thresholds | null;
  /**
   * How many hosts the reading below was computed FROM. "Majority 10/30/60/100"
   * over one reporting host is a majority of one, which on a single-agent
   * tenant is every reading there is; the count is passed so the line can say
   * so instead of implying a fleet agreed on something.
   */
  reportingHosts: number;
  /** What the last threshold write said about its durability; "" until one is sent. */
  ladderNote?: string;
  /**
   * That last write is not the tenant's ladder, so a tenant ladder will be
   * pushed back over it — see useFleetControls.applyThresholds. Tones the note
   * as a caveat rather than as an aside.
   */
  ladderTemporary?: boolean;
  onThreshold: (key: keyof Thresholds, value: string) => void;
  onApplyThresholds: () => void;
  targetCount: number;
  onKillSwitchOn: () => void;
  onKillSwitchOff: () => void;
  onThaw: () => void;
}) {
  return (
    <aside className="fleet-rail">
      <section className="fleet-panel">
        <PanelTitle title="Apply Changes To" />
        <div className="fleet-segment">
          <button
            className={applyMode === "all" ? "is-active" : ""}
            type="button"
            onClick={() => onApplyMode("all")}
          >
            All hosts
          </button>
          <button
            className={applyMode === "sel" ? "is-active" : ""}
            type="button"
            onClick={() => onApplyMode("sel")}
          >
            Selected only
          </button>
        </div>
        <p className="fleet-muted">
          {applyMode === "all"
            ? "Writes target every configured peer."
            : `Writes target ${selectedCount} selected host${selectedCount === 1 ? "" : "s"}.`}
        </p>
      </section>

      {/*
        A disabled control that does not say why reads as a broken one. This
        states the reason once, at the head of the rail, so an operator whose
        account is read-only learns it here rather than by pressing the
        kill-switch during an incident and watching nothing happen.
      */}
      {writesDisabledReason ? (
        <p className="fleet-rail__blocked" role="status">
          {writesDisabledReason}
        </p>
      ) : null}

      <section className="fleet-panel">
        <PanelTitle title="Posture Preset" />
        <div className="fleet-postures">
          {PRESETS.map((preset) => (
            <button
              className={`fleet-posture fleet-posture--${preset.tone}`}
              disabled={writesDisabled}
              key={preset.name}
              title={writesDisabledReason || undefined}
              type="button"
              onClick={() => onPreset(preset.name)}
            >
              <span>{preset.eyebrow}</span>
              <strong>{preset.label}</strong>
              <small>{preset.description}</small>
            </button>
          ))}
        </div>
      </section>

      <section className="fleet-panel">
        <PanelTitle title="Thresholds" />
        <div className="fleet-thresholds">
          <ThresholdInput label="Throttle" value={thresholdDraft.throttle_at} onChange={(value) => onThreshold("throttle_at", value)} />
          <ThresholdInput label="Tarpit" value={thresholdDraft.tarpit_at} onChange={(value) => onThreshold("tarpit_at", value)} />
          <ThresholdInput label="Quarantine" value={thresholdDraft.quarantine_at} onChange={(value) => onThreshold("quarantine_at", value)} />
          <ThresholdInput label="Sever" value={thresholdDraft.sever_at} onChange={(value) => onThreshold("sever_at", value)} />
        </div>
        <div className="fleet-panel__row">
          <span className={thresholdDirty ? "fleet-dirty" : "fleet-muted"}>
            {thresholdDirty ? "Unsaved changes" : ladderReading(reportingHosts, majorityThresholds)}
          </span>
          <button
            className="fleet-btn fleet-btn--primary"
            disabled={writesDisabled || !thresholdDirty}
            title={writesDisabledReason || undefined}
            type="button"
            onClick={onApplyThresholds}
          >
            <Check size={15} />
            Apply
          </button>
        </div>
        {/*
          The durability of the LAST write, left on screen after its toast has
          gone. A targeted ladder is pushed back over by the control plane's
          reconciler a couple of minutes later, which is exactly when an
          operator returns to this panel asking why the numbers moved — and a
          toast they can no longer read is not an answer.
        */}
        {ladderNote ? (
          <p className={ladderTemporary ? "fleet-rail__blocked" : "fleet-muted"} role="status">
            {ladderNote}
          </p>
        ) : null}
      </section>

      <section className="fleet-panel">
        <PanelTitle title="Emergency Controls" />
        <div className="fleet-actions">
          <button
            className="fleet-btn fleet-btn--danger"
            disabled={writesDisabled}
            title={writesDisabledReason || undefined}
            type="button"
            onClick={onKillSwitchOn}
          >
            <Power size={15} />
            Kill-switch on
          </button>
          <button
            className="fleet-btn"
            disabled={writesDisabled}
            title={writesDisabledReason || undefined}
            type="button"
            onClick={onKillSwitchOff}
          >
            <Activity size={15} />
            Kill-switch off
          </button>
          <button
            className="fleet-btn"
            disabled={writesDisabled}
            title={writesDisabledReason || undefined}
            type="button"
            onClick={onThaw}
          >
            <Unlock size={15} />
            Thaw quarantine
          </button>
        </div>
        <p className="fleet-muted">Current target set: {targetCount} host{targetCount === 1 ? "" : "s"}.</p>
      </section>
    </aside>
  );
}

function ThresholdInput({
  label,
  value,
  onChange
}: {
  label: string;
  value: number;
  onChange: (value: string) => void;
}) {
  return (
    <label>
      <span>{label}</span>
      <input min={1} type="number" value={Number.isFinite(value) ? value : ""} onChange={(event) => onChange(event.target.value)} />
    </label>
  );
}
