/**
 * Guardrails — what containment must always refuse to touch.
 *
 * # Why this is the one setting that can only ever be widened
 *
 * The worst outcome of an enforcement bug is not a missed detection: it is
 * locking every operator out of the estate the platform is supposed to be
 * protecting. A host nobody can reach cannot be remediated, and a network
 * uplink that has been severed cannot be un-severed from the other end of it.
 *
 * So the agent carries a compiled-in floor — the SSH family, sudo, su, login,
 * systemd — that it re-unions on every apply. No entry here can remove it, and
 * neither can a validly signed command from a compromised control plane. That
 * floor is rendered as fixed chips rather than as unchecked checkboxes,
 * because a control that silently restores its own value reads as broken.
 *
 * # The asymmetry the UI has to state
 *
 * Binaries narrow live: the setter replaces the additions and re-unions the
 * floor. Addresses do not — the agent's device protect-list is add-only at
 * runtime, precisely because dropping the uplink is the one edit that can
 * blackhole the path you would use to undo it. Removing an address here
 * changes the desired state and takes effect on that agent's next restart.
 * Saying "removed" flatly would be the more comfortable copy and the false one.
 */
import { useCallback, useEffect, useState } from "react";
import { Plus, ShieldCheck, Trash2 } from "lucide-react";
import { InlineNotice, cx } from "./components";
import { getJSON, putJSON } from "../../lib/api";

export interface ProtectedState {
  /** Compiled into every agent; re-unioned on apply; not editable. */
  floor: string[];
  /** Additions only — never the union, so both planes mean the same thing. */
  binaries: string[];
  macs: string[];
  process_plane: boolean;
  device_plane: boolean;
  macs_are_add_only: boolean;
  /** True on the control plane: intent, not a reading of any agent. */
  desired_only?: boolean;
  error?: string;
}

interface ApplyResult {
  ok?: boolean;
  acked?: number;
  dispatched_to?: number;
  detail?: string;
  warning?: string;
  skipped?: string[];
  note?: string;
}

/** Absolute path, because the agent compares the binary field exactly. */
export function validateBinary(v: string): string {
  const s = v.trim();
  if (!s) return "";
  if (!s.startsWith("/")) {
    return "Use the absolute path. Matching is exact, so a bare name would protect nothing while looking protected.";
  }
  if (s.includes(" ")) return "A path with a space in it will not match the recorded binary.";
  return "";
}

/** Six octets, colon or hyphen separated — what the agent's parser accepts. */
export function validateMAC(v: string): string {
  const s = v.trim();
  if (!s) return "";
  if (!/^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$/.test(s)) {
    return "That is not a MAC address. An address the agent cannot parse is silently not protected.";
  }
  return "";
}

export function GuardrailControls({ onChanged }: { onChanged?: () => void }) {
  const [state, setState] = useState<ProtectedState | null>(null);
  const [loadError, setLoadError] = useState("");
  const [bins, setBins] = useState<string[]>([]);
  const [macs, setMacs] = useState<string[]>([]);
  const [draftBin, setDraftBin] = useState("");
  const [draftMac, setDraftMac] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);

  const load = useCallback(async () => {
    try {
      const raw = await getJSON<Partial<ProtectedState>>("/api/settings/protected");
      // Normalise on the way in. A payload from an older engine, or a 200 with
      // a body this component did not expect, must leave the panel rendering
      // rather than throwing inside .map — the Sensor Health panel crashed on
      // exactly that, on a field the server simply omitted.
      const s: ProtectedState = {
        floor: Array.isArray(raw?.floor) ? raw.floor : [],
        binaries: Array.isArray(raw?.binaries) ? raw.binaries : [],
        macs: Array.isArray(raw?.macs) ? raw.macs : [],
        process_plane: raw?.process_plane !== false,
        device_plane: raw?.device_plane === true,
        macs_are_add_only: raw?.macs_are_add_only !== false,
        desired_only: raw?.desired_only === true,
        error: raw?.error
      };
      setState(s);
      setBins(s.binaries);
      setMacs(s.macs);
      setLoadError("");
    } catch (e) {
      // Absent is not empty. Rendering "nothing is protected" when the read
      // failed would invite an operator to arm a plane believing the uplink
      // is exposed, or to re-add entries that are already in force.
      setLoadError(e instanceof Error ? e.message : "could not read the guardrails");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const binErr = validateBinary(draftBin);
  const macErr = validateMAC(draftMac);
  const dirty =
    JSON.stringify(bins) !== JSON.stringify(state?.binaries ?? []) ||
    JSON.stringify(macs) !== JSON.stringify(state?.macs ?? []);
  const removingMac = (state?.macs ?? []).some((m) => !macs.includes(m));

  function addBin() {
    const v = draftBin.trim();
    if (!v || binErr || bins.includes(v)) return;
    setBins([...bins, v].sort());
    setDraftBin("");
  }
  function addMac() {
    const v = draftMac.trim().toLowerCase();
    if (!v || macErr || macs.includes(v)) return;
    setMacs([...macs, v].sort());
    setDraftMac("");
  }

  async function apply() {
    setBusy(true);
    setResult(null);
    try {
      const res = await putJSON<ApplyResult>("/api/settings/protected", {
        binaries: bins,
        macs,
        reason: reason.trim()
      });
      // Report what actually happened, including the parts that did not.
      // dispatched_to is present only on the control plane, where an offline
      // agent genuinely did not receive this and is not retried.
      const parts: string[] = [];
      if (typeof res.dispatched_to === "number") {
        parts.push(`${res.acked ?? 0} of ${res.dispatched_to} agent(s) acked`);
      } else {
        parts.push("applied on this host");
      }
      if (res.warning) parts.push(res.warning);
      if (res.detail) parts.push(res.detail);
      setResult({ ok: !res.warning, message: parts.join(" — ") });
      setReason("");
      await load();
      onChanged?.();
    } catch (e) {
      setResult({ ok: false, message: e instanceof Error ? e.message : "failed" });
    } finally {
      setBusy(false);
    }
  }

  if (loadError) {
    return (
      <InlineNotice tone="warn" title="Guardrails could not be read">
        {loadError}. That is not the same as nothing being protected — nothing is being claimed either way.
      </InlineNotice>
    );
  }
  if (!state) return <p className="soc-settings-help">Reading the protect-lists…</p>;

  return (
    <div className="soc-guardrails">
      {state.error ? (
        <InlineNotice tone="warn" title="Not stored on this deployment">
          {state.error}
        </InlineNotice>
      ) : null}

      <div className="soc-guardrail-block">
        <div className="soc-guardrail-blockhead">
          <ShieldCheck size={13} aria-hidden="true" />
          <strong>Always protected</strong>
          <span className="soc-settings-badge is-deploy-managed">fixed</span>
        </div>
        <p className="soc-settings-help">
          Compiled into every agent and added back on every apply. Containment refuses these whatever else is
          configured, and no command — signed or not — can strip them. This is what stops a mistake locking you
          out of your own estate.
        </p>
        <div className="soc-chiprow">
          {state.floor.length === 0 ? (
            <span className="soc-chip is-empty">this deployment did not report its fixed list</span>
          ) : null}
          {state.floor.map((f) => (
            <span key={f} className="soc-chip is-fixed">
              {f}
            </span>
          ))}
        </div>
      </div>

      <div className="soc-guardrail-block">
        <div className="soc-guardrail-blockhead">
          <strong>Also protect these binaries</strong>
          <span className="soc-settings-badge is-live">editable</span>
        </div>
        <p className="soc-settings-help">
          Your jump hosts, your monitoring agent, anything whose death is worse than the incident. Absolute
          paths — matching is exact.
        </p>
        <div className="soc-chiprow">
          {bins.length === 0 ? <span className="soc-chip is-empty">none beyond the fixed list</span> : null}
          {bins.map((b) => (
            <span key={b} className="soc-chip">
              {b}
              <button
                type="button"
                aria-label={`Remove ${b}`}
                onClick={() => setBins(bins.filter((x) => x !== b))}
              >
                <Trash2 size={11} aria-hidden="true" />
              </button>
            </span>
          ))}
        </div>
        <div className="soc-guardrail-add">
          <input
            value={draftBin}
            onChange={(e) => setDraftBin(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                addBin();
              }
            }}
            placeholder="/opt/monitoring/agent"
            aria-label="Binary to protect"
          />
          <button
            type="button"
            className="soc-ghost-button"
            aria-label="Add protected binary"
            disabled={!draftBin.trim() || !!binErr}
            onClick={addBin}
          >
            <Plus size={12} aria-hidden="true" /> Add
          </button>
        </div>
        {binErr ? <p className="soc-settings-caveat">{binErr}</p> : null}
      </div>

      <div className="soc-guardrail-block">
        <div className="soc-guardrail-blockhead">
          <strong>Protect these network addresses</strong>
          <span className={cx("soc-settings-badge", state.device_plane ? "is-live" : "is-not-wired")}>
            {state.device_plane ? "device plane attached" : "no device plane here"}
          </span>
        </div>
        <p className="soc-settings-help">
          The default gateway, the uplink, the DHCP and DNS servers, the control plane itself. Quarantine and
          sever are refused for these; throttle and tarpit still apply, because those are recoverable.
        </p>
        <div className="soc-chiprow">
          {macs.length === 0 ? <span className="soc-chip is-empty">none</span> : null}
          {macs.map((m) => (
            <span key={m} className="soc-chip">
              {m}
              <button
                type="button"
                aria-label={`Remove ${m}`}
                onClick={() => setMacs(macs.filter((x) => x !== m))}
              >
                <Trash2 size={11} aria-hidden="true" />
              </button>
            </span>
          ))}
        </div>
        <div className="soc-guardrail-add">
          <input
            value={draftMac}
            onChange={(e) => setDraftMac(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                addMac();
              }
            }}
            placeholder="0a:1b:2c:3d:4e:5f"
            aria-label="Address to protect"
          />
          <button
            type="button"
            className="soc-ghost-button"
            aria-label="Add protected address"
            disabled={!draftMac.trim() || !!macErr}
            onClick={addMac}
          >
            <Plus size={12} aria-hidden="true" /> Add
          </button>
        </div>
        {macErr ? <p className="soc-settings-caveat">{macErr}</p> : null}
      </div>

      {removingMac ? (
        <InlineNotice tone="warn" title="Removing an address does not un-protect a running agent">
          The agent's device protect-list is add-only while it is running, on purpose — dropping the uplink is the
          one edit that can blackhole the path you would use to undo it. This removal is stored and takes effect
          on that agent's next restart.
        </InlineNotice>
      ) : null}

      {state.desired_only ? (
        <InlineNotice tone="info" title="This is the tenant's intent, not a reading of each agent">
          The control plane stores the desired list and pushes it to the agents it can currently see. No heartbeat
          field carries an agent's live protect-list, so this page cannot confirm what any single host holds — the
          ack count below is what it can honestly report.
        </InlineNotice>
      ) : null}

      <div className="soc-settings-form">
        <label>
          <span>Reason — recorded in the audit chain</span>
          <input
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="jump hosts and the top-of-rack uplink must never be contained"
          />
        </label>
        <button
          type="button"
          className="soc-action-button ok"
          disabled={busy || !dirty || reason.trim().length < 3}
          onClick={() => void apply()}
        >
          {busy ? "Applying…" : "Apply guardrails"}
        </button>
      </div>
      {!dirty && !busy ? <p className="soc-settings-caveat">No change to apply.</p> : null}

      {result ? <div className={cx("soc-sensor-result", result.ok ? "ok" : "bad")}>{result.message}</div> : null}
    </div>
  );
}
