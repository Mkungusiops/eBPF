/**
 * Settings — what an operator tunes after deployment.
 *
 * # The rule that decides what appears here
 *
 * A setting that can only make the platform act LESS is safe to expose. One
 * that can make it act MORE needs validation, and where it changes the meaning
 * of stored data, versioning first.
 *
 * That is why suppressions are here and scoring WEIGHTS are not. A bad
 * suppression costs a missed detection — bounded, and it shows up as a
 * coverage gap on Sensor Health. A bad weight could push every process past
 * the sever threshold: the same failure class as the unvalidated threshold
 * ladder that could sever a fleet from one malformed request.
 *
 * Weights would also make stored alerts incomparable, because nothing records
 * which ruleset produced a score. That prerequisite has to land first.
 *
 * # What is deliberately not here
 *
 * Anything the deploy rewrites wholesale, and every secret. The deploy writes
 * engine.yaml, agent.yaml and controlplane.env as whole-file heredocs on each
 * run, so a console that edited them would be lying by the next deploy.
 */
import { useCallback, useEffect, useState } from "react";
import { Trash2 } from "lucide-react";
import { EmptyState, InlineNotice, cx } from "./components";
import { api, getJSON, postJSON } from "../../lib/api";
import { LIFECYCLE_LABEL, SETTINGS_SECTIONS } from "./settingsModel";
import { ResponseControls, type Thresholds } from "./SettingsResponse";
import { GuardrailControls } from "./SettingsGuardrails";
import { ChangeControlControls } from "./SettingsChangeControl";
import { RetentionControls } from "./SettingsRetention";
import { AccessTrailPanel } from "./SettingsAccessTrail";

export interface Suppression {
  id: number;
  binary: string;
  policy?: string;
  parent?: string;
  reason: string;
  actor?: string;
  created_at?: string;
  /** Absent when the deployment cannot report it — never rendered as 0. */
  hits?: number;
}

/** A binary actually producing findings here, offered as a starting point. */
/** The live enforcement posture, read-only here. */
interface ChokeState {
  mode?: string;
  dry_run?: boolean;
  kill_switched?: boolean | null;
  thresholds?: Record<string, number>;
}

export interface Candidate {
  binary: string;
  policy?: string;
  events: number;
  suppressed: boolean;
}

interface SuppressionsResponse {
  suppressions: Suppression[];
  candidates?: Candidate[];
  /** Non-empty when the candidate query failed. Absent ≠ empty. */
  candidate_error?: string;
  window?: string;
  hits_known: boolean;
  effect: string;
}

export function SettingsBody({ open }: { open: boolean }) {
  const [data, setData] = useState<SuppressionsResponse | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [binary, setBinary] = useState("");
  const [policy, setPolicy] = useState("");
  const [reason, setReason] = useState("");
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);
  const [picked, setPicked] = useState("");
  const [active, setActive] = useState("noise");
  const [choke, setChoke] = useState<ChokeState | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await getJSON<SuppressionsResponse>("/api/settings/suppressions"));
      setError("");
      // Read-only, and best-effort: the Response section shows the live ladder
      // so an operator can see what they would be changing. A failure here
      // leaves those rows blank rather than failing the whole page — the
      // suppression controls do not depend on it.
      try {
        setChoke(await getJSON<ChokeState>("/api/choke/state"));
      } catch {
        setChoke(null);
      }
    } catch (e) {
      // Absent, not empty. A settings page that renders "no suppressions" when
      // it could not reach the server invites an operator to add one that
      // already exists.
      setError(e instanceof Error ? e.message : "could not load settings");
    }
  }, []);

  useEffect(() => {
    if (open) void load();
  }, [open, load]);

  if (!open) return null;

  async function add() {
    setBusy(true);
    setResult(null);
    try {
      const res = await postJSON<{ note?: string }>("/api/settings/suppressions", {
        binary: binary.trim(),
        policy: policy.trim(),
        reason: reason.trim()
      });
      setResult({ ok: true, message: res.note || "added" });
      setBinary("");
      setPolicy("");
      setReason("");
      setPicked("");
      await load();
    } catch (e) {
      setResult({ ok: false, message: e instanceof Error ? e.message : "failed" });
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: number) {
    setBusy(true);
    setResult(null);
    try {
      await api(`/api/settings/suppressions?id=${id}`, { method: "DELETE" });
      setResult({ ok: true, message: "removed — detection for this pattern resumes immediately" });
      await load();
    } catch (e) {
      setResult({ ok: false, message: e instanceof Error ? e.message : "failed" });
    } finally {
      setBusy(false);
    }
  }

  const rows = data?.suppressions ?? [];
  const candidates = (data?.candidates ?? []).filter((c) => !c.suppressed || rows.length === 0);
  const section = SETTINGS_SECTIONS.find((x) => x.id === active) ?? SETTINGS_SECTIONS[0];

  return (
    <div className="soc-settings">
      {/* Two panes. A settings surface is a place you NAVIGATE, not a page you
          scroll: the sections have different owners, and a platform engineer
          looking for retention should not have to read past an analyst's
          suppression list to find it. */}
      <nav className="soc-settings-nav" aria-label="Settings sections">
        {SETTINGS_SECTIONS.map((sec) => (
          <button
            key={sec.id}
            type="button"
            className={cx("soc-settings-navitem", sec.id === section.id && "is-on")}
            onClick={() => setActive(sec.id)}
          >
            <strong>{sec.title}</strong>
            <span>{sec.owner}</span>
          </button>
        ))}
      </nav>

      <div className="soc-settings-pane">
        {/* The section leads with the QUESTION, not the mechanism. "When should
            the platform act?" is findable; "circuit thresholds" is not, unless
            you already know the answer. */}
        <header className="soc-settings-head">
          <h3>{section.title}</h3>
          <p>{section.question}</p>
        </header>

        {section.rows.map((row) => (
          <section key={row.key} className="soc-settings-row">
            <div className="soc-settings-rowhead">
              <strong>{row.label}</strong>
              <span className={cx("soc-settings-badge", `is-${row.lifecycle}`)}>
                {LIFECYCLE_LABEL[row.lifecycle]}
              </span>
              <span className="soc-settings-badge is-scope">{row.scope}</span>
            </div>
            <p className="soc-settings-help">{row.help}</p>
            {row.caveat ? <p className="soc-settings-caveat">{row.caveat}</p> : null}

            {/* Only a row the platform can actually change gets a control. A
                disabled input next to "set by deploy" invites someone to keep
                clicking it. */}
            {row.key === "suppressions" ? (
              <SuppressionsControl
                data={data}
                rows={rows}
                candidates={candidates}
                error={error}
                busy={busy}
                result={result}
                binary={binary}
                policy={policy}
                reason={reason}
                picked={picked}
                setBinary={setBinary}
                setPolicy={setPolicy}
                setReason={setReason}
                setPicked={setPicked}
                onAdd={() => void add()}
                onRemove={(id) => void remove(id)}
              />
            ) : null}

            {/* Response rows share one control: the ladder, the mode and the
                kill-switch are one decision an operator makes together, and
                splitting them into three widgets made each look smaller than
                it is. Rendered once, on the first row of the section. */}
            {row.key === "thresholds" ? (
              <ResponseControls
                thresholds={(choke?.thresholds as Thresholds | undefined) ?? null}
                mode={choke?.mode ?? ""}
                killSwitched={choke?.kill_switched}
                onChanged={() => void load()}
              />
            ) : null}

            {/* Guardrails: the protect-lists. One control, because the binary
                list and the address list are one statement — "what this
                platform must never touch here" — and an operator who protects
                the jump hosts and forgets the uplink has protected neither. */}
            {row.key === "protected" ? <GuardrailControls onChanged={() => void load()} /> : null}

            {/* Change control. The queue, the four-eyes rule and the TTL were
                all running already; only the switch was deploy-time, which
                made the one setting a security lead most wants during an
                incident the one they could not reach. */}
            {row.key === "dual-control" ? <ChangeControlControls /> : null}

            {/* Retention. tenants.retention_days shipped in migration 0001 and
                nothing read it, so a customer contractually held to 14 days
                could have 14 stored here and keep 30. */}
            {row.key === "retention" ? <RetentionControls onChanged={() => void load()} /> : null}

            {/* The access trail. Written on every cross-tenant and refused
                authorization, and readable BY THE TENANT — an MSSP whose
                customers cannot see provider access has asked them to take it
                on faith. */}
            {row.key === "access-trail" ? <AccessTrailPanel /> : null}
          </section>
        ))}
      </div>
    </div>
  );
}

/** The one section with a real control, kept out of the layout above. */
function SuppressionsControl(p: {
  data: SuppressionsResponse | null;
  rows: Suppression[];
  candidates: Candidate[];
  error: string;
  busy: boolean;
  result: { ok: boolean; message: string } | null;
  binary: string;
  policy: string;
  reason: string;
  picked: string;
  setBinary: (v: string) => void;
  setPolicy: (v: string) => void;
  setReason: (v: string) => void;
  setPicked: (v: string) => void;
  onAdd: () => void;
  onRemove: (id: number) => void;
}) {
  return (
    <>
      {p.error ? (
        <InlineNotice tone="warn" title="Settings could not be read">
          {p.error}. This is not the same as having no suppressions — nothing is being claimed either way.
        </InlineNotice>
      ) : null}
      {p.data?.candidate_error ? (
        <InlineNotice tone="warn" title="Could not work out what is noisy here">
          {p.data.candidate_error}. That is not the same as nothing being noisy — add one by hand if you already
          know the path.
        </InlineNotice>
      ) : null}
      {p.result ? (
        <div className={cx("soc-sensor-result", p.result.ok ? "ok" : "bad")}>{p.result.message}</div>
      ) : null}

      {p.candidates.length > 0 ? (
        <>
          <p className="soc-settings-lead">
            Busiest detections on this host in the last {p.data?.window ?? "7d"} — ranked by how often each fired,
            which is volume, not severity. Anything already handled by a built-in rule is left out.
          </p>
          <div className="soc-settings-cards">
            {p.candidates.map((c) => (
              <article key={c.binary + c.policy} className="soc-settings-card">
                <div>
                  <strong>{c.binary}</strong>
                  {c.policy ? <span className="soc-tech-pill">{c.policy}</span> : null}
                </div>
                <span className="soc-settings-count">{c.events.toLocaleString()} events</span>
                <button type="button" className="soc-ghost-button" onClick={() => {
                  p.setBinary(c.binary);
                  p.setPolicy(c.policy ?? "");
                  p.setReason("");
                  p.setPicked(c.binary);
                }}>
                  Expected here
                </button>
              </article>
            ))}
          </div>
        </>
      ) : null}

      {p.picked ? (
        <InlineNotice tone="warn" title={`Suppress ${p.picked}?`}>
          It stops adding to a score on this host. Say why — the reason goes into the tamper-evident audit chain,
          and it is what tells the next analyst why this is quiet.
        </InlineNotice>
      ) : null}

      <div className="soc-settings-form">
        <label>
          <span>Binary — absolute path, matched exactly</span>
          <input value={p.binary} onChange={(e) => p.setBinary(e.target.value)} placeholder="/opt/backup/agent" />
        </label>
        <label>
          <span>Detection — optional; empty means any</span>
          <input value={p.policy} onChange={(e) => p.setPolicy(e.target.value)} placeholder="sensitive-file-access" />
        </label>
        <label>
          <span>Reason — recorded in the audit chain</span>
          <input value={p.reason} onChange={(e) => p.setReason(e.target.value)} placeholder="our backup agent reads credential paths nightly" />
        </label>
        <button
          type="button"
          className="soc-action-button ok"
          disabled={p.busy || !p.binary.trim().startsWith("/") || p.reason.trim().length < 3}
          onClick={p.onAdd}
        >
          {p.busy ? "Applying…" : "Add suppression"}
        </button>
      </div>

      {p.rows.length > 0 ? (
        <div className="soc-settings-cards">
          {p.rows.map((s) => (
            <article key={s.id} className="soc-settings-card">
              <div>
                <strong>{s.binary}</strong>
                {s.policy ? <span className="soc-tech-pill">{s.policy}</span> : null}
                <em>{s.reason}</em>
              </div>
              <span className="soc-settings-count">
                {p.data?.hits_known ? (s.hits ? `fired ${s.hits}×` : "never fired — check the path") : "count not reported"}
              </span>
              <button type="button" className="soc-ghost-button" disabled={p.busy} onClick={() => p.onRemove(s.id)}>
                <Trash2 size={12} aria-hidden="true" /> Remove
              </button>
            </article>
          ))}
        </div>
      ) : null}
    </>
  );
}
