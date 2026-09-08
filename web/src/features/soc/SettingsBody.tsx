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
import { InlineNotice, cx } from "./components";
import { api, getJSON, postJSON } from "../../lib/api";
import { useResponseAuthority } from "./api";
import { LIFECYCLE_LABEL, SETTINGS_SECTIONS } from "./settingsModel";
import { ResponseControls, responseWithheldNow, type Thresholds } from "./SettingsResponse";
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
  // The suppression list is a WRITE on the same page as the ladder, the
  // enforcement mode and the kill-switch, and it was the one this page's
  // permission sweep missed entirely: adding a suppression tells the platform
  // to stop scoring a binary, which is a detection an operator gives up. It is
  // gated on the same shared predicate as the three above.
  //
  // `withheld` rather than `readOnlyAccount`, for the same reason as those
  // three: `readOnlyAccount` is false before whoami answers, and this panel
  // loads /api/settings/suppressions on modal open independently of the SOC
  // poll — so it painted a live, writable list throughout a whoami outage.
  const { readOnlyAccount, withheld, withheldReason } = useResponseAuthority();
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
    // The guard behind the disabled controls, asked of the authority store at
    // the moment of the request. The form can be filled in and submitted from a
    // panel that was drawn before whoami answered; the request must still not
    // leave.
    const denied = responseWithheldNow();
    if (denied) {
      setResult({ ok: false, message: denied });
      return;
    }
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
    // Removing a suppression resumes detection, which is the safe direction —
    // but it is still a write to a tenant's configuration, recorded in the
    // audit chain under this operator's name, so it is refused on exactly the
    // same terms as adding one.
    const denied = responseWithheldNow();
    if (denied) {
      setResult({ ok: false, message: denied });
      return;
    }
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
                withheld={withheld}
                withheldReason={withheldReason}
                withheldKind={withheld ? (readOnlyAccount ? "permission" : "pending") : null}
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

            {/* Platform. The row is read-only by design — the deploy rewrites
                these files whole — but read-only meant "no control", and the
                one section a platform engineer opens to ask "where does this
                run, and against what?" rendered the question, the caveat about
                the value, and no value. It shows the effective configuration
                the servers already report, and names what none of them do. */}
            {row.key === "runtime" ? <RuntimePanel /> : null}
          </section>
        ))}
      </div>
    </div>
  );
}

/** The one section with a real control, kept out of the layout above. */
function SuppressionsControl(p: {
  /** Whether a write may be sent at all — see useResponseAuthority in api.ts. */
  withheld: boolean;
  /** The sentence for whichever refusal it is; null when nothing is withheld. */
  withheldReason: string | null;
  /**
   * WHICH refusal, passed rather than inferred from the sentence: "permission"
   * is a claim about this account, "pending" is a claim about what the console
   * has been told. Printing the first while the answer is in flight tells a
   * responder they are read-only, which is its own false statement.
   */
  withheldKind: "permission" | "pending" | null;
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

      {/* Stated once, in the language of whichever refusal it is. The list
          below stays on the page and readable: what is suppressed on this host
          is a READING, and an analyst triaging a quiet binary needs it whether
          or not they may change it.

          Only the two COMMITS go inert — Add and Remove. The fields and the
          "Expected here" shortcut stay live, the same rule the choke plane's
          threshold simulator follows: composing a suppression is the reader's,
          and taking the keyboard away from someone working out what to ask an
          administrator for withholds more than the server does. */}
      {p.withheld ? (
        <InlineNotice
          tone="warn"
          title={p.withheldKind === "permission" ? "Read-only account" : "Checking what this account may do"}
        >
          {p.withheldReason} The suppression list below is shown as a reading only.
        </InlineNotice>
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
                <button type="button" className="soc-ghost-button"
                  onClick={() => {
                    p.setBinary(c.binary);
                    p.setPolicy(c.policy ?? "");
                    p.setReason("");
                    p.setPicked(c.binary);
                  }}
                >
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
          disabled={p.withheld || p.busy || !p.binary.trim().startsWith("/") || p.reason.trim().length < 3}
          title={p.withheldReason ?? undefined}
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
              <button type="button" className="soc-ghost-button" disabled={p.withheld || p.busy}
                title={p.withheldReason ?? undefined} onClick={() => p.onRemove(s.id)}>
                <Trash2 size={12} aria-hidden="true" /> Remove
              </button>
            </article>
          ))}
        </div>
      ) : null}
    </>
  );
}

/* --------------------------------------------------------------- platform */

/**
 * The effective runtime configuration — the Platform section's missing value.
 *
 * The row is captioned "The deployed shape of this installation" and its caveat
 * promises "Shown as the effective value. Secrets are deliberately absent." For
 * a long time it showed nothing at all: the section a platform engineer opens to
 * answer "where does this run, and against what?" rendered the question, the
 * caveat about the value, and no value.
 *
 * # Where these come from, and why nothing new is asked for
 *
 * Every field is read off an endpoint the console already calls — /api/version,
 * /api/system-health and /api/whoami. Both planes answer all three, and the two
 * answer differently: the engine describes the host it defends (store backend
 * and target, BPF backend and attached links, OTLP endpoint, log level, the
 * auth mechanisms), while the control plane describes a fleet (agents seen,
 * whether the central store is readable) and says outright that it cannot
 * observe a kernel.
 *
 * # What is NOT served, and is said so rather than invented
 *
 * Neither server reports the address it binds or whether it terminates TLS;
 * neither reports the identity provider it trusts; the control plane reports no
 * log or metrics configuration and does not name its store backend. Those are
 * rendered as an explicit "not served by this deployment" with the reason,
 * because a settings page that quietly drops half a promise is the same defect
 * in a smaller font. Secrets stay absent: the store target arrives already
 * redacted, and nothing here asks for a credential.
 *
 * # A source that did not answer, which is a third thing again
 *
 * The three reads are independent and any one of them can fail on its own. That
 * is NOT "not served by this deployment" and it is NOT a value: each field
 * carries the source that owes it (see fromSource), and a field whose source
 * stayed silent renders as unread with the endpoint named. The alternative is
 * what this panel used to do — fall through to a default and print it as a
 * measurement of a box nothing had read.
 */
export interface RuntimeField {
  label: string;
  /** What the servers report. Empty means nothing here answers it. */
  value: string;
  /** Why the value reads as it does — or, with no value, what would have to serve it. */
  detail?: string;
  /**
   * Why an empty value is empty. The two reasons are different claims and must
   * not be rendered as one.
   *
   * "not-served" is a fact about the product: no deployment of this shape
   * reports the field. "unread" is a fact about this page load: the endpoint
   * that would have reported it did not answer. Showing the first when the
   * second is true tells a platform engineer their installation lacks a
   * capability it actually has.
   */
  absence?: "not-served" | "unread";
}

export interface RuntimeGroup {
  title: string;
  fields: RuntimeField[];
}

function asObject(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function asText(value: unknown): string {
  if (typeof value === "string") return value.trim();
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (typeof value === "boolean") return value ? "yes" : "no";
  return "";
}

/** Whether an endpoint answered at all. RuntimePanel hands back null when a read failed. */
function answered(payload: unknown): boolean {
  return payload !== null && payload !== undefined && typeof payload === "object" && !Array.isArray(payload);
}

/**
 * A field whose facts come from ONE endpoint, and what it says when that
 * endpoint stayed silent.
 *
 * The three reads are independent, so /api/system-health can 500 while
 * /api/version answers — and every health-backed field then fell through to its
 * own default and rendered that default as a measurement: Tetragon said "not
 * connected", the exporter said "disabled — nothing is exported". Both are
 * operational facts about a host nothing here had read, and an operator acting
 * on either would go looking for a sensor that is running. Same shape for
 * /api/version: a failed read used to assert "hidden — production" about the
 * lab surfaces, which is the one claim on this page that must never be guessed.
 *
 * So: no answer from the source, no claim from the field — the field names the
 * source that owed it instead.
 */
function fromSource(
  source: string,
  sourceAnswered: boolean,
  label: string,
  read: () => Omit<RuntimeField, "label">
): RuntimeField {
  if (sourceAnswered) return { label, ...read() };
  return {
    label,
    value: "",
    absence: "unread",
    detail: `${source} did not answer, so nothing here was read from this deployment.`
  };
}

/**
 * Fold the three reads into what the section promises. Pure, and separate from
 * the fetching, because WHICH deployment answered decides what can honestly be
 * claimed — and that is the part worth testing against both shapes.
 */
export function runtimeGroups(version: unknown, health: unknown, whoami: unknown, origin: string): RuntimeGroup[] {
  const v = asObject(version);
  const h = asObject(health);
  const w = asObject(whoami);
  const store = asObject(h.store);
  const bpf = asObject(h.bpf);
  const observability = asObject(h.observability);
  const auth = asObject(h.auth);
  const tetragon = asObject(h.tetragon);

  const hasVersion = answered(version);
  const hasHealth = answered(health);
  const hasWhoami = answered(whoami);
  const fromVersion = (label: string, read: () => Omit<RuntimeField, "label">) =>
    fromSource("/api/version", hasVersion, label, read);
  const fromHealth = (label: string, read: () => Omit<RuntimeField, "label">) =>
    fromSource("/api/system-health", hasHealth, label, read);
  const fromWhoami = (label: string, read: () => Omit<RuntimeField, "label">) =>
    fromSource("/api/whoami", hasWhoami, label, read);

  // Which plane answered, taken from what it SAID rather than guessed: only the
  // control plane counts agents, and only it reports a fleet policy scope. Both
  // signals live on reads that can fail, so `planeKnown` gates the fields whose
  // wording asserts which deployment this is.
  const planeKnown = hasHealth || hasWhoami;
  const fleet = h.agents !== undefined || asText(w.policy_scope) === "fleet";

  const revision = asText(v.revision) || asText(v.build);
  const dirty = v.dirty === true;
  const startedAt = asText(v.started_at) || asText(h.started_at);
  const uptime = asText(h.uptime);
  const tenants = Array.isArray(w.tenants) ? w.tenants.map(asText).filter(Boolean) : [];

  /**
   * `sha` is the console's build-change signal on both planes — and it measures
   * a different thing on each, so it cannot be described with one sentence.
   *
   * The engine serves a hash of the frontend assets it embeds (api/http.go's
   * versionSHA), so it moves whenever the shipped UI moves, including for a
   * rebuild from an uncommitted tree. The control plane serves its Go build
   * identity instead (controlplane/http.go hands back buildinfo.Info.String() —
   * the release tag, or the short revision, with "-dirty" appended), so it does
   * NOT move when only the console assets are rebuilt from the same commit.
   *
   * Calling both "the hash of the shipped UI" stated the engine's meaning on a
   * control plane, where it told an operator to expect a change that will not
   * come. When neither health nor whoami answered we do not know which box this
   * is, so the field says both meanings rather than picking one.
   */
  const buildSignal = fromVersion(planeKnown ? (fleet ? "Build identity" : "Console assets") : "Build signal", () => ({
    value: asText(v.sha),
    detail: !planeKnown
      ? "reported as `sha`, and it means different things per plane: the engine's is a hash of the UI assets it embeds, the control plane's is its Go build identity. Which of the two this is could not be determined — neither /api/system-health nor /api/whoami answered."
      : fleet
        ? "the control plane reports its Go build identity here — the release tag, or the short revision with -dirty appended — not an asset hash. The console watches it for change to offer a reload, so rebuilding the UI from the same commit will not prompt one."
        : "a hash of the frontend assets this engine embeds. It moves whenever the shipped UI moves, and is what drives the reload prompt."
  }));

  const build: RuntimeField[] = [
    fromVersion("Release", () => ({
      value: asText(v.version) || "no release tag",
      detail: asText(v.version)
        ? asText(v.product) || undefined
        : "built from a branch rather than cut from a tag, so the revision below is what identifies this build"
    })),
    fromVersion("Source revision", () => ({
      value: revision ? `${revision}${dirty ? " · built from a dirty tree" : ""}` : "",
      detail: revision
        ? undefined
        : "the build carries no revision, which happens when it was compiled outside a git checkout"
    })),
    fromVersion("Built at", () => ({
      value: asText(v.built_at),
      detail: asText(v.built_at) ? undefined : "this build reports no build time"
    })),
    // Two endpoints can serve this one, so it is only unread when both are.
    fromSource("neither /api/version nor /api/system-health", hasVersion || hasHealth, "Running since", () => ({
      value: startedAt ? `${startedAt}${uptime ? ` · up ${uptime}` : ""}` : "",
      detail: startedAt
        ? undefined
        : hasVersion && hasHealth
          ? "neither endpoint reported a start time"
          : "the endpoint that answered reported no start time, and the other one did not answer"
    })),
    buildSignal,
    fromVersion("Lab surfaces", () => ({
      value: v.lab_mode === true ? "exposed — this deployment is a lab" : "hidden — production",
      detail:
        v.lab_mode === true
          ? "Attack Sim, Honeypots and the Rule Simulator are offered here, and Attack Sim runs a script as root on the host being defended."
          : "the attack runner, honeypots and the rule simulator are withheld from the rail and the command palette."
    }))
  ];

  const listeners: RuntimeField[] = [
    {
      label: "Console reached at",
      value: origin,
      detail: "what this browser connected to. Anything in front of it — a reverse proxy, a different hostname — is not visible from here."
    },
    {
      label: "Listen address and TLS",
      value: "",
      absence: "not-served",
      detail:
        "neither server reports the address it binds or whether it terminates TLS itself. That lives in the deploy's unit files and nginx config."
    }
  ];

  const storeFields: RuntimeField[] = fleet
    ? [
        fromHealth("Central store", () => ({
          value: store.ok === true ? "readable" : asText(store.error) || (store.ok === false ? "unreadable" : ""),
          detail:
            store.ok === false
              ? "every tenant-scoped read fails while this is true — it is the single fault that takes the whole console down."
              : "the control plane reports whether the store answers, not which engine or DSN backs it."
        }))
      ]
    : [
        fromHealth("Backend", () => ({
          value: asText(store.backend),
          detail: asText(store.backend) ? undefined : "this build did not report a store backend"
        })),
        fromHealth("Target", () => ({
          value: asText(store.target),
          detail: asText(store.target)
            ? "a file path, or a DSN the server redacts before serving it. Credentials never reach the console."
            : "this build did not report a store target"
        }))
      ];

  const identity: RuntimeField[] = [
    fromWhoami("Signed in as", () => ({
      value: [asText(w.user) || asText(w.subject), asText(w.role)].filter(Boolean).join(" · "),
      detail: asText(w.user) || asText(w.subject) ? undefined : "/api/whoami named no user, so this session cannot be described"
    })),
    fleet
      ? fromWhoami("Tenant scope", () => ({
          value:
            w.cross_tenant === true
              ? "every tenant (cross-tenant operator)"
              : tenants.join(", ") || "no tenant claim on this session",
          detail: "what this session may read. Cross-tenant reads are recorded in the access trail."
        }))
      : // "single host" is a claim about WHICH deployment this is, so it needs a
        // plane that was actually observed rather than the default of the guess.
        fromSource("neither /api/system-health nor /api/whoami", planeKnown, "Tenant scope", () => ({
          value: "single host — this engine has one operator and no tenant boundary"
        })),
    fleet
      ? {
          label: "Identity provider",
          value: "",
          absence: "not-served",
          detail:
            "the control plane does not serve the issuer or client it trusts. Roles and tenant scope are provisioned in Keycloak by the deploy."
        }
      : fromHealth("Operator credentials", () => ({
          value: [asText(auth.hash) && `${asText(auth.hash)} password hashes`, asText(auth.sessions), asText(auth.csrf)]
            .filter(Boolean)
            .join(" · "),
          detail: asText(auth.rate_limit) ? `Login attempts are limited to ${asText(auth.rate_limit)}.` : undefined
        }))
  ];

  const telemetry: RuntimeField[] = fleet
    ? [
        fromHealth("Kernel sensor", () => ({
          value: asText(h.kernel_sensor),
          detail: "the control plane defends no host of its own; what each agent's kernel reports is on Sensor Health."
        })),
        fromHealth("Agents reporting", () => ({
          value:
            h.agents === undefined
              ? ""
              : `${asText(h.agents_fresh)} of ${asText(h.agents)} seen in the last 90 seconds${
                  asText(h.last_seen) ? ` · newest ${asText(h.last_seen)}` : ""
                }`,
          detail: "an agent is counted stale after three missed 30-second heartbeats."
        })),
        {
          label: "Metrics and logs",
          value: "",
          absence: "not-served",
          detail: "the control plane does not report its OTLP endpoint or its log configuration; the engine does."
        }
      ]
    : [
        fromHealth("Kernel sensor", () => ({
          value: asText(bpf.backend)
            ? `${asText(bpf.backend)} · ${asText(bpf.attached_links)}/${asText(bpf.expected_links)} programs attached`
            : "",
          detail: !asText(bpf.backend)
            ? "this build reported no BPF backend"
            : bpf.healthy === false
              ? "fewer programs are attached than this build expects — see Sensor Health."
              : undefined
        })),
        fromHealth("Tetragon", () => ({ value: tetragon.connected === true ? "connected" : "not connected" })),
        fromHealth("Metrics export", () => ({
          value: asText(observability.otlp_endpoint) || "disabled — nothing is exported",
          detail: asText(observability.otlp_endpoint) ? undefined : "no OTLP endpoint is configured on this host."
        })),
        fromHealth("Logs", () => ({
          value: [asText(observability.log_format), asText(observability.log_level)].filter(Boolean).join(" at "),
          detail: [asText(observability.log_format), asText(observability.log_level)].some(Boolean)
            ? undefined
            : "this build reported no log format or level"
        }))
      ];

  return [
    { title: "Build", fields: build },
    { title: "Listeners", fields: listeners },
    { title: "Store", fields: storeFields },
    { title: "Identity", fields: identity },
    { title: "Telemetry", fields: telemetry }
  ];
}

export function RuntimePanel() {
  const [groups, setGroups] = useState<RuntimeGroup[] | null>(null);
  const [loadError, setLoadError] = useState("");
  /**
   * The endpoints that did not answer this load.
   *
   * A partial read is the dangerous case, not the total one: with /api/version
   * answering and /api/system-health down the pane still renders, and a reader
   * who does not notice which fields went blank will take the rest of the
   * section as a description of the running box. Naming the silent sources at
   * the top says how much of this page was actually measured.
   */
  const [silent, setSilent] = useState<string[]>([]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      // redirectOn401 is off on purpose: a settings pane must never be the
      // thing that navigates an operator to the login page. The route's own
      // poll owns that decision.
      const read = async (path: string) => {
        try {
          return await getJSON<unknown>(path, { redirectOn401: false });
        } catch {
          return null;
        }
      };
      const [version, health, whoami] = await Promise.all([
        read("/api/version"),
        read("/api/system-health"),
        read("/api/whoami")
      ]);
      if (cancelled) return;
      if (version === null && health === null) {
        setLoadError("neither /api/version nor /api/system-health answered");
        return;
      }
      setSilent(
        [
          version === null ? "/api/version" : "",
          health === null ? "/api/system-health" : "",
          whoami === null ? "/api/whoami" : ""
        ].filter(Boolean)
      );
      setGroups(runtimeGroups(version, health, whoami, typeof window === "undefined" ? "" : window.location.origin));
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (loadError) {
    return (
      <InlineNotice tone="warn" title="The running configuration could not be read">
        {loadError}. Nothing is being claimed about how this installation is deployed.
      </InlineNotice>
    );
  }
  if (!groups) return <p className="soc-settings-help">Reading the running configuration…</p>;

  return (
    <div className="soc-guardrails">
      {silent.length > 0 ? (
        <InlineNotice tone="warn" title="Not every source answered">
          {silent.join(" and ")} did not answer, so the fields they serve are shown as unread rather than as a value.
        </InlineNotice>
      ) : null}
      {groups.map((group) => (
        <div key={group.title} className="soc-guardrail-block">
          <div className="soc-guardrail-blockhead">
            <strong>{group.title}</strong>
          </div>
          {group.fields.map((field) => (
            <p key={field.label} className={field.value ? "soc-settings-help" : "soc-settings-caveat"}>
              <strong>{field.label}</strong>{" "}
              {field.value ? (
                <code>{field.value}</code>
              ) : field.absence === "unread" ? (
                /* A source that stayed silent is NOT a deployment that lacks the
                   capability, and the badge must not say it is: "not served by
                   this deployment" next to Tetragon reads as a box with no
                   Tetragon, which is a fact nothing here measured. */
                <span className="soc-settings-badge">could not be read</span>
              ) : (
                <span className="soc-settings-badge is-not-wired">not served by this deployment</span>
              )}
              {field.detail ? <> — {field.detail}</> : null}
            </p>
          ))}
        </div>
      ))}
    </div>
  );
}
