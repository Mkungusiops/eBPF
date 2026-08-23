/**
 * Detections — the surface a customer uses to see and change what the kernel is
 * watching for.
 *
 * It replaces the read-only "Policy viewer", which showed four facts per policy
 * of which two were false on the multi-tenant console: an `alerts` count that
 * was structurally always 0 (an alert carries no policy field — alerts come
 * from a cumulative chain score, not one policy), and a mode pill that fell
 * back to the literal string "loaded" whenever the server did not send a
 * status, which on the control plane is always.
 *
 * What it shows instead is what the KERNEL reports, per host, off the
 * heartbeat: which policies are loaded, on how many agents, in which mode, and
 * which expected ones are missing — the case an alert count can never reveal,
 * because a policy that never loaded and a policy that is simply quiet look
 * identical in every count.
 *
 * # The push is honest about being a push
 *
 * Changing a policy dispatches a signed command to every agent the control
 * plane currently knows about, and each one acks. It does NOT converge: an
 * agent offline at that moment does not get it and is not retried. So this
 * reports "acked by N of M dispatched" and never "fleet updated", and it tells
 * the operator to confirm on the next heartbeat. Convergence needs a persisted
 * desired state and a reconcile loop, and until those exist claiming it would
 * be the same class of lie this console has been carrying all along.
 */
import { useCallback, useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, HelpCircle, Pencil, Trash2, Upload } from "lucide-react";
import { EmptyState, cx } from "./components";
import { postJSON } from "../../lib/api";
import { DETECTION_TEMPLATES, type DetectionTemplate } from "./detectionTemplates";
import type { SocPolicy } from "./types";

/**
 * The two planes answer with two different SHAPES because they made two
 * different promises.
 *
 * The control plane dispatched a signed command and counted acks: it cannot say
 * the fleet is updated, only that N of M agents replied, so it returns
 * acked/dispatched_to plus a convergence note.
 *
 * The engine applied to its own kernel and knows the result per policy: reach
 * is not in doubt, DURABILITY is — a policy can be live now and gone at the
 * next Tetragon restart. So it returns applied/failed plus a per-policy outcome
 * map and a durability flag.
 *
 * Rendered separately rather than flattened into one set of fields. Collapsing
 * them would force one plane's wording onto the other's facts, which is how a
 * surface ends up claiming more than it knows.
 */
interface PushResult {
  ok: boolean;
  error?: string;
  // Fleet (control plane)
  acked?: number;
  dispatched_to?: number;
  detail?: string;
  convergence_note?: string;
  // Host (engine)
  host?: string;
  applied?: number;
  failed?: number;
  outcome?: Record<string, string>;
  durable?: boolean;
  durability_note?: string;
}

export function DetectionsBody({
  policies,
  open,
  onRefresh,
  canPush,
  scope
}: {
  policies: SocPolicy[];
  open: boolean;
  onRefresh: () => void;
  /**
   * Whether this deployment can change detection policy at all. The control
   * plane can, by dispatching a signed command to its agents; the engine can,
   * by applying to its own host's Tetragon. A deployment with neither — a
   * fake/dev engine with no Tetragon connection — reports false, and the
   * authoring surface is hidden rather than offering a button that cannot work.
   */
  canPush: boolean;
  /**
   * How far a change reaches. "fleet" dispatches to every agent the control
   * plane knows about and does not converge; "host" applies directly to the
   * one machine this console runs on. The words differ throughout because the
   * PROMISE differs: a fleet push is acked, a host apply is done.
   */
  scope: "fleet" | "host";
}) {
  const [yaml, setYaml] = useState("");
  const [name, setName] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PushResult | null>(null);
  const [pushOpen, setPushOpen] = useState(false);
  const [picked, setPicked] = useState<DetectionTemplate | null>(null);
  // Checked on every keystroke rather than on submit: the point is to catch a
  // mistake while the operator is still looking at the line that caused it.
  const checks = preflight(name, yaml);
  // Removal is a separate flow with its own reason, not a mode of the push
  // form: they are dispatched as different commands and one must never be
  // reachable by mis-clicking the other.
  const [removing, setRemoving] = useState<SocPolicy | null>(null);
  // The name being edited in place, if any. Distinct from a copy: an edit
  // REPLACES the running detection under its own name, so the form has to warn
  // about that and the button has to say "replace", not "push".
  const [editing, setEditing] = useState<string>("");
  const [removeReason, setRemoveReason] = useState("");

  // A policy the kernel does not have is the finding an alert count cannot
  // produce. Surfaced first, because it is the only item here that means
  // something is wrong right now.
  // Only alarm on a policy the server SAID is not loaded — never on one it
  // could not tell us about.
  //
  // This shipped wrong once and the screenshot was damning: the single-tenant
  // engine does not send loaded_agents, so every policy read as 0 and the panel
  // announced "4 expected detections not loaded on any host" on a host running
  // all four. A console that invents a coverage gap is worse than the count it
  // replaced, because this one is styled as an alarm.
  const missing = useMemo(
    () => policies.filter((p) => p.expected && p.kernelStateKnown && (p.loadedAgents ?? 0) === 0),
    [policies]
  );
  const unknown = useMemo(() => policies.filter((p) => !p.kernelStateKnown), [policies]);
  const enforcing = useMemo(
    () => policies.filter((p) => p.kernelMode === "enforce"),
    [policies]
  );

  const push = useCallback(async () => {
    if (!name.trim() || !yaml.trim() || reason.trim().length < 3) return;
    setBusy(true);
    setResult(null);
    try {
      const res = await postJSON<PushResult>("/api/policies/push", {
        policies: [{ name: name.trim(), yaml, mode: "monitor" }],
        reason: reason.trim()
      });
      setResult(res);
      setEditing("");
      onRefresh();
    } catch (err) {
      setResult({
        ok: false,
        error: err instanceof Error ? err.message : "push failed"
      });
    } finally {
      setBusy(false);
    }
  }, [name, yaml, reason, onRefresh]);

  /**
   * Put an expected detection back on a host that is missing it.
   *
   * The reason is generated rather than asked for: the operator is restoring
   * the platform's own shipped detection to its intended state, which is not a
   * judgement call the way authoring or removing one is. Demanding a
   * justification to undo a gap would just add friction to the safe direction.
   */
  async function restore(policy: SocPolicy) {
    setBusy(true);
    setResult(null);
    try {
      const res = await postJSON<PushResult>("/api/policies/push", {
        policies: [{ name: policy.name, yaml: policy.yaml, mode: "monitor" }],
        reason: `restore missing expected detection ${policy.name}`
      });
      setResult(res);
      onRefresh();
    } catch (err) {
      setResult({ ok: false, error: err instanceof Error ? err.message : "restore failed" });
    } finally {
      setBusy(false);
    }
  }

  /**
   * Take a policy off.
   *
   * The console could push and never remove, which is not a missing
   * convenience — it is a trap. A policy that turns out to be too broad floods
   * the pipeline, and the only way to stop it was to SSH to the host, which is
   * precisely the workflow this surface exists to replace. Removal goes through
   * the same path as the push, with the same required reason.
   */
  async function remove(policy: SocPolicy) {
    setBusy(true);
    setResult(null);
    try {
      const res = await postJSON<PushResult>("/api/policies/push", {
        remove: [policy.name],
        reason: removeReason.trim()
      });
      setResult(res);
      setRemoving(null);
      setRemoveReason("");
      onRefresh();
    } catch (err) {
      setResult({
        ok: false,
        error: err instanceof Error ? err.message : "removal failed"
      });
    } finally {
      setBusy(false);
    }
  }

  if (!open) return null;

  return (
    <div className="soc-detections">
      {/* This screen is opened by an analyst who did not build the product.
          Without a sentence saying what a "detection" is here and what the
          states mean, the red banner below is alarming and unactionable. */}
      <div className="soc-detections-explain">
        <p>
          A <strong>detection</strong> is an eBPF policy loaded into each host's kernel. It decides what
          the platform can see — a technique with no policy loaded is invisible, and no amount of alert
          triage will reveal it.
        </p>
        <ul>
          <li><strong>loaded on N hosts</strong> — the kernel confirms it is watching. Nothing to do.</li>
          <li><strong>NOT LOADED</strong> — the kernel says it is absent. That host is blind to this
            technique. Push it below, or check the agent on Sensor Health.</li>
          <li><strong>load state unknown</strong> — this deployment could not ask the kernel. Not a
            gap; not a confirmation either.</li>
          <li><strong>monitor / enforce</strong> — monitor records, enforce <em>kills</em> without an
            audit row or a kill-switch. Everything here should read monitor.</li>
        </ul>
      </div>
      {unknown.length > 0 ? (
        <div className="soc-detections-unknown">
          This deployment does not report which policies the kernel has loaded, so coverage below is
          unknown rather than confirmed. Nothing is inferred from that silence.
        </div>
      ) : null}

      {missing.length > 0 ? (
        <div className="soc-detections-alarm">
          <AlertTriangle size={14} aria-hidden="true" />
          <div>
            <strong>{missing.length} expected detection{missing.length === 1 ? "" : "s"} not loaded on any host</strong>
            <span>{missing.map((p) => p.name).join(", ")} — no host is watching for this. An alert count cannot show you this: a policy that never loaded looks exactly like one that is quiet.</span>
          </div>
        </div>
      ) : null}

      {enforcing.length > 0 ? (
        <div className="soc-detections-alarm">
          <AlertTriangle size={14} aria-hidden="true" />
          <div>
            <strong>{enforcing.length} policy in ENFORCE mode</strong>
            <span>{enforcing.map((p) => p.name).join(", ")} — an enforcing TracingPolicy kills independently of the containment ladder, with no audit row and no kill-switch.</span>
          </div>
        </div>
      ) : null}

      <div className="soc-detections-list">
        {policies.length === 0 ? (
          <EmptyState title="No detections reported" detail="No agent has reported its kernel policy set yet. This is not the same as a host with no detections loaded — nothing has told us either way." />
        ) : (
          policies.map((p) => (
            <article
              key={p.name}
              className={cx(
                "soc-detections-card",
                p.kernelStateKnown && (p.loadedAgents ?? 0) === 0 && "is-missing",
                !p.kernelStateKnown && "is-unknown"
              )}
            >
              <div className="soc-detections-head">
                {!p.kernelStateKnown
                  ? <HelpCircle size={13} aria-hidden="true" />
                  : (p.loadedAgents ?? 0) > 0
                    ? <CheckCircle2 size={13} aria-hidden="true" />
                    : <AlertTriangle size={13} aria-hidden="true" />}
                <strong>{p.name}</strong>
                {p.mitre ? <span className="soc-tech-pill">{p.mitre}</span> : null}
                <span className="soc-detections-loaded">
                  {!p.kernelStateKnown
                    ? "load state unknown"
                    : p.loadedAgents
                      ? `loaded on ${p.loadedAgents} host${p.loadedAgents === 1 ? "" : "s"}`
                      : "NOT LOADED"}
                  {p.kernelMode ? ` · ${p.kernelMode}` : ""}
                </span>
              </div>
              <p>{p.description || "No description supplied by the policy."}</p>

              {/* Removal is offered only where there is something to remove.
                  A policy the kernel does not have, or one whose load state we
                  could not read, has no removal to dispatch — and offering the
                  button anyway would let an operator "remove" a policy and be
                  told it worked when nothing happened. */}
              {/* Which actions a card offers depends on what the KERNEL says
                  about it, and the two cases are disjoint:
                    loaded   → Edit (replace it) and Remove (take it off)
                    missing  → Restore (put the expected one back)
                  An earlier version nested Restore inside the loaded branch,
                  where its own `loadedAgents === 0` condition could never be
                  true, so the button existed and could not appear. Unknown
                  load state offers nothing: acting needs a diagnosis. */}
              {canPush && p.expected && p.yaml && p.kernelStateKnown && (p.loadedAgents ?? 0) === 0 ? (
                <div className="soc-detections-cardactions">
                  <button
                    type="button"
                    className="soc-action-button ok soc-detections-restore"
                    disabled={busy}
                    onClick={() => void restore(p)}
                  >
                    {busy ? "Restoring…" : "Restore this detection"}
                  </button>
                </div>
              ) : null}

              {canPush && p.kernelStateKnown && (p.loadedAgents ?? 0) > 0 ? (
                removing?.name === p.name ? (
                  <div className="soc-detections-remove">
                    {p.expected ? (
                      <strong className="soc-detections-warn">
                        {p.name} is a detection this platform ships{p.mitre ? ` for ${p.mitre}` : ""}. Removing it
                        leaves that technique uncovered until it is pushed back.
                      </strong>
                    ) : null}
                    <label>
                      <span>Reason — recorded with the signed command</span>
                      <input
                        value={removeReason}
                        onChange={(e) => setRemoveReason(e.target.value)}
                        placeholder="CAB-1234: too noisy on the billing estate"
                        autoFocus
                      />
                    </label>
                    <div className="soc-detections-chips">
                      <button
                        type="button"
                        className="soc-action-button bad"
                        disabled={busy || removeReason.trim().length < 3}
                        onClick={() => void remove(p)}
                      >
                        {busy ? "Applying…" : `Remove ${p.name} from ${scope === "fleet" ? "the fleet" : "this host"}`}
                      </button>
                      <button
                        type="button"
                        className="soc-ghost-button"
                        onClick={() => { setRemoving(null); setRemoveReason(""); }}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="soc-detections-cardactions">
                    {/* Editing is the commonest day-2 operation on a detection
                        — "this is too noisy, narrow the paths" — and it was the
                        one letter of CRUD the console did not have. Without it
                        an operator had to retype the exact metadata.name from
                        memory and paste a whole body, and the only affordance
                        that looked like editing (Copy) deliberately renames
                        away from the original. */}
                    {p.yaml ? (
                      <button
                        type="button"
                        className="soc-ghost-button soc-detections-remove-open"
                        onClick={() => {
                          setPicked(null);
                          setEditing(p.name);
                          setName(p.name);
                          setYaml(p.yaml || "");
                          setReason("");
                          setPushOpen(true);
                        }}
                      >
                        <Pencil size={12} aria-hidden="true" /> Edit
                      </button>
                    ) : null}
                    <button
                      type="button"
                      className="soc-ghost-button soc-detections-remove-open"
                      onClick={() => { setRemoving(p); setRemoveReason(""); }}
                    >
                      <Trash2 size={12} aria-hidden="true" /> {scope === "fleet" ? "Remove from fleet" : "Remove from this host"}
                    </button>
                  </div>
                )
              ) : null}
            </article>
          ))
        )}
      </div>

      <div className="soc-detections-push">
        {!canPush ? (
          <p className="soc-detections-note">
            This deployment has no Tetragon connection, so it cannot load or unload a detection. It can only
            report what it is told. Check the agent on Sensor Health.
          </p>
        ) : (
        <button
          type="button"
          className="soc-ghost-button"
          onClick={() => {
            setPushOpen((v) => !v);
            setEditing("");
            setPicked(null);
          }}
        >
          <Upload size={13} aria-hidden="true" /> {pushOpen ? "Cancel" : "Write or upload a detection"}
        </button>
        )}

        {pushOpen ? (
          <div className="soc-detections-form">
            {/* A blank textarea assumes the operator knows Tetragon's dialect.
                Nobody arrives knowing it, so the form starts by handing them
                something that already works — either a scaffold for the thing
                they are trying to do, or a copy of a policy running on this
                estate right now. Editing something that loads beats debugging
                something that does not. */}
            <div className="soc-detections-start">
              <span className="soc-stat-label">Start from a template</span>
              <div className="soc-detections-chips">
                {DETECTION_TEMPLATES.map((t) => (
                  <button
                    key={t.id}
                    type="button"
                    className={cx("soc-detections-chip", picked?.id === t.id && "is-on")}
                    title={t.intent}
                    onClick={() => { setPicked(t); setName(t.name); setYaml(t.yaml); }}
                  >
                    {t.title}
                  </button>
                ))}
              </div>

              {/* Copying a policy that is already loaded is the other honest
                  starting point: it is known-good on THIS kernel, which a
                  generic template cannot promise. Only offered where the
                  deployment actually serves the body. */}
              {policies.some((p) => p.yaml) ? (
                <>
                  <span className="soc-stat-label">
                    {policies.some((p) => p.yamlSource === "host")
                      ? "…or copy a policy running on this host"
                      : "…or copy a policy this platform ships"}
                  </span>
                  <div className="soc-detections-chips">
                    {policies.filter((p) => p.yaml).map((p) => (
                      <button
                        key={p.name}
                        type="button"
                        className="soc-detections-chip"
                        title={
                          p.yamlSource === "host"
                            ? `Load a copy of ${p.name} as it exists on this host — known to load on this kernel`
                            : `Load a copy of the source this platform ships for ${p.name}. An agent on an older build may carry an older revision.`
                        }
                        onClick={() => {
                          setPicked(null);
                          setName(`${p.name}-copy`);
                          setYaml(renameInCopy(p.yaml || "", p.name, `${p.name}-copy`));
                        }}
                      >
                        {p.name}
                      </button>
                    ))}
                  </div>
                </>
              ) : null}
            </div>

            {editing ? (
              <div className="soc-detections-guide soc-detections-editing">
                <strong>Editing {editing} — this REPLACES the detection that is running now.</strong>
                <span>
                  The name must stay <code>{editing}</code>: that is what identifies it in the kernel.
                  Change it and you create a second detection instead of updating this one.
                </span>
                <span className="soc-detections-caveat">
                  If the edited policy fails to load, the previous version is put back automatically and
                  you will be told so. Coverage is only lost if that restore also fails, which is reported
                  explicitly.
                </span>
              </div>
            ) : null}

            {picked ? (
              <div className="soc-detections-guide">
                <strong>{picked.intent}</strong>
                <span>This loads as-is. Push it unchanged to see it work, then edit:</span>
                <ol>{picked.editThese.map((e) => <li key={e}>{e}</li>)}</ol>
              </div>
            ) : null}

            <label>
              <span>Policy name — must match <code>metadata.name</code> in the YAML below</span>
              <input value={name} onChange={(e) => setName(e.target.value)} placeholder="sensitive-file-access" />
            </label>
            <label>
              <span>TracingPolicy YAML</span>
              <textarea value={yaml} onChange={(e) => setYaml(e.target.value)} spellCheck={false} rows={12} />
            </label>
            <label>
              <span>Reason — recorded with the signed command</span>
              <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="CAB-1234: widen credential paths" />
            </label>
            {checks.blocking.length || checks.warnings.length ? (
              <div className={cx("soc-detections-check", checks.blocking.length ? "bad" : "warn")}>
                <strong>{checks.blocking.length ? "Fix before dispatching" : "Worth checking"}</strong>
                <ul>
                  {checks.blocking.map((m) => <li key={m}>{m}</li>)}
                  {checks.warnings.map((m) => <li key={m}>{m}</li>)}
                </ul>
              </div>
            ) : null}
            <p className="soc-detections-note">
              Pushed in <strong>monitor</strong> mode. Enforce cannot be set from here: an enforcing policy
              kills with no audit row, no reversal and no kill-switch, so arming one stays a deliberate act
              on the host.
            </p>
            <button
              type="button"
              className="soc-action-button ok"
              disabled={busy || !name.trim() || !yaml.trim() || reason.trim().length < 3 || checks.blocking.length > 0}
              onClick={() => void push()}
            >
              {busy
                ? (scope === "fleet" ? "Dispatching…" : "Applying…")
                : editing
                  ? `Replace ${editing}`
                  : scope === "fleet"
                    ? "Dispatch signed command"
                    : "Apply to this host"}
            </button>
          </div>
        ) : null}

        {result ? (
          <div className={cx("soc-detections-result", result.ok ? "ok" : "bad")}>
            {result.error ? (
              <strong>{result.error}</strong>
            ) : scope === "host" ? (
              <>
                {/* "applied", not "acked": on this plane the change either
                    reached the kernel or it did not, and the applier said
                    which per policy. There is no fleet to be uncertain about. */}
                <strong>
                  {result.failed
                    ? `${result.applied ?? 0} applied, ${result.failed} failed on ${result.host || "this host"}`
                    : `Applied to ${result.host || "this host"}`}
                </strong>
                {result.outcome ? (
                  <ul className="soc-detections-outcome">
                    {Object.entries(result.outcome).map(([n, v]) => (
                      <li key={n}><code>{n}</code> — {v}</li>
                    ))}
                  </ul>
                ) : null}
                {/* Durability is the one thing this plane genuinely cannot be
                    sure of, so it is never folded into the success line. */}
                {result.durability_note ? (
                  <span className="soc-detections-warn">{result.durability_note}</span>
                ) : null}
                {result.ok && result.durable !== false ? (
                  <span className="soc-detections-caveat">
                    Live in the kernel now and written to Tetragon's load directory, so it survives a restart.
                    Anything it matches appears on the timeline tagged with its name.
                  </span>
                ) : null}
              </>
            ) : (
              <>
                {/* "acked by", never "updated". */}
                <strong>Acked by {result.acked ?? 0} of {result.dispatched_to ?? 0} agent{result.dispatched_to === 1 ? "" : "s"}</strong>
                {result.detail ? <span>{result.detail}</span> : null}
                {result.convergence_note ? <span className="soc-detections-caveat">{result.convergence_note}</span> : null}
                {/* An ack is not the end of the task, and an operator who has
                    never done this has no way to know what the end looks like.
                    Naming the next observable — the heartbeat, then the events
                    — is the difference between a dispatched command and a
                    detection someone can confirm is working. */}
                {(result.acked ?? 0) > 0 ? (
                  <span className="soc-detections-caveat">
                    Next: agents report their kernel policy set on each heartbeat (about every 30s). Reopen
                    this panel then — the policy should read <strong>loaded on {result.acked} host
                    {result.acked === 1 ? "" : "s"}</strong>. Anything it matches appears on the timeline
                    tagged with its name.
                  </span>
                ) : null}
              </>
            )}
          </div>
        ) : null}
      </div>
    </div>
  );
}

/**
 * Rename a policy in a copy of its own YAML.
 *
 * A copy has to be renamed before it is pushed: Tetragon keys a TracingPolicy
 * on metadata.name, so pushing an edited copy under the original's name
 * REPLACES the running original rather than adding to it. Someone
 * experimenting with a variant of a live detection would silently take the
 * live one away, which is the opposite of what "copy" means.
 *
 * Matching is anchored on the old name's exact value rather than on `name:`,
 * because `name:` also appears inside the options block (`name: "policy-mode"`)
 * and a looser match would rewrite that too.
 */
export function renameInCopy(yaml: string, from: string, to: string): string {
  const literal = from.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return yaml.replace(new RegExp(`(^\\s*name:\\s*)"?${literal}"?\\s*$`, "m"), `$1"${to}"`);
}

/**
 * Check a policy before it is dispatched, not after.
 *
 * Every problem listed here fails on the agent, minutes later, as a Tetragon
 * error relayed through an ack — by which point the operator has lost the
 * thread between what they typed and what came back. They are all decidable
 * from the text, so they are decided here.
 *
 * The name mismatch is the one that matters most and reads as least important:
 * the console sends `name` as the identifier while Tetragon keys on
 * metadata.name, so a mismatch does not error at all. It applies a policy under
 * a name the operator never chose, cannot find in the list, and cannot remove.
 *
 * Deliberately NOT a YAML validator. A real parse would catch more, and the
 * cost of being wrong is asymmetric: a validator that rejects a policy Tetragon
 * would have accepted teaches operators to distrust the form and paste around
 * it. Everything below is a certainty, so `blocking` can safely gate the
 * button; anything less certain belongs in `warnings`, which never gates.
 */
export function preflight(name: string, yaml: string): { blocking: string[]; warnings: string[] } {
  const blocking: string[] = [];
  const warnings: string[] = [];
  const body = yaml.trim();
  if (!body) return { blocking, warnings };

  if (!/apiVersion:\s*cilium\.io\/v1alpha1/.test(body)) {
    blocking.push("Missing `apiVersion: cilium.io/v1alpha1` — Tetragon will not recognise this document.");
  }

  if (!/kind:\s*TracingPolicy/.test(body)) {
    blocking.push("Missing `kind: TracingPolicy`.");
  }

  const declared = metadataName(body);
  if (!declared) {
    blocking.push("No `metadata.name` — Tetragon identifies a policy by that field.");
  } else if (name.trim() && declared !== name.trim()) {
    blocking.push(
      `The name field says "${name.trim()}" but metadata.name says "${declared}". ` +
      "Tetragon keys on metadata.name, so these must match or the policy loads under a name you cannot find later."
    );
  }

  if (!/kprobes:|tracepoints:|uprobes:|lsm:/.test(body)) {
    blocking.push("No `kprobes:`, `tracepoints:`, `uprobes:` or `lsm:` block — this policy would hook nothing.");
  }
  if (!/matchActions:/.test(body)) {
    warnings.push("No `matchActions:` — without an action such as `Post`, matches are counted but produce no events.");
  }

  // Enforcement is refused server-side; saying so here costs a round trip less
  // and explains the refusal at the moment the operator typed the cause.
  for (const action of ["Sigkill", "Override", "Signal"]) {
    if (new RegExp(`action:\\s*${action}`).test(body)) {
      blocking.push(
        `\`${action}\` is an enforcing action, which cannot be pushed from the console: ` +
        "it kills with no audit row, no reversal and no kill-switch. Use the containment ladder instead."
      );
    }
  }
  if (/value:\s*"?enforce"?/.test(body)) {
    blocking.push("`policy-mode: enforce` cannot be pushed from the console. Leave it as monitor.");
  }

  return { blocking, warnings };
}

/**
 * Read metadata.name out of a TracingPolicy without a YAML parser.
 *
 * `name:` occurs several times in a policy — under options as
 * `name: "policy-mode"`, and inside selectors — and only the one at metadata's
 * indentation counts. Mirrors internal/policyassets.metadataName on the server
 * so the console and the control plane never disagree about what a policy is
 * called.
 */
function metadataName(body: string): string {
  let inMetadata = false;
  for (const raw of body.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (!line.trim() || line.trim().startsWith("#")) continue;
    if (!/^[ \t]/.test(line)) {
      // A new top-level key ends the block, so `name:` under spec is never
      // mistaken for the policy's own name.
      inMetadata = line.startsWith("metadata:");
      continue;
    }
    if (!inMetadata) continue;
    const field = line.trim();
    if (!field.startsWith("name:")) continue;
    const value = field.slice("name:".length).trim().replace(/^["']|["']$/g, "");
    if (value) return value;
  }
  return "";
}
