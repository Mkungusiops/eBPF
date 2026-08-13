// Rich SOC panel bodies. The base SocRoute keeps the live-data plumbing; these
// components render the enterprise-grade surfaces (MITRE matrix, honeypot grid,
// kprobe board, fleet console, notification center, risk gauge) that the modal
// shells host. Each body is data-driven off the same snapshot the route already
// fetches, so nothing here introduces new network calls beyond explicit probes.
import { useCallback, useEffect, useMemo, useState, type Dispatch, type SetStateAction } from "react";
import { Activity, AlertTriangle, Bell, FileCode, FileDown, Globe, Plus, RadioTower, Search, Shield, ShieldCheck, Target, Trash2, Volume2 } from "lucide-react";
import { cx, EmptyState, Sparkline } from "./components";
import { fetchPolicyStats, probeFleetHosts } from "./api";
import type {
  Severity,
  SocAlert,
  SocEvent,
  SocHoneypot,
  SocPolicy,
  SocPolicyStat,
  SocWhoami
} from "./types";

/* ------------------------------------------------------------------ helpers */

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function useLocalState<T>(key: string, fallback: T): [T, (v: T | ((p: T) => T)) => void] {
  const [state, setState] = useState<T>(() => {
    if (typeof window === "undefined") return fallback;
    try {
      const raw = window.localStorage.getItem(key);
      return raw == null ? fallback : (JSON.parse(raw) as T);
    } catch {
      return fallback;
    }
  });
  const set = useCallback(
    (v: T | ((p: T) => T)) => {
      setState((prev) => {
        const next = typeof v === "function" ? (v as (p: T) => T)(prev) : v;
        try {
          window.localStorage.setItem(key, JSON.stringify(next));
        } catch {
          /* operator-convenience persistence; ignore quota/serialise failures */
        }
        return next;
      });
    },
    [key]
  );
  return [state, set];
}

function clock(ts?: string): string {
  if (!ts) return "—";
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function relTime(ts: string | undefined, now: number): string {
  if (!ts) return "—";
  const date = new Date(ts).getTime();
  if (Number.isNaN(date)) return "—";
  const secs = Math.max(0, Math.round((now - date) / 1000));
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

function formatBytes(n?: number): string {
  if (n === undefined || !Number.isFinite(n)) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function fmtNum(n: number): string {
  return n.toLocaleString();
}

function formatTime(iso?: string): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  return new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/* ----------------------------------------------------------- shared widgets */

export function StatGrid({ children }: { children: React.ReactNode }) {
  return <div className="soc-stat-grid">{children}</div>;
}

export function StatCard({
  label,
  value,
  sub,
  tone
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  tone?: "accent" | "good" | "warn" | "danger";
}) {
  return (
    <div className={cx("soc-stat-card", tone && `tone-${tone}`)}>
      <div className="soc-stat-label">{label}</div>
      <div className="soc-stat-value">{value}</div>
      {sub !== undefined ? <div className="soc-stat-sub">{sub}</div> : null}
    </div>
  );
}

interface ChipOption<T extends string> {
  key: T;
  label: string;
  count?: number;
  tone?: "danger" | "warn" | "good" | "accent" | "info";
}

export function FilterChips<T extends string>({
  options,
  value,
  onChange
}: {
  options: Array<ChipOption<T>>;
  value: T;
  onChange: (value: T) => void;
}) {
  return (
    <div className="soc-chip-row" role="tablist" aria-label="filters">
      {options.map((opt) => (
        <button
          key={opt.key}
          type="button"
          role="tab"
          aria-selected={value === opt.key}
          className={cx("soc-chip", value === opt.key && "is-active", opt.tone && `tone-${opt.tone}`)}
          onClick={() => onChange(opt.key)}
        >
          {opt.label}
          {opt.count !== undefined ? <span className="soc-chip-count">{opt.count}</span> : null}
        </button>
      ))}
    </div>
  );
}

export function SearchField({
  value,
  onChange,
  placeholder
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
}) {
  return (
    <label className="soc-search-field">
      <Search size={15} aria-hidden="true" />
      <input
        type="search"
        value={value}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
      />
    </label>
  );
}

function Meter({ value, max, tone }: { value: number; max: number; tone?: string }) {
  const pct = Math.max(2, Math.min(100, (value / Math.max(1, max)) * 100));
  return (
    <div className="soc-meter">
      <i className={tone ? `tone-${tone}` : undefined} style={{ width: `${pct}%` }} />
    </div>
  );
}

/* --------------------------------------------------------- MITRE ATT&CK data */

interface MitreTechnique {
  id: string;
  name: string;
}
interface MitreTactic {
  id: string;
  name: string;
  techniques: MitreTechnique[];
}

// Curated ATT&CK slice matching the host-runtime telemetry this engine emits.
// Cells light up when an observed technique id (from alerts/policies) matches.
export const MITRE_MATRIX: MitreTactic[] = [
  {
    id: "TA0001",
    name: "Initial Access",
    techniques: [
      { id: "T1190", name: "Exploit Public App" },
      { id: "T1133", name: "External Remote Svc" },
      { id: "T1078", name: "Valid Accounts" }
    ]
  },
  {
    id: "TA0002",
    name: "Execution",
    techniques: [
      { id: "T1059", name: "Command/Scripting Interpreter" },
      { id: "T1106", name: "Native API" },
      { id: "T1204", name: "User Execution" }
    ]
  },
  {
    id: "TA0003",
    name: "Persistence",
    techniques: [
      { id: "T1543", name: "Create/Modify System Process" },
      { id: "T1547", name: "Boot/Logon Autostart" },
      { id: "T1136", name: "Create Account" }
    ]
  },
  {
    id: "TA0004",
    name: "Privilege Escalation",
    techniques: [
      { id: "T1548", name: "Abuse Elevation Control" },
      { id: "T1068", name: "Exploit for PrivEsc" },
      { id: "T1055", name: "Process Injection" }
    ]
  },
  {
    id: "TA0005",
    name: "Defense Evasion",
    techniques: [
      { id: "T1027", name: "Obfuscated Files" },
      { id: "T1070", name: "Indicator Removal" },
      { id: "T1562", name: "Impair Defenses" }
    ]
  },
  {
    id: "TA0006",
    name: "Credential Access",
    techniques: [
      { id: "T1003", name: "OS Credential Dumping" },
      { id: "T1555", name: "Creds from Stores" },
      { id: "T1110", name: "Brute Force" }
    ]
  },
  {
    id: "TA0007",
    name: "Discovery",
    techniques: [
      { id: "T1057", name: "Process Discovery" },
      { id: "T1083", name: "File/Dir Discovery" },
      { id: "T1018", name: "Remote System Discovery" }
    ]
  },
  {
    id: "TA0008",
    name: "Lateral Movement",
    techniques: [
      { id: "T1021", name: "Remote Services" },
      { id: "T1570", name: "Lateral Tool Transfer" }
    ]
  },
  {
    id: "TA0011",
    name: "Command & Control",
    techniques: [
      { id: "T1071", name: "Application Layer Protocol" },
      { id: "T1095", name: "Non-App Layer Protocol" }
    ]
  }
];

const ALL_TECHNIQUE_IDS = new Set(MITRE_MATRIX.flatMap((t) => t.techniques.map((tech) => tech.id)));

function techniqueId(raw?: string): string | undefined {
  if (!raw) return undefined;
  const match = /T\d{4}/.exec(raw);
  return match ? match[0] : undefined;
}

export function techniqueName(raw?: string): string | undefined {
  const id = techniqueId(raw);
  if (!id) return undefined;
  for (const tactic of MITRE_MATRIX) {
    const hit = tactic.techniques.find((t) => t.id === id);
    if (hit) return hit.name;
  }
  return undefined;
}

// Known detection-policy names → the ATT&CK technique they cover. The engine
// does not (yet) stamp `mitre` onto every policy or alert — the real agents ship
// raw policy names — so the console derives the mapping from the stable policy
// names it already knows. This is what lets the Navigator show real coverage
// instead of an all-gaps matrix. Honest: each of these policies genuinely
// detects its mapped technique.
const POLICY_MITRE: Record<string, string> = {
  "sensitive-file-access": "T1003", // reads /etc/shadow, /etc/passwd
  "override-credential-read": "T1555", // credential store access
  "privilege-escalation": "T1548", // sudo / setuid abuse
  "reverse-shell": "T1059", // shell -c / interpreter
  "sever-pipe-to-shell": "T1059",
  "shell-egress-throttle": "T1071", // shell talking out (C2)
  "network-tools-tarpit": "T1071", // nc/socat/ncat egress
  "outbound-connections": "T1071", // tcp_connect from shells/LOLBins
  "container-escape": "T1068", // exploit for priv-esc / escape
  "agent-loop-cap": "T1059"
};

// Keyword fallback when neither a mitre tag nor a known policy name is present —
// reads the technique straight off what the alert describes.
function techniqueFromText(text?: string): string | undefined {
  if (!text) return undefined;
  const t = text.toLowerCase();
  if (/\/etc\/shadow|\/etc\/passwd|credential|\.ssh|password/.test(t)) return "T1003";
  if (/sudo|sudoers|privilege|escalat|setuid|elevation/.test(t)) return "T1548";
  if (/reverse shell|\/bin\/sh -c|interpreter|scripting/.test(t)) return "T1059";
  if (/outbound|connection|\bnc\b|ncat|socat|\bcurl\b|\bwget\b|c2|beacon/.test(t)) return "T1071";
  if (/container|escape|exploit/.test(t)) return "T1068";
  return undefined;
}

export function techniqueForPolicy(policy: SocPolicy): string | undefined {
  return techniqueId(policy.mitre) || POLICY_MITRE[policy.name];
}

export function techniqueForAlert(alert: SocAlert, techByPolicy: Map<string, string>): string | undefined {
  return (
    techniqueId(alert.mitreId) ||
    (alert.policyName ? techByPolicy.get(alert.policyName) ?? POLICY_MITRE[alert.policyName] : undefined) ||
    techniqueFromText([alert.title, alert.description, alert.args].filter(Boolean).join(" "))
  );
}

/* ------------------------------------------------------------ MITRE Navigator */

// The coverage model, computed once and shared by the Navigator UI and the PDF
// so the two never disagree. Three distinct states per technique — the honest
// picture the flat "observed only" view was missing:
//   observed — a detection actually fired (count > 0)
//   covered  — a policy maps to it, but it has not fired (capability, dormant)
//   gap      — NO policy maps to it: a blind spot an attacker could use unseen
export type MitreCoverageModel = ReturnType<typeof buildMitreCoverageModel>;

export function buildMitreCoverageModel(
  mitreRows: Array<{ label: string; value: number; meta?: string; id?: string }>,
  alerts: SocAlert[],
  policies: SocPolicy[]
) {
  // technique id -> policies that provide detection coverage for it (using the
  // policy's mitre tag when present, else the known policy-name mapping)
  const policiesByTech = new Map<string, SocPolicy[]>();
  const techByPolicy = new Map<string, string>();
  for (const policy of policies) {
    const id = techniqueForPolicy(policy);
    if (!id) continue;
    techByPolicy.set(policy.name, id);
    const list = policiesByTech.get(id) ?? [];
    list.push(policy);
    policiesByTech.set(id, list);
  }

  // technique id -> the alerts that fired it, and the hit count derived from
  // them. Alerts are the ground truth for "observed"; mitreRows only add hits
  // for techniques a policy tagged directly.
  const alertsByTech = new Map<string, SocAlert[]>();
  const observed = new Map<string, number>();
  for (const alert of alerts) {
    const id = techniqueForAlert(alert, techByPolicy);
    if (!id) continue;
    const list = alertsByTech.get(id) ?? [];
    list.push(alert);
    alertsByTech.set(id, list);
    observed.set(id, (observed.get(id) || 0) + 1);
  }
  for (const row of mitreRows) {
    const id = techniqueId(row.label) || techniqueId(row.id);
    if (id && !observed.has(id)) observed.set(id, row.value);
  }

  const total = ALL_TECHNIQUE_IDS.size;
  const covered = [...ALL_TECHNIQUE_IDS].filter((id) => policiesByTech.has(id));
  const observedIds = [...ALL_TECHNIQUE_IDS].filter((id) => (observed.get(id) || 0) > 0);
  const gaps = [...ALL_TECHNIQUE_IDS].filter((id) => !policiesByTech.has(id));
  const hitTotal = observedIds.reduce((sum, id) => sum + (observed.get(id) || 0), 0);

  const stateOf = (id: string): "observed" | "covered" | "gap" =>
    (observed.get(id) || 0) > 0 ? "observed" : policiesByTech.has(id) ? "covered" : "gap";

  return {
    policiesByTech,
    alertsByTech,
    observed,
    stateOf,
    total,
    coveredCount: covered.length,
    observedCount: observedIds.length,
    gapCount: gaps.length,
    gapIds: gaps,
    hitTotal,
    coveragePct: Math.round((covered.length / total) * 100),
    /**
     * Whether coverage can be COMPUTED here at all.
     *
     * Coverage is derived from policies carrying an ATT&CK mapping. A fleet may
     * run policies this build has never heard of — the control plane maps by
     * name lookup and returns empty strings rather than guessing — and then
     * nothing maps, `covered` is empty, and the percentage comes out 0.
     *
     * "0% coverage" is a definitive claim that the estate detects nothing. The
     * truth is that coverage is unmeasurable here. Reporting the former, in a
     * document handed to a customer, is the difference between "we cannot tell
     * you" and "you are completely exposed".
     */
    mappingAvailable: policies.length === 0 || policiesByTech.size > 0
  };
}

type MitreFilter = "all" | "observed" | "covered" | "gaps";

export function MitreNavigatorBody({
  mitreRows,
  alerts,
  policies,
  onExport
}: {
  mitreRows: Array<{ label: string; value: number; meta?: string; id?: string }>;
  alerts: SocAlert[];
  policies: SocPolicy[];
  onExport: () => void;
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const [filter, setFilter] = useState<MitreFilter>("all");

  const model = useMemo(() => buildMitreCoverageModel(mitreRows, alerts, policies), [mitreRows, alerts, policies]);

  const matches = (id: string) => {
    if (filter === "all") return true;
    const s = model.stateOf(id);
    if (filter === "observed") return s === "observed";
    if (filter === "covered") return s === "covered" || s === "observed";
    return s === "gap";
  };

  const detail = selected
    ? {
        id: selected,
        name: MITRE_MATRIX.flatMap((t) => t.techniques).find((t) => t.id === selected)?.name ?? "",
        tactic: MITRE_MATRIX.find((t) => t.techniques.some((x) => x.id === selected))?.name ?? "",
        state: model.stateOf(selected),
        count: model.observed.get(selected) || 0,
        policies: model.policiesByTech.get(selected) ?? [],
        firing: (model.alertsByTech.get(selected) ?? []).slice(0, 8)
      }
    : null;

  return (
    <div className={cx("soc-mitre", detail && "has-detail")}>
      <div className="soc-mitre-head">
        <div className="soc-mitre-stats">
          <button
            type="button"
            className={cx("soc-mitre-stat", filter === "covered" && "is-active")}
            onClick={() => setFilter(filter === "covered" ? "all" : "covered")}
          >
            <span className="soc-stat-label"><ShieldCheck size={12} aria-hidden="true" /> Coverage</span>
            <strong>{model.mappingAvailable ? `${model.coveragePct}%` : "n/a"}</strong>
            <em>
              {model.mappingAvailable
                ? `${model.coveredCount} / ${model.total} techniques`
                : "no ATT&CK mapping published"}
            </em>
          </button>
          <button
            type="button"
            className={cx("soc-mitre-stat tone-observed", filter === "observed" && "is-active")}
            onClick={() => setFilter(filter === "observed" ? "all" : "observed")}
          >
            <span className="soc-stat-label"><Target size={12} aria-hidden="true" /> Observed</span>
            <strong>{model.observedCount}</strong>
            <em>{fmtNum(model.hitTotal)} technique hits</em>
          </button>
          <button
            type="button"
            className={cx("soc-mitre-stat tone-gap", filter === "gaps" && "is-active")}
            onClick={() => setFilter(filter === "gaps" ? "all" : "gaps")}
          >
            <span className="soc-stat-label"><AlertTriangle size={12} aria-hidden="true" /> Blind spots</span>
            <strong>{model.gapCount}</strong>
            <em>no detection policy</em>
          </button>
        </div>
        <button type="button" className="soc-ghost-button" onClick={onExport}>
          <FileDown size={14} aria-hidden="true" /> Export coverage PDF
        </button>
      </div>

      <div className="soc-mitre-main">
        <div className="soc-mitre-grid scrollbar">
          {MITRE_MATRIX.map((tactic) => {
            const covered = tactic.techniques.filter((t) => model.stateOf(t.id) !== "gap").length;
            return (
              <div key={tactic.id} className="soc-mitre-col">
                <header>
                  <span className="soc-mitre-tactic">{tactic.name}</span>
                  <span className="soc-mitre-fraction">{covered}/{tactic.techniques.length}</span>
                  <i style={{ width: `${(covered / tactic.techniques.length) * 100}%` }} />
                </header>
                <div className="soc-mitre-cells">
                  {tactic.techniques.map((tech) => {
                    const state = model.stateOf(tech.id);
                    const count = model.observed.get(tech.id) || 0;
                    const isSelected = selected === tech.id;
                    const dimmed = !matches(tech.id);
                    return (
                      <button
                        key={tech.id}
                        type="button"
                        className={cx(
                          "soc-mitre-cell",
                          `is-${state}`,
                          isSelected && "is-selected",
                          dimmed && "is-dimmed"
                        )}
                        onClick={() => setSelected(isSelected ? null : tech.id)}
                        title={`${tech.id} ${tech.name} · ${state}${count ? ` · ${count} hits` : ""}`}
                      >
                        <span className="soc-mitre-id">
                          {tech.id}
                          {count ? <em>×{count}</em> : null}
                        </span>
                        <span className="soc-mitre-name">{tech.name}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>

        {detail ? (
          <aside className="soc-mitre-detail" data-panel="mitre-technique-detail">
            <header>
              <div>
                <span className="soc-mitre-detail-tactic">{detail.tactic}</span>
                <h3>{detail.id} · {detail.name}</h3>
              </div>
              <button type="button" className="soc-close-button" onClick={() => setSelected(null)} aria-label="Close">×</button>
            </header>

            <span className={cx("soc-mitre-state-badge", `is-${detail.state}`)}>
              {detail.state === "observed" ? <><Target size={12} /> Observed · {detail.count} hits</>
                : detail.state === "covered" ? <><Shield size={12} /> Covered · dormant</>
                : <><AlertTriangle size={12} /> Blind spot · no detection</>}
            </span>

            <section>
              <span className="soc-stat-label">Detection policies</span>
              {detail.policies.length ? (
                detail.policies.map((p) => (
                  <div key={p.name} className="soc-mitre-policy">
                    <strong>{p.name}</strong>
                    {p.description ? <span>{p.description}</span> : null}
                  </div>
                ))
              ) : (
                <p className="soc-mitre-gap-note">
                  No policy maps to this technique — an adversary using it would go undetected.
                  Author a TracingPolicy tagged <code>{detail.id}</code> to close the gap.
                </p>
              )}
            </section>

            {detail.firing.length ? (
              <section>
                <span className="soc-stat-label">Recent detections ({detail.firing.length})</span>
                {detail.firing.map((a) => (
                  <div key={a.id} className={cx("soc-mitre-firing", `sev-${a.severity}`)}>
                    <span className="soc-mitre-firing-title">{a.title}</span>
                    <span className="soc-mitre-firing-meta">score {a.score} · {formatTime(a.timestamp)}</span>
                  </div>
                ))}
              </section>
            ) : null}
          </aside>
        ) : null}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------ Policy viewer */

export function PoliciesBody({
  policies,
  alerts,
  events,
  policyStats,
  now
}: {
  policies: SocPolicy[];
  alerts: SocAlert[];
  events: SocEvent[];
  policyStats: SocPolicyStat[];
  now: number;
}) {
  const [query, setQuery] = useState("");
  const [openYaml, setOpenYaml] = useState<string | null>(null);

  const enriched = useMemo(() => {
    const postsByPolicy = new Map<string, SocPolicyStat>();
    for (const stat of policyStats) postsByPolicy.set(stat.name, stat);
    const lastByPolicy = new Map<string, string>();
    const countByPolicy = new Map<string, number>();
    for (const alert of alerts) {
      if (!alert.policyName) continue;
      countByPolicy.set(alert.policyName, (countByPolicy.get(alert.policyName) || 0) + 1);
      const prev = lastByPolicy.get(alert.policyName);
      if (!prev || alert.timestamp > prev) lastByPolicy.set(alert.policyName, alert.timestamp);
    }
    for (const event of events) {
      if (!event.policyName) continue;
      const prev = lastByPolicy.get(event.policyName);
      if (!prev || event.timestamp > prev) lastByPolicy.set(event.policyName, event.timestamp);
    }
    return policies.map((policy) => ({
      policy,
      stat: postsByPolicy.get(policy.name),
      alerts: countByPolicy.get(policy.name) || 0,
      last: lastByPolicy.get(policy.name)
    }));
  }, [policies, policyStats, alerts, events]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return enriched;
    return enriched.filter(
      ({ policy }) =>
        policy.name.toLowerCase().includes(q) ||
        (policy.mitre || "").toLowerCase().includes(q) ||
        (policy.description || "").toLowerCase().includes(q)
    );
  }, [enriched, query]);

  return (
    <div className="soc-policies">
      <div className="soc-toolbar">
        <SearchField value={query} onChange={setQuery} placeholder="Search policies, kprobes, MITRE IDs…" />
        <span className="soc-toolbar-meta">
          {filtered.length} policy {filtered.length === 1 ? "file" : "files"}
        </span>
      </div>
      {filtered.length ? (
        <div className="soc-policy-list">
          {filtered.map(({ policy, stat, alerts: alertCount, last }) => {
            const tech = techniqueId(policy.mitre);
            return (
              <article key={policy.name} className="soc-policy-card">
                <div className="soc-policy-main">
                  <div className="soc-policy-title">
                    <strong>{policy.name}</strong>
                    <span className={cx("soc-policy-mode", stat?.status ? "is-on" : "")}>
                      {stat?.status || "loaded"}
                    </span>
                    {policy.mitre ? (
                      <span className="soc-tech-pill">
                        <b>{tech}</b> {policy.mitre.replace(tech || "", "").trim() || techniqueName(policy.mitre)}
                      </span>
                    ) : null}
                  </div>
                  <p>{policy.description || "No description supplied by the policy."}</p>
                  <div className="soc-policy-meta">
                    <span>
                      kernel posts <b>{stat ? fmtNum(stat.posts) : "—"}</b>
                    </span>
                    <span>
                      alerts <b className={alertCount ? "is-hot" : ""}>{fmtNum(alertCount)}</b>
                    </span>
                    <span>
                      last triggered <b>{last ? relTime(last, now) : "—"}</b>
                    </span>
                  </div>
                </div>
                <div className="soc-policy-actions">
                  <button
                    type="button"
                    className="soc-ghost-button"
                    onClick={() => setOpenYaml(openYaml === policy.name ? null : policy.name)}
                    disabled={!policy.yaml}
                  >
                    <FileCode size={13} aria-hidden="true" /> YAML
                  </button>
                </div>
                {openYaml === policy.name && policy.yaml ? (
                  <pre className="soc-policy-yaml scrollbar">{policy.yaml}</pre>
                ) : null}
              </article>
            );
          })}
        </div>
      ) : (
        <EmptyState
          title={query ? "No policies match the search" : "No policies returned"}
          detail="GET /api/policies is wired read-only."
        />
      )}
    </div>
  );
}

/* --------------------------------------------------------------- Honeypots */

type HoneypotFilter = "all" | "triggered" | "recent" | "dormant" | "untouched";
type HoneypotSort = "hits" | "last" | "path" | "size";

function commonPrefix(paths: string[]): string {
  if (!paths.length) return "";
  let prefix = paths[0];
  for (const path of paths.slice(1)) {
    while (!path.startsWith(prefix) && prefix) prefix = prefix.slice(0, -1);
  }
  const cut = prefix.lastIndexOf("/");
  return cut > 0 ? prefix.slice(0, cut + 1) : prefix;
}

export function HoneypotsBody({ honeypots, now }: { honeypots: SocHoneypot[]; now: number }) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<HoneypotFilter>("all");
  const [sort, setSort] = useState<HoneypotSort>("hits");

  const prefix = useMemo(() => commonPrefix(honeypots.map((h) => h.path)), [honeypots]);

  const isRecent = (h: SocHoneypot) =>
    Boolean(h.lastSeen) && now - new Date(h.lastSeen as string).getTime() < 60_000;

  const stats = useMemo(() => {
    const totalHits = honeypots.reduce((sum, h) => sum + h.hits, 0);
    const accessed = honeypots.filter((h) => h.hits > 0).length;
    const hot = honeypots.filter(isRecent).length;
    return { totalHits, accessed, hot };
  }, [honeypots, now]);

  const counts: Record<HoneypotFilter, number> = {
    all: honeypots.length,
    triggered: honeypots.filter((h) => h.hits > 0).length,
    recent: honeypots.filter(isRecent).length,
    dormant: honeypots.filter((h) => h.hits > 0 && !isRecent(h)).length,
    untouched: honeypots.filter((h) => h.hits === 0).length
  };

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    let list = honeypots.filter((h) => {
      if (q && !h.path.toLowerCase().includes(q) && !(h.description || "").toLowerCase().includes(q)) return false;
      if (filter === "triggered") return h.hits > 0;
      if (filter === "recent") return isRecent(h);
      if (filter === "dormant") return h.hits > 0 && !isRecent(h);
      if (filter === "untouched") return h.hits === 0;
      return true;
    });
    list = [...list].sort((a, b) => {
      if (sort === "hits") return b.hits - a.hits;
      if (sort === "size") return (b.bytes || 0) - (a.bytes || 0);
      if (sort === "path") return a.path.localeCompare(b.path);
      return (b.lastSeen || "").localeCompare(a.lastSeen || "");
    });
    return list;
  }, [honeypots, query, filter, sort, now]);

  const maxHits = Math.max(1, ...honeypots.map((h) => h.hits));

  return (
    <div className="soc-honeypots">
      <StatGrid>
        <StatCard label="Decoys" value={honeypots.length} sub={`${stats.accessed} accessed`} />
        <StatCard label="Total hits" value={fmtNum(stats.totalHits)} sub="alerts triggered" tone={stats.totalHits ? "danger" : undefined} />
        <StatCard label="Hot now" value={stats.hot} sub="triggered <1min" tone={stats.hot ? "warn" : undefined} />
        <StatCard label="Accessed" value={stats.accessed} sub="decoys touched" />
      </StatGrid>

      {prefix ? (
        <p className="soc-honeypot-prefix">
          Prefix <code>{prefix}</code> — any access fires a <span className="soc-honey">🍯</span> alert.
        </p>
      ) : null}

      <div className="soc-toolbar">
        <SearchField value={query} onChange={setQuery} placeholder="filter by path or description…" />
        <FilterChips
          value={filter}
          onChange={setFilter}
          options={[
            { key: "all", label: "ALL", count: counts.all },
            { key: "triggered", label: "🔥 TRIGGERED", count: counts.triggered, tone: "danger" },
            { key: "recent", label: "⚡ RECENT", count: counts.recent, tone: "warn" },
            { key: "dormant", label: "DORMANT", count: counts.dormant },
            { key: "untouched", label: "UNTOUCHED", count: counts.untouched }
          ]}
        />
      </div>

      <div className="soc-sort-row">
        <span>sort</span>
        {(["hits", "last", "path", "size"] as HoneypotSort[]).map((key) => (
          <button
            key={key}
            type="button"
            className={cx("soc-sort", sort === key && "is-active")}
            onClick={() => setSort(key)}
          >
            {key}
          </button>
        ))}
      </div>

      {rows.length ? (
        <div className="soc-honeypot-list">
          {rows.map((h) => {
            const triggered = h.hits > 0;
            return (
              <article key={h.path} className={cx("soc-honeypot-row", triggered && "is-triggered")}>
                <div className="soc-honeypot-id">
                  <span className="soc-honey">🍯</span>
                  <div>
                    <strong>{h.path}</strong>
                    <span>{h.description || "decoy file"} · {formatBytes(h.bytes)}</span>
                  </div>
                </div>
                <Meter value={h.hits} max={maxHits} tone={triggered ? "danger" : undefined} />
                <div className="soc-honeypot-stat">
                  <span>
                    hits <b className={triggered ? "is-hot" : ""}>{h.hits}</b>
                  </span>
                  <span>last {h.lastSeen ? relTime(h.lastSeen, now) : "—"}</span>
                </div>
                <span className={cx("soc-honeypot-badge", triggered ? "is-triggered" : "is-untouched")}>
                  {triggered ? "TRIGGERED" : "UNTOUCHED"}
                </span>
              </article>
            );
          })}
        </div>
      ) : (
        <EmptyState
          title="No honeypots match the current filter"
          detail="Decoy files are seeded under the honeypots directory and fire critical alerts on access."
        />
      )}
    </div>
  );
}

/* -------------------------------------------------------- Kprobe performance */

type KprobeBand = "all" | "hot" | "warm" | "calm" | "idle" | "over";
type KprobeSort = "rate" | "posts" | "name" | "mem";

// Per-probe rate history, module-level so it survives the modal opening and
// closing — the sparklines rebuild from what the console has already sampled
// rather than resetting to a flat line each time you reopen the panel.
// Neither the engine nor the control plane reports a per-policy RATE — only the
// cumulative `posts` counter — so the rate is derived here from the delta of
// that counter between snapshot samples. Each sample is {t, posts}; the rate is
// (Δposts / Δtime) and the sparkline is the Δposts series. Module-level so it
// survives the modal opening and closing.
interface KprobeSample { t: number; posts: number }
const KPROBE_HISTORY = new Map<string, KprobeSample[]>();
const KPROBE_HISTORY_LEN = 30;

// posts delta between the two most recent samples, as a per-minute rate.
function kprobeRateFromHistory(name: string): number {
  const h = KPROBE_HISTORY.get(name);
  if (!h || h.length < 2) return 0;
  const a = h[h.length - 2];
  const b = h[h.length - 1];
  const dt = b.t - a.t;
  // Ignore a stale pair spanning a long gap (e.g. reopening after minutes) — the
  // next poll produces a tight pair and a real rate.
  if (dt <= 0 || dt > 60_000) return 0;
  return Math.max(0, ((b.posts - a.posts) / dt) * 60_000);
}

// The per-interval posts deltas — the shape the sparkline draws.
function kprobeDeltaSeries(name: string): number[] {
  const h = KPROBE_HISTORY.get(name) ?? [];
  const out: number[] = [];
  for (let i = 1; i < h.length; i++) out.push(Math.max(0, h[i].posts - h[i - 1].posts));
  return out;
}

export function KprobeBody({ policyStats: propStats }: { policyStats: SocPolicyStat[] }) {
  const [threshold, setThreshold] = useLocalState<number>("soc.kprobeThreshold", 99);
  const [query, setQuery] = useState("");
  const [band, setBand] = useState<KprobeBand>("all");
  const [sort, setSort] = useState<KprobeSort>("rate");

  // Self-poll the live stats on a fast cadence so the derived rate and sparklines
  // actually MOVE. The shared snapshot only refreshes every 30s — far too slow to
  // watch a probe heat up — so this panel fetches /api/policy-stats every 3s while
  // it is open, and each poll advances the posts counter that the rate is derived
  // from. Falls back to the snapshot prop until the first live poll lands.
  const [live, setLive] = useState<SocPolicyStat[] | null>(null);
  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    const tick = async () => {
      const stats = await fetchPolicyStats(controller.signal);
      if (!cancelled && stats.length) setLive(stats);
    };
    void tick();
    // 3s was chosen to make per-probe rate moves visible, but each call is a
    // server-side aggregate over the tenant's recent telemetry — at 3s the
    // requests outran their own query time and piled up on the database. 15s
    // still reads as live for a rate panel and cuts that load fivefold.
    const id = window.setInterval(() => void tick(), 15_000);
    return () => { cancelled = true; controller.abort(); window.clearInterval(id); };
  }, []);
  const policyStats = live ?? propStats;

  // Prefer a reported rate; otherwise derive it from the posts counter.
  const rate = (s: SocPolicyStat) => s.ratePerMin ?? kprobeRateFromHistory(s.name);
  const bandOf = (s: SocPolicyStat): Exclude<KprobeBand, "all"> => {
    const r = rate(s);
    if (r > threshold) return "over";
    if (r === 0) return "idle";
    if (r < threshold * 0.25) return "calm";
    if (r < threshold * 0.6) return "warm";
    return "hot";
  };

  const totalPosts = policyStats.reduce((sum, s) => sum + s.posts, 0);
  const hottest = policyStats.reduce<SocPolicyStat | null>((best, s) => (!best || rate(s) > rate(best) ? s : best), null);
  const enabled = policyStats.filter((s) => (s.status || "").toLowerCase() !== "disabled").length;
  const totalMem = policyStats.reduce((sum, s) => sum + (s.memoryBytes || 0), 0);

  // Record a {t, posts} sample once per DATA update (keyed on total posts, which
  // only moves when the snapshot refreshes — not on filter/search re-renders).
  useEffect(() => {
    const now = Date.now();
    for (const s of policyStats) {
      const h = KPROBE_HISTORY.get(s.name) ?? [];
      const last = h[h.length - 1];
      if (!last || s.posts !== last.posts || now - last.t > 4_000) {
        h.push({ t: now, posts: s.posts });
        if (h.length > KPROBE_HISTORY_LEN) h.shift();
        KPROBE_HISTORY.set(s.name, h);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [totalPosts]);

  // A probe is spiking if its latest per-interval delta is well above its own
  // recent baseline — a sudden jump matters even below the absolute threshold.
  const spikeOf = (s: SocPolicyStat): boolean => {
    const series = kprobeDeltaSeries(s.name);
    if (series.length < 4) return false;
    const latest = series[series.length - 1];
    const prior = series.slice(0, -1);
    const avg = prior.reduce((a, b) => a + b, 0) / prior.length;
    return latest > Math.max(avg * 1.8, 3) && latest > avg + 2;
  };
  const spiking = policyStats.filter(spikeOf).length;

  const counts = useMemo(() => {
    const acc: Record<KprobeBand, number> = { all: policyStats.length, hot: 0, warm: 0, calm: 0, idle: 0, over: 0 };
    for (const s of policyStats) acc[bandOf(s)] += 1;
    return acc;
  }, [policyStats, threshold]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    let list = policyStats.filter((s) => {
      if (q && !s.name.toLowerCase().includes(q)) return false;
      if (band !== "all") return bandOf(s) === band;
      return true;
    });
    list = [...list].sort((a, b) => {
      if (sort === "posts") return b.posts - a.posts;
      if (sort === "name") return a.name.localeCompare(b.name);
      if (sort === "mem") return (b.memoryBytes || 0) - (a.memoryBytes || 0);
      return rate(b) - rate(a);
    });
    return list;
  }, [policyStats, query, band, sort, threshold]);

  const maxRate = Math.max(1, threshold, ...policyStats.map(rate));

  return (
    <div className="soc-kprobes">
      <StatGrid>
        <StatCard label="Policies" value={`${enabled}`} sub={`${policyStats.length} loaded`} />
        <StatCard
          label="Spiking now"
          value={`${spiking}`}
          sub={spiking ? "above own baseline" : "all steady"}
          tone={spiking ? "danger" : undefined}
        />
        <StatCard
          label="Hottest"
          value={hottest && rate(hottest) ? `${fmtNum(Math.round(rate(hottest)))}/min` : "—"}
          sub={hottest && rate(hottest) ? hottest.name : "0/min"}
          tone={hottest && rate(hottest) > threshold ? "danger" : undefined}
        />
        <StatCard label="Kernel mem" value={formatBytes(totalMem)} sub={`BPF maps · ${fmtNum(totalPosts)} posts`} />
        <StatCard
          label="Threshold"
          value={
            <input
              type="number"
              className="soc-inline-number"
              value={threshold}
              min={1}
              onChange={(event) => setThreshold(Math.max(1, Number(event.target.value) || 1))}
            />
          }
          sub="/min within limits"
        />
      </StatGrid>

      <div className="soc-toolbar">
        <SearchField value={query} onChange={setQuery} placeholder="filter by name…" />
        <FilterChips
          value={band}
          onChange={setBand}
          options={[
            { key: "all", label: "ALL", count: counts.all },
            { key: "hot", label: "🔥 HOT", count: counts.hot, tone: "danger" },
            { key: "warm", label: "⚡ WARM", count: counts.warm, tone: "warn" },
            { key: "calm", label: "✓ CALM", count: counts.calm, tone: "good" },
            { key: "idle", label: "○ IDLE", count: counts.idle },
            { key: "over", label: "⚠ OVER", count: counts.over, tone: "danger" }
          ]}
        />
      </div>

      <div className="soc-sort-row">
        <span>sort</span>
        {(["rate", "posts", "name", "mem"] as KprobeSort[]).map((key) => (
          <button key={key} type="button" className={cx("soc-sort", sort === key && "is-active")} onClick={() => setSort(key)}>
            {key}
          </button>
        ))}
      </div>

      {rows.length ? (
        <div className="soc-kprobe-list">
          {rows.map((s) => {
            const b = bandOf(s);
            const history = kprobeDeltaSeries(s.name);
            const spiking = spikeOf(s);
            return (
              <article key={s.name} className={cx("soc-kprobe-card", `band-${b}`, spiking && "is-spiking")}>
                <div className="soc-kprobe-head">
                  <strong>{s.name}</strong>
                  {spiking ? (
                    <span className="soc-kprobe-spike"><Activity size={11} aria-hidden="true" /> spiking</span>
                  ) : (
                    <span className={cx("soc-kprobe-band", `band-${b}`)}>{b}</span>
                  )}
                </div>
                {history.length > 1 ? (
                  <div className="soc-kprobe-spark">
                    <Sparkline values={history} tone={spiking || b === "over" ? "danger" : b === "hot" ? "warn" : "accent"} />
                  </div>
                ) : (
                  <Meter value={rate(s)} max={maxRate} tone={b === "over" || b === "hot" ? "danger" : b === "warm" ? "warn" : "good"} />
                )}
                <div className="soc-kprobe-meta">
                  <span>
                    rate <b>{rate(s) ? `${fmtNum(Math.round(rate(s)))}/min` : "—"}</b>
                  </span>
                  <span>
                    posts <b>{fmtNum(s.posts)}</b>
                  </span>
                  <span>
                    mem <b>{formatBytes(s.memoryBytes)}</b>
                  </span>
                </div>
              </article>
            );
          })}
        </div>
      ) : (
        <EmptyState
          title="No policies match the current filter"
          detail="GET /api/policy-stats may return 503 when Tetragon is unavailable."
        />
      )}
    </div>
  );
}

/* ------------------------------------------------------------------- Fleet */

type FleetState = "up" | "down" | "probing" | "unknown";

interface FleetProbe {
  state: FleetState;
  rttMs?: number;
  status?: number;
  error?: string;
}

// This panel is the operator's OWN directory: the console serving it, plus the
// peers they typed in. It deliberately does not enumerate the backend's enrolled
// agents — those have their own surfaces, and mixing them in both duplicated the
// self row on an engine and made a hand-maintained list look auto-populated.
type FleetRowKind = "self" | "local";

interface FleetRow {
  name: string;
  url: string;
  kind: FleetRowKind;
  probe?: FleetProbe;
}

/** Peers are addressed over http(s); a bare host would resolve as a relative URL. */
export function normalizePeerUrl(raw: string): { url?: string; error?: string } {
  const trimmed = raw.trim().replace(/\/+$/, "");
  if (!trimmed) return { error: "Enter a peer URL." };
  if (!/^https?:\/\//i.test(trimmed)) {
    return { error: "Include the scheme, e.g. https://engine.example.io or http://192.168.1.10:8080" };
  }
  try {
    return { url: new URL(trimmed).origin };
  } catch {
    return { error: "That is not a valid URL." };
  }
}

export function FleetBody({
  hosts,
  setHosts,
  whoami,
  currentTracked
}: {
  hosts: Array<{ name: string; url: string }>;
  setHosts: (next: Array<{ name: string; url: string }>) => void;
  whoami: SocWhoami;
  currentTracked: number;
}) {
  const [probes, setProbes] = useState<Record<string, FleetProbe>>({});
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [addError, setAddError] = useState("");

  // Always present the host serving this console as the first, self-evident row.
  const selfUrl = typeof window !== "undefined" ? window.location.origin : "";

  const rows = useMemo<FleetRow[]>(() => {
    const self: FleetRow = { name: whoami.host || "this console", url: selfUrl, kind: "self" };
    const localRows: FleetRow[] = hosts.map((host) => ({
      name: host.name,
      url: host.url,
      kind: "local",
      probe: probes[host.url]
    }));
    return [self, ...localRows];
  }, [hosts, probes, selfUrl, whoami.host]);

  const probeTargets = useMemo(() => hosts.map((h) => h.url), [hosts]);

  const probe = useCallback(async (targets: string[]) => {
    if (targets.length === 0) return;
    setProbes((prev) => {
      const next = { ...prev };
      for (const target of targets) next[target] = { ...next[target], state: "probing" };
      return next;
    });
    try {
      const results = await probeFleetHosts(targets);
      setProbes((prev) => {
        const next = { ...prev };
        for (const result of results) {
          next[result.url] = {
            state: result.reachable ? "up" : "down",
            rttMs: result.rtt_ms,
            status: result.status,
            error: result.error
          };
        }
        return next;
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "probe failed";
      setProbes((prev) => {
        const next = { ...prev };
        for (const target of targets) next[target] = { state: "down", error: message };
        return next;
      });
    }
  }, []);

  // Probe on open. The probe is a single same-origin call the server fans out,
  // so there is no longer a reason to make the operator ask: a freshly-opened
  // panel showing UNKNOWN for a host that is plainly up was the original
  // complaint. "Ping all" stays for an explicit re-check.
  useEffect(() => {
    void probe(probeTargets);
    // Deliberately on mount only — re-probing on every hosts change would fire
    // mid-typing as the operator edits the directory.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function addHost() {
    const { url: normalized, error } = normalizePeerUrl(url);
    if (!normalized) {
      setAddError(error ?? "Invalid URL.");
      return;
    }
    if (normalized === selfUrl || hosts.some((h) => h.url === normalized)) {
      setAddError("That host is already listed.");
      return;
    }
    setAddError("");
    setHosts([...hosts, { name: name.trim() || normalized, url: normalized }]);
    setName("");
    setUrl("");
    void probe([normalized]); // answer "is it up?" immediately, not on next click
  }

  function removeHost(target: string) {
    setHosts(hosts.filter((h) => h.url !== target));
  }

  const stateOf = (row: FleetRow): FleetState =>
    row.kind === "self" ? "up" : row.probe?.state ?? "unknown";
  const reachable = rows.filter((row) => stateOf(row) === "up").length;
  const down = rows.filter((row) => stateOf(row) === "down").length;

  return (
    <div className="soc-fleet">
      <StatGrid>
        <StatCard label="Hosts" value={rows.length} />
        <StatCard label="Reachable" value={reachable} tone={reachable ? "good" : undefined} />
        <StatCard label="Down" value={down} tone={down ? "danger" : undefined} />
        <StatCard label="Tracked (sum)" value={fmtNum(currentTracked)} />
      </StatGrid>

      <div className="soc-fleet-add">
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="name (e.g. ebpf-2)" />
        <input
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            if (addError) setAddError("");
          }}
          placeholder="https://engine.example.io"
          aria-invalid={addError ? true : undefined}
        />
        <button type="button" className="soc-ghost-button" onClick={addHost}>
          <Plus size={14} aria-hidden="true" /> Add host
        </button>
        <button
          type="button"
          className="soc-ghost-button"
          onClick={() => void probe(probeTargets)}
          disabled={probeTargets.length === 0}
        >
          <RadioTower size={14} aria-hidden="true" /> Ping all
        </button>
      </div>
      {addError ? <p className="soc-fleet-error">{addError}</p> : null}

      <div className="soc-fleet-table">
        <div className="soc-fleet-th">
          <span>Name</span>
          <span>URL</span>
          <span>RTT</span>
          <span>Status</span>
          <span>Actions</span>
        </div>
        {rows.map((row) => {
          const state = stateOf(row);
          const rtt = row.probe?.rttMs;
          // A peer that answers 401 is up and simply does not know this session.
          // Saying so beats a bare DOWN that sends operators hunting a dead host.
          const detail =
            row.probe?.error ??
            (row.probe?.status && row.probe.status >= 400 ? `HTTP ${row.probe.status} — reachable, not signed in` : undefined);
          return (
            <div key={`${row.kind}:${row.url || row.name}`} className="soc-fleet-tr">
              <span className={cx("soc-fleet-state", `is-${state}`)}>
                <i /> {row.name}
              </span>
              <code title={detail || row.url}>{row.url || "—"}</code>
              <span>{rtt !== undefined ? `${rtt} ms` : "—"}</span>
              <span className={cx("soc-fleet-status", `is-${state}`)} title={detail}>
                {state.toUpperCase()}
              </span>
              <span className="soc-fleet-actions">
                <a className="soc-mini-link" href={`${row.url.replace(/\/$/, "")}/`}>
                  SOC
                </a>
                <a className="soc-mini-link" href={`${row.url.replace(/\/$/, "")}/choke`}>
                  Choke
                </a>
                {row.kind === "local" ? (
                  <button type="button" className="soc-mini-x" onClick={() => removeHost(row.url)} aria-label="remove host">
                    <Trash2 size={12} aria-hidden="true" />
                  </button>
                ) : null}
              </span>
            </div>
          );
        })}
      </div>
      <p className="soc-fleet-foot">
        Probes run on this host, not in your browser, so peers on other origins are reported honestly. A peer that
        answers <code>401</code> is up — it just does not share this console's session.
      </p>
    </div>
  );
}

/* ----------------------------------------------------------- Notifications */

interface NotifyHistoryItem {
  title?: string;
  body?: string;
  ts?: string;
  read?: boolean;
  severity?: Severity;
}

type NotifyTab = "all" | "unread" | "critical" | "high";
type NotifyChannels = { inApp: boolean; desktop: boolean; audio: boolean };

export function NotificationsBody({
  history,
  active,
  channels,
  onActiveChange,
  onChannelsChange,
  onMarkAllRead,
  onClearAll
}: {
  history: NotifyHistoryItem[];
  active: boolean;
  channels: NotifyChannels;
  onActiveChange: Dispatch<SetStateAction<boolean>>;
  onChannelsChange: Dispatch<SetStateAction<NotifyChannels>>;
  onMarkAllRead?: () => void;
  onClearAll?: () => void;
}) {
  const [minSeverity, setMinSeverity] = useLocalState<Severity>("soc.notifyMinSeverity", "high");
  const [throttleMin, setThrottleMin] = useLocalState<number>("soc.notifyThrottleMin", 0);
  const [quietStart, setQuietStart] = useLocalState<string>("soc.notifyQuietStart", "");
  const [quietEnd, setQuietEnd] = useLocalState<string>("soc.notifyQuietEnd", "");
  const [tab, setTab] = useState<NotifyTab>("all");
  const [search, setSearch] = useState("");

  const permission =
    typeof Notification !== "undefined" ? Notification.permission : ("default" as NotificationPermission);

  const unread = history.filter((h) => !h.read).length;
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return history.filter((h) => {
      if (tab === "unread" && h.read) return false;
      if (tab === "critical" && h.severity !== "critical") return false;
      if (tab === "high" && h.severity !== "high") return false;
      if (q && !(h.title || "").toLowerCase().includes(q) && !(h.body || "").toLowerCase().includes(q)) return false;
      return true;
    });
  }, [history, tab, search]);

  const toggleChannel = (key: keyof NotifyChannels) => onChannelsChange((prev) => ({ ...prev, [key]: !prev[key] }));

  return (
    <div className="soc-notify">
      <section className="soc-notify-section">
        <div className="soc-notify-row is-master">
          <div>
            <strong>Active</strong>
            <span>
              When off, alerts above the threshold still appear in the live feed but no badge ticks and no channel fires.
            </span>
          </div>
          <Toggle on={active} onClick={() => onActiveChange(!active)} label={active ? "ON" : "OFF · ALERTS IGNORED"} />
        </div>
      </section>

      <section className={cx("soc-notify-section", !active && "is-disabled")}>
        <h4>
          Delivery channels
          {!active ? <em>disabled while alerts are off</em> : null}
        </h4>
        <div className="soc-notify-row">
          <div>
            <strong>
              <Bell size={13} aria-hidden="true" /> In-app history &amp; badge
            </strong>
            <span>Drives the rail bell badge and the list below. Survives reload (per-browser).</span>
          </div>
          <Toggle on={channels.inApp} onClick={() => toggleChannel("inApp")} label={channels.inApp ? "ON" : "OFF"} />
        </div>
        <div className="soc-notify-row">
          <div>
            <strong>
              <Globe size={13} aria-hidden="true" /> Browser desktop popup
            </strong>
            <span>
              Native OS notification when this tab is unfocused.
              {permission === "denied" ? <b className="soc-perm-denied"> DENIED</b> : null}
            </span>
          </div>
          <Toggle
            on={channels.desktop && permission !== "denied"}
            onClick={() => {
              if (permission === "default" && typeof Notification !== "undefined") void Notification.requestPermission();
              toggleChannel("desktop");
            }}
            label={channels.desktop ? "ON" : "OFF"}
          />
        </div>
        <div className="soc-notify-row">
          <div>
            <strong>
              <Volume2 size={13} aria-hidden="true" /> Audio chime
            </strong>
            <span>Plays only when this tab is unfocused. Skipped during quiet hours.</span>
          </div>
          <Toggle on={channels.audio} onClick={() => toggleChannel("audio")} label={channels.audio ? "ON" : "OFF"} />
        </div>
      </section>

      <section className="soc-notify-section">
        <h4>Filters &amp; quiet hours</h4>
        <div className="soc-notify-field">
          <div>
            <strong>Minimum severity</strong>
            <span>Only alerts at this level or above pass the filter.</span>
          </div>
          <select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value as Severity)}>
            {SEVERITY_ORDER.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
        <div className="soc-notify-field">
          <div>
            <strong>Throttle duplicates</strong>
            <span>Suppress repeats of the same alert title within this window.</span>
          </div>
          <select value={throttleMin} onChange={(e) => setThrottleMin(Number(e.target.value))}>
            <option value={0}>off</option>
            <option value={1}>1 min</option>
            <option value={5}>5 min</option>
            <option value={15}>15 min</option>
          </select>
        </div>
        <div className="soc-notify-field">
          <div>
            <strong>Quiet hours</strong>
            <span>Mute popup &amp; audio between these times. History keeps recording.</span>
          </div>
          <div className="soc-notify-quiet">
            <input type="time" value={quietStart} onChange={(e) => setQuietStart(e.target.value)} />
            <span>→</span>
            <input type="time" value={quietEnd} onChange={(e) => setQuietEnd(e.target.value)} />
          </div>
        </div>
      </section>

      <section className="soc-notify-section">
        <div className="soc-notify-history-head">
          <FilterChips
            value={tab}
            onChange={setTab}
            options={[
              { key: "all", label: "ALL", count: history.length },
              { key: "unread", label: "UNREAD", count: unread },
              { key: "critical", label: "CRITICAL", count: history.filter((h) => h.severity === "critical").length, tone: "danger" },
              { key: "high", label: "HIGH", count: history.filter((h) => h.severity === "high").length, tone: "warn" }
            ]}
          />
          <SearchField value={search} onChange={setSearch} placeholder="Search title or exec_id…" />
        </div>
        {filtered.length ? (
          <div className="soc-notify-history scrollbar">
            {filtered.slice(0, 50).map((item, index) => (
              <article key={`${item.ts || index}`} className={cx("soc-notify-item", !item.read && "is-unread")}>
                <span className={cx("soc-notify-dot", item.severity && `severity-${item.severity}`)} />
                <div>
                  <strong>{item.title || "Notification"}</strong>
                  <span>{item.body || "No body"}</span>
                </div>
                <time>{clock(item.ts)}</time>
              </article>
            ))}
          </div>
        ) : (
          <EmptyState title="No notifications yet" detail="They'll appear here when alerts fire." />
        )}
        <footer className="soc-notify-foot">
          <span>
            {history.length} in history · {unread} unread
          </span>
          <div>
            <button type="button" className="soc-ghost-button" disabled={!unread} onClick={onMarkAllRead}>
              Mark all read
            </button>
            <button type="button" className="soc-ghost-button tone-danger" disabled={!history.length} onClick={onClearAll}>
              Clear all
            </button>
          </div>
        </footer>
      </section>
    </div>
  );
}

/* --------------------------------------------------------- Account / profile */

export function AccountBody({
  user,
  host,
  role,
  theme,
  streamState,
  versionSha,
  storageKeyCount
}: {
  user: string;
  host: string;
  role?: string;
  theme: "dark" | "light";
  streamState: string;
  versionSha?: string;
  storageKeyCount: number;
}) {
  const initials = user.slice(0, 2).toUpperCase();
  const streamUp = streamState === "live";
  return (
    <div className="soc-account">
      <header className="soc-account-id">
        <div className="soc-account-avatar" aria-hidden="true">
          {initials}
        </div>
        <div>
          <strong>{user}</strong>
          <span>{role || "operator"} · {host}</span>
        </div>
        <span className={cx("soc-account-stream", streamUp && "is-live")}>
          <i />
          {streamState}
        </span>
      </header>

      <dl className="soc-account-grid">
        <div>
          <dt>Host</dt>
          <dd>{host}</dd>
        </div>
        <div>
          <dt>Session</dt>
          <dd className={streamUp ? "is-good" : undefined}>{streamUp ? "active" : streamState}</dd>
        </div>
        <div>
          <dt>Theme</dt>
          <dd>{theme}</dd>
        </div>
        <div>
          <dt>Build</dt>
          <dd>{versionSha ? versionSha.slice(0, 10) : "—"}</dd>
        </div>
      </dl>

      <div className="soc-account-actions">
        <span className="soc-account-theme">Theme: {theme} (follows your OS setting)</span>
        <a className="soc-account-signout" href="/api/logout">
          Sign out
        </a>
      </div>

      <p className="soc-account-foot">{storageKeyCount} local preference keys stored in this browser.</p>
    </div>
  );
}

function Toggle({ on, onClick, label }: { on: boolean; onClick: () => void; label: string }) {
  return (
    <button type="button" className={cx("soc-toggle", on && "is-on")} onClick={onClick} aria-pressed={on}>
      <i />
      <span>{label}</span>
    </button>
  );
}

/* -------------------------------------------------------------- Risk gauge */

function riskMeta(score: number): { label: string; tone: string } {
  if (score >= 80) return { label: "critical", tone: "danger" };
  if (score >= 45) return { label: "high", tone: "warn" };
  if (score >= 18) return { label: "elevated", tone: "accent" };
  return { label: "low", tone: "good" };
}

const RISK_TONE_COLOR: Record<string, string> = {
  danger: "#f0556b",
  warn: "#ff8a4c",
  accent: "#6b8afd",
  good: "#34d399"
};

export function RiskGauge({
  score,
  ratePerHour,
  counts,
  contributors,
  window: windowLabel
}: {
  score: number;
  /**
   * The weighted alert RATE the score is derived from. Shown because the dial is
   * a normalised 0..100 and the breakdown below it is a raw count for the
   * window — the rate is what ties them together, and it is the figure that is
   * actually comparable between one window and the next.
   */
  ratePerHour?: number;
  counts: Record<Severity, number>;
  contributors: Array<{ title: string; score: number; severity: Severity }>;
  window?: string;
}) {
  const meta = riskMeta(score);
  const color = RISK_TONE_COLOR[meta.tone];
  // Semicircle arc: 180° sweep from left to right, filled proportionally.
  const radius = 80;
  const cx0 = 100;
  const cy0 = 100;
  const circumference = Math.PI * radius;
  const filled = (Math.min(100, Math.max(0, score)) / 100) * circumference;

  const arcPath = `M ${cx0 - radius} ${cy0} A ${radius} ${radius} 0 0 1 ${cx0 + radius} ${cy0}`;

  const weights: Array<{ sev: Severity; weight: number }> = [
    { sev: "critical", weight: 8 },
    { sev: "high", weight: 3 },
    { sev: "medium", weight: 1 }
  ];
  const maxContribution = Math.max(1, ...weights.map((w) => counts[w.sev] * w.weight));

  return (
    <div className="soc-risk-gauge">
      <div className="soc-gauge-dial">
        <svg viewBox="0 0 200 116" role="img" aria-label={`Risk score ${score}, ${meta.label}`}>
          <path className="soc-gauge-track" d={arcPath} strokeWidth={14} fill="none" strokeLinecap="round" />
          <path
            className="soc-gauge-fill"
            d={arcPath}
            strokeWidth={14}
            fill="none"
            strokeLinecap="round"
            stroke={color}
            strokeDasharray={`${filled} ${circumference}`}
            style={{ filter: `drop-shadow(0 0 6px ${color}66)` }}
          />
        </svg>
        <div className="soc-gauge-readout">
          <strong style={{ color }}>{score}</strong>
          <span className={`severity-${meta.label === "elevated" ? "medium" : meta.label === "critical" ? "critical" : meta.label === "high" ? "high" : "low"}`}>
            {meta.label}
          </span>
          {windowLabel ? <em>window: {windowLabel}</em> : null}
          {ratePerHour !== undefined && ratePerHour > 0 ? <em>{Math.round(ratePerHour)} weighted/hr</em> : null}
        </div>
      </div>

      <div className="soc-gauge-breakdown">
        <span className="soc-stat-label">Severity contribution · weights crit×8 high×3 med×1</span>
        {weights.map(({ sev, weight }) => {
          const contribution = counts[sev] * weight;
          return (
            <div key={sev} className="soc-gauge-bar">
              <span className={`severity-${sev}`}>{sev}</span>
              <Meter value={contribution} max={maxContribution} tone={sev === "critical" ? "danger" : sev === "high" ? "warn" : "accent"} />
              <em>
                {counts[sev]} × {weight} = {contribution}
              </em>
            </div>
          );
        })}
      </div>

      {contributors.length ? (
        <div className="soc-gauge-contributors">
          <span className="soc-stat-label">Top threat contributors</span>
          {contributors.slice(0, 5).map((c, i) => (
            <div key={`${c.title}-${i}`} className="soc-gauge-contributor">
              <span className={cx("soc-notify-dot", `severity-${c.severity}`)} />
              <strong>{c.title}</strong>
              <em>{c.score}</em>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
