// Rich SOC panel bodies. The base SocRoute keeps the live-data plumbing; these
// components render the enterprise-grade surfaces (MITRE matrix, honeypot grid,
// kprobe board, fleet console, notification center, risk gauge) that the modal
// shells host. Each body is data-driven off the same snapshot the route already
// fetches, so nothing here introduces new network calls beyond explicit probes.
import { useCallback, useMemo, useState, type Dispatch, type SetStateAction } from "react";
import { Bell, FileCode, FileDown, Globe, Plus, RadioTower, Search, Trash2, Volume2 } from "lucide-react";
import { cx, EmptyState } from "./components";
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

/* ------------------------------------------------------------ MITRE Navigator */

export function MitreNavigatorBody({
  mitreRows,
  alerts,
  onExport
}: {
  mitreRows: Array<{ label: string; value: number; meta?: string; id?: string }>;
  alerts: SocAlert[];
  onExport: () => void;
}) {
  const [selected, setSelected] = useState<string | null>(null);

  const observed = useMemo(() => {
    const counts = new Map<string, number>();
    for (const row of mitreRows) {
      const id = techniqueId(row.label) || techniqueId(row.id);
      if (id) counts.set(id, (counts.get(id) || 0) + row.value);
    }
    for (const alert of alerts) {
      const id = techniqueId(alert.mitreId);
      if (id && !mitreRows.length) counts.set(id, (counts.get(id) || 0) + 1);
    }
    return counts;
  }, [mitreRows, alerts]);

  const totalTechniques = ALL_TECHNIQUE_IDS.size;
  const observedInMatrix = [...observed.keys()].filter((id) => ALL_TECHNIQUE_IDS.has(id));
  const observedCount = observedInMatrix.length;
  const hitTotal = [...observed.entries()]
    .filter(([id]) => ALL_TECHNIQUE_IDS.has(id))
    .reduce((sum, [, n]) => sum + n, 0);
  const coverage = Math.round((observedCount / totalTechniques) * 100);

  return (
    <div className="soc-mitre">
      <div className="soc-mitre-head">
        <div className="soc-mitre-stats">
          <div className="soc-mitre-stat">
            <span className="soc-stat-label">Coverage</span>
            <strong>{coverage}%</strong>
            <em>
              {observedCount} / {totalTechniques} techniques
            </em>
          </div>
          <div className="soc-mitre-stat tone-danger">
            <span className="soc-stat-label">Observed</span>
            <strong>{fmtNum(hitTotal)}</strong>
            <em>technique hits</em>
          </div>
        </div>
        <button type="button" className="soc-ghost-button" onClick={onExport}>
          <FileDown size={14} aria-hidden="true" /> Export coverage PDF
        </button>
      </div>

      <div className="soc-mitre-grid scrollbar">
        {MITRE_MATRIX.map((tactic) => {
          const hitsInCol = tactic.techniques.filter((t) => observed.has(t.id)).length;
          return (
            <div key={tactic.id} className="soc-mitre-col">
              <header>
                <span className="soc-mitre-tactic">{tactic.name}</span>
                <span className="soc-mitre-fraction">
                  {hitsInCol}/{tactic.techniques.length}
                </span>
                <i style={{ width: `${(hitsInCol / tactic.techniques.length) * 100}%` }} />
              </header>
              <div className="soc-mitre-cells">
                {tactic.techniques.map((tech) => {
                  const count = observed.get(tech.id) || 0;
                  const active = count > 0;
                  const isSelected = selected === tech.id;
                  return (
                    <button
                      key={tech.id}
                      type="button"
                      className={cx("soc-mitre-cell", active && "is-observed", isSelected && "is-selected")}
                      onClick={() => setSelected(isSelected ? null : tech.id)}
                      title={`${tech.id} ${tech.name}${active ? ` · ${count} hits` : ""}`}
                    >
                      <span className="soc-mitre-id">
                        {tech.id}
                        {active ? <em>×{count}</em> : null}
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

export function KprobeBody({ policyStats }: { policyStats: SocPolicyStat[] }) {
  const [threshold, setThreshold] = useLocalState<number>("soc.kprobeThreshold", 99);
  const [query, setQuery] = useState("");
  const [band, setBand] = useState<KprobeBand>("all");
  const [sort, setSort] = useState<KprobeSort>("rate");

  const rate = (s: SocPolicyStat) => s.ratePerMin ?? 0;
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
        <StatCard label="Total posts" value={fmtNum(totalPosts)} sub="since engine start" />
        <StatCard
          label="Hottest"
          value={hottest && rate(hottest) ? `${fmtNum(rate(hottest))}/min` : "—"}
          sub={hottest && rate(hottest) ? hottest.name : "0/min"}
          tone={hottest && rate(hottest) > threshold ? "danger" : undefined}
        />
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
            return (
              <article key={s.name} className={cx("soc-kprobe-card", `band-${b}`)}>
                <div className="soc-kprobe-head">
                  <strong>{s.name}</strong>
                  <span className={cx("soc-kprobe-band", `band-${b}`)}>{b}</span>
                </div>
                <Meter value={rate(s)} max={maxRate} tone={b === "over" || b === "hot" ? "danger" : b === "warm" ? "warn" : "good"} />
                <div className="soc-kprobe-meta">
                  <span>
                    rate <b>{rate(s) ? `${fmtNum(rate(s))}/min` : "—"}</b>
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

interface FleetProbe {
  state: "up" | "down" | "probing" | "unknown";
  rttMs?: number;
  user?: string;
  host?: string;
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

  // Always present the host serving this console as the first, self-evident row.
  const selfUrl = typeof window !== "undefined" ? window.location.origin : "";
  const allHosts = useMemo(() => {
    const withSelf = [{ name: "this", url: selfUrl, self: true }, ...hosts.map((h) => ({ ...h, self: false }))];
    return withSelf;
  }, [hosts, selfUrl]);

  const probeHost = useCallback(async (target: string) => {
    setProbes((prev) => ({ ...prev, [target]: { ...prev[target], state: "probing" } }));
    const started = performance.now();
    try {
      const res = await fetch(`${target.replace(/\/$/, "")}/api/whoami`, {
        credentials: "include",
        signal: AbortSignal.timeout(4000)
      });
      const rttMs = Math.round(performance.now() - started);
      if (!res.ok) {
        setProbes((prev) => ({ ...prev, [target]: { state: "down", rttMs } }));
        return;
      }
      const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
      setProbes((prev) => ({
        ...prev,
        [target]: {
          state: "up",
          rttMs,
          user: typeof body.user === "string" ? body.user : undefined,
          host: typeof body.host === "string" ? body.host : undefined
        }
      }));
    } catch {
      setProbes((prev) => ({ ...prev, [target]: { state: "down", rttMs: Math.round(performance.now() - started) } }));
    }
  }, []);

  const pingAll = useCallback(() => {
    for (const host of allHosts) void probeHost(host.url);
  }, [allHosts, probeHost]);

  function addHost() {
    const trimmed = url.trim();
    if (!trimmed) return;
    setHosts([...hosts, { name: name.trim() || trimmed, url: trimmed }]);
    setName("");
    setUrl("");
  }

  function removeHost(target: string) {
    setHosts(hosts.filter((h) => h.url !== target));
  }

  const reachable = allHosts.filter((h) => probes[h.url]?.state === "up").length;
  const down = allHosts.filter((h) => probes[h.url]?.state === "down").length;

  return (
    <div className="soc-fleet">
      <StatGrid>
        <StatCard label="Hosts" value={allHosts.length} />
        <StatCard label="Reachable" value={reachable} tone={reachable ? "good" : undefined} />
        <StatCard label="Down" value={down} tone={down ? "danger" : undefined} />
        <StatCard label="Tracked (sum)" value={fmtNum(currentTracked)} />
      </StatGrid>

      <div className="soc-fleet-add">
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="name (e.g. ebpf-2)" />
        <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="http://192.168.x.y:8080" />
        <button type="button" className="soc-ghost-button" onClick={addHost}>
          <Plus size={14} aria-hidden="true" /> Add host
        </button>
        <button type="button" className="soc-ghost-button" onClick={pingAll}>
          <RadioTower size={14} aria-hidden="true" /> Ping all
        </button>
      </div>

      <div className="soc-fleet-table">
        <div className="soc-fleet-th">
          <span>Name</span>
          <span>URL</span>
          <span>RTT</span>
          <span>Status</span>
          <span>Actions</span>
        </div>
        {allHosts.map((host) => {
          const probe = probes[host.url];
          const state = host.self && !probe ? "up" : probe?.state || "unknown";
          return (
            <div key={host.url} className="soc-fleet-tr">
              <span className={cx("soc-fleet-state", `is-${state}`)}>
                <i /> {host.self ? whoami.host || host.name : host.name}
              </span>
              <code title={host.url}>{host.url || "—"}</code>
              <span>{probe?.rttMs !== undefined ? `${probe.rttMs} ms` : "—"}</span>
              <span className={cx("soc-fleet-status", `is-${state}`)}>{state.toUpperCase()}</span>
              <span className="soc-fleet-actions">
                <a className="soc-mini-link" href={`${host.url.replace(/\/$/, "")}/`}>
                  SOC
                </a>
                <a className="soc-mini-link" href={`${host.url.replace(/\/$/, "")}/choke`}>
                  Choke
                </a>
                {!host.self ? (
                  <button type="button" className="soc-mini-x" onClick={() => removeHost(host.url)} aria-label="remove host">
                    <Trash2 size={12} aria-hidden="true" />
                  </button>
                ) : null}
              </span>
            </div>
          );
        })}
      </div>
      <p className="soc-fleet-foot">
        Cross-origin probes use credentials <code>include</code>. Log in to a peer once in another tab so the shared cookie
        is reused for subsequent probes.
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
  counts,
  contributors,
  window: windowLabel
}: {
  score: number;
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
