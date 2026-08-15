// The watchlist surface, plus the count the sidebar badge reads.
import { useMemo, useState } from "react";
import { Radio } from "lucide-react";
import type * as React from "react";
import { cx } from "./components";
import { DEFAULT_WATCHLIST } from "./dashboard";
import { peerFromEvent } from "./telemetry";
import type { Severity, SocAlert, SocEvent } from "./types";

type WatchKind = keyof typeof DEFAULT_WATCHLIST;
interface WatchHit {
  kind: WatchKind;
  term: string;
  hits: number;
  lastSeen?: string;
  severity?: Severity;
}

export function watchCount(watchlist: typeof DEFAULT_WATCHLIST) {
  return watchlist.paths.length + watchlist.ips.length + watchlist.binaries.length;
}

/**
 * An ACTIVE watchlist. The old one was a notepad — terms sat in localStorage and
 * never did anything. Now every watched path / IP / binary is matched against
 * the live alert + event stream: each shows a hit count, when it last fired, and
 * the worst severity it drew. Triggered watches surface at the top so an
 * operator sees "the thing I'm watching for is happening right now."
 */
export function WatchlistBody({
  watchlist,
  setWatchlist,
  alerts,
  events
}: {
  watchlist: typeof DEFAULT_WATCHLIST;
  setWatchlist: React.Dispatch<React.SetStateAction<typeof DEFAULT_WATCHLIST>>;
  alerts: SocAlert[];
  events: SocEvent[];
}) {
  const [kind, setKind] = useState<WatchKind>("paths");
  const [value, setValue] = useState("");

  const results = useMemo<WatchHit[]>(() => {
    const eventHay = events.map((e) => ({
      hay: [e.process, e.path, e.args, peerFromEvent(e)].filter(Boolean).join(" ").toLowerCase(),
      ts: e.timestamp
    }));
    const alertHay = alerts.map((a) => ({
      hay: [a.title, a.description, a.args].filter(Boolean).join(" ").toLowerCase(),
      ts: a.timestamp,
      sev: a.severity
    }));
    const sevRank: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

    const out: WatchHit[] = [];
    for (const k of ["paths", "ips", "binaries"] as WatchKind[]) {
      for (const term of watchlist[k]) {
        const needle = term.toLowerCase();
        let hits = 0;
        let lastSeen: string | undefined;
        let severity: Severity | undefined;
        const note = (ts?: string, sev?: Severity) => {
          hits += 1;
          if (ts && (!lastSeen || Date.parse(ts) > Date.parse(lastSeen))) lastSeen = ts;
          if (sev && (!severity || sevRank[sev] > sevRank[severity])) severity = sev;
        };
        for (const e of eventHay) if (e.hay.includes(needle)) note(e.ts);
        for (const a of alertHay) if (a.hay.includes(needle)) note(a.ts, a.sev);
        out.push({ kind: k, term, hits, lastSeen, severity });
      }
    }
    return out.sort((a, b) => b.hits - a.hits);
  }, [watchlist, alerts, events]);

  const triggered = results.filter((r) => r.hits > 0);
  const now = Date.now();
  const ago = (iso?: string) => {
    if (!iso) return "never";
    const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
    return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)}m ago` : `${Math.round(s / 3600)}h ago`;
  };
  const remove = (k: WatchKind, term: string) =>
    setWatchlist((cur) => ({ ...cur, [k]: cur[k].filter((t) => t !== term) }));

  return (
    <div className="soc-watch">
      <div className="soc-watch-add">
        <select value={kind} onChange={(e) => setKind(e.target.value as WatchKind)}>
          <option value="paths">path</option>
          <option value="ips">ip</option>
          <option value="binaries">binary</option>
        </select>
        <input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") { const t = value.trim(); if (t && !watchlist[kind].includes(t)) { setWatchlist((c) => ({ ...c, [kind]: [...c[kind], t] })); setValue(""); } } }}
          placeholder={kind === "ips" ? "e.g. 185.220.101.1" : kind === "binaries" ? "e.g. /usr/bin/nc" : "e.g. /etc/shadow"}
        />
        <button
          type="button"
          onClick={() => { const t = value.trim(); if (t && !watchlist[kind].includes(t)) { setWatchlist((c) => ({ ...c, [kind]: [...c[kind], t] })); setValue(""); } }}
        >
          Watch
        </button>
      </div>

      {triggered.length ? (
        <div className="soc-watch-triggered">
          <span className="soc-stat-label"><Radio size={12} aria-hidden="true" /> Triggered now · {triggered.length}</span>
          <div className="soc-watch-triggered-row">
            {triggered.slice(0, 6).map((r) => (
              <span key={`${r.kind}-${r.term}`} className={cx("soc-watch-pill", r.severity && `sev-${r.severity}`)}>
                {r.term}<b>{r.hits}</b>
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {results.length === 0 ? (
        <p className="soc-graph-selection-empty">
          Nothing watched yet. Add a path, IP, or binary above and it will be matched live against every alert and event in range.
        </p>
      ) : (
        <div className="soc-watch-list">
          {results.map((r) => (
            <div key={`${r.kind}-${r.term}`} className={cx("soc-watch-item", r.hits > 0 && "is-hot", r.severity && `sev-${r.severity}`)}>
              <span className="soc-watch-kind">{r.kind === "paths" ? "path" : r.kind === "ips" ? "ip" : "bin"}</span>
              <span className="soc-watch-term" title={r.term}>{r.term}</span>
              <span className="soc-watch-meta">
                {r.hits > 0 ? (
                  <>
                    <b className="soc-watch-count">{r.hits} hit{r.hits === 1 ? "" : "s"}</b>
                    <em>{ago(r.lastSeen)}</em>
                    {r.severity ? <i className={`sev-${r.severity}`}>{r.severity}</i> : null}
                  </>
                ) : (
                  <em className="soc-watch-quiet">no hits in range</em>
                )}
              </span>
              <button type="button" className="soc-watch-remove" onClick={() => remove(r.kind, r.term)} aria-label={`Remove ${r.term}`}>×</button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
