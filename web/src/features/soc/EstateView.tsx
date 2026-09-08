// THE ESTATE-WIDE VIEW: what a provider's console shows when it is pointed at
// no single customer.
//
// The console had exactly one thing to say to an MSSP operator — "you are
// looking at one customer, and here is which" — which is honest but not the
// answer to the question they open the console with: how is the whole book of
// business doing. This section answers that, under the rule the endpoint behind
// it enforces (see estate.ts and engine/internal/controlplane/estate.go):
//
//   1. EVERY NUMBER IS DECOMPOSABLE ON SCREEN. Each tile carries the per-
//      customer parts it was folded from, and the customer table under them
//      shows every part without a click. An aggregate a provider cannot break
//      down per customer is the same defect as a console presenting one
//      customer as the estate, one level up — that defect is what the scope
//      banner exists to correct, and this view must not reintroduce it.
//   2. A CUSTOMER THAT COULD NOT BE READ IS VISIBLE AS UNREAD, never as a zero
//      and never silently dropped. A summary that quietly omits a failed read
//      is a false all-clear, and this console has shipped that class of defect
//      repeatedly.
//   3. POSTURE IS THE WORST CUSTOMER'S SCORE, LABELLED AS SUCH — never a mean.
//      An average hides one customer on fire behind nine quiet ones.
//
// There is no telemetry-throughput tile. The store has no windowed
// count-by-kind primitive, so the endpoint omits the figure rather than
// guessing it, and an empty slot here would state "zero events" — a claim
// nothing in the system can support.
import { AlertTriangle, RefreshCw, Server } from "lucide-react";
import { useState } from "react";
import { cx } from "./components";
import { rangeLabel } from "./format";
import { estateTiles, orderedTenants, unreadTenants, useEstateSummary, type EstateSummary, type EstateTile } from "./estate";
import "./estate.css";

function count(value: number): string {
  return value.toLocaleString();
}

function readStamp(readAt: number | null): string {
  if (!readAt) return "";
  return new Date(readAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/**
 * The per-customer parts of one tile.
 *
 * An unread customer appears here with no number at all. Rendering a dash and
 * the reason rather than a 0 is the whole point: the two look similar and mean
 * opposite things, and only one of them is evidence that the estate is calm.
 */
function TileBreakdown({ tile, hidden }: { tile: EstateTile; hidden: boolean }) {
  // Rendered even while collapsed, hidden rather than unmounted, so the
  // `aria-controls` on the tile's toggle always points at something that
  // exists — a control that announces it expands a region which is not in the
  // document is a control a screen reader cannot follow.
  return (
    <ul className="soc-estate-breakdown" id={`estate-breakdown-${tile.key}`} data-metric={tile.key} hidden={hidden}>
      {tile.contributions.map((part) => (
        <li key={part.tenant} className={cx(part.status === "unread" && "is-unread")}>
          <span className="soc-estate-breakdown-tenant">{part.tenant}</span>
          {part.status === "read" ? (
            <>
              <strong>{count(part.value ?? 0)}</strong>
              {part.detail ? <em>{part.detail}</em> : null}
            </>
          ) : (
            <>
              <strong>not read</strong>
              <em>{part.unreadReason}</em>
            </>
          )}
        </li>
      ))}
      {tile.contributions.length === 0 ? <li className="is-unread">No customer contributed to this figure.</li> : null}
    </ul>
  );
}

/**
 * The estate's risk.
 *
 * The worst customer's score and their name, never an average, with the count
 * on each side of the concern threshold beside it. Unscored customers are
 * printed separately and are explicitly NOT counted as below concern: their
 * read failed, so their posture is unknown, and folding "unknown" into "fine"
 * is the same false all-clear one level down.
 */
function EstatePosture({ summary }: { summary: EstateSummary }) {
  const posture = summary.posture;
  const measured = summary.tenantsRead > 0;
  return (
    <div className={cx("soc-estate-posture", measured && posture.worstScore >= posture.concernThreshold && "is-concern")}>
      <div className="soc-estate-posture-score">
        <span>Worst customer posture</span>
        <strong>{measured ? posture.worstScore : "—"}</strong>
        {measured ? <small>/100</small> : null}
      </div>
      <div className="soc-estate-posture-body">
        {measured ? (
          <p>
            The highest score on the estate is <b>{posture.worstTenant || "an unnamed customer"}</b>&rsquo;s.{" "}
            <b>This is not an estate average</b> — a mean would hide one customer on fire behind nine quiet ones.
          </p>
        ) : (
          <p>
            No customer could be read, so the estate has <b>no posture</b>. This is an unmeasured estate, not a calm one.
          </p>
        )}
        <p className="soc-estate-posture-split">
          <span className="is-concern">
            {posture.tenantsAtOrAboveConcern} at or above the concern threshold ({posture.concernThreshold})
          </span>
          <span>{posture.tenantsBelowConcern} below it</span>
          {posture.tenantsUnscored > 0 ? (
            <span className="is-unread">
              {posture.tenantsUnscored} unscored — their read failed, so they are not &ldquo;below concern&rdquo;
            </span>
          ) : null}
        </p>
        {posture.scale ? <p className="soc-estate-fineprint">{posture.scale}</p> : null}
      </div>
    </div>
  );
}

/** Every customer's contribution to every tile, without a click. See rule 1. */
function EstateTenantTable({ summary }: { summary: EstateSummary }) {
  return (
    <div className="soc-estate-table-wrap">
      <table className="soc-estate-table">
        <caption>
          Every figure above, per customer. Worst posture first; customers that could not be read are last, because
          unknown is not calm.
        </caption>
        <thead>
          <tr>
            <th scope="col">Customer</th>
            <th scope="col">Posture</th>
            <th scope="col">Alerts</th>
            <th scope="col">Actions</th>
            <th scope="col">Held</th>
            <th scope="col">Severed</th>
            <th scope="col">Agents</th>
            <th scope="col">Dropped</th>
          </tr>
        </thead>
        <tbody>
          {orderedTenants(summary).map((row) =>
            row.status === "read" ? (
              <tr key={row.tenant} data-tenant={row.tenant} data-status="read">
                <th scope="row">{row.tenant}</th>
                <td className={cx(row.posture >= summary.posture.concernThreshold && "is-concern")}>{row.posture}</td>
                <td>{count(row.alerts)}</td>
                <td>{count(row.decisions)}</td>
                <td>{count(row.contained)}</td>
                <td>{count(row.severed)}</td>
                <td>
                  {row.agentsFresh}/{row.agents} fresh
                </td>
                <td>{count(row.droppedRecords)}</td>
              </tr>
            ) : (
              // ONE CELL, NOT SEVEN ZEROES. A row of zeroes for a customer
              // nobody could read is indistinguishable from a quiet customer,
              // and it is the reading an operator would act on.
              <tr key={row.tenant} data-tenant={row.tenant} data-status="unread" className="is-unread">
                <th scope="row">{row.tenant}</th>
                <td colSpan={7}>
                  <b>Not read.</b> {row.unreadReason || "this customer could not be read"} — it contributes nothing to
                  the totals above, and no figure here is a zero.
                </td>
              </tr>
            )
          )}
        </tbody>
      </table>
    </div>
  );
}

export function EstateView({
  enabled,
  rangeMin,
  onSelectTenant
}: {
  /**
   * Cross-tenant operator AND no customer selected. Both halves live in the
   * route, and the request is issued only while this is true — a tenant-bound
   * console must never send it, and a provider looking at one customer is not
   * looking at the estate.
   */
  enabled: boolean;
  rangeMin: number;
  /** Jumping from a customer's row straight into that customer's console. */
  onSelectTenant?: (tenant: string) => void;
}) {
  const { summary, loading, error, notOffered, readAt, refresh } = useEstateSummary(enabled, rangeMin);
  const [openTile, setOpenTile] = useState<string | null>(null);

  if (!enabled) return null;
  // A server that does not offer the endpoint gets no banner and no error: the
  // console degrades to the per-customer view it had before this existed, the
  // same way a refused customer roster leaves the top bar alone.
  if (notOffered) return null;

  if (error) {
    return (
      <section className="soc-estate is-error" aria-label="Estate summary">
        <div className="soc-estate-alarm">
          <AlertTriangle size={16} />
          <span>
            <b>The estate could not be read.</b> {error} No estate figures are shown, because a partial estate presented
            as the estate is the reading this view exists to prevent.
          </span>
          <button type="button" onClick={refresh}>
            Retry
          </button>
        </div>
      </section>
    );
  }

  if (!summary) {
    return (
      <section className="soc-estate is-loading" aria-label="Estate summary">
        <div className="soc-estate-alarm">
          <RefreshCw size={16} />
          <span>Reading every customer&rsquo;s window…</span>
        </div>
      </section>
    );
  }

  const tiles = estateTiles(summary);
  const unread = unreadTenants(summary);
  const measured = summary.tenantsRead > 0;

  return (
    <section className="soc-estate" aria-label="Estate summary">
      <header className="soc-estate-head">
        <div className="soc-estate-title">
          <Server size={16} />
          <div>
            <h2>The estate — every customer you reach</h2>
            <p>
              {summary.tenantsRead} of {summary.tenantsTotal} customer{summary.tenantsTotal === 1 ? "" : "s"} read over
              the last {rangeLabel(summary.windowMin || rangeMin)}
              {readAt ? ` · read at ${readStamp(readAt)}` : ""}
              {summary.rosterSource ? ` · roster: ${summary.rosterSource}` : ""}
            </p>
          </div>
        </div>
        <button type="button" className="soc-estate-refresh" onClick={refresh} disabled={loading}>
          <RefreshCw size={14} />
          {loading ? "Reading…" : "Refresh"}
        </button>
      </header>

      {/* THE CUSTOMERS THIS ANSWER IS MISSING, said before any total is read.
          A number that silently excludes a customer is worse than no number,
          because it looks complete. */}
      {unread.length > 0 ? (
        <div className="soc-estate-alarm is-unread" role="status">
          <AlertTriangle size={16} />
          <div>
            <p>
              <b>
                {unread.length} customer{unread.length === 1 ? "" : "s"} could not be read
              </b>{" "}
              and contribute nothing below — every total here is short by whatever they hold:
            </p>
            <ul className="soc-estate-unread-list">
              {unread.map((row) => (
                <li key={row.tenant} data-tenant={row.tenant}>
                  <b>{row.tenant}</b> — {row.unreadReason || "no reason given"}
                </li>
              ))}
            </ul>
            {summary.budgetExceeded ? (
              <p>
                The fan-out ran out of time, so the customers still outstanding when it expired are reported unread
                rather than waited for.
              </p>
            ) : null}
          </div>
        </div>
      ) : null}

      <EstatePosture summary={summary} />

      {/* Numbers are withheld entirely when nothing could be read. A grid of
          zeroes over an estate nobody could measure is a false all-clear, and
          it is the one this view would be most believed on. */}
      {measured ? (
        <div className="soc-estate-tiles">
          {tiles.map((tile) => {
            const open = openTile === tile.key;
            return (
              <div key={tile.key} className={cx("soc-estate-tile", open && "is-open")} data-metric={tile.key}>
                <button
                  type="button"
                  onClick={() => setOpenTile(open ? null : tile.key)}
                  aria-expanded={open}
                  aria-controls={`estate-breakdown-${tile.key}`}
                >
                  <span className="soc-estate-tile-label">{tile.label}</span>
                  <strong className="soc-estate-tile-value">
                    {tile.floor ? "≥ " : ""}
                    {count(tile.value)}
                  </strong>
                  <span className="soc-estate-tile-sub">{tile.sub}</span>
                  <span className="soc-estate-tile-more">
                    {open ? "Hide" : "Per customer"} ({tile.contributions.length})
                  </span>
                </button>
                {tile.partsMismatch ? (
                  <p className="soc-estate-mismatch">
                    The customers listed here add up to {count(tile.partsMismatch.sumOfParts)}, not{" "}
                    {count(tile.value)}. Trust the parts: a total that cannot be broken down is not one you can check.
                  </p>
                ) : null}
                <TileBreakdown tile={tile} hidden={!open} />
              </div>
            );
          })}
        </div>
      ) : null}

      {measured ? (
        <div className="soc-estate-technique">
          <h3>Most-seen technique across the estate</h3>
          {summary.top.technique ? (
            <>
              <p>
                <b>{summary.top.technique}</b> — {count(summary.top.count)} alert
                {summary.top.count === 1 ? "" : "s"}, the mode across customers.
              </p>
              <ul className="soc-estate-breakdown" data-metric="technique">
                {Object.entries(summary.top.byTenant)
                  .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
                  .map(([tenant, n]) => (
                    <li key={tenant}>
                      <span className="soc-estate-breakdown-tenant">{tenant}</span>
                      <strong>{count(n)}</strong>
                    </li>
                  ))}
              </ul>
              {/* Without this split a technique driven entirely by one noisy
                  customer looks identical to a campaign across the estate. */}
              <p className="soc-estate-fineprint">
                {summary.top.sampled
                  ? "At least one customer's split came from a sample of the window's newest alerts, not all of them. "
                  : ""}
                {summary.top.alertsWithoutTechnique > 0
                  ? `${count(summary.top.alertsWithoutTechnique)} alert(s) carried no technique at all, so this does not cover every alert. `
                  : ""}
                {summary.top.note || ""}
              </p>
            </>
          ) : (
            <p className="soc-estate-fineprint">{summary.top.note || "No alert in this window carried a MITRE technique."}</p>
          )}
        </div>
      ) : null}

      <EstateTenantTable summary={summary} />

      {onSelectTenant && summary.tenants.length > 0 ? (
        <div className="soc-estate-jump">
          <span>Open one customer&rsquo;s console:</span>
          {orderedTenants(summary).map((row) => (
            <button key={row.tenant} type="button" onClick={() => onSelectTenant(row.tenant)}>
              {row.tenant}
            </button>
          ))}
        </div>
      ) : null}

      {/* WHAT THIS VIEW DOES NOT SHOW, stated rather than left as a gap.
          Telemetry throughput has no tile because the store cannot count
          records by kind over a window; an empty tile would be read as zero
          events, which is a claim the platform cannot make. */}
      <p className="soc-estate-fineprint soc-estate-absent">
        Telemetry throughput is not shown for the estate: the store has no windowed count-by-kind primitive, so no
        cross-customer figure exists for it. It is absent rather than zero.
        {summary.maxTenants ? ` This response fans out over at most ${summary.maxTenants} customers.` : ""}
      </p>
    </section>
  );
}
