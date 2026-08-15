// What the console is currently disclosing about its own data.
//
// Four separate statements, deliberately not merged: an endpoint is failing;
// an endpoint is disabled; the server capped its aggregation; the client buffer
// does not span the window. Each has a different remedy and a different level
// of alarm, and each has been wrong on a live console at least once — the
// comments below say how.
import { InlineNotice } from "./components";
import { formatDuration, rangeLabel } from "./format";
import type { SocWindowModel } from "./useSocWindowModel";

export function SocNotices({ model, rangeMin }: { model: SocWindowModel; rangeMin: number }) {
  const { activeEndpointErrors, countsUnfounded, storeFault, disabledEndpoints, serverStats, statsSupported, windowCoverage } = model;
  return (
    <>
      {activeEndpointErrors.length ? (
        <InlineNotice
          tone={countsUnfounded ? "danger" : "warn"}
          title={
            countsUnfounded
              ? "Telemetry feed is down — the counts below are not a measurement of this window."
              : "Some read-only SOC endpoints are unavailable."
          }
        >
          {countsUnfounded
            ? `${
                storeFault
                  ? `The control plane cannot read its central store (${storeFault}), so every telemetry endpoint is failing together. `
                  : ""
              }Showing only what the live stream has delivered since the last successful load. Do not read these totals, deltas or the posture score as the state of the ${rangeLabel(
                rangeMin
              )} window. ${activeEndpointErrors.map(([key, error]) => `${key}: ${error}`).join("; ")}`
            : activeEndpointErrors.map(([key, error]) => `${key}: ${error}`).join("; ")}
        </InlineNotice>
      ) : null}
      {disabledEndpoints.length ? (
        <InlineNotice tone="info" title="Disabled endpoint state detected.">
          {disabledEndpoints.join(", ")}
        </InlineNotice>
      ) : null}
      {serverStats?.truncated ? (
        <InlineNotice tone="warn" title="Counts are a floor — this window exceeds the server's scan limit.">
          More alerts fall in this {rangeLabel(rangeMin)} window than the control plane will aggregate in one pass.
          Narrow the range for exact totals.
        </InlineNotice>
      ) : null}
      {!windowCoverage.complete ? (
        serverStats ? (
          // Counts, deltas and the timeline are server-computed and cover the
          // whole window; only the row-level panels are buffer-bound.
          //
          // This used to be a full-width band on every load, which is the
          // wrong shape for the message: it is not a page-level condition,
          // it is a property of three specific panels, and a permanent
          // interstitial is one operators stop reading. The disclosure now
          // rides on the affected panels' own headers (see coveragePill),
          // where it is visible at the moment the rows are being read and
          // absent from the panels it never applied to.
          null
        ) : (
          <InlineNotice tone="warn" title="Partial window — counts below are a floor, not a total.">
            The console holds only the most recent {formatDuration(windowCoverage.coveredMs)} of this{" "}
            {rangeLabel(rangeMin)} window ({windowCoverage.shortFeeds.join(" and ")} reach no further back)
            {statsSupported ? "" : ", and this server does not provide window totals"}. Narrow the range to see a
            complete picture.
          </InlineNotice>
        )
      ) : null}
    </>
  );
}
