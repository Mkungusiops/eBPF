/**
 * Access trail — who opened this tenant's estate, and who was refused.
 *
 * # Why a customer needs this and not just the provider
 *
 * On an MSSP control plane the customer is not the operator. Safaricom's own
 * analysts cannot see which MSOC engineer opened their estate at 3am unless the
 * platform shows them, and "trust us, it is logged" is a promise about a table
 * only the provider can read — which is not a transparency control.
 *
 * So the same rows are cut two ways: a cross-tenant operator sees the whole
 * trail including attempts on tenants they were refused, a tenant-bound analyst
 * sees exactly the rows naming their own tenant. Neither view invents a row the
 * other cannot see.
 *
 * # The omission that has to be stated
 *
 * Ordinary own-tenant reads are not recorded. They are the overwhelming
 * majority and carry no information, and holding them would bury the entries an
 * auditor is looking for. But a reader who does not know that would conclude
 * from an empty list that nobody read anything — so the panel says it, rather
 * than letting the absence speak.
 */
import { useCallback, useEffect, useState } from "react";
import { ShieldAlert, ShieldCheck } from "lucide-react";
import { InlineNotice, cx } from "./components";
import { getJSON } from "../../lib/api";
import { isRouteNotServed } from "./settingsModel";

export interface AccessRecord {
  subject: string;
  tenant_id: string;
  action: string;
  allowed: boolean;
  cross_tenant: boolean;
  detail?: string;
  at: string;
}

export interface AccessTrail {
  supported: boolean;
  records: AccessRecord[];
  scope?: string;
  viewing?: string;
  returned?: number;
  total?: number;
  truncated?: boolean;
  cross_tenant?: boolean;
  records_kept?: string;
  detail?: string;
  error?: string;
}

function when(iso: string): string {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return iso;
  return new Date(t).toLocaleString();
}

export function AccessTrailPanel() {
  const [data, setData] = useState<AccessTrail | null>(null);
  const [loadError, setLoadError] = useState("");
  const [unsupported, setUnsupported] = useState(false);

  const load = useCallback(async () => {
    try {
      const raw = await getJSON<Partial<AccessTrail>>("/api/operator-audit?limit=100");
      setData({
        supported: raw?.supported !== false,
        // Normalised on the way in: a 200 with a body this component did not
        // expect must leave the panel rendering rather than throwing in .map.
        records: Array.isArray(raw?.records) ? raw.records : [],
        scope: raw?.scope,
        viewing: raw?.viewing,
        returned: raw?.returned,
        total: raw?.total,
        truncated: raw?.truncated === true,
        cross_tenant: raw?.cross_tenant === true,
        records_kept: raw?.records_kept,
        detail: raw?.detail,
        error: raw?.error
      });
      setUnsupported(false);
      setLoadError("");
    } catch (e) {
      const msg = e instanceof Error ? e.message : "could not read the access trail";
      // A single-tenant engine has one operator and no tenant boundary to
      // cross, so it does not serve this route. That is not a failure.
      if (isRouteNotServed(e)) {
        setUnsupported(true);
        setLoadError("");
      } else {
        setLoadError(msg);
      }
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (unsupported) {
    return (
      <InlineNotice tone="info" title="Not applicable to this deployment">
        This is a single-host engine with one operator and no tenant boundary, so there is no cross-tenant access
        to record.
      </InlineNotice>
    );
  }
  if (loadError) {
    return (
      <InlineNotice tone="warn" title="The access trail could not be read">
        {loadError}. That is not the same as nobody having accessed anything — nothing is being claimed either way.
      </InlineNotice>
    );
  }
  if (!data) return <p className="soc-settings-help">Reading the access trail…</p>;

  if (!data.supported) {
    return (
      <InlineNotice tone="warn" title="No durable access trail on this deployment">
        {data.detail ||
          "Access records live only in memory here and are lost on restart, so nothing can be shown about who accessed what before now."}
      </InlineNotice>
    );
  }
  if (data.error) {
    return (
      <InlineNotice tone="warn" title="The access trail could not be read">
        {data.error}
      </InlineNotice>
    );
  }

  const denied = data.records.filter((r) => !r.allowed).length;

  return (
    <div className="soc-guardrails">
      <div className="soc-guardrail-block">
        <div className="soc-guardrail-blockhead">
          {denied > 0 ? <ShieldAlert size={13} aria-hidden="true" /> : <ShieldCheck size={13} aria-hidden="true" />}
          <strong>{data.viewing === "all tenants" ? "Every tenant" : "This tenant"}</strong>
          <span className={cx("soc-settings-badge", denied > 0 ? "is-not-wired" : "is-live")}>
            {denied > 0 ? `${denied} refused` : "none refused"}
          </span>
        </div>
        <p className="soc-settings-help">
          {data.records_kept ||
            "Cross-tenant access and every refused attempt. Ordinary own-tenant reads are not recorded."}
        </p>
        {data.truncated ? (
          <p className="soc-settings-caveat">
            Showing the newest {data.returned} of {data.total}. This is not the whole trail.
          </p>
        ) : null}
      </div>

      {data.records.length === 0 ? (
        <p className="soc-settings-caveat">
          No cross-tenant access and no refused attempt has been recorded. Ordinary reads by operators of this
          tenant are not recorded, so this being empty does not mean nobody read anything.
        </p>
      ) : (
        <div className="soc-accesstrail">
          {data.records.map((r, i) => (
            <div key={`${r.at}-${r.subject}-${i}`} className={cx("soc-accessrow", r.allowed ? "" : "is-denied")}>
              <span className="soc-accessrow-when">{when(r.at)}</span>
              <span className="soc-accessrow-who">{r.subject || "unknown"}</span>
              <span className={cx("soc-settings-badge", r.allowed ? "is-live" : "is-not-wired")}>
                {r.allowed ? "allowed" : "refused"}
              </span>
              <span className="soc-accessrow-what">
                {r.action} on {r.tenant_id || "—"}
              </span>
              {r.detail ? <span className="soc-accessrow-why">{r.detail}</span> : null}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
