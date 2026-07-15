import { Building2, ShieldCheck } from "lucide-react";

import { useTenantStore } from "../stores/tenant";
import "./TenantSwitcher.css";

// TenantSwitcher lets an operator choose which authorized tenant the console's
// panels read. It only offers tenants the operator can access; the server
// (internal/authz) is the real enforcement, so this is UX, not security. A
// cross-tenant MSOC operator is badged; picking arbitrary tenants for them needs
// the tenant-list API (fleet/identity service) and is left to that wiring.
export function TenantSwitcher() {
  const identity = useTenantStore((s) => s.identity);
  const active = useTenantStore((s) => s.activeTenant);
  const switchTenant = useTenantStore((s) => s.switchTenant);

  if (!identity) return null;

  const options = identity.tenants;
  const canSwitch = options.length > 1;

  return (
    <div className="tenant-switcher" data-testid="tenant-switcher">
      <Building2 className="tenant-switcher__icon" size={16} aria-hidden />
      <span className="tenant-switcher__subject">{identity.subject}</span>
      {canSwitch ? (
        <select
          className="tenant-switcher__select"
          aria-label="Active tenant"
          value={active ?? ""}
          onChange={(e) => switchTenant(e.target.value)}
        >
          {options.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      ) : (
        <span className="tenant-switcher__single">{active ?? (identity.crossTenant ? "all tenants" : "—")}</span>
      )}
      {identity.crossTenant && (
        <span className="tenant-switcher__badge" title="cross-tenant MSOC role">
          <ShieldCheck size={12} aria-hidden /> MSOC
        </span>
      )}
    </div>
  );
}
