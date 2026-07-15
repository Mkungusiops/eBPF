// Pure multi-tenant logic for console v2 (no React/fetch), mirroring the
// server's authz so the UI never offers an obviously-invalid action. The SERVER
// (internal/authz + the BFF) is always the real authority; this only shapes UX.

export interface TenantIdentity {
  /** operator subject (from the BFF session, never a token) */
  subject: string;
  /** tenants the operator may access without a cross-tenant role */
  tenants: string[];
  /** holds an MSOC cross-tenant role */
  crossTenant: boolean;
}

/** Shape of GET /api/whoami served by the BFF. */
export interface WhoamiResponse {
  subject: string;
  tenants: string[] | null;
  cross_tenant: boolean;
}

export function parseWhoami(raw: WhoamiResponse): TenantIdentity {
  return {
    subject: raw.subject,
    tenants: raw.tenants ?? [],
    crossTenant: Boolean(raw.cross_tenant)
  };
}

/**
 * canAccessTenant mirrors authz.Authorize: an operator reaches a tenant if it is
 * in their authorized set, or they hold a cross-tenant role.
 */
export function canAccessTenant(id: TenantIdentity | undefined, tenant: string): boolean {
  if (!id || !tenant) return false;
  return id.crossTenant || id.tenants.includes(tenant);
}

/** defaultTenant is the initial active tenant after login. */
export function defaultTenant(id: TenantIdentity): string | undefined {
  return id.tenants[0];
}

/**
 * nextActiveTenant resolves a switch request: it returns the requested tenant
 * only if permitted, otherwise the current one (the server would reject an
 * unauthorized switch anyway).
 */
export function nextActiveTenant(
  id: TenantIdentity | undefined,
  current: string | undefined,
  requested: string
): string | undefined {
  return canAccessTenant(id, requested) ? requested : current;
}
