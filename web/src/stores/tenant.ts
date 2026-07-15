import { create } from "zustand";

import { defaultTenant, nextActiveTenant, type TenantIdentity } from "../lib/tenantCore";

interface TenantStore {
  identity?: TenantIdentity;
  activeTenant?: string;
  /** Set after the BFF whoami resolves; defaults the active tenant. */
  setIdentity: (id: TenantIdentity) => void;
  /** Tenant switcher: ignores switches the operator is not authorized for. */
  switchTenant: (tenant: string) => void;
  clear: () => void;
}

/**
 * useTenantStore holds the console's tenant UX state. It is NOT an authority —
 * every API call is authorized server-side by internal/authz. The switcher only
 * chooses which authorized tenant the panels read.
 */
export const useTenantStore = create<TenantStore>((set) => ({
  identity: undefined,
  activeTenant: undefined,
  setIdentity: (id) => set({ identity: id, activeTenant: defaultTenant(id) }),
  switchTenant: (tenant) =>
    set((s) => ({ activeTenant: nextActiveTenant(s.identity, s.activeTenant, tenant) })),
  clear: () => set({ identity: undefined, activeTenant: undefined })
}));
