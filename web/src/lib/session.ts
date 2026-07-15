// Console v2 session bootstrap. On load, the app asks the BFF who it is
// (fetchWhoami over the same-origin session cookie); a 401 means no session, so
// we hand off to the BFF login flow. The tenant identity is placed in the tenant
// store; the server (authz) remains the authority for every subsequent call.

import { ApiError } from "./api";
import { fetchWhoami, loginUrl } from "./console";
import type { TenantIdentity } from "./tenantCore";
import { useTenantStore } from "../stores/tenant";

export type SessionStatus = "authenticated" | "redirecting" | "error";

// SessionDeps are injectable for testing; production uses the defaults.
export interface SessionDeps {
  whoami: () => Promise<TenantIdentity>;
  setIdentity: (id: TenantIdentity) => void;
  redirect: (url: string) => void;
}

const defaultDeps: SessionDeps = {
  whoami: fetchWhoami,
  setIdentity: (id) => useTenantStore.getState().setIdentity(id),
  redirect: (url) => {
    window.location.href = url;
  }
};

/**
 * loadSession resolves the operator's identity into the tenant store, or hands
 * off to login on 401. It never throws: it returns a status the shell renders.
 */
export async function loadSession(deps: SessionDeps = defaultDeps): Promise<SessionStatus> {
  try {
    const identity = await deps.whoami();
    deps.setIdentity(identity);
    return "authenticated";
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      deps.redirect(loginUrl());
      return "redirecting";
    }
    return "error";
  }
}
