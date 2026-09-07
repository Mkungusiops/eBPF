// Whether the signed-in account may send containment and configuration writes.
//
// Shared by BOTH choke planes — the process gateway in this folder and the
// device gateway in features/devices — because they ask the same question of
// the same whoami payload and must answer it identically. The two planes arm
// independently (a device sever and a process sever are different commands to
// different enforcers), but the permission behind them is one grant:
// authz.CanRespond, published by the control plane's handleWhoami as
// `can_respond`.
//
// Three states, and the third is the one that matters. `null` means the server
// did not say, and it must be read as PERMITTED: only the multi-tenant control
// plane publishes `can_respond` at all, so treating a missing field as false
// would take the kill-switch away from every single-tenant operator on the
// grounds of a permission model their server does not implement.
export function readCanRespond(whoami: unknown): boolean | null {
  if (!whoami || typeof whoami !== "object") return null;
  const record = whoami as Record<string, unknown>;
  const raw = record.can_respond ?? record.canRespond;
  return typeof raw === "boolean" ? raw : null;
}

/**
 * Why a control is withheld, said in the language of PERMISSION.
 *
 * Not "unavailable", not "disabled", not "not enabled on this deployment". An
 * operator who reads any of those goes looking for a broken estate; the truth
 * is that the control works, the estate is fine, and this account may not use
 * it. Naming the wrong cause during an incident costs the minutes it takes to
 * rule out an outage that never happened.
 */
export function readOnlyReason(subject: string): string {
  return (
    `Your account is read-only: it can watch ${subject}, but not contain or reconfigure it. ` +
    `Ask an operator with response rights to send this.`
  );
}

/** The short form, for a button's `title` where a sentence will not fit. */
export const READ_ONLY_TITLE = "Your account is read-only — it has no response rights.";
