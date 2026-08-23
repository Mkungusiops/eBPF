/**
 * The enforcement ladder — shared vocabulary for every surface that can contain
 * something (correlation graph, Choke Gateway, Devices).
 *
 * There is one state machine in the product and it must read identically
 * everywhere: an operator who learns the ladder on the graph should not have to
 * relearn it on Devices. The rungs, the ordering, the "only climbs" rule and the
 * copy all live here so the three surfaces cannot drift apart.
 */

export const LADDER = ["pristine", "throttled", "tarpit", "quarantined", "severed"] as const;

export type Rung = (typeof LADDER)[number];

/** The verb that moves a target ONTO a rung. */
export const ACTION_FOR_RUNG: Record<Rung, string> = {
  pristine: "pristine", // a release, not a downward step
  throttled: "throttle",
  tarpit: "tarpit",
  quarantined: "quarantine",
  severed: "sever"
};

/** The rung an action lands on — used to confirm the target actually moved. */
export const RUNG_FOR_ACTION: Record<string, Rung> = {
  pristine: "pristine",
  throttle: "throttled",
  tarpit: "tarpit",
  quarantine: "quarantined",
  sever: "severed"
};

/** Button copy. Distinct from the rung name: rungs are states, buttons are verbs. */
export const LABEL_FOR_RUNG: Record<Rung, string> = {
  pristine: "Pristine",
  throttled: "Throttle",
  tarpit: "Tarpit",
  quarantined: "Quarantine",
  severed: "Sever"
};

/** Actions the server rejects without a reason, so the UI collects it up-front. */
export const REASON_REQUIRED: ReadonlySet<Rung> = new Set<Rung>(["quarantined", "severed"]);

export function ladderIndex(state: string | undefined): number {
  const i = LADDER.indexOf((state ?? "pristine") as Rung);
  return i < 0 ? 0 : i;
}

export interface EnforcementTarget {
  /** exec_id for a process, MAC for a device. */
  id: string;
  /** What the operator sees: binary name, or hostname/MAC. */
  label: string;
  pid?: number;
  /** Host/agent the target sits on, when known. */
  host?: string;
}

export interface EnforcementResult {
  ok: boolean;
  detail: string;
}

/**
 * Why the top rung behaves differently per target kind.
 *
 * A process sever is a SIGKILL: the process no longer exists, so nothing —
 * including release — can apply afterwards. The thaw endpoint still returns 200
 * and changes nothing, which reads as a successful action that silently did
 * nothing, so the whole ladder is disabled instead.
 *
 * A device sever is a reversible drop rule. Verified against the live engine:
 * sever -> severed, then thaw -> pristine. Copying the process rule here would
 * have disabled a release that genuinely works.
 */
export interface TerminalPolicy {
  /** True when reaching the top rung ends the target's life. */
  terminal: boolean;
  /** Shown once the target is on the top rung. */
  terminalNote?: string;
  /** Shown between the first press of the top rung and its confirmation. */
  confirmNote: string;
}

export const PROCESS_TERMINAL: TerminalPolicy = {
  terminal: true,
  terminalNote:
    "Terminal state — this process was severed (SIGKILL). Nothing further can be applied, and it cannot be released.",
  confirmNote: "sends SIGKILL. This cannot be undone — press again to confirm."
};

export const DEVICE_TERMINAL: TerminalPolicy = {
  terminal: false,
  confirmNote:
    "cuts this device off the network. It stays severed until released — press again to confirm."
};

/**
 * The audit chain has THREE states, and collapsing them to a boolean makes a
 * false statement in one direction or the other.
 *
 * The single-tenant engine hash-chains its decisions and answers
 * `{ok: true, total: N}`. The multi-tenant control plane does NOT chain
 * centrally — each agent chains its own — and answers
 * `{ok: false, supported: false}`. A surface that tests only `ok === false`
 * therefore reports BROKEN on every multi-tenant deployment, permanently, for
 * a check that was never run.
 *
 * Measured on console.adanianlabs.io 2026-08-22: the Choke Gateway footer read
 * "chain broken @ ?", the System Health tile read "broken", the assurance
 * banner read "CHAIN BROKEN" in alarm red, and the downloadable board report
 * carried `audit.intact: false` — all four telling a customer its
 * tamper-evidence had failed when the control plane simply does not maintain a
 * central chain. That is the single worst thing to be wrong about on a
 * compliance surface.
 *
 * This lives in common/ rather than in one of the callers because the same
 * verdict is rendered in six places across the Choke and Devices surfaces, and
 * the fix has already been applied to two of them and missed on the other four
 * once — see the drift note at the top of ChokeRoute.tsx.
 */
export type AuditVerdict = "verified" | "broken" | "unverifiable";

export function auditVerdict(audit?: { ok?: boolean; supported?: boolean } | null): AuditVerdict {
  if (!audit) return "unverifiable";
  if (audit.supported === false) return "unverifiable";
  return audit.ok === false ? "broken" : "verified";
}

/** Short label for a status pill or footer. */
export function auditVerdictLabel(verdict: AuditVerdict): string {
  if (verdict === "unverifiable") return "not verified here";
  return verdict === "broken" ? "broken" : "verified";
}

/** Whether this verdict should be rendered as an alarm. "unverifiable" must not be. */
export function auditVerdictIsAlarm(verdict: AuditVerdict): boolean {
  return verdict === "broken";
}
