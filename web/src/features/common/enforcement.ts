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
