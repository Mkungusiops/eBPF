/**
 * The settings model: what is configurable, who asks, and what happens when
 * you change it.
 *
 * # Why this is data rather than JSX
 *
 * The first version was a single page of suppression controls — an ANALYST
 * surface. "Settings" for a platform means the questions a customer's platform
 * team asks after handover, and those have different owners, different
 * lifecycles, and on a multi-tenant deployment different SCOPES. Encoding that
 * as data means the page cannot quietly present a restart-required knob as
 * live, or a platform-wide one as per-tenant, because every row has to declare
 * both.
 *
 * # Lifecycle is not decoration
 *
 * This codebase's recurring defect is a surface claiming more than it can do.
 * A settings page is where that does the most damage: an operator changes a
 * value, sees no error, and believes the platform now behaves differently.
 * Every row therefore states which of these it is, and the UI renders them
 * differently rather than making them all look like editable fields.
 */
export type Lifecycle =
  /** Applies immediately and survives a restart. */
  | "live"
  /** Applies immediately, LOST on restart — the honest label for a runtime-only knob. */
  | "live-not-persisted"
  /** Stored, but the process must restart before it takes effect. */
  | "restart-required"
  /** Owned by the deploy. Shown as a value; editing it here would be a lie by the next deploy. */
  | "deploy-managed"
  /** The mechanism exists and nothing drives it yet. Stated, never rendered as a control. */
  | "not-wired";

/** On a multi-tenant control plane, who a change affects. */
export type Scope = "per-tenant" | "platform-wide" | "this-host";

export interface SettingRow {
  key: string;
  label: string;
  /** The question an operator is actually asking. */
  help: string;
  lifecycle: Lifecycle;
  scope: Scope;
  /** Rendered when the lifecycle means the value cannot simply be trusted. */
  caveat?: string;
}

export interface SettingSection {
  id: string;
  /** Phrased as the question, not the mechanism — that is what makes it findable. */
  title: string;
  question: string;
  /** Who in a customer organisation owns this. */
  owner: string;
  rows: SettingRow[];
}

export const LIFECYCLE_LABEL: Record<Lifecycle, string> = {
  live: "Live",
  "live-not-persisted": "Live · not saved",
  "restart-required": "Needs restart",
  "deploy-managed": "Set by deploy",
  "not-wired": "Not available yet"
};

/**
 * The sections, ordered by how often a customer touches them.
 *
 * Everything here is a knob that genuinely exists. Nothing aspirational:
 * a settings page listing a control the platform does not have is worse than
 * one that omits it, because the operator plans around it.
 */
export const SETTINGS_SECTIONS: SettingSection[] = [
  {
    id: "noise",
    title: "Noise",
    question: "Something we know is fine keeps producing findings.",
    owner: "SOC analyst",
    rows: [
      {
        key: "suppressions",
        label: "Expected behaviour",
        help: "Stop a binary you recognise from adding to a score. The event is still recorded and the binary can still be contained by hand.",
        lifecycle: "live",
        scope: "per-tenant"
      }
    ]
  },
  {
    id: "response",
    title: "Response",
    question: "When should the platform act, and is it allowed to act on its own?",
    owner: "Security lead",
    rows: [
      {
        key: "thresholds",
        label: "Containment ladder, mode and emergency stop",
        help: "The scores at which a process is throttled, tarpitted, quarantined and severed — whether the ladder acts on its own, and the switch that stops everything.",
        lifecycle: "live-not-persisted",
        scope: "per-tenant",
        caveat:
          "Applies immediately across the fleet, but is NOT stored: a restart returns the host to its deployed values. " +
          "Persisting it is the next piece of work."
      },
    ]
  },
  {
    id: "guardrails",
    title: "Guardrails",
    question: "What must this platform never touch?",
    owner: "Platform team",
    rows: [
      {
        key: "protected",
        label: "Protected binaries and devices",
        help: "Processes and MAC addresses that containment must always refuse — the defence against locking yourself out of your own estate.",
        lifecycle: "live-not-persisted",
        scope: "per-tenant",
        caveat:
          "Takes effect immediately. On the control plane the list is stored per tenant and re-pushed on every " +
          "change; on a single-tenant engine it lives in the running gateway, so a restart falls back to what " +
          "the deploy configured. The compiled-in floor survives either way and cannot be removed from here."
      }
    ]
  },
  {
    id: "evidence",
    title: "Evidence",
    question: "How long do we keep it, and are we losing any?",
    owner: "Compliance",
    rows: [
      {
        key: "retention",
        label: "Event and alert retention",
        help: "How long telemetry is kept before pruning. Containment decisions are never pruned.",
        lifecycle: "live",
        scope: "per-tenant",
        caveat:
          "A tenant may only ever SHORTEN its horizon. Asking for longer than the deployment keeps is stored and " +
          "has no effect, because the platform-wide prune has already removed those rows. Below the floor the " +
          "request is raised to it: the console compares every range against the prior range of the same length."
      }
    ]
  },
  {
    id: "access",
    title: "Access",
    question: "Who can do what, and does anything need a second pair of eyes?",
    owner: "Platform team",
    rows: [
      {
        key: "rbac",
        label: "Roles and tenant scope",
        help: "Which operators can read, respond, and act across tenants.",
        lifecycle: "deploy-managed",
        scope: "platform-wide",
        caveat: "Provisioned in Keycloak by the deploy. Change it there, not here."
      },
      {
        key: "access-trail",
        label: "Who accessed what",
        help: "Cross-tenant access and every refused attempt, recorded durably and readable by the tenant itself.",
        lifecycle: "live",
        scope: "per-tenant",
        caveat:
          "Ordinary own-tenant reads are not recorded — they are the majority and would bury the entries that " +
          "matter. An empty trail therefore does not mean nobody read anything."
      },
      {
        key: "dual-control",
        label: "Second operator for destructive actions",
        help: "Hold quarantine, sever and fleet arming in an approval queue until someone other than the requester approves them.",
        lifecycle: "live",
        scope: "per-tenant",
        caveat:
          "Takes effect on the next request; nothing needs restarting. If the platform was deployed with " +
          "four-eyes mandated it cannot be switched off here — a tenant may only tighten. Switching it off " +
          "never releases requests already waiting in the queue."
      }
    ]
  },
  {
    id: "platform",
    title: "Platform",
    question: "Where does this run, and against what?",
    owner: "Platform team",
    rows: [
      {
        key: "runtime",
        label: "Listeners, store, identity, telemetry",
        help: "The deployed shape of this installation.",
        lifecycle: "deploy-managed",
        scope: "platform-wide",
        caveat:
          "The deploy rewrites these config files whole on every run, so anything edited here would be silently " +
          "reverted. Shown as the effective value. Secrets are deliberately absent."
      }
    ]
  }
];
