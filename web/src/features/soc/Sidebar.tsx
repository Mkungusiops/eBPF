// The left navigation rail.
//
// Production information architecture: jobs-to-be-done, not a flat panel dump.
// The grouping and the "active" rule are the interesting part and both live
// here, so the composition root only has to say which surface is open.
import {
  Activity,
  Bell,
  ChevronDown,
  Clock,
  Cpu,
  Database,
  Download,
  Eye,
  FileText,
  Gauge,
  GitBranch,
  HelpCircle,
  LayoutDashboard,
  Menu,
  Network,
  Radar,
  Settings,
  ShieldAlert,
  Sparkles,
  Wifi,
  UserCircle,
  X,
  Zap
, SlidersHorizontal } from "lucide-react";
import type * as React from "react";
import { cx } from "./components";
import { useLocalJsonState } from "./hooks";
import { SOC_PANEL_INVENTORY } from "./panelInventory";
import { PANELS, type OpenSurface } from "./dashboard";

export function SocSidebar({
  sidebarOpen,
  openSurface,
  onToggleSidebar,
  onCloseSidebar,
  onOpenSurface,
  onOpenAssistant,
  assistantOpen,
  assistantAvailable,
  watchlistCount,
  labMode,
  notificationBadge,
  userName
}: {
  /** Whether this deployment exposes the demo/lab surfaces. See SocVersion.labMode. */
  labMode: boolean;
  sidebarOpen: boolean;
  openSurface: OpenSurface | null;
  onToggleSidebar: () => void;
  onCloseSidebar: () => void;
  onOpenSurface: (surface: OpenSurface) => void;
  /**
   * The assistant is NOT an OpenSurface. The surfaces are mutually exclusive
   * overlays, so routing the assistant through them would close whatever the
   * analyst was reading — exactly what platform-assistant.md §5 forbids. It
   * gets its own pair of props so it can be open ALONGSIDE any surface.
   */
  onOpenAssistant: () => void;
  assistantOpen: boolean;
  /**
   * Whether this deployment has an assistant.
   *
   * Behaviour & Intel is reached FROM the assistant now, so it no longer needs
   * a nav entry of its own — except when there is no assistant to reach it
   * from. Enrichment is on by default and the assistant is opt-in and off by
   * default, so that case is the common one, not the edge one: without this
   * fallback a deployment with no model configured could not see whether its
   * behavioural baseline was ready or its threat-intel feeds had loaded.
   */
  assistantAvailable: boolean;
  watchlistCount: number;
  notificationBadge: number | undefined;
  userName: string;
}) {
  return (
    <>
      <aside className="soc-sidebar" data-panel={PANELS["left-sidebar"].id}>
        <button
          type="button"
          className="soc-sidebar-toggle"
          onClick={onToggleSidebar}
          aria-label="Toggle sidebar"
          title="Toggle sidebar"
        >
          <Menu size={18} />
        </button>
        {/* Production information architecture: jobs-to-be-done, not a flat panel
            dump. The two choke gateways — the platform's UVP — are elevated into
            their own "Respond" group at the top. Demo/diagnostic tools are kept
            but relocated under Manage; the Command Palette is a ⌘K shortcut, not a
            nav destination. Items map only to surfaces that actually exist. */}
        <SidebarSection title="Overview">
          {/* Dashboard is "here" only when no tool overlay is open (a KPI drill is
              still a dashboard interaction). Opening any tool moves the highlight
              to that tool and returns it here on close. */}
          <SidebarLink icon={LayoutDashboard} label="Dashboard" href="/" active={openSurface === null || openSurface === "kpi"} />
        </SidebarSection>
        <SidebarSection title="Respond">
          <SidebarLink icon={ShieldAlert} label="Choke Gateway" href="/choke" />
          <SidebarLink icon={Wifi} label="Device Choke" href="/devices" />
        </SidebarSection>
        <SidebarSection title="Detect & Investigate">
          <SidebarButton icon={Gauge} label="MITRE Coverage" onClick={() => onOpenSurface("mitre")} active={openSurface === "mitre"} />
          <SidebarButton icon={GitBranch} label="Correlation Graph" onClick={() => onOpenSurface("graph")} active={openSurface === "graph"} />
          <SidebarButton icon={Clock} label="Time Machine" onClick={() => onOpenSurface("time-machine")} active={openSurface === "time-machine"} />
        </SidebarSection>
        <SidebarSection title="Intelligence">
          {/* Top of Intelligence, above Watchlist: it is an intelligence
              surface, and inventing a group for one item makes the nav worse.
              Same Sparkles icon as the drill-panel assistant so the two read as
              one feature rather than two products. */}
          <SidebarButton icon={Sparkles} label="Assistant" onClick={onOpenAssistant} active={assistantOpen} />
          {/* Behaviour & Intel is opened from inside the Assistant, so it earns
              a nav entry only when there is no assistant to open it from.
              Without this the panel would be unreachable on every deployment
              that has not configured a model — which is the default. */}
          {!assistantAvailable ? (
            <SidebarButton icon={Radar} label="Behaviour & Intel" onClick={() => onOpenSurface("behaviour")} active={openSurface === "behaviour"} />
          ) : null}
          <SidebarButton icon={Eye} label="Watchlist" onClick={() => onOpenSurface("watchlist")} badge={watchlistCount} active={openSurface === "watchlist"} />
          {labMode ? (
            <SidebarButton icon={Database} label="Honeypots" onClick={() => onOpenSurface("honeypots")} active={openSurface === "honeypots"} />
          ) : null}
        </SidebarSection>
        <SidebarSection title="Manage">
          <SidebarButton icon={FileText} label="Policies" onClick={() => onOpenSurface("policies")} active={openSurface === "policies"} />
          {/* Lab surfaces. Hidden unless the server says this deployment is a
              lab — see SocVersion.labMode. Attack Sim runs a script as root on
              the host being defended (and, on the control plane, writes
              fabricated alerts into the tenant's real evidence store);
              Honeypots reports invented decoy hits there; the Rule Simulator
              tunes a severity ladder that no endpoint can actually persist, so
              a tuning session in it changes nothing anywhere. */}
          {labMode ? (
            <SidebarButton icon={Settings} label="Rule Simulator" onClick={() => onOpenSurface("simulator")} active={openSurface === "simulator"} />
          ) : null}
          {labMode ? (
            <SidebarButton icon={Zap} label="Attack Sim" onClick={() => onOpenSurface("attacks")} active={openSurface === "attacks"} />
          ) : null}
          <SidebarButton icon={Network} label="Fleet" onClick={() => onOpenSurface("fleet")} active={openSurface === "fleet"} />
          <SidebarButton icon={Cpu} label="Sensor Health" onClick={() => onOpenSurface("kprobes")} active={openSurface === "kprobes"} />
          {/* Tuning lives next to the surface that shows what needs tuning. */}
          <SidebarButton icon={SlidersHorizontal} label="Settings" onClick={() => onOpenSurface("settings")} active={openSurface === "settings"} />
          <SidebarButton icon={Download} label="Reports" onClick={() => onOpenSurface("export")} active={openSurface === "export"} />
        </SidebarSection>
        <SidebarSection title="Settings">
          <SidebarButton
            icon={Bell}
            label="Notifications"
            onClick={() => onOpenSurface("notifications")}
            badge={notificationBadge}
            active={openSurface === "notifications"}
          />
          <SidebarButton icon={HelpCircle} label="Help" onClick={() => onOpenSurface("help")} active={openSurface === "help"} />
        </SidebarSection>
        <div className="soc-sidebar-spacer" />
        <SidebarSection title="Account">
          <SidebarButton icon={UserCircle} label={userName} onClick={() => onOpenSurface("profile")} active={openSurface === "profile"} />
          <SidebarLink icon={X} label="Sign out" href="/api/logout" />
        </SidebarSection>
        {/* The denominator is derived, not typed. It was a literal 31, so
            adding the Behaviour & Reputation panel made the console report
            "32/31 SOC panels" — a small thing that says loudly the numbers on
            this screen are not maintained. */}
        <div className="soc-sidebar-foot">{SOC_PANEL_INVENTORY.length} SOC panels</div>
      </aside>

      {/* Phone-only dismiss scrim for the overlay sidebar drawer. */}
      <button
        type="button"
        className="soc-sidebar-scrim"
        aria-label="Close menu"
        tabIndex={sidebarOpen ? 0 : -1}
        onClick={onCloseSidebar}
      />
    </>
  );
}

function SidebarSection({
  title,
  children,
  collapsible = true,
  defaultOpen = true
}: {
  title: string;
  children: React.ReactNode;
  collapsible?: boolean;
  defaultOpen?: boolean;
}) {
  const slug = title.toLowerCase().replace(/[^a-z0-9]+/g, "-");
  // v2: the nav IA was reshaped, so old persisted collapse state is discarded —
  // everyone starts from the intended expanded default rather than inheriting a
  // stale all-collapsed rail that hides the whole menu.
  const [open, setOpen] = useLocalJsonState<boolean>(`soc.nav.v2.${slug}`, defaultOpen);
  // Overview / Account stay pinned (Dashboard and Sign out must always be one
  // click away); the functional tool groups collapse so a long production nav
  // stays scannable.
  if (!collapsible) {
    return (
      <div className="soc-sidebar-section">
        <div className="soc-sidebar-label">{title}</div>
        {children}
      </div>
    );
  }
  return (
    <div className={cx("soc-sidebar-section", !open && "is-collapsed")}>
      <button
        type="button"
        className="soc-sidebar-label soc-sidebar-group-toggle"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
      >
        <span>{title}</span>
        <ChevronDown size={13} className="soc-sidebar-caret" aria-hidden="true" />
      </button>
      {/* Always rendered; collapse hides items via CSS only in the expanded
          sidebar, so the icon-only rail keeps every icon reachable. */}
      <div className="soc-sidebar-group-items">{children}</div>
    </div>
  );
}

function SidebarButton({
  icon: Icon,
  label,
  onClick,
  badge,
  active
}: {
  icon: typeof Activity;
  label: string;
  onClick: () => void;
  badge?: number;
  active?: boolean;
}) {
  return (
    <button
      type="button"
      className={cx("soc-sidebar-item", active && "is-active")}
      onClick={onClick}
      title={label}
      aria-current={active ? "true" : undefined}
    >
      <Icon size={16} strokeWidth={1.75} />
      <span>{label}</span>
      {badge ? <em>{badge}</em> : null}
    </button>
  );
}

function SidebarLink({
  icon: Icon,
  label,
  href,
  active
}: {
  icon: typeof Activity;
  label: string;
  href: string;
  active?: boolean;
}) {
  // "Active" is passed in from the current view — it tracks the open surface and
  // returns to Dashboard when nothing is open, so the highlight moves with the
  // operator instead of sitting permanently on one item.
  return (
    <a className={cx("soc-sidebar-item", active && "is-active")} href={href} title={label} aria-current={active ? "page" : undefined}>
      <Icon size={16} strokeWidth={1.75} />
      <span>{label}</span>
    </a>
  );
}
