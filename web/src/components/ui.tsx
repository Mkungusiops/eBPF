import * as Dialog from "@radix-ui/react-dialog";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import * as Popover from "@radix-ui/react-popover";
import { AlertTriangle, CheckCircle2, ChevronDown, Loader2, X } from "lucide-react";
import { ReactNode } from "react";
import { LinkLike } from "../lib/nav";

type Tone = "neutral" | "good" | "warn" | "danger" | "info";

const toneClass: Record<Tone, string> = {
  neutral: "border-white/10 bg-white/5 text-muted",
  good: "border-good/30 bg-good/10 text-good",
  warn: "border-warn/30 bg-warn/10 text-warn",
  danger: "border-danger/30 bg-danger/10 text-danger",
  info: "border-info/30 bg-info/10 text-info"
};

export function Button({
  children,
  tone = "neutral",
  className = "",
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { tone?: Tone }) {
  return (
    <button
      className={`inline-flex h-9 items-center justify-center gap-2 rounded-md border px-3 text-sm font-medium transition hover:bg-white/10 disabled:cursor-not-allowed disabled:opacity-50 ${toneClass[tone]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}

export function Panel({
  title,
  eyebrow,
  actions,
  children,
  className = "",
  testId
}: {
  title: string;
  eyebrow?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  testId?: string;
}) {
  return (
    <section
      data-testid={testId}
      className={`rounded-lg border border-white/10 bg-panel/92 p-4 shadow-glow ${className}`}
    >
      <div className="mb-3 flex min-h-8 items-start justify-between gap-3">
        <div>
          {eyebrow ? <div className="text-[11px] font-semibold uppercase tracking-wide text-dim">{eyebrow}</div> : null}
          <h2 className="text-sm font-semibold text-text">{title}</h2>
        </div>
        {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
      </div>
      {children}
    </section>
  );
}

export function StatCard({
  label,
  value,
  hint,
  tone = "neutral"
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: Tone;
}) {
  return (
    <div className="rounded-lg border border-white/10 bg-row/70 p-3">
      <div className="text-[11px] font-medium uppercase text-dim">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${tone === "neutral" ? "text-text" : toneClass[tone].split(" ").at(-1)}`}>
        {value}
      </div>
      {hint ? <div className="mt-1 text-xs text-muted">{hint}</div> : null}
    </div>
  );
}

export function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: Tone }) {
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-semibold ${toneClass[tone]}`}>
      {children}
    </span>
  );
}

export function StatusBadge({ value }: { value?: string }) {
  const normalized = String(value ?? "unknown").toLowerCase();
  const tone: Tone =
    normalized.includes("sever") || normalized.includes("quarantine") || normalized.includes("kill")
      ? "danger"
      : normalized.includes("tarpit") || normalized.includes("warn")
        ? "warn"
        : normalized.includes("enforcing") || normalized.includes("live") || normalized.includes("ok")
          ? "good"
          : normalized.includes("throttle") || normalized.includes("detect")
            ? "info"
            : "neutral";
  return <Badge tone={tone}>{normalized}</Badge>;
}

export function EmptyState({ title, body }: { title: string; body?: string }) {
  return (
    <div className="rounded-md border border-dashed border-white/15 bg-row/40 p-5 text-center">
      <div className="text-sm font-semibold text-text">{title}</div>
      {body ? <div className="mt-1 text-xs text-muted">{body}</div> : null}
    </div>
  );
}

export function LoadingState({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 rounded-md border border-white/10 bg-row/40 p-4 text-sm text-muted">
      <Loader2 className="h-4 w-4 animate-spin" />
      {label}
    </div>
  );
}

export function ErrorState({ title = "Unable to load", body }: { title?: string; body?: string }) {
  return (
    <div className="flex items-start gap-3 rounded-md border border-danger/30 bg-danger/10 p-4 text-sm">
      <AlertTriangle className="mt-0.5 h-4 w-4 text-danger" />
      <div>
        <div className="font-semibold text-danger">{title}</div>
        {body ? <div className="mt-1 text-muted">{body}</div> : null}
      </div>
    </div>
  );
}

export function Modal({
  title,
  trigger,
  children
}: {
  title: string;
  trigger: ReactNode;
  children: ReactNode;
}) {
  return (
    <Dialog.Root>
      <Dialog.Trigger asChild>{trigger}</Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/60" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 max-h-[86vh] w-[min(760px,92vw)] -translate-x-1/2 -translate-y-1/2 overflow-auto rounded-lg border border-white/10 bg-panel p-5 shadow-glow">
          <div className="mb-4 flex items-center justify-between gap-3">
            <Dialog.Title className="text-base font-semibold">{title}</Dialog.Title>
            <Dialog.Close asChild>
              <Button aria-label="Close">
                <X className="h-4 w-4" />
              </Button>
            </Dialog.Close>
          </div>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export function Menu({
  label,
  items
}: {
  label: ReactNode;
  items: Array<{ label: string; href?: string; onSelect?: () => void }>;
}) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <Button>
          {label}
          <ChevronDown className="h-3.5 w-3.5" />
        </Button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content className="z-50 min-w-48 rounded-md border border-white/10 bg-panel p-1 shadow-glow">
          {items.map((item) => (
            <DropdownMenu.Item
              key={item.label}
              className="cursor-pointer rounded px-3 py-2 text-sm outline-none hover:bg-white/10"
              onSelect={item.onSelect}
            >
              {item.href ? <a href={item.href}>{item.label}</a> : item.label}
            </DropdownMenu.Item>
          ))}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

export function InfoPopover({ label, children }: { label: ReactNode; children: ReactNode }) {
  return (
    <Popover.Root>
      <Popover.Trigger asChild>
        <Button>{label}</Button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content className="z-50 w-[min(440px,92vw)] rounded-lg border border-white/10 bg-panel p-4 shadow-glow">
          {children}
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}

export function DataTable<T>({
  rows,
  columns,
  empty
}: {
  rows: T[];
  columns: Array<{ key: string; header: string; render: (row: T) => ReactNode }>;
  empty?: ReactNode;
}) {
  if (rows.length === 0) {
    return <>{empty ?? <EmptyState title="No rows" />}</>;
  }
  return (
    <div className="overflow-x-auto rounded-md border border-white/10">
      <table className="w-full min-w-[720px] border-collapse text-left text-sm">
        <thead className="bg-row text-[11px] uppercase text-dim">
          <tr>
            {columns.map((column) => (
              <th key={column.key} className="px-3 py-2 font-semibold">
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index} className="border-t border-white/10 odd:bg-white/[0.015] hover:bg-white/5">
              {columns.map((column) => (
                <td key={column.key} className="px-3 py-2 align-top">
                  {column.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ToastInline({ ok, children }: { ok?: boolean; children: ReactNode }) {
  if (!children) return null;
  return (
    <div className={`inline-flex items-center gap-2 rounded-md border px-3 py-2 text-sm ${ok ? toneClass.good : toneClass.danger}`}>
      {ok ? <CheckCircle2 className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4" />}
      {children}
    </div>
  );
}

export function NavLink({ href, children }: LinkLike) {
  const active = typeof window !== "undefined" && window.location.pathname === href;
  return (
    <a
      href={href}
      className={`rounded-md px-3 py-2 text-sm font-medium transition hover:bg-white/10 ${active ? "bg-accent/15 text-accent" : "text-muted"}`}
    >
      {children}
    </a>
  );
}
