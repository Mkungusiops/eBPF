import type { ButtonHTMLAttributes } from "react";

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
}: ButtonHTMLAttributes<HTMLButtonElement> & { tone?: Tone }) {
  return (
    <button
      className={`inline-flex h-9 items-center justify-center gap-2 rounded-md border px-3 text-sm font-medium transition hover:bg-white/10 disabled:cursor-not-allowed disabled:opacity-50 ${toneClass[tone]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}
