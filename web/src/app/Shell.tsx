import { Shield, TerminalSquare } from "lucide-react";
import { ReactNode, useEffect, useState } from "react";
import { getJSON } from "../lib/api";
import { loadJSON, saveJSON } from "../lib/storage";
import type { Whoami } from "../lib/types";
import { Button, Menu, NavLink, StatusBadge } from "../components/ui";

const nav = [
  { href: "/", label: "SOC" },
  { href: "/choke", label: "Choke" },
  { href: "/devices", label: "Devices" },
  { href: "/fleet", label: "Fleet" }
];

function applyTheme(theme: "dark" | "light") {
  document.documentElement.classList.toggle("theme-light", theme === "light");
  document.documentElement.classList.toggle("theme-dark", theme === "dark");
  const fav = document.getElementById("appFavicon") as HTMLLinkElement | null;
  if (fav) fav.href = theme === "light" ? "/favicon-light.svg" : "/favicon.svg";
  saveJSON("soc.theme", theme);
}

export function Shell({
  title,
  subtitle,
  streamState,
  children
}: {
  title: string;
  subtitle?: string;
  streamState?: string;
  children: ReactNode;
}) {
  const [whoami, setWhoami] = useState<Whoami | null>(null);
  const [theme, setTheme] = useState<"dark" | "light">(() => loadJSON("soc.theme", "dark"));

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  useEffect(() => {
    void getJSON<Whoami>("/api/whoami").then(setWhoami).catch(() => undefined);
  }, []);

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-30 border-b border-white/10 bg-surface/90 backdrop-blur">
        <div className="flex min-h-16 flex-wrap items-center justify-between gap-3 px-4 lg:px-6">
          <div className="flex min-w-0 items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-lg border border-accent/25 bg-accent/10 text-accent">
              <Shield className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <h1 className="truncate text-base font-semibold">{title}</h1>
              <p className="truncate text-xs text-muted">{subtitle ?? "Runtime-security operations console"}</p>
            </div>
          </div>
          <nav className="flex flex-wrap items-center gap-1">
            {nav.map((item) => (
              <NavLink href={item.href} key={item.href}>
                {item.label}
              </NavLink>
            ))}
          </nav>
          <div className="flex items-center gap-2">
            {streamState ? <StatusBadge value={streamState} /> : null}
            <Button onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>{theme === "dark" ? "Light" : "Dark"}</Button>
            <Menu
              label={
                <span className="inline-flex items-center gap-2">
                  <TerminalSquare className="h-4 w-4" />
                  <span className="mono">{whoami?.user ?? "operator"}</span>
                </span>
              }
              items={[{ label: "Sign out", href: "/api/logout" }]}
            />
          </div>
        </div>
      </header>
      <main className="mx-auto w-full max-w-[1800px] px-4 py-5 lg:px-6">{children}</main>
    </div>
  );
}
