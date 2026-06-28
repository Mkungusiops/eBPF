import { Download, Eye, EyeOff, Loader2, LogIn, Moon, Share2, Sun, X } from "lucide-react";
import { FormEvent, useEffect, useMemo, useState } from "react";
import { Button } from "../../components/ui";
import { usePwaInstall, type PwaInstallPlatform } from "../../lib/pwaInstall";
import { loadJSON, saveJSON } from "../../lib/storage";

type Theme = "dark" | "light";
type InstallPhase = "idle" | "checking" | "prompting";

export function readLoginTheme(): Theme {
  try {
    const raw = window.localStorage.getItem("soc.theme");
    if (raw === "light" || raw === "dark") return raw;
  } catch {
    // Storage failures should not block login.
  }
  const stored = loadJSON<Theme>("soc.theme", "dark");
  return stored === "light" ? "light" : "dark";
}

export function applyLoginTheme(theme: Theme): void {
  document.documentElement.classList.toggle("theme-light", theme === "light");
  document.documentElement.classList.toggle("theme-dark", theme === "dark");
  document.body.classList.toggle("theme-light", theme === "light");
  document.body.classList.toggle("theme-dark", theme === "dark");
  const favicon = document.getElementById("appFavicon") as HTMLLinkElement | null;
  if (favicon) favicon.href = theme === "light" ? "/favicon-light.svg" : "/favicon.svg";
}

export function LoginPage({ initialTheme }: { initialTheme?: Theme }) {
  const [showPassword, setShowPassword] = useState(false);
  const [theme, setTheme] = useState<Theme>(() => initialTheme || readLoginTheme());
  const [installOpen, setInstallOpen] = useState(false);
  const [installPhase, setInstallPhase] = useState<InstallPhase>("idle");
  const install = usePwaInstall();
  const hasError = useMemo(() => new URLSearchParams(window.location.search).get("err") === "1", []);
  const installBusy = install.preparing || installPhase !== "idle";
  const installLabel =
    install.preparing
      ? "Preparing install"
      : installPhase === "checking"
        ? "Checking install"
        : installPhase === "prompting"
          ? "Opening install"
          : "Install app";

  useEffect(() => {
    applyLoginTheme(theme);
    saveJSON("soc.theme", theme);
  }, [theme]);

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    const form = event.currentTarget;
    if (!form.checkValidity()) return;
  }

  async function handleInstallClick(): Promise<void> {
    if (installBusy) return;
    setInstallOpen(false);
    try {
      if (install.available) {
        setInstallPhase("prompting");
        const prompted = await install.promptInstall();
        if (!prompted) setInstallOpen(true);
        return;
      }

      setInstallPhase("checking");
      const promptReady =
        install.platform === "desktop-chromium" || install.platform === "android-browser"
          ? await install.waitForPrompt(2200)
          : await delay(650).then(() => false);
      if (promptReady) {
        setInstallPhase("prompting");
        const prompted = await install.promptInstall();
        if (!prompted) setInstallOpen(true);
        return;
      }
      setInstallOpen(true);
    } finally {
      setInstallPhase("idle");
    }
  }

  return (
    <main className="grid min-h-screen place-items-center px-4 py-10">
      <div className="fixed right-5 top-5 z-10 flex gap-2">
        {!install.installed ? (
          <button
            type="button"
            title={installLabel}
            aria-label={installLabel}
            aria-busy={installBusy}
            disabled={installBusy}
            className="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-slate-900/10 bg-panel/85 px-3 text-sm font-medium text-muted shadow-glow backdrop-blur transition hover:border-accent/40 hover:text-accent dark:border-white/10"
            onClick={() => void handleInstallClick()}
          >
            {installBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
            <span className={installBusy ? "inline" : "hidden sm:inline"}>
              {install.preparing
                ? "Preparing..."
                : installPhase === "checking"
                  ? "Checking..."
                  : installPhase === "prompting"
                    ? "Opening..."
                    : "Install"}
            </span>
          </button>
        ) : null}
        <button
          type="button"
          title={theme === "light" ? "Switch to dark theme" : "Switch to light theme"}
          aria-label={theme === "light" ? "Switch to dark theme" : "Switch to light theme"}
          className="grid h-10 w-10 place-items-center rounded-md border border-slate-900/10 bg-panel/85 text-muted shadow-glow backdrop-blur transition hover:border-accent/40 hover:text-accent dark:border-white/10"
          onClick={() => setTheme((value) => (value === "light" ? "dark" : "light"))}
        >
          {theme === "light" ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
        </button>
      </div>
      <section className="w-full max-w-md rounded-lg border border-white/10 bg-panel p-6 shadow-glow">
        <div className="mb-6">
          <div className="mb-3 inline-flex rounded-md border border-accent/25 bg-accent/10 px-3 py-1 text-xs font-semibold text-accent">
            eBPF runtime security
          </div>
          <h1 className="text-2xl font-semibold">Operator login</h1>
          <p className="mt-2 text-sm text-muted">Authenticate with the Go-managed session cookie and CSRF model.</p>
        </div>
        {hasError ? (
          <div className="mb-4 rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
            Invalid credentials.
          </div>
        ) : null}
        <form method="POST" action="/api/login" autoComplete="off" onSubmit={handleSubmit} className="space-y-4">
          <label className="block text-sm">
            <span className="mb-1 block text-muted">Username</span>
            <input
              name="user"
              autoComplete="username"
              required
              autoFocus
              className="h-10 w-full rounded-md border border-white/10 bg-row px-3 text-text outline-none focus:border-accent"
            />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block text-muted">Password</span>
            <div className="flex rounded-md border border-white/10 bg-row focus-within:border-accent">
              <input
                name="pass"
                type={showPassword ? "text" : "password"}
                autoComplete="current-password"
                required
                className="h-10 min-w-0 flex-1 bg-transparent px-3 text-text outline-none"
              />
              <button
                type="button"
                aria-label={showPassword ? "Hide password" : "Show password"}
                className="grid w-10 place-items-center text-muted"
                onClick={() => setShowPassword((value) => !value)}
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </label>
          <Button type="submit" tone="info" className="w-full">
            <LogIn className="h-4 w-4" />
            Sign in
          </Button>
        </form>
      </section>
      {installOpen ? <InstallHelp platform={install.platform} onClose={() => setInstallOpen(false)} /> : null}
    </main>
  );
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function InstallHelp({ platform, onClose }: { platform: PwaInstallPlatform; onClose: () => void }) {
  const copy =
    platform === "ios-browser"
      ? {
          title: "Install on iPhone or iPad",
          body: "Tap Share, then Add to Home Screen. If iOS shows Open as Web App, leave it enabled before tapping Add.",
          note: "The installed app opens as its own web app from the Home Screen and device search.",
        }
      : platform === "android-browser"
        ? {
            title: "Install on Android",
            body: "Use a normal Chrome or Edge tab, open the browser menu, then choose Install app. If prompted, keep the app install option selected instead of a plain shortcut.",
            note: "Incognito and temporary profiles cannot create the persistent app. A real installed PWA remains available from the launcher and search.",
          }
        : platform === "desktop-chromium"
          ? {
              title: "Use a regular Edge or Chrome profile",
              body: "Close InPrivate, Incognito, and Guest windows. Open this URL in a normal Edge or Chrome profile, then use the address-bar app icon or choose Apps, then Install this site as an app.",
              note: "Private and Guest profiles cannot create the persistent macOS app, even when the PWA itself is valid.",
            }
          : platform === "desktop-safari"
            ? {
                title: "Install on Safari",
                body: "Use File, then Add to Dock when Safari offers it.",
                note: "The app manifest, icons, and offline worker are already published.",
              }
            : {
                title: "Install app",
                body: "Open the browser menu and choose Install app or Add to Home Screen.",
                note: "If the browser only creates a bookmark or shortcut, removing that icon also removes the launcher entry.",
              };

  return (
    <div
      className="fixed inset-0 z-40 grid place-items-center bg-black/55 px-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="install-help-title"
      onClick={(event) => event.target === event.currentTarget && onClose()}
    >
      <section className="w-full max-w-sm rounded-lg border border-white/10 bg-panel p-5 shadow-glow">
        <div className="mb-4 flex items-start justify-between gap-4">
          <div>
            <div className="mb-2 inline-flex rounded-md border border-info/30 bg-info/10 px-2 py-1 text-xs font-semibold text-info">
              PWA ready
            </div>
            <h2 id="install-help-title" className="text-lg font-semibold">
              {copy.title}
            </h2>
          </div>
          <button
            type="button"
            aria-label="Close install help"
            className="grid h-9 w-9 shrink-0 place-items-center rounded-md border border-white/10 bg-white/5 text-muted hover:text-text"
            onClick={onClose}
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex items-start gap-3 rounded-md border border-white/10 bg-row/60 p-3">
          <Share2 className="mt-0.5 h-4 w-4 shrink-0 text-info" />
          <div>
            <p className="text-sm font-medium text-text">{copy.body}</p>
            <p className="mt-1 text-xs text-muted">{copy.note}</p>
          </div>
        </div>
        <Button type="button" tone="info" className="mt-4 w-full" onClick={onClose}>
          Done
        </Button>
      </section>
    </div>
  );
}
