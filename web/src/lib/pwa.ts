const LOGIN_FIRST_CONTROL_RELOAD_KEY = "soc.pwa.login.first-control-reload";

function isStandaloneDisplay(): boolean {
  const nav = window.navigator as Navigator & { standalone?: boolean };
  return Boolean(nav.standalone || window.matchMedia?.("(display-mode: standalone)").matches);
}

function isChromiumInstallBrowser(): boolean {
  const ua = navigator.userAgent.toLowerCase();
  const iOS = /ipad|iphone|ipod/.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  if (iOS) return false;
  return /chrome|chromium|crios|edg|edga|edgios/.test(ua) && !/firefox|fxios/.test(ua);
}

function markLoginFirstControlReload(): boolean {
  try {
    if (window.sessionStorage.getItem(LOGIN_FIRST_CONTROL_RELOAD_KEY) === "1") return false;
    window.sessionStorage.setItem(LOGIN_FIRST_CONTROL_RELOAD_KEY, "1");
    return true;
  } catch {
    return false;
  }
}

function clearLoginFirstControlReload(): void {
  try {
    window.sessionStorage.removeItem(LOGIN_FIRST_CONTROL_RELOAD_KEY);
  } catch {
    // Ignore blocked storage. It only disables the reload guard reset.
  }
}

function reloadLoginAfterFirstControlReady(): void {
  if (window.location.pathname !== "/login") return;
  if (!isChromiumInstallBrowser() || isStandaloneDisplay()) return;

  navigator.serviceWorker.ready
    .then(() => {
      if (navigator.serviceWorker.controller) {
        clearLoginFirstControlReload();
        return;
      }
      if (!markLoginFirstControlReload()) return;
      window.location.reload();
    })
    .catch(() => {
      /* offline support is non-critical; ignore registration failures */
    });
}

// Registers the service worker emitted by vite-plugin-pwa. The worker is
// generated only by `vite build`, so we skip registration in dev (it would
// 404) and in test. Registration is best-effort: failures never block the app.
export function registerServiceWorker(): void {
  if (!import.meta.env.PROD) return;
  if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return;

  // When a replacement worker takes control, reload once so the page runs
  // against the fresh worker. Do not reload on first install: that can race
  // with the login install button and erase the operator's click.
  const hadController = Boolean(navigator.serviceWorker.controller);
  let reloaded = false;
  navigator.serviceWorker.addEventListener("controllerchange", () => {
    // The login route has an install button; update reloads can consume the
    // trusted click that Chromium requires for the native install prompt.
    if (window.location.pathname === "/login") return;
    if (!hadController) return;
    if (reloaded) return;
    reloaded = true;
    window.location.reload();
  });

  const register = () => {
    navigator.serviceWorker.register("/sw.js", { scope: "/" }).catch(() => {
      /* offline support is non-critical; ignore registration failures */
    });
  };

  register();
  reloadLoginAfterFirstControlReady();
}
