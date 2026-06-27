// Registers the service worker emitted by vite-plugin-pwa. The worker is
// generated only by `vite build`, so we skip registration in dev (it would
// 404) and in test. Registration is best-effort: failures never block the app.
export function registerServiceWorker(): void {
  if (!import.meta.env.PROD) return;
  if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return;

  // When a new worker (skipWaiting + clientsClaim) takes control, reload once
  // so the page runs against the fresh worker — this is what heals a client
  // stuck on a previously-broken worker. Guarded so it can never loop.
  let reloaded = false;
  navigator.serviceWorker.addEventListener("controllerchange", () => {
    if (reloaded) return;
    reloaded = true;
    window.location.reload();
  });

  const register = () => {
    navigator.serviceWorker.register("/sw.js", { scope: "/" }).catch(() => {
      /* offline support is non-critical; ignore registration failures */
    });
  };

  if (document.readyState === "complete") register();
  else window.addEventListener("load", register, { once: true });
}
