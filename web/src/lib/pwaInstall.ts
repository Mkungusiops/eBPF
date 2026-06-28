import { useCallback, useEffect, useMemo, useRef, useState } from "react";

type BeforeInstallPromptEvent = Event & {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: "accepted" | "dismissed"; platform: string }>;
};

type PwaInstallWindow = Window & {
  __ebpfPwaInstallPrompt?: BeforeInstallPromptEvent | null;
  __ebpfPwaInstalled?: boolean;
};

const INSTALL_PROMPT_READY_EVENT = "ebpf:pwa-install-ready";
const APP_INSTALLED_EVENT = "ebpf:pwa-installed";

export type PwaInstallPlatform =
  | "browser-prompt"
  | "desktop-chromium"
  | "android-browser"
  | "ios-browser"
  | "desktop-safari"
  | "manual";

export type PwaInstallState = {
  available: boolean;
  installed: boolean;
  preparing: boolean;
  platform: PwaInstallPlatform;
  promptInstall: () => Promise<boolean>;
  waitForPrompt: (timeoutMs?: number) => Promise<boolean>;
};

function isStandalone(): boolean {
  if (typeof window === "undefined") return false;
  const nav = window.navigator as Navigator & { standalone?: boolean };
  return Boolean(
    nav.standalone ||
      window.matchMedia?.("(display-mode: standalone)").matches ||
      (window as PwaInstallWindow).__ebpfPwaInstalled,
  );
}

function isBeforeInstallPromptEvent(event: Event | null | undefined): event is BeforeInstallPromptEvent {
  const candidate = event as Partial<BeforeInstallPromptEvent> | null | undefined;
  return Boolean(candidate && typeof candidate.prompt === "function" && candidate.userChoice);
}

function getStoredPrompt(): BeforeInstallPromptEvent | null {
  if (typeof window === "undefined") return null;
  const prompt = (window as PwaInstallWindow).__ebpfPwaInstallPrompt;
  return isBeforeInstallPromptEvent(prompt) ? prompt : null;
}

function storePrompt(prompt: BeforeInstallPromptEvent): void {
  (window as PwaInstallWindow).__ebpfPwaInstallPrompt = prompt;
}

function clearStoredPrompt(): void {
  (window as PwaInstallWindow).__ebpfPwaInstallPrompt = null;
}

function platformForUserAgent(): PwaInstallPlatform {
  if (typeof navigator === "undefined") return "manual";
  const ua = navigator.userAgent.toLowerCase();
  const iOS = /ipad|iphone|ipod/.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  if (iOS) return "ios-browser";

  const chromium = /chrome|chromium|crios|edg|edga|edgios/.test(ua) && !/firefox|fxios/.test(ua);
  const android = /android/.test(ua);
  if (android && chromium) return "android-browser";
  if (chromium) return "desktop-chromium";

  const safari = /^((?!chrome|android|crios|fxios|edg|edga|edgios).)*safari/i.test(ua);
  if (safari) return "desktop-safari";
  return "manual";
}

function shouldWaitForLoginControl(): boolean {
  if (!import.meta.env.PROD) return false;
  if (typeof window === "undefined" || typeof navigator === "undefined") return false;
  if (window.location.pathname !== "/login") return false;
  if (!("serviceWorker" in navigator) || navigator.serviceWorker.controller) return false;
  if (isStandalone()) return false;

  const platform = platformForUserAgent();
  return platform === "desktop-chromium" || platform === "android-browser";
}

export function usePwaInstall(): PwaInstallState {
  const initialPrompt = useMemo(() => getStoredPrompt(), []);
  const [promptEvent, setPromptEvent] = useState<BeforeInstallPromptEvent | null>(initialPrompt);
  const [installed, setInstalled] = useState(() => isStandalone());
  const [preparing, setPreparing] = useState(() => shouldWaitForLoginControl());
  const promptRef = useRef<BeforeInstallPromptEvent | null>(initialPrompt);
  const waitersRef = useRef(new Set<(ready: boolean) => void>());
  const fallbackPlatform = useMemo(() => platformForUserAgent(), []);

  useEffect(() => {
    const resolveWaiters = (ready: boolean) => {
      for (const resolve of waitersRef.current) resolve(ready);
      waitersRef.current.clear();
    };
    const acceptPrompt = (event: Event | null | undefined) => {
      if (!isBeforeInstallPromptEvent(event)) return;
      event.preventDefault();
      storePrompt(event);
      promptRef.current = event;
      setPromptEvent(event);
      resolveWaiters(true);
    };
    const onBeforeInstallPrompt = (event: Event) => acceptPrompt(event);
    const onPromptReady = () => acceptPrompt(getStoredPrompt());
    const onInstalled = () => {
      clearStoredPrompt();
      promptRef.current = null;
      setPromptEvent(null);
      setInstalled(true);
      resolveWaiters(false);
    };
    const onModeChange = () => setInstalled(isStandalone());
    const media = window.matchMedia?.("(display-mode: standalone)");

    acceptPrompt(getStoredPrompt());
    window.addEventListener("beforeinstallprompt", onBeforeInstallPrompt);
    window.addEventListener(INSTALL_PROMPT_READY_EVENT, onPromptReady);
    window.addEventListener("appinstalled", onInstalled);
    window.addEventListener(APP_INSTALLED_EVENT, onInstalled);
    if (media?.addEventListener) media.addEventListener("change", onModeChange);
    else media?.addListener?.(onModeChange);
    return () => {
      window.removeEventListener("beforeinstallprompt", onBeforeInstallPrompt);
      window.removeEventListener(INSTALL_PROMPT_READY_EVENT, onPromptReady);
      window.removeEventListener("appinstalled", onInstalled);
      window.removeEventListener(APP_INSTALLED_EVENT, onInstalled);
      if (media?.removeEventListener) media.removeEventListener("change", onModeChange);
      else media?.removeListener?.(onModeChange);
      resolveWaiters(false);
    };
  }, []);

  useEffect(() => {
    if (!preparing || !("serviceWorker" in navigator)) return;

    let cancelled = false;
    const finish = () => {
      if (!cancelled) setPreparing(false);
    };
    const releaseTimer = window.setTimeout(finish, 4500);
    const onControllerChange = () => finish();

    navigator.serviceWorker.addEventListener("controllerchange", onControllerChange);
    navigator.serviceWorker.ready
      .then(() => {
        if (navigator.serviceWorker.controller) finish();
        else window.setTimeout(finish, 1800);
      })
      .catch(finish);

    return () => {
      cancelled = true;
      window.clearTimeout(releaseTimer);
      navigator.serviceWorker.removeEventListener("controllerchange", onControllerChange);
    };
  }, [preparing]);

  const waitForPrompt = useCallback((timeoutMs = 1800): Promise<boolean> => {
    if (promptRef.current || getStoredPrompt()) return Promise.resolve(true);
    return new Promise((resolve) => {
      let timer = 0;
      const finish = (ready: boolean) => {
        waitersRef.current.delete(finish);
        window.clearTimeout(timer);
        resolve(ready);
      };
      waitersRef.current.add(finish);
      timer = window.setTimeout(() => finish(false), timeoutMs);
    });
  }, []);

  const promptInstall = useCallback(async (): Promise<boolean> => {
    const prompt = promptRef.current ?? getStoredPrompt();
    if (!prompt) return false;
    try {
      await prompt.prompt();
      await prompt.userChoice.catch(() => undefined);
      return true;
    } catch {
      return false;
    } finally {
      clearStoredPrompt();
      promptRef.current = null;
      setPromptEvent(null);
    }
  }, []);

  return {
    available: Boolean(promptEvent),
    installed,
    preparing,
    platform: promptEvent ? "browser-prompt" : fallbackPlatform,
    promptInstall,
    waitForPrompt,
  };
}
