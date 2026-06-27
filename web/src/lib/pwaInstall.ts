import { useCallback, useEffect, useMemo, useRef, useState } from "react";

type BeforeInstallPromptEvent = Event & {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: "accepted" | "dismissed"; platform: string }>;
};

export type PwaInstallPlatform = "browser-prompt" | "chromium" | "ios-browser" | "desktop-safari" | "manual";

export type PwaInstallState = {
  available: boolean;
  installed: boolean;
  platform: PwaInstallPlatform;
  promptInstall: () => Promise<boolean>;
  waitForPrompt: (timeoutMs?: number) => Promise<boolean>;
};

function isStandalone(): boolean {
  if (typeof window === "undefined") return false;
  const nav = window.navigator as Navigator & { standalone?: boolean };
  return Boolean(nav.standalone || window.matchMedia?.("(display-mode: standalone)").matches);
}

function platformForUserAgent(): PwaInstallPlatform {
  if (typeof navigator === "undefined") return "manual";
  const ua = navigator.userAgent.toLowerCase();
  const iOS = /ipad|iphone|ipod/.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  if (iOS) return "ios-browser";

  const chromium = /chrome|chromium|crios|edg|edga|edgios/.test(ua) && !/firefox|fxios/.test(ua);
  if (chromium) return "chromium";

  const safari = /^((?!chrome|android|crios|fxios|edg|edga|edgios).)*safari/i.test(ua);
  if (safari) return "desktop-safari";
  return "manual";
}

export function usePwaInstall(): PwaInstallState {
  const [promptEvent, setPromptEvent] = useState<BeforeInstallPromptEvent | null>(null);
  const [installed, setInstalled] = useState(() => isStandalone());
  const promptRef = useRef<BeforeInstallPromptEvent | null>(null);
  const waitersRef = useRef(new Set<(ready: boolean) => void>());
  const fallbackPlatform = useMemo(() => platformForUserAgent(), []);

  useEffect(() => {
    const resolveWaiters = (ready: boolean) => {
      for (const resolve of waitersRef.current) resolve(ready);
      waitersRef.current.clear();
    };
    const onBeforeInstallPrompt = (event: Event) => {
      event.preventDefault();
      const prompt = event as BeforeInstallPromptEvent;
      promptRef.current = prompt;
      setPromptEvent(prompt);
      resolveWaiters(true);
    };
    const onInstalled = () => {
      promptRef.current = null;
      setPromptEvent(null);
      setInstalled(true);
      resolveWaiters(false);
    };
    const onModeChange = () => setInstalled(isStandalone());
    const media = window.matchMedia?.("(display-mode: standalone)");

    window.addEventListener("beforeinstallprompt", onBeforeInstallPrompt);
    window.addEventListener("appinstalled", onInstalled);
    if (media?.addEventListener) media.addEventListener("change", onModeChange);
    else media?.addListener?.(onModeChange);
    return () => {
      window.removeEventListener("beforeinstallprompt", onBeforeInstallPrompt);
      window.removeEventListener("appinstalled", onInstalled);
      if (media?.removeEventListener) media.removeEventListener("change", onModeChange);
      else media?.removeListener?.(onModeChange);
      resolveWaiters(false);
    };
  }, []);

  const waitForPrompt = useCallback((timeoutMs = 1800): Promise<boolean> => {
    if (promptRef.current) return Promise.resolve(true);
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
    const prompt = promptRef.current;
    if (!prompt) return false;
    await prompt.prompt();
    const choice = await prompt.userChoice;
    promptRef.current = null;
    setPromptEvent(null);
    return choice.outcome === "accepted";
  }, []);

  return {
    available: Boolean(promptEvent),
    installed,
    platform: promptEvent ? "browser-prompt" : fallbackPlatform,
    promptInstall,
    waitForPrompt,
  };
}
