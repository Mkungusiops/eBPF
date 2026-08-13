import { createContext, ReactNode, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { getJSON } from "./api";
import { createRafStreamBatcher, shouldProbeWhoami } from "./streamCore";
import type { StreamFrame } from "./types";
import { useStreamStore, type SharedStreamState } from "../stores/stream";

interface StreamContextValue {
  state: SharedStreamState;
  retries: number;
  messageCount: number;
  lastMessageAt?: number;
  lastEventAt?: number;
  frames: StreamFrame[];
  latestBatch: StreamFrame[];
  batchId: number;
  error?: string;
  reconnect: () => void;
}

const StreamContext = createContext<StreamContextValue | null>(null);

export function StreamProvider({ children }: { children: ReactNode }) {
  const state = useStreamStore((store) => store.state);
  const retries = useStreamStore((store) => store.retries);
  const messageCount = useStreamStore((store) => store.messageCount);
  const lastMessageAt = useStreamStore((store) => store.lastMessageAt);
  const lastEventAt = useStreamStore((store) => store.lastEventAt);
  const frames = useStreamStore((store) => store.frames);
  const latestBatch = useStreamStore((store) => store.latestBatch);
  const batchId = useStreamStore((store) => store.batchId);
  const error = useStreamStore((store) => store.error);
  const sourceRef = useRef<EventSource | null>(null);
  const retryRef = useRef(0);
  const [reconnectNonce, setReconnectNonce] = useState(0);

  const reconnect = useCallback(() => {
    sourceRef.current?.close();
    sourceRef.current = null;
    setReconnectNonce((current) => current + 1);
  }, []);

  useEffect(() => {
    let cancelled = false;
    let timeout: number | undefined;
    useStreamStore.getState().reset();
    const batcher = createRafStreamBatcher({
      schedule: (callback) => window.requestAnimationFrame(callback),
      cancel: (id) => window.cancelAnimationFrame(id),
      publish: (batch) => useStreamStore.getState().batchReceived(batch, Date.now())
    });

    const connect = () => {
      if (cancelled) return;
      useStreamStore.getState().connecting(retryRef.current === 0 ? "connecting" : "reconnect");
      if (typeof EventSource === "undefined") {
        useStreamStore.getState().failed(retryRef.current + 1, "EventSource unavailable");
        return;
      }
      const source = new EventSource("/api/stream");
      sourceRef.current = source;

      source.onopen = () => {
        retryRef.current = 0;
        useStreamStore.getState().opened(Date.now());
      };

      source.onmessage = (event) => {
        const now = Date.now();
        try {
          const frame = JSON.parse(event.data) as StreamFrame;
          if (frame.type !== "heartbeat") {
            batcher.push(frame);
          } else {
            useStreamStore.getState().heartbeat(now);
          }
        } catch {
          useStreamStore.getState().failed(retryRef.current, "Malformed stream frame");
        }
      };

      source.onerror = () => {
        source.close();
        retryRef.current += 1;
        useStreamStore.getState().failed(retryRef.current, "stream reconnecting");
        if (shouldProbeWhoami(retryRef.current)) {
          void getJSON("/api/whoami", { redirectOn401: true }).catch(() => undefined);
        }
        const delay = Math.min(30000, 1000 * 2 ** Math.min(retryRef.current, 5));
        timeout = window.setTimeout(connect, delay);
      };
    };

    connect();
    return () => {
      cancelled = true;
      batcher.cancel();
      sourceRef.current?.close();
      if (timeout) window.clearTimeout(timeout);
    };
  }, [reconnectNonce]);

  const value = useMemo(
    () => ({
      state,
      retries,
      messageCount,
      lastMessageAt,
      lastEventAt,
      frames,
      latestBatch,
      batchId,
      error,
      reconnect
    }),
    [state, retries, messageCount, lastMessageAt, lastEventAt, frames, latestBatch, batchId, error, reconnect]
  );

  return <StreamContext.Provider value={value}>{children}</StreamContext.Provider>;
}

export function useStream(): StreamContextValue {
  const value = useContext(StreamContext);
  if (!value) throw new Error("useStream must be used inside StreamProvider");
  return value;
}
