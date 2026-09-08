import { createContext, ReactNode, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { getJSON } from "./api";
import { tenantScopedPath, useTenantScope } from "./tenantScope";
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
  // THE CUSTOMER THE TAIL BELONGS TO, and whether the console can name one yet.
  // /api/stream goes through authorizeRead like every other read, so it honours
  // ?tenant= — and a connection opened without one keeps delivering the
  // account's default customer for as long as it stays open. Both are
  // dependencies of the connect effect: a switch tears the socket down and
  // re-opens it for the customer now on screen, and the barrier below re-opens
  // it once there is a customer to name.
  const scope = useTenantScope();
  const selectedTenant = scope.selected;
  // pendingTenantHydration() made reactive — the same barrier, from the same
  // promise (see buildScopeView in lib/tenantScope.ts). Read from the store
  // rather than called directly because an effect cannot be re-run by a promise
  // it did not depend on: a deferred connect that fired between the selection
  // landing and React re-rendering opened a socket the very next effect run
  // immediately closed.
  const confirmingCustomer = scope.hydrating;

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
      // Scoped through the same accessor as every other request, so the tail
      // and the panels beside it cannot describe different customers. A switch
      // re-runs this effect, which resets the shared store above before
      // reaching here — so the customer just left leaves no frame behind in the
      // buffer the new connection starts filling.
      const source = new EventSource(tenantScopedPath("/api/stream"));
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

    // THE TAIL WAITS FOR THE CUSTOMER TOO. This is the one request that does
    // not go through lib/api.ts's funnel — an EventSource is opened directly —
    // so it was the one request the hydration barrier did not hold. Opened
    // before the selection landed, it named no customer, and the control plane
    // resolves a tenant-less read to the account's DEFAULT customer: the socket
    // then delivered that customer's alerts into a console on its way to
    // another one, under a "live" pill, for as long as it took the selection to
    // arrive. Re-opening on the selection healed the URL and the buffer, but not
    // the operator who had already read those frames.
    //
    // So nothing is opened while the barrier stands. The store is left in the
    // reset "connecting" state it was just put in, which is exactly what the
    // wait is; settling flips this flag and re-runs the effect. A retry that
    // re-opens hydration passes through here too, closing the tail while the
    // console cannot say whose frames it would be carrying. With no barrier at
    // all — every tenant-bound console — this connects in the mount tick,
    // exactly as it did before any of this existed.
    if (!confirmingCustomer) connect();
    return () => {
      cancelled = true;
      batcher.cancel();
      sourceRef.current?.close();
      if (timeout) window.clearTimeout(timeout);
    };
  }, [reconnectNonce, selectedTenant, confirmingCustomer]);

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
