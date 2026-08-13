import type { StreamFrame } from "./types";

export const STREAM_FRAME_CAP = 500;
export const STREAM_WHOAMI_PROBE_RETRY = 3;

export function reduceStreamFrames(
  current: StreamFrame[],
  batch: StreamFrame[],
  cap = STREAM_FRAME_CAP
): StreamFrame[] {
  const material = batch.filter((frame) => frame.type !== "heartbeat");
  if (!material.length) return current.slice(0, cap);
  return [...material.reverse(), ...current].slice(0, cap);
}

export function shouldProbeWhoami(retries: number): boolean {
  return retries >= STREAM_WHOAMI_PROBE_RETRY;
}

export function createRafStreamBatcher({
  schedule,
  cancel,
  publish
}: {
  schedule: (callback: () => void) => number;
  cancel: (id: number) => void;
  publish: (batch: StreamFrame[]) => void;
}) {
  let queued: StreamFrame[] = [];
  let frameId: number | null = null;

  const flush = () => {
    if (frameId !== null) {
      cancel(frameId);
      frameId = null;
    }
    const batch = queued;
    queued = [];
    if (batch.length) publish(batch);
  };

  return {
    push(frame: StreamFrame) {
      if (frame.type === "heartbeat") return;
      queued.push(frame);
      if (frameId !== null) return;
      frameId = schedule(() => {
        frameId = null;
        const batch = queued;
        queued = [];
        if (batch.length) publish(batch);
      });
    },
    flush,
    cancel() {
      if (frameId !== null) {
        cancel(frameId);
        frameId = null;
      }
      queued = [];
    }
  };
}
