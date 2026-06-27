import { create } from "zustand";
import { reduceStreamFrames } from "../lib/streamCore";
import type { StreamFrame } from "../lib/types";

export type SharedStreamState = "connecting" | "live" | "reconnect" | "down";

interface StreamStore {
  state: SharedStreamState;
  retries: number;
  messageCount: number;
  lastMessageAt?: number;
  lastEventAt?: number;
  frames: StreamFrame[];
  latestBatch: StreamFrame[];
  batchId: number;
  error?: string;
  connecting: (state: SharedStreamState) => void;
  opened: (at: number) => void;
  heartbeat: (at: number) => void;
  batchReceived: (batch: StreamFrame[], at: number) => void;
  failed: (retries: number, error: string) => void;
  reset: () => void;
}

const initialState = {
  state: "connecting" as SharedStreamState,
  retries: 0,
  messageCount: 0,
  frames: [],
  latestBatch: [],
  batchId: 0,
  error: undefined
};

export const useStreamStore = create<StreamStore>((set) => ({
  ...initialState,
  connecting: (state) =>
    set((current) => ({
      ...current,
      state,
      error: undefined
    })),
  opened: (at) =>
    set((current) => ({
      ...current,
      state: "live",
      retries: 0,
      lastMessageAt: at,
      error: undefined
    })),
  heartbeat: (at) =>
    set((current) => ({
      ...current,
      state: "live",
      lastMessageAt: at,
      messageCount: current.messageCount + 1,
      error: undefined
    })),
  batchReceived: (batch, at) =>
    set((current) => ({
      ...current,
      state: "live",
      lastMessageAt: at,
      lastEventAt: at,
      messageCount: current.messageCount + batch.length,
      frames: reduceStreamFrames(current.frames, batch),
      latestBatch: batch,
      batchId: current.batchId + 1,
      error: undefined
    })),
  failed: (retries, error) =>
    set((current) => ({
      ...current,
      state: retries > 5 ? "down" : "reconnect",
      retries,
      error
    })),
  reset: () => set({ ...initialState, frames: [], latestBatch: [] })
}));
