import { SSE_CONTRACT } from "../../e2e/support/contracts";
import { fakeModeStreamFrames } from "../../e2e/support/fixtures";
import {
  STREAM_FRAME_CAP,
  createRafStreamBatcher,
  reduceStreamFrames,
  shouldProbeWhoami
} from "../lib/streamCore";
import type { StreamFrame } from "../lib/types";

describe("SSE certification contract", () => {
  it("uses the single backend stream endpoint", () => {
    expect(SSE_CONTRACT.endpoint).toBe("/api/stream");
  });

  it("keeps Fleet and Devices poll-only", () => {
    expect(SSE_CONTRACT.consumers).toEqual(["soc", "choke"]);
    expect(SSE_CONTRACT.pollOnlyRoutes).toEqual(["devices", "fleet"]);
  });

  it("represents heartbeats as freshness-only stream frames", () => {
    expect(fakeModeStreamFrames[0]).toEqual({ type: "heartbeat", payload: {} });
    expect(SSE_CONTRACT.staleAfterMs).toBe(30_000);
    expect(SSE_CONTRACT.watchdogAfterMs).toBe(45_000);
  });

  it("caps material stream frames and keeps newest frames first", () => {
    const flood = Array.from({ length: STREAM_FRAME_CAP + 20 }, (_, index): StreamFrame => ({
      type: "event",
      payload: { id: index }
    }));

    const reduced = reduceStreamFrames([], flood);

    expect(reduced).toHaveLength(STREAM_FRAME_CAP);
    expect(reduced[0].payload).toEqual({ id: STREAM_FRAME_CAP + 19 });
    expect(reduced.at(-1)?.payload).toEqual({ id: 20 });
  });

  it("batches SSE floods behind one animation frame", () => {
    const scheduled: Array<() => void> = [];
    const published: StreamFrame[][] = [];
    const batcher = createRafStreamBatcher({
      schedule: (callback) => {
        scheduled.push(callback);
        return scheduled.length;
      },
      cancel: () => undefined,
      publish: (batch) => published.push(batch)
    });

    for (let index = 0; index < 100; index += 1) {
      batcher.push({ type: "alert", payload: { id: index } });
    }

    expect(scheduled).toHaveLength(1);
    scheduled[0]();
    expect(published).toHaveLength(1);
    expect(published[0]).toHaveLength(100);
  });

  it("probes whoami after repeated stream failures", () => {
    expect(shouldProbeWhoami(1)).toBe(false);
    expect(shouldProbeWhoami(2)).toBe(false);
    expect(shouldProbeWhoami(3)).toBe(true);
  });
});
