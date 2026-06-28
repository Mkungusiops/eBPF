import { useEffect, useMemo, useRef, useState } from "react";
import { Pause, Play, RotateCcw, X } from "lucide-react";
import "./EventReplay.css";

// One normalized event shape so every drill-in panel (SOC, Choke, …) can feed
// its kernel-event list to the same replay widget.
export interface ReplayEvent {
  id: string;
  time: string | number;
  kind: string;
  detail?: string;
}

const SPEEDS = [1, 2, 4];
const BASE_TICK_MS = 750;
const MAX_EVENTS = 120;

function formatClock(value: string | number): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value ?? "—");
  return date.toLocaleTimeString([], { hour12: false });
}

// Reconstruct a process's behaviour by stepping through its kernel events in
// order. Event-stepped (not wall-clock) because event timestamps are sparse —
// the value is the causal sequence, not the literal gaps between events.
export function EventReplay({
  events,
  emptyLabel = "No process events loaded yet."
}: {
  events: ReplayEvent[];
  emptyLabel?: string;
}) {
  const ordered = useMemo(
    () =>
      [...events]
        .sort((a, b) => new Date(a.time).getTime() - new Date(b.time).getTime())
        .slice(-MAX_EVENTS),
    [events]
  );
  const count = ordered.length;

  // cursor === null → idle (show the whole list); otherwise the replay head.
  const [cursor, setCursor] = useState<number | null>(null);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const rowRefs = useRef<Array<HTMLDivElement | null>>([]);

  // Reset replay state whenever the underlying event set changes (new drill).
  useEffect(() => {
    setCursor(null);
    setPlaying(false);
  }, [count, ordered[0]?.id]);

  useEffect(() => {
    if (!playing) return;
    const interval = window.setInterval(() => {
      setCursor((prev) => {
        const next = (prev == null ? 0 : prev) + 1;
        if (next >= count) {
          setPlaying(false);
          return count - 1;
        }
        return next;
      });
    }, Math.max(140, BASE_TICK_MS / speed));
    return () => window.clearInterval(interval);
  }, [playing, speed, count]);

  useEffect(() => {
    if (cursor == null) return;
    rowRefs.current[cursor]?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [cursor]);

  if (count === 0) return <div className="event-replay-empty">{emptyLabel}</div>;

  const active = cursor != null;
  const head = cursor ?? count - 1;

  const play = () => {
    setCursor((prev) => (prev == null || prev >= count - 1 ? 0 : prev));
    setPlaying(true);
  };
  const scrub = (value: number) => {
    setPlaying(false);
    setCursor(value);
  };

  return (
    <div className="event-replay">
      <div className="event-replay-bar">
        <button
          type="button"
          className="er-btn er-play"
          onClick={() => (playing ? setPlaying(false) : play())}
          aria-label={playing ? "Pause replay" : "Replay event timeline"}
        >
          {playing ? <Pause size={13} aria-hidden="true" /> : <Play size={13} aria-hidden="true" />}
          {playing ? "Pause" : "Replay"}
        </button>
        <button
          type="button"
          className="er-btn er-icon"
          onClick={() => {
            setCursor(0);
            setPlaying(true);
          }}
          title="Restart"
          aria-label="Restart replay"
        >
          <RotateCcw size={13} aria-hidden="true" />
        </button>
        <div className="er-speed" role="group" aria-label="Replay speed">
          {SPEEDS.map((value) => (
            <button key={value} type="button" className={value === speed ? "is-active" : ""} onClick={() => setSpeed(value)}>
              {value}×
            </button>
          ))}
        </div>
        <input
          className="er-scrub"
          type="range"
          min={0}
          max={Math.max(0, count - 1)}
          value={active ? head : 0}
          onChange={(event) => scrub(Number(event.target.value))}
          aria-label="Replay position"
        />
        <span className="er-readout">
          {active ? `${head + 1} / ${count} · ${formatClock(ordered[head].time)}` : `${count} events`}
        </span>
        {active ? (
          <button
            type="button"
            className="er-btn er-icon"
            onClick={() => {
              setPlaying(false);
              setCursor(null);
            }}
            title="Exit replay — show all"
            aria-label="Exit replay"
          >
            <X size={13} aria-hidden="true" />
          </button>
        ) : null}
      </div>

      <div className="event-replay-list">
        {ordered.map((event, index) => {
          const state = !active ? "all" : index < head ? "past" : index === head ? "current" : "future";
          return (
            <div
              key={event.id}
              ref={(element) => {
                rowRefs.current[index] = element;
              }}
              className={`event-replay-row is-${state}`}
            >
              <span className="er-time">{formatClock(event.time)}</span>
              <strong className="er-kind">{event.kind || "—"}</strong>
              <code className="er-detail">{event.detail || "—"}</code>
            </div>
          );
        })}
      </div>
    </div>
  );
}
