// One formatter per idea, shared by every SOC surface.
//
// These all started life as inline expressions next to the thing they rendered,
// which is how the console ended up telling an operator two different things
// about the same number: the window selector printed "10080m" while every
// notice on the same page called that window "7d". A second copy of a formatter
// is a drift waiting to happen, so each one lives here exactly once.

// The window selector's own vocabulary — "5m", "60m", "24h".
export function rangeLabel(rangeMin: number): string {
  // Days once past a day. The old form returned "24h" for ANY range >= 1440,
  // so a 7-day window would have been labelled 24h everywhere the label is
  // used — including the notices that state which window a number covers.
  if (rangeMin >= 1440) {
    const days = Math.round(rangeMin / 1440);
    return days === 1 ? "24h" : `${days}d`;
  }
  if (rangeMin >= 60) return `${Math.round(rangeMin / 60)}h`;
  return `${rangeMin}m`;
}

// A span in plain words: "45s", "3m", "1h 12m".
export function formatDuration(ms: number): string {
  const totalSec = Math.max(0, Math.round(ms / 1000));
  if (totalSec < 60) return `${totalSec}s`;
  const min = Math.round(totalSec / 60);
  if (min < 60) return `${min}m`;
  const hr = Math.floor(min / 60);
  const rem = min % 60;
  return rem ? `${hr}h ${rem}m` : `${hr}h`;
}

export function formatTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "n/a";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function shortId(value: string) {
  return value.length > 18 ? `${value.slice(0, 8)}...${value.slice(-6)}` : value;
}

export function baseName(path?: string): string {
  if (!path) return "process";
  const idx = path.lastIndexOf("/");
  return idx >= 0 ? path.slice(idx + 1) || path : path;
}

export function shortGraphLabel(value: string, max = 24) {
  const clean = value.replace(/\s+/g, " ").trim();
  if (!clean) return "unknown";
  if (clean.length <= max) return clean;
  const leaf = clean.split("/").filter(Boolean).at(-1);
  const candidate = leaf && leaf.length <= Math.max(10, max) ? leaf : clean;
  if (candidate.length <= max) return candidate;
  const side = Math.max(5, Math.floor((max - 3) / 2));
  return `${candidate.slice(0, side)}...${candidate.slice(-side)}`;
}
