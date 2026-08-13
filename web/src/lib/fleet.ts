export function majority(values: Array<string | number | boolean | undefined | null>): string {
  const counts = new Map<string, number>();
  for (const value of values) {
    if (value == null) continue;
    const key = String(value);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  let best = "";
  let bestCount = 0;
  for (const [key, count] of counts) {
    if (count > bestCount) {
      best = key;
      bestCount = count;
    }
  }
  return best;
}

export function detectDrift(rows: Array<{ ok?: boolean; data?: Record<string, unknown> }>) {
  const okRows = rows.filter((row) => row.ok && row.data);
  const mode = majority(okRows.map((row) => row.data?.mode as string | undefined));
  const kill = majority(okRows.map((row) => Boolean(row.data?.kill_switched)));
  const thresholds = majority(okRows.map((row) => JSON.stringify(row.data?.thresholds ?? {})));
  return { mode, kill, thresholds };
}
