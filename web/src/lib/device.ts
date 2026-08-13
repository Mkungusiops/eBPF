const FLAG = {
  THROTTLE: 1,
  TARPIT: 2,
  QUARANTINE: 4,
  SEVER: 8
} as const;

export function flagName(flags = 0): string {
  if (flags & FLAG.SEVER) return "sever";
  if (flags & FLAG.QUARANTINE) return "quarantine";
  if (flags & FLAG.TARPIT) return "tarpit";
  if (flags & FLAG.THROTTLE) return "throttle";
  return "none";
}

export function formatBytes(bytes = 0): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx++;
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[idx]}`;
}

export function macSlug(mac: string): string {
  return mac.replace(/:/g, "-").toLowerCase();
}
