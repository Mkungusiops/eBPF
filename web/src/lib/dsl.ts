export interface FilterToken {
  key?: string;
  op?: ":" | ">" | "<" | ">=" | "<=";
  value: string;
  negated?: boolean;
}

export function parseQuery(query: string): FilterToken[] {
  return query
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map((raw) => {
      const negated = raw.startsWith("!");
      const text = negated ? raw.slice(1) : raw;
      const match = text.match(/^([a-zA-Z_][\w-]*)(>=|<=|:|>|<)(.+)$/);
      if (!match) return { value: text, negated };
      return { key: match[1], op: match[2] as FilterToken["op"], value: match[3], negated };
    });
}

export function matchesQuery(record: Record<string, unknown>, query: string): boolean {
  const tokens = parseQuery(query);
  if (tokens.length === 0) return true;
  const haystack = JSON.stringify(record).toLowerCase();
  return tokens.every((token) => {
    const value = token.value.toLowerCase();
    const matched = token.key
      ? String(record[token.key] ?? "").toLowerCase().includes(value)
      : haystack.includes(value);
    return token.negated ? !matched : matched;
  });
}
