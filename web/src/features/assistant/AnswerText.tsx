/**
 * Renders an assistant answer as readable text.
 *
 * The panel used `white-space: pre-wrap` on the raw string, so a model that
 * emitted `**Assessment**` printed literal asterisks and a 64-character exec id
 * ate three lines on a narrow panel. Correct content, unreadable presentation —
 * and on an incident console, unreadable is a real cost, not a cosmetic one.
 *
 * Deliberately NOT a markdown library. The assistant is instructed to write
 * plain prose with simple bullets, so this handles exactly what leaks through
 * that instruction — bold, headings, bullets, inline code — and nothing else.
 * Pulling in a markdown renderer would add a dependency (and an HTML injection
 * surface) to display text a security product received from a language model.
 * Everything here goes through React as text, so nothing can inject markup.
 */

/** Collapses a long opaque id to something a human can compare at a glance. */
function shortenIds(text: string): string {
  // 24+ chars of base64-ish id: keep enough to distinguish, drop the rest.
  return text.replace(/\b([A-Za-z0-9+/_-]{10})[A-Za-z0-9+/_-]{14,}\b/g, "$1…");
}

/** Strips inline markdown emphasis, returning renderable segments. */
function inline(text: string, keyPrefix: string) {
  const out: React.ReactNode[] = [];
  // `code` and **bold** are the two that actually appear.
  const re = /(`[^`]+`)|(\*\*[^*]+\*\*)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith("`")) {
      out.push(
        <code key={`${keyPrefix}-c${i}`} className="asst__code">
          {tok.slice(1, -1)}
        </code>
      );
    } else {
      out.push(<strong key={`${keyPrefix}-b${i}`}>{tok.slice(2, -2)}</strong>);
    }
    last = m.index + tok.length;
    i += 1;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export function AnswerText({ content }: { content: string }) {
  const lines = shortenIds(content).split("\n");
  const blocks: React.ReactNode[] = [];
  let bullets: string[] = [];

  const flush = (key: string) => {
    if (bullets.length === 0) return;
    blocks.push(
      <ul className="asst__list" key={`ul-${key}`}>
        {bullets.map((b, i) => (
          <li key={`${key}-${i}`}>{inline(b, `${key}-${i}`)}</li>
        ))}
      </ul>
    );
    bullets = [];
  };

  lines.forEach((raw, idx) => {
    const line = raw.trimEnd();
    const key = String(idx);

    // Bullet: "- x", "* x", or "1. x" — all three show up.
    const bullet = line.match(/^\s*(?:[-*•]|\d+\.)\s+(.*)$/);
    if (bullet) {
      bullets.push(bullet[1]);
      return;
    }
    flush(key);

    if (line.trim() === "") return;

    // A heading, however the model spelled it: "## X", "**X**", or "X:" alone.
    const heading =
      line.match(/^#{1,6}\s+(.*)$/) ||
      line.match(/^\*\*(.+?)\*\*:?\s*$/) ||
      line.match(/^([A-Z][A-Za-z ]{2,30}):\s*$/);
    if (heading) {
      blocks.push(
        <p className="asst__h" key={`h-${key}`}>
          {heading[1].replace(/\*\*/g, "").trim()}
        </p>
      );
      return;
    }

    blocks.push(
      <p className="asst__p" key={`p-${key}`}>
        {inline(line, key)}
      </p>
    );
  });
  flush("end");

  return <div className="asst__content">{blocks}</div>;
}
