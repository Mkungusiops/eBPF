import type { Chat } from "./chatApi";

/**
 * Date grouping for the conversation list.
 *
 * Taken from the reference implementation in ~/Code/m, and it is the single
 * change that makes history usable rather than merely present: an operator
 * looks for "the one from yesterday", never for a position in a list. A flat
 * reverse-chronological list is a scroll; grouped, it is a memory.
 *
 * Pinned is a group of its own and comes first, because the incident being
 * worked is the conversation reopened twenty times.
 */
export interface ChatGroup {
  label: string;
  pinned?: boolean;
  chats: Chat[];
}

/** Exported so a test can pin behaviour to a fixed clock rather than today. */
export function groupChats(chats: Chat[], now: Date = new Date()): ChatGroup[] {
  const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const day = 86_400_000;

  const pinned: Chat[] = [];
  const today: Chat[] = [];
  const yesterday: Chat[] = [];
  const week: Chat[] = [];
  const older: Chat[] = [];

  for (const c of chats) {
    if (c.pinned_at) {
      pinned.push(c);
      continue;
    }
    // An unparseable timestamp must not silently drop a conversation from the
    // list — it lands in Older, where it is still reachable.
    const t = Date.parse(c.updated_at);
    if (Number.isNaN(t)) {
      older.push(c);
    } else if (t >= startOfToday) {
      today.push(c);
    } else if (t >= startOfToday - day) {
      yesterday.push(c);
    } else if (t >= startOfToday - 7 * day) {
      week.push(c);
    } else {
      older.push(c);
    }
  }

  return [
    { label: "Pinned", pinned: true, chats: pinned },
    { label: "Today", chats: today },
    { label: "Yesterday", chats: yesterday },
    { label: "Previous 7 days", chats: week },
    { label: "Older", chats: older }
  ].filter((g) => g.chats.length > 0);
}
