import { describe, expect, it } from "vitest";
import { groupChats } from "./chatGroups";
import type { Chat } from "./chatApi";

// A fixed clock. Grouping tested against `new Date()` passes today and fails at
// midnight, or on the machine of whoever runs CI in another timezone.
const NOW = new Date("2026-08-16T14:00:00Z");

function chat(over: Partial<Chat> & { id: string }): Chat {
  return {
    title: over.id,
    mode: "chat",
    created_at: "2026-08-01T00:00:00Z",
    updated_at: "2026-08-16T10:00:00Z",
    ...over
  } as Chat;
}

describe("groupChats", () => {
  it("puts pinned conversations first, whatever their date", () => {
    // The incident being worked is the conversation reopened twenty times. It
    // must not sink down the list because it started last week.
    const groups = groupChats(
      [
        chat({ id: "recent", updated_at: NOW.toISOString() }),
        chat({ id: "old-but-pinned", updated_at: "2026-01-01T00:00:00Z", pinned_at: "2026-08-16T09:00:00Z" })
      ],
      NOW
    );
    expect(groups[0].label).toBe("Pinned");
    expect(groups[0].chats.map((c) => c.id)).toEqual(["old-but-pinned"]);
  });

  it("separates today, yesterday, the last week and older", () => {
    const groups = groupChats(
      [
        chat({ id: "t", updated_at: "2026-08-16T09:00:00Z" }),
        chat({ id: "y", updated_at: "2026-08-15T09:00:00Z" }),
        chat({ id: "w", updated_at: "2026-08-12T09:00:00Z" }),
        chat({ id: "o", updated_at: "2026-06-01T09:00:00Z" })
      ],
      NOW
    );
    expect(groups.map((g) => g.label)).toEqual(["Today", "Yesterday", "Previous 7 days", "Older"]);
    expect(groups.map((g) => g.chats[0].id)).toEqual(["t", "y", "w", "o"]);
  });

  it("omits empty groups rather than rendering bare headings", () => {
    const groups = groupChats([chat({ id: "t", updated_at: "2026-08-16T09:00:00Z" })], NOW);
    expect(groups.map((g) => g.label)).toEqual(["Today"]);
  });

  it("never drops a conversation, even with an unusable timestamp", () => {
    // Losing a row silently is worse than filing it in the wrong group: the
    // operator concludes their conversation was deleted.
    const groups = groupChats([chat({ id: "broken", updated_at: "not-a-date" })], NOW);
    expect(groups.flatMap((g) => g.chats).map((c) => c.id)).toEqual(["broken"]);
  });

  it("returns nothing for no conversations", () => {
    expect(groupChats([], NOW)).toEqual([]);
  });
});
