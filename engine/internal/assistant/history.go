package assistant

import "strings"

// Conversation history: the difference between an assistant and a search box.
//
// # What was wrong
//
// Run built its message list from exactly two things — the system prompt and
// the question just asked. Prior turns were never passed to the model. The
// control plane was faithfully PERSISTING every exchange to Postgres, the
// console was rendering the thread, and the model saw none of it.
//
// So every message was the analyst's first. "What about that host?" had no
// referent. "Are you sure?" was answered as a fresh question about certainty.
// An analyst who asked a question, got an answer, and asked a follow-up was
// talking to something with no memory of the sentence before — which is the
// specific behaviour that makes a chat surface feel mechanical rather than
// unintelligent. The tools were fine; the conversation did not exist.
//
// # Bounds, and why each one
//
// History is attacker-adjacent input even though the attacker is the analyst
// themselves: it arrives in a request body, and on the engine there is no
// server-side store to check it against. None of that lets a caller read
// anything they could not already read — tool authorization comes from their
// session cookie, not from anything here — but it does let them spend tokens
// and steer the model. So:
//
//   - Only "user" and "assistant" roles survive. A forged "system" turn would
//     otherwise let the request body rewrite the operating instructions,
//     including the evidence rules, from a field the console never sets.
//   - Tool-call structures are dropped. Replaying a tool result the server did
//     not produce is how a fabricated "policy_stats shows…" gets laundered into
//     the transcript as though a tool had returned it — the exact failure the
//     shared rules spend a paragraph forbidding.
//   - Bounded in turns and in bytes, oldest dropped first. An unbounded thread
//     on a paid inference endpoint is a cost incident, and a long enough one
//     pushes the system prompt out of the model's effective attention, which
//     silently disables the grounding discipline.
//
// On the control plane the history is loaded from the CHAT STORE instead, keyed
// by the chat id and re-checked against the caller's scope. That is strictly
// better — it is what was actually said, not what the client claims was said —
// and it is why the client-supplied path exists only as the fallback for the
// single-tenant engine, which has no history store at all.

const (
	// maxHistoryTurns is how many prior messages are carried.
	maxHistoryTurns = 20
	// maxHistoryBytes bounds the whole thread.
	maxHistoryBytes = 16 << 10
	// maxMessageBytes bounds one turn. A pasted log dump in message three must
	// not evict every other turn.
	maxMessageBytes = 4 << 10
)

// SanitiseHistory normalises prior turns into what may be replayed to a model.
//
// Returns the newest messages that fit the bounds, in chronological order.
func SanitiseHistory(in []Message) []Message {
	kept := make([]Message, 0, len(in))
	for _, m := range in {
		role := strings.ToLower(strings.TrimSpace(m.Role))
		if role != "user" && role != "assistant" {
			continue
		}
		content := strings.TrimSpace(m.Content)
		if content == "" {
			continue
		}
		if len(content) > maxMessageBytes {
			// Truncated with a marker rather than dropped: an analyst who
			// pasted a large log still needs the model to know they did.
			content = content[:maxMessageBytes] + "\n…[truncated]"
		}
		// Only Role and Content survive. Anything else — tool calls, tool call
		// ids, names — is reconstructed server-side or not at all.
		kept = append(kept, Message{Role: role, Content: content})
	}

	if len(kept) > maxHistoryTurns {
		kept = kept[len(kept)-maxHistoryTurns:]
	}
	// Drop from the OLDEST end until the byte budget is met: the turns nearest
	// the current question are the ones that resolve its pronouns.
	total := 0
	for _, m := range kept {
		total += len(m.Content)
	}
	for total > maxHistoryBytes && len(kept) > 1 {
		total -= len(kept[0].Content)
		kept = kept[1:]
	}
	return kept
}
