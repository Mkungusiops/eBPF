package assistant

import (
	"context"
	"strings"
	"testing"
)

// blankProvider returns empty content and no tool calls, which is what kimi-k3
// does at a measurable rate. `replyAfter` lets a test give a real answer on a
// later call, so the retry path can be told apart from the give-up path.
type blankProvider struct {
	calls      int
	replyAfter int // 0 = never reply
	reply      string
}

func (p *blankProvider) Name() string { return "blank" }
func (p *blankProvider) Complete(_ context.Context, _ []Message, _ []Tool) (Message, error) {
	p.calls++
	if p.replyAfter > 0 && p.calls >= p.replyAfter {
		return Message{Role: "assistant", Content: p.reply}, nil
	}
	return Message{Role: "assistant", Content: ""}, nil
}

// An empty reply is not a greeting.
//
// assertsNothing("") satisfied every clause it had — no words, no digits — so
// a blank model reply was classified as a reply that makes no claim: no retry,
// no ungrounded warning, and an EMPTY BUBBLE on the console. An analyst reads
// that as the assistant having nothing to say about their incident, which is a
// far stronger statement than "the provider returned nothing".
func TestAnEmptyReplyIsNotTreatedAsAGreeting(t *testing.T) {
	if assertsNothing("") {
		t.Fatal("an empty string was classified as a reply that asserts nothing")
	}
	if assertsNothing("   \n\t ") {
		t.Fatal("whitespace-only content was classified as a reply that asserts nothing")
	}
	// The real greeting case must still work, or this fix breaks the fix it
	// sits on top of.
	if !assertsNothing("Hello — what would you like to look at?") {
		t.Fatal("a genuine greeting stopped counting as a no-claim reply")
	}
}

// A blank FIRST reply must not end the run.
//
// Scoped deliberately to that one claim. A model that then answers without
// calling a tool still meets the pre-existing grounding nudge, and asserting an
// exact call count here would be testing that mechanism rather than this one —
// which is how a test starts failing for a reason it was never about.
func TestABlankReplyDoesNotEndTheRun(t *testing.T) {
	p := &blankProvider{replyAfter: 2, reply: "web-01 is the noisiest host"}
	r := &Runner{Provider: p, Tools: NewRegistry(), MaxCalls: 4}

	ans, err := r.Run(context.Background(), "ask", "which host is noisiest?", "")
	if err != nil {
		t.Fatal(err)
	}
	if p.calls < 2 {
		t.Fatalf("provider called %d time(s) — the blank reply was accepted instead of retried", p.calls)
	}
	// The give-up message belongs to a provider that stayed blank. This one
	// spoke on its second call, so reporting a provider failure would be wrong.
	if strings.Contains(ans.Content, "empty reply from the model provider") {
		t.Fatalf("a provider that recovered was still reported as failing: %q", ans.Content)
	}
}

// After the retry, the console must be told what happened rather than shown
// nothing. Never blank, and never labelled NoClaim — that flag suppresses the
// ungrounded banner, and a provider failure is exactly what an analyst needs to
// see.
func TestAPersistentlyBlankProviderIsReportedNotRendered(t *testing.T) {
	p := &blankProvider{}
	r := &Runner{Provider: p, Tools: NewRegistry(), MaxCalls: 4}

	ans, err := r.Run(context.Background(), "ask", "which host is noisiest?", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(ans.Content) == "" {
		t.Fatal("a blank reply reached the console as a blank answer")
	}
	if !strings.Contains(strings.ToLower(ans.Content), "provider") {
		t.Fatalf("the answer does not say this was a provider failure: %q", ans.Content)
	}
	if ans.NoClaim {
		t.Fatal("a provider failure was labelled NoClaim, which hides the warning banner")
	}
	// Exactly two attempts: an incident console cannot be held open retrying a
	// provider that is not answering.
	if p.calls != 2 {
		t.Fatalf("provider called %d times, want 2", p.calls)
	}
}
