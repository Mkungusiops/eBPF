package assistant

import (
	"context"
	"errors"
)

// OperatorMessage turns a Runner.Run error into the one sentence an operator
// sees in the console.
//
// Why this exists: every upstream problem used to arrive as the same opaque
// "the assistant could not complete this request", which is three different
// operator actions collapsed into one. A rate limit means wait and retry; a
// timeout means the question was too big or the model is slow; an unreachable
// provider means the platform is broken and retrying is pointless.
//
// The strings are fixed and chosen here, never interpolated from the upstream
// error. The provider's own message can carry its URL, its model name, or the
// echoed key, and this text goes to a browser — that constraint is why the
// message was generic in the first place, and it survives.
func OperatorMessage(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrRateLimited):
		// Deliberately not "wait a minute": on the deployed gateway this is a
		// concurrency limit shared across tenants, so it clears when the other
		// callers finish, not when a clock elapses.
		return "the assistant is rate limited right now — too many requests are in flight. Try again in a moment."
	case errors.Is(err, ErrOverloaded):
		return "the assistant's model service is busy right now. Try again in a moment."
	case errors.Is(err, context.DeadlineExceeded):
		return "the assistant ran out of time on this question. Try a narrower question, or ask again."
	case errors.Is(err, context.Canceled):
		return "the request was cancelled."
	default:
		return "the assistant could not complete this request"
	}
}

// ClientAbandoned reports whether an error is the caller hanging up rather than
// anything being wrong here — a closed panel, a navigated-away tab, an explicit
// Cancel. It is the difference between a Warn worth investigating and an Info.
func ClientAbandoned(err error) bool {
	return errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}
