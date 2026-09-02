package assistant

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The provider returns `error` as a bare STRING on 429 and as an object
// elsewhere. Decoding it as an object destroyed the whole body, so a rate limit
// reached the operator as "provider returned unreadable JSON" — the one status
// where knowing the reason changes what they do.
func TestCompleteClassifiesRateLimitBeforeDecoding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"429 with a string error", http.StatusTooManyRequests,
			`{"error":"rate limit exceeded: 3 concurrent requests"}`, ErrRateLimited},
		{"429 with an object error", http.StatusTooManyRequests,
			`{"error":{"message":"slow down","type":"rate_limit"}}`, ErrRateLimited},
		{"429 with an unparseable body", http.StatusTooManyRequests,
			`<html>too many requests</html>`, ErrRateLimited},
		{"503 overloaded", http.StatusServiceUnavailable,
			`{"error":"upstream at capacity"}`, ErrOverloaded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()

			cfg := DefaultConfig()
			cfg.BaseURL = srv.URL
			t.Setenv(cfg.APIKeyEnv, "test-key")
			_, err := NewOpenAICompatible(cfg, nil).Complete(context.Background(), []Message{{Role: "user"}}, nil)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want it to wrap %v", err, tc.want)
			}
			// The upstream text is kept for the JOURNAL...
			if tc.status == http.StatusTooManyRequests && strings.Contains(tc.body, "concurrent") &&
				!strings.Contains(err.Error(), "concurrent") {
				t.Errorf("upstream detail lost from the logged error: %v", err)
			}
			// ...and kept OUT of what the browser is shown.
			if msg := OperatorMessage(err); strings.Contains(msg, srv.URL) || strings.Contains(msg, "concurrent") {
				t.Errorf("operator message leaks upstream detail: %q", msg)
			}
		})
	}
}

// A per-completion timeout must still read as a deadline after passing through
// http.Client, url.Error and the provider's own wrap — that chain is what
// OperatorMessage keys on to say "slow" instead of "broken".
func TestTimeoutSurvivesTheErrorChain(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer func() { close(block); srv.Close() }()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL
	cfg.Timeout = 150 * time.Millisecond
	t.Setenv(cfg.APIKeyEnv, "test-key")
	_, err := NewOpenAICompatible(cfg, nil).Complete(context.Background(), []Message{{Role: "user"}}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a client timeout did not survive as DeadlineExceeded: %v", err)
	}
	if got, want := OperatorMessage(err), "ran out of time"; !strings.Contains(got, want) {
		t.Errorf("operator message %q does not contain %q", got, want)
	}
	if ClientAbandoned(err) {
		t.Error("a timeout was misread as the caller hanging up; it would be logged at Info and never investigated")
	}
}

// The caller closing the panel is not a platform fault. It was logged at Warn,
// which put five identical lines in the journal that read like five upstream
// failures during triage.
func TestClientHangupIsDistinguishedFromAFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := fmt.Errorf("assistant: provider unreachable: %w", ctx.Err())
	if !ClientAbandoned(err) {
		t.Fatalf("a cancelled caller was not recognised: %v", err)
	}
	if ClientAbandoned(fmt.Errorf("wrapped: %w", ErrRateLimited)) {
		t.Error("a rate limit was misread as the caller hanging up")
	}
}

// Every branch must yield a sentence, and none of them the empty string — an
// empty error event renders as a blank red box in the console.
func TestOperatorMessageAlwaysSaysSomething(t *testing.T) {
	for _, err := range []error{
		ErrRateLimited, ErrOverloaded, context.DeadlineExceeded, context.Canceled,
		errors.New("assistant: provider returned no choices"),
	} {
		if msg := OperatorMessage(err); strings.TrimSpace(msg) == "" {
			t.Errorf("%v produced an empty operator message", err)
		}
	}
	if OperatorMessage(nil) != "" {
		t.Error("a nil error produced a message")
	}
}

// The budget must exceed the per-call timeout, or the loop cannot complete even
// one full-length call plus its follow-up. This is the defect that made every
// multi-step answer fail the day upstream slowed down.
func TestRunBudgetExceedsASingleCompletion(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.RunBudget <= cfg.Timeout {
		t.Fatalf("RunBudget %s must exceed Timeout %s; a tool loop cannot finish otherwise",
			cfg.RunBudget, cfg.Timeout)
	}
	if cfg.MaxToolCalls < 1 {
		t.Fatalf("MaxToolCalls %d leaves the assistant unable to read anything", cfg.MaxToolCalls)
	}
}
