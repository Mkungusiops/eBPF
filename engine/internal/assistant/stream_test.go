package assistant

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestStreamEmitsEveryStepBeforeTheAnswer is the behaviour the feature exists
// for: an analyst watching a fifteen-second tool loop must see it WORKING.
// A stream that only delivers its events once the run finishes is a slower
// request/response endpoint wearing an SSE content type.
func TestStreamEmitsEveryStepBeforeTheAnswer(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer api.Close()

	// Records the order events reached the wire, so "steps arrived first" is
	// asserted rather than assumed.
	var order []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stream, ok := NewStreamWriter(w)
		if !ok {
			t.Error("httptest.ResponseRecorder cannot flush")
			return
		}
		run := &Runner{
			Provider: &twoToolProvider{},
			Tools:    DefaultTools(),
			Client:   NewReadOnlyClient(5*time.Second, nil),
			BaseURL:  api.URL,
			MaxCalls: 4,
			OnStep: func(st Step) {
				order = append(order, "step:"+st.Tool)
				stream.Step(st)
			},
		}
		ans, err := run.Run(r.Context(), "ask", "how bad is it?", "")
		if err != nil {
			stream.Error("failed")
			return
		}
		order = append(order, "answer")
		stream.Answer(ans)
	}))
	defer srv.Close()

	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
	// Without this, nginx buffers the whole response and per-step progress
	// silently stops existing in production while passing every local test.
	if resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Error("X-Accel-Buffering is not disabled; nginx will buffer the stream")
	}

	var events []string
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "event: ") {
			events = append(events, strings.TrimPrefix(sc.Text(), "event: "))
		}
	}
	if len(events) < 2 {
		t.Fatalf("stream carried %d events (%v); want steps followed by an answer", len(events), events)
	}
	if events[len(events)-1] != "answer" {
		t.Errorf("last event is %q, want answer — a client cannot tell success from a dropped connection", events[len(events)-1])
	}
	for _, e := range events[:len(events)-1] {
		if e != "step" {
			t.Errorf("event %q arrived before the answer; only steps should", e)
		}
	}
	if len(order) == 0 || order[len(order)-1] != "answer" {
		t.Errorf("run order was %v; every step must be emitted before the answer", order)
	}
}

// A frame must be terminated by a blank line, or the browser holds each event
// until the next arrives and progress is permanently one step stale.
func TestStreamFramesAreBlankLineTerminated(t *testing.T) {
	rec := httptest.NewRecorder()
	stream, ok := NewStreamWriter(rec)
	if !ok {
		t.Fatal("recorder cannot flush")
	}
	stream.Step(Step{Tool: "list_alerts", Path: "/api/alerts", Bytes: 12, Duration: "3ms"})
	stream.Answer(Answer{Agent: "ask", Content: "fine", Grounded: true})

	body := rec.Body.String()
	for _, frame := range []string{"event: step\ndata: ", "event: answer\ndata: "} {
		if !strings.Contains(body, frame) {
			t.Errorf("missing frame %q in:\n%s", frame, body)
		}
	}
	if strings.Count(body, "\n\n") < 2 {
		t.Errorf("frames are not blank-line terminated:\n%q", body)
	}
}

// A run with no OnStep must behave exactly as it always has. The streaming hook
// is optional precisely so the two endpoints stay one code path.
func TestNilOnStepIsNotAFailure(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer api.Close()

	run := &Runner{
		Provider: &twoToolProvider{},
		Tools:    DefaultTools(),
		Client:   NewReadOnlyClient(5*time.Second, nil),
		BaseURL:  api.URL,
		MaxCalls: 4,
	}
	ans, err := run.Run(context.Background(), "ask", "q", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(ans.Steps) == 0 {
		t.Error("no steps recorded; the answer would be reported ungrounded")
	}
}

// twoToolProvider calls two tools, then answers.
type twoToolProvider struct{ turn int }

func (p *twoToolProvider) Name() string { return "two-tool" }

func (p *twoToolProvider) Complete(_ context.Context, _ []Message, _ []Tool) (Message, error) {
	p.turn++
	if p.turn > 2 {
		return Message{Role: "assistant", Content: "quiet"}, nil
	}
	name := "list_alerts"
	if p.turn == 2 {
		name = "alert_statistics"
	}
	var m Message
	var tc ToolCall
	tc.ID = name
	tc.Type = "function"
	tc.Function.Name = name
	tc.Function.Arguments = "{}"
	m.Role = "assistant"
	m.ToolCalls = []ToolCall{tc}
	return m, nil
}
