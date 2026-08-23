package assistant

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Server-sent events for a run in progress.
//
// # Why this exists, and why it streams STEPS rather than tokens
//
// platform-assistant.md §3 calls abortable streaming non-negotiable and §6
// records it as deferred. The reason it matters here is specific: the latency
// in an answer is not the model writing, it is the TOOL LOOP — up to six reads
// against the engine's own API before the model has a word to say. An analyst
// watching "Reading telemetry…" for fifteen seconds cannot tell work from a
// hang, and AssistantPanel's own design notes say progress must be named rather
// than spun.
//
// So this streams the investigation, not the prose. Each tool call is announced
// as it completes — which endpoint, how much came back, how long it took — and
// the finished Answer arrives as one final event. That is the information an
// analyst actually wants during the wait, and it is the same provenance trace
// the answer carries afterwards, only sooner.
//
// The event names are part of the contract with the console:
//
//	event: step     one completed tool call (a Step)
//	event: answer   the finished Answer; always last on success
//	event: error    the run failed; always last on failure
//
// A client that receives neither `answer` nor `error` before the stream closes
// must treat the run as failed. Silence is not success.

// StreamWriter emits assistant events to an http.ResponseWriter.
//
// Not safe for concurrent use: one run, one writer, one goroutine. The tool loop
// is sequential, so that costs nothing and removes a class of interleaved-frame
// bug that would be invisible until a slow tenant hit it.
type StreamWriter struct {
	w  http.ResponseWriter
	fl http.Flusher
}

// NewStreamWriter prepares w for SSE and returns a writer, or false when the
// ResponseWriter cannot flush.
//
// Reported rather than ignored: without flushing, every event buffers until the
// handler returns and "streaming" silently becomes a slower version of the
// request/response endpoint — working, testable, and useless. The caller falls
// back to a normal JSON response instead of pretending.
func NewStreamWriter(w http.ResponseWriter) (*StreamWriter, bool) {
	fl, ok := w.(http.Flusher)
	if !ok {
		return nil, false
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("Connection", "keep-alive")
	// Without this, nginx buffers the whole response and the console sees one
	// burst at the end. Both deployments sit behind nginx, so a stream that
	// works on loopback and not in production is the default outcome.
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	return &StreamWriter{w: w, fl: fl}, true
}

// Step announces one completed tool call.
func (s *StreamWriter) Step(st Step) { s.send("step", st) }

// Answer sends the finished answer. Always the last event on success.
func (s *StreamWriter) Answer(a Answer) { s.send("answer", a) }

// Error ends the stream with a failure.
//
// The message is written by the caller and must already be safe for a browser —
// provider errors can carry upstream detail and an API key lives in this
// process. Callers log the real error and send a generic one, exactly as the
// non-streaming handlers do.
func (s *StreamWriter) Error(msg string) { s.send("error", map[string]string{"error": msg}) }

func (s *StreamWriter) send(event string, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		// A frame that will not marshal must not kill the stream: the analyst
		// loses one progress line, not the answer.
		body = []byte(`{"error":"unserialisable event"}`)
	}
	// SSE frames are terminated by a BLANK LINE. Omitting it makes the browser
	// hold the event until the next one arrives, which turns per-step progress
	// into progress that is always one step behind.
	_, _ = fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", event, body)
	s.fl.Flush()
}
