package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Config is everything the assistant needs to talk to a model.
//
// BaseURL, Model and the key are all configuration rather than code, which is
// the single design decision that lets a self-hosted OpenAI-compatible endpoint
// work with no new code path.
type Config struct {
	// BaseURL is the OpenAI-compatible root, e.g. https://host/v1
	BaseURL string `yaml:"base_url"`
	// Model is the model id to request. It is the FAST path: a drill panel asks
	// one focused question and the analyst is waiting on the answer with the
	// panel still open.
	Model string `yaml:"model"`
	// DeepModel is an optional second model for sustained conversations in the
	// history sidebar, where the analyst is investigating rather than glancing
	// and a slower, stronger reasoner earns its latency.
	//
	// Empty means NO SPLIT — one model everywhere, which is the default and
	// what every deployment gets until someone deliberately configures two.
	//
	// # Why this is bound to the conversation and not to the request
	//
	// AssistantChatProvider states the rule this must not break: "a question
	// started inside a drill panel has to be the SAME conversation, opened
	// wider". Choosing per request would put two models in one thread — same
	// history, different voice, different failure modes, mid-investigation.
	// Choosing once, when the conversation is created, keeps one conversation
	// to one model for its whole life, including across a config change.
	DeepModel string `yaml:"deep_model"`
	// APIKeyEnv names the environment variable holding the key. The KEY ITSELF
	// IS NEVER A CONFIG FIELD: config files get committed, copied into deploy
	// scripts, and printed in support bundles. Naming the variable keeps the
	// secret in the process environment, the way CP_ADMIN_TOKEN already works.
	APIKeyEnv string `yaml:"api_key_env"`
	// Timeout bounds a SINGLE completion.
	Timeout time.Duration `yaml:"timeout"`
	// RunBudget bounds one whole answer: the tool-calling loop, every
	// completion in it, and the closing summarising call.
	//
	// It exists because these were the same number, and the handlers passed the
	// single-completion Timeout as the deadline for the entire run. Runner.Run
	// issues up to MaxToolCalls completions plus a closing one, so a six-step
	// answer had to finish seven provider calls inside the time allotted to
	// one. While upstream answered in ~1s that fitted easily and the assistant
	// looked fine for eight days; when upstream slowed to 50-130s per call on
	// 2026-08-24, the first completion consumed the whole budget and every
	// answer failed. One number cannot bound both.
	RunBudget time.Duration `yaml:"run_budget"`
	// MaxToolCalls bounds one answer's tool-calling loop. A model that keeps
	// asking for data is a model that will keep asking forever; an incident
	// console cannot wait on that.
	MaxToolCalls int `yaml:"max_tool_calls"`
}

// DefaultConfig is deliberately DISABLED (no BaseURL). The assistant is opt-in:
// a security product should not acquire an outbound dependency on a third-party
// inference endpoint because someone upgraded.
func DefaultConfig() Config {
	return Config{
		APIKeyEnv: "OPEN_WEIGHT_API_KEY",
		// 45s per call sheds a pathologically slow completion instead of
		// letting it eat the answer; 150s for the run leaves room for the
		// seven calls a full tool loop makes. Measured over 7 days on the
		// deployed gateway: gpt-oss:120b 246/246 OK, mean 1.1s, max 9.0s;
		// kimi-k3 259 calls, mean 13.9s, max 129.4s with 19 over 60s.
		Timeout:      45 * time.Second,
		RunBudget:    150 * time.Second,
		MaxToolCalls: 6,
	}
}

// ModelFor picks the model for an exchange.
//
// deep is true for a sustained conversation in the history sidebar and false
// for a drill panel's one-shot question. With no DeepModel configured both
// answer the same, so a single-model deployment cannot accidentally acquire a
// second one.
func (c Config) ModelFor(deep bool) string {
	if deep && strings.TrimSpace(c.DeepModel) != "" {
		return strings.TrimSpace(c.DeepModel)
	}
	return strings.TrimSpace(c.Model)
}

// KnownModel reports whether id is one this deployment is configured to use.
//
// A stored conversation carries the model it was created with, and that value
// comes back out of a database. Sending an unrecognised id straight to the
// inference endpoint because a row was edited, a migration went sideways, or a
// model was removed from the config would turn a data problem into a request
// against something nobody configured. Callers fall back to Model instead.
func (c Config) KnownModel(id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	return id == strings.TrimSpace(c.Model) || (c.DeepModel != "" && id == strings.TrimSpace(c.DeepModel))
}

// WithModel returns a copy of the config pinned to one model id.
//
// A copy rather than a mutable field on the provider: the four call sites that
// build a Runner each resolve their own model, and a shared provider whose
// model could be reassigned between requests is a data race that would show up
// as one analyst's answer arriving from the other one's model.
func (c Config) WithModel(id string) Config {
	if strings.TrimSpace(id) != "" {
		c.Model = strings.TrimSpace(id)
	}
	return c
}

// Enabled reports whether the assistant is configured. Everything downstream
// checks this so an unconfigured deployment behaves as if the feature does not
// exist, rather than erroring on every request.
func (c Config) Enabled() bool {
	return strings.TrimSpace(c.BaseURL) != "" && strings.TrimSpace(c.Model) != ""
}

// APIKey reads the key from the environment. Returns "" when unset — callers
// treat that as "not configured" rather than failing, so a misconfigured box
// degrades to no-assistant instead of a broken console.
func (c Config) APIKey() string {
	if c.APIKeyEnv == "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(c.APIKeyEnv))
}

// readOnlyTransport is the THIRD read-only layer (doc.go).
//
// The registry refuses to admit a mutating tool, and Tool's method cannot be
// set to anything but GET from outside this package. This is the backstop for
// the case both of those miss: code inside this package changed later, by
// someone who did not read doc.go, to issue a request directly. The transport
// does not care who built the request.
type readOnlyTransport struct{ base http.RoundTripper }

var errMutatingBlocked = errors.New("assistant: refusing a non-GET request from a read-only client")

func (t readOnlyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet {
		return nil, fmt.Errorf("%w: %s %s", errMutatingBlocked, req.Method, req.URL.Path)
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// NewReadOnlyClient returns an http.Client that physically cannot mutate.
// Used for every tool call.
func NewReadOnlyClient(timeout time.Duration, base http.RoundTripper) *http.Client {
	return &http.Client{Timeout: timeout, Transport: readOnlyTransport{base: base}}
}

// ── OpenAI-compatible wire types ───────────────────────────────────────────
// Only the subset actually used. A fuller struct would imply support for
// parameters this package does not set and cannot honour.

type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
}

type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type chatRequest struct {
	Model       string     `json:"model"`
	Messages    []Message  `json:"messages"`
	Tools       []wireTool `json:"tools,omitempty"`
	Temperature float64    `json:"temperature"`
	Stream      bool       `json:"stream"`
	ToolChoice  string     `json:"tool_choice,omitempty"`
}

type wireTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

type chatResponse struct {
	Choices []struct {
		Message      Message `json:"message"`
		FinishReason string  `json:"finish_reason"`
	} `json:"choices"`
	// Two upstreams, three shapes. Ollama Cloud returns
	//   429  {"error": "too many concurrent requests"}            a STRING
	//   503  {"error": {"message": "...", "type": "api_error"}}   an OBJECT
	// and the gateway's own limiter returns FastAPI's
	//   429  {"detail": "Rate limit exceeded. Retry in ~7s."}
	// The object-only struct that used to be here made the STRING form fail the
	// whole decode, so a plain rate limit reached the operator as a Go type
	// error and the status check below was never reached.
	Error  *providerError `json:"error,omitempty"`
	Detail *providerError `json:"detail,omitempty"`
}

// providerError accepts either form. A custom unmarshaller rather than a
// json.RawMessage at the call site: which shapes exist is the provider's
// business, and exactly one place should have to know there is more than one.
type providerError struct {
	Message string
	Type    string
}

func (e *providerError) UnmarshalJSON(b []byte) error {
	var text string
	if err := json.Unmarshal(b, &text); err == nil {
		e.Message = text
		return nil
	}
	var obj struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		// Neither shape. Keep the raw text rather than failing the decode: an
		// unparseable error body is still the only evidence there is.
		e.Message = strings.TrimSpace(string(b))
		return nil
	}
	e.Message, e.Type = obj.Message, obj.Type
	return nil
}

// Sentinels, so a handler can tell "wait and retry" from "the model is slow"
// from "this is broken" WITHOUT parsing an error string or seeing upstream
// text. errors.Is works through the %w wrapping below.
var (
	// ErrRateLimited is upstream refusing on volume. On the deployed gateway
	// this is a CONCURRENCY limit ("too many concurrent requests"), not a
	// per-minute one — fewer simultaneous asks helps, waiting alone may not.
	ErrRateLimited = errors.New("assistant: provider rate limited")
	// ErrOverloaded is upstream accepting but unable to serve right now.
	ErrOverloaded = errors.New("assistant: provider overloaded")
)

// Provider is the model transport. An interface so tests substitute a
// deterministic responder: an assistant tested against a live model is a test
// whose result depends on someone else's deployment.
type Provider interface {
	Complete(ctx context.Context, msgs []Message, tools []Tool) (Message, error)
	Name() string
}

// OpenAICompatible speaks the /chat/completions dialect. It is the only
// provider needed for a self-hosted endpoint, vLLM, or OpenAI itself.
type OpenAICompatible struct {
	cfg    Config
	client *http.Client
}

func NewOpenAICompatible(cfg Config, client *http.Client) *OpenAICompatible {
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	return &OpenAICompatible{cfg: cfg, client: client}
}

func (p *OpenAICompatible) Name() string { return "openai-compatible:" + p.cfg.Model }

func (p *OpenAICompatible) Complete(ctx context.Context, msgs []Message, tools []Tool) (Message, error) {
	key := p.cfg.APIKey()
	if key == "" {
		return Message{}, fmt.Errorf("assistant: %s is unset", p.cfg.APIKeyEnv)
	}

	wire := make([]wireTool, 0, len(tools))
	for _, t := range tools {
		var w wireTool
		w.Type = "function"
		w.Function.Name = t.Name
		w.Function.Description = t.Description
		w.Function.Parameters = t.Params
		wire = append(wire, w)
	}

	body, err := json.Marshal(chatRequest{
		Model:    p.cfg.Model,
		Messages: msgs,
		Tools:    wire,
		// Temperature 0: two analysts asking the same question of the same
		// incident must get the same answer. Sampling variety is a feature for
		// prose and a liability for evidence.
		Temperature: 0,
		Stream:      false,
	})
	if err != nil {
		return Message{}, err
	}

	url := strings.TrimRight(p.cfg.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Message{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)

	resp, err := p.client.Do(req)
	if err != nil {
		return Message{}, fmt.Errorf("assistant: provider unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Buffered rather than streamed off the decoder: the status has to stay
	// classifiable even when the body is something no struct here describes —
	// a proxy's HTML error page, a truncated response. Capped, because an error
	// body from an upstream nobody here controls is untrusted input.
	const maxErrorBody = 1 << 20
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	if readErr != nil {
		return Message{}, fmt.Errorf("assistant: reading provider response (status %d): %w", resp.StatusCode, readErr)
	}

	var out chatResponse
	decodeErr := json.Unmarshal(raw, &out)

	// Whatever the provider said about itself, redacted. Either shape, either
	// field, or the raw body when it is neither.
	detail := ""
	switch {
	case out.Error != nil && out.Error.Message != "":
		detail = out.Error.Message
	case out.Detail != nil && out.Detail.Message != "":
		detail = out.Detail.Message
	case decodeErr != nil:
		detail = strings.TrimSpace(string(raw))
	}
	if len(detail) > 300 {
		detail = detail[:300]
	}
	detail = redact(detail, key)

	// STATUS FIRST. This check used to sit BELOW the decode, so any body that
	// did not fit the struct returned "unreadable JSON" and the status — the
	// one thing always present and always meaningful — was never consulted.
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return Message{}, fmt.Errorf("%w (status %d): %s", ErrRateLimited, resp.StatusCode, detail)
	case resp.StatusCode == http.StatusServiceUnavailable,
		resp.StatusCode == http.StatusBadGateway,
		resp.StatusCode == http.StatusGatewayTimeout:
		return Message{}, fmt.Errorf("%w (status %d): %s", ErrOverloaded, resp.StatusCode, detail)
	case resp.StatusCode != http.StatusOK:
		return Message{}, fmt.Errorf("assistant: provider status %d: %s", resp.StatusCode, detail)
	}

	// A 200 whose body carries an error, or which does not parse at all.
	if decodeErr != nil {
		return Message{}, fmt.Errorf("assistant: provider returned unreadable JSON (status %d): %w", resp.StatusCode, decodeErr)
	}
	if detail != "" {
		// The key is in this process's memory; make certain no error path can
		// echo it back to a browser.
		return Message{}, fmt.Errorf("assistant: provider error: %s", detail)
	}
	if len(out.Choices) == 0 {
		return Message{}, errors.New("assistant: provider returned no choices")
	}
	return out.Choices[0].Message, nil
}

// redact removes the API key from anything that might reach a log or a browser.
func redact(s, key string) string {
	if key == "" {
		return s
	}
	return strings.ReplaceAll(s, key, "[redacted]")
}
