package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	// Model is the model id to request.
	Model string `yaml:"model"`
	// APIKeyEnv names the environment variable holding the key. The KEY ITSELF
	// IS NEVER A CONFIG FIELD: config files get committed, copied into deploy
	// scripts, and printed in support bundles. Naming the variable keeps the
	// secret in the process environment, the way CP_ADMIN_TOKEN already works.
	APIKeyEnv string `yaml:"api_key_env"`
	// Timeout bounds a single completion.
	Timeout time.Duration `yaml:"timeout"`
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
		APIKeyEnv:    "OPEN_WEIGHT_API_KEY",
		Timeout:      60 * time.Second,
		MaxToolCalls: 6,
	}
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
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

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

	var out chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Message{}, fmt.Errorf("assistant: provider returned unreadable JSON (status %d): %w", resp.StatusCode, err)
	}
	if out.Error != nil {
		// The key is in this process's memory; make certain no error path can
		// echo it back to a browser.
		return Message{}, fmt.Errorf("assistant: provider error: %s", redact(out.Error.Message, key))
	}
	if resp.StatusCode != http.StatusOK {
		return Message{}, fmt.Errorf("assistant: provider status %d", resp.StatusCode)
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
