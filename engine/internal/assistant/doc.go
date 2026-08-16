// Package assistant is the SOC analyst assistant: an LLM given READ-ONLY access
// to this engine's own telemetry, so an analyst can ask "why did this score 117"
// and get an answer grounded in the actual process chain rather than a guess.
//
// # The security decision this package encodes
//
// An LLM next to a containment console is a security decision, not a feature
// decision. This engine can SIGKILL processes and sever devices from the
// network. The threat model (docs/plan/threat-model.md) already names the risk
// this creates — EN-2 dual control exists precisely to stop ONE ACTOR
// CONTAINING MANY HOSTS — and an agent holding containment tools is exactly
// that actor, minus the second pair of eyes.
//
// So the assistant gets queries. A human presses the button.
//
// That is not enforced by a prompt. A prompt is a request; a registry is a
// constraint. Read-only here is structural, in three independent layers:
//
//  1. Tool.Method is unexported and set only by NewReadTool, which hard-codes
//     GET. There is no exported way to construct a Tool with any other method.
//  2. Registry.Register rejects a non-GET method, a path on the containment
//     denylist, or a path outside the read allowlist — loudly, at wiring time,
//     not at request time.
//  3. The http.RoundTripper handed to tools refuses any non-GET request. A tool
//     that builds its own request still cannot mutate.
//
// Layer 2 catches mistakes early and legibly. Layer 3 catches them absolutely.
// Both exist because the cost of being wrong once is an LLM quarantining a
// production host with no operator involved.
//
// registry_test.go is the ratchet: it enumerates every registered tool and
// fails the build if any maps to a mutating method or a containment path. It
// also asserts the denylist still covers every containment endpoint the API
// actually serves, so ADDING a containment route without updating this package
// breaks the build rather than silently widening what the assistant can reach.
// Same idea as internal/isolationguard.
//
// # Provider
//
// The provider is OpenAI-compatible and takes its base URL from configuration,
// which is the whole reason a self-hosted endpoint needs no new code path here.
// The API key is read from the environment server-side and never crosses to the
// browser: the console talks to this engine, and this engine talks to the model.
package assistant
