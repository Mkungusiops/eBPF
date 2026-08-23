package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"

	"github.com/jeffmk/ebpf-poc-engine/internal/policyapply"
)

// The engine can now change what its own kernel watches. These pin the rules
// that make that safe to expose in a console, each of which exists because the
// alternative has already cost this project something.

type stubSensors struct{ addErr error }

func (s stubSensors) AddTracingPolicy(context.Context, *tetragon.AddTracingPolicyRequest, ...grpc.CallOption) (*tetragon.AddTracingPolicyResponse, error) {
	return nil, s.addErr
}
func (s stubSensors) DeleteTracingPolicy(context.Context, *tetragon.DeleteTracingPolicyRequest, ...grpc.CallOption) (*tetragon.DeleteTracingPolicyResponse, error) {
	return nil, nil
}
func (s stubSensors) ListTracingPolicies(context.Context, *tetragon.ListTracingPoliciesRequest, ...grpc.CallOption) (*tetragon.ListTracingPoliciesResponse, error) {
	return &tetragon.ListTracingPoliciesResponse{}, nil
}
func (s stubSensors) ConfigureTracingPolicy(context.Context, *tetragon.ConfigureTracingPolicyRequest, ...grpc.CallOption) (*tetragon.ConfigureTracingPolicyResponse, error) {
	return nil, nil
}

const validPolicy = "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: p\n"

// withApplier installs a client for the duration of one test and restores the
// previous one, so tests cannot leak capability into each other.
func withApplier(t *testing.T, c policyapply.Client, dir string) {
	t.Helper()
	sensorsMu.Lock()
	prevC, prevD := sensors, durableDir
	sensorsMu.Unlock()
	SetPolicyApplier(c, dir)
	t.Cleanup(func() {
		sensorsMu.Lock()
		sensors, durableDir = prevC, prevD
		sensorsMu.Unlock()
	})
}

func push(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	s := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/policies/push", strings.NewReader(body))
	s.handlePolicyPush(rec, req)
	return rec
}

func TestPushRefusesEnforceMode(t *testing.T) {
	// An enforcing TracingPolicy kills independently of the choke ladder: no
	// audit row, no reversal, no kill-switch. This project has already lost a
	// host to one. Arming it must not be reachable by pasting YAML into a form.
	withApplier(t, stubSensors{}, t.TempDir())
	rec := push(t, `{"reason":"r","policies":[{"name":"p","yaml":"`+"x"+`","mode":"enforce"}]}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "kill-switch") {
		t.Fatalf("the refusal should explain why, got: %s", rec.Body.String())
	}
}

func TestPushRefusesAnUnknownMode(t *testing.T) {
	// Not silently coerced to monitor: a mode this build does not understand
	// means the caller expected something this build cannot promise.
	withApplier(t, stubSensors{}, t.TempDir())
	rec := push(t, `{"reason":"r","policies":[{"name":"p","yaml":"x","mode":"audit"}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
}

func TestPushRequiresAReason(t *testing.T) {
	// Changing what a production kernel watches is a change an auditor asks
	// about, and the reason is what the audit row carries.
	withApplier(t, stubSensors{}, t.TempDir())
	rec := push(t, `{"policies":[{"name":"p","yaml":"x"}]}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "reason") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestPushRejectsAnEmptyRequest(t *testing.T) {
	withApplier(t, stubSensors{}, t.TempDir())
	rec := push(t, `{"reason":"r"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
}

func TestPushRejectsAnOversizedDocument(t *testing.T) {
	withApplier(t, stubSensors{}, t.TempDir())
	huge := strings.Repeat("y", maxPolicyBytes+1)
	rec := push(t, `{"reason":"r","policies":[{"name":"p","yaml":"`+huge+`"}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
}

func TestPushIs503WithoutATetragonConnection(t *testing.T) {
	// A deployment with no Tetragon (the -fake dev mode) must say which
	// capability is missing, not fail as though the operator sent something
	// wrong. The console hides the button on the same signal.
	withApplier(t, nil, "")
	rec := push(t, `{"reason":"r","policies":[{"name":"p","yaml":"x"}]}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", rec.Code)
	}
	if CanPushPolicy() {
		t.Fatal("CanPushPolicy must be false with no client — the console gates the surface on it")
	}
}

func TestPushReportsLiveButNotDurableWithoutCountingItAsFailed(t *testing.T) {
	// The single-host honesty problem is DURABILITY, not reach. A policy that
	// loaded but could not be persisted is genuinely both useful now and gone
	// at the next restart; folding it into either column is the lie.
	withApplier(t, stubSensors{}, "/definitely/not/a/directory")
	rec := push(t, `{"reason":"r","policies":[{"name":"p","yaml":`+jsonStr(validPolicy)+`}]}`)

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["durable"] != false {
		t.Fatalf("durable should be false, got %v", got["durable"])
	}
	if got["failed"].(float64) != 0 {
		t.Fatalf("a live-but-not-durable policy is not a failure, got failed=%v", got["failed"])
	}
	if _, ok := got["durability_note"]; !ok {
		t.Fatal("the response must name the durability problem, not just flag it")
	}
}

func TestPushSurfacesTetragonsRejectionPerPolicy(t *testing.T) {
	withApplier(t, stubSensors{addErr: errors.New("symbol not found")}, t.TempDir())
	rec := push(t, `{"reason":"r","policies":[{"name":"p","yaml":`+jsonStr(validPolicy)+`}]}`)

	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["ok"] != false {
		t.Fatalf("a rejected policy must not report ok, got %v", got["ok"])
	}
	outcome, _ := got["outcome"].(map[string]any)
	if !strings.Contains(outcome["p"].(string), "symbol not found") {
		t.Fatalf("Tetragon's own words were lost: %v", outcome)
	}
}

func TestPushRefusesNonPost(t *testing.T) {
	withApplier(t, stubSensors{}, t.TempDir())
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handlePolicyPush(rec, httptest.NewRequest(http.MethodGet, "/api/policies/push", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, want 405", rec.Code)
	}
}

func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// The push response names the host the change landed on, and that name is
// resolved lazily by HandleWhoami. Any caller that had not loaded the console
// first got host:"" — including scripts and the audit trail. The browser always
// calls whoami, which is exactly why this survived every UI check.
func TestPushNamesTheHostWithoutRelyingOnWhoami(t *testing.T) {
	withApplier(t, stubSensors{}, t.TempDir())
	rec := push(t, `{"reason":"r","policies":[{"name":"p","yaml":`+jsonStr(validPolicy)+`}]}`)

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["host"] == "" || got["host"] == nil {
		t.Fatal("host is empty — resolveServerIdentity was not called before the response was built")
	}
}
