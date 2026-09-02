package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
)

func operatorAuditServer(t *testing.T) *Server {
	t.Helper()
	s := &Server{registry: heartbeat.NewRegistry(), auditor: authz.NewMemAuditor()}
	s.cfg.Logf = func(string, ...any) {}
	s.cfg.AdminToken = "admin-secret"
	return s
}

// Without a durable store, the honest answer is "not supported" — never an
// empty list. An empty access trail reads as "nobody accessed anything", which
// is the one conclusion a memory ring erased by the last restart cannot support.
func TestOperatorAuditSaysSoWhenThereIsNoDurableTrail(t *testing.T) {
	s := operatorAuditServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/operator-audit", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	w := httptest.NewRecorder()
	s.handleOperatorAudit(w, req)

	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["supported"] != false {
		t.Fatalf("supported=%v, want false with no durable store", got["supported"])
	}
	if d, _ := got["detail"].(string); d == "" {
		t.Fatal("no detail explaining why the trail is unavailable")
	}
}

func TestOperatorAuditRefusesAnUnauthenticatedRead(t *testing.T) {
	s := operatorAuditServer(t)
	w := httptest.NewRecorder()
	s.handleOperatorAudit(w, httptest.NewRequest(http.MethodGet, "/api/operator-audit", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401 — the access trail names other tenants", w.Code)
	}
}

// The route must be registered. An endpoint that builds, tests, and is never
// mounted is this codebase's recurring defect shape in its purest form.
func TestOperatorAuditRouteIsMounted(t *testing.T) {
	s := operatorAuditServer(t)
	mux, ok := s.buildHTTP().(*http.ServeMux)
	if !ok {
		t.Skip("buildHTTP no longer returns a ServeMux")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/operator-audit", nil)
	if _, pattern := mux.Handler(req); pattern != "/api/operator-audit" {
		t.Fatalf("matched %q, want the operator-audit route", pattern)
	}
}
