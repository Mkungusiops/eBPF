package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// /api/run-attack executes a script AS ROOT on the host this binary is
// defending. It must not be reachable on a deployment that did not ask for it.
func TestLabSurfacesAre404WhenLabModeIsOff(t *testing.T) {
	prev := LabMode
	LabMode = false
	t.Cleanup(func() { LabMode = prev })

	s := &Server{}
	called := false
	h := s.labOnly(func(http.ResponseWriter, *http.Request) { called = true })

	for _, path := range []string{"/api/attacks", "/api/run-attack", "/api/honeypots"} {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest("GET", path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s -> %d, want 404 with lab mode off", path, w.Code)
		}
	}
	if called {
		t.Fatal("the handler ran with lab mode off — this one can execute code as root")
	}
}

// 404 rather than 403: a 403 confirms the endpoint exists, which is a hint
// worth withholding on a surface that runs commands.
func TestLabGateDoesNotAdvertiseTheEndpoint(t *testing.T) {
	prev := LabMode
	LabMode = false
	t.Cleanup(func() { LabMode = prev })

	s := &Server{}
	w := httptest.NewRecorder()
	s.labOnly(func(http.ResponseWriter, *http.Request) {})(w, httptest.NewRequest("POST", "/api/run-attack", nil))
	if w.Code == http.StatusForbidden {
		t.Fatal("403 confirms the endpoint exists; use 404")
	}
}

// It must still work in a lab — the e2e suite and demos depend on it.
func TestLabSurfacesWorkWhenLabModeIsOn(t *testing.T) {
	prev := LabMode
	LabMode = true
	t.Cleanup(func() { LabMode = prev })

	s := &Server{}
	called := false
	w := httptest.NewRecorder()
	s.labOnly(func(http.ResponseWriter, *http.Request) { called = true })(w, httptest.NewRequest("GET", "/api/attacks", nil))
	if !called {
		t.Fatal("lab mode on: the handler must run")
	}
}

// The default must be off. A build that ships with it on would put a
// root-privileged attack runner on every customer estate.
func TestLabModeDefaultsOff(t *testing.T) {
	if LabMode {
		t.Fatal("LabMode must default to false")
	}
}
