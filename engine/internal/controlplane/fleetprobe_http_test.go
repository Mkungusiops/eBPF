package controlplane_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
	"github.com/jeffmk/ebpf-poc-engine/internal/controlplane"
	"github.com/jeffmk/ebpf-poc-engine/internal/mtls"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
)

// cpProbeServer stands up a control plane with only the HTTP surface wired,
// which is all /api/fleet/probe needs.
func cpProbeServer(t *testing.T) string {
	t.Helper()
	ca, err := mtls.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	signer, _, _ := signing.GenerateKey()
	cs, err := centralstore.Open(filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	cp, err := controlplane.New(controlplane.Config{
		CA: ca, ServerName: "127.0.0.1", FleetSigner: signer, FleetKeyID: "k",
		Store: cs, AdminToken: "admin-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	hlis, _ := net.Listen("tcp", "127.0.0.1:0")
	hsrv := &http.Server{Handler: cp.HTTP()}
	go func() { _ = hsrv.Serve(hlis) }()
	t.Cleanup(func() { _ = hsrv.Close() })
	return "http://" + hlis.Addr().String()
}

func postProbe(t *testing.T, base, token string, urls []string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"urls": urls})
	req, _ := http.NewRequest(http.MethodPost, base+"/api/fleet/probe?tenant=tenant-a", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m
}

// The probe reaches out from the control plane, so it must never be anonymous.
func TestFleetProbeRequiresAuth(t *testing.T) {
	base := cpProbeServer(t)
	if status, _ := postProbe(t, base, "", []string{"http://example.invalid/"}); status != http.StatusUnauthorized {
		t.Fatalf("want 401 without a token, got %d", status)
	}
}

// The end the operator sees: a peer on a different origin — exactly the
// console/engine split that the browser-side probe could not resolve — is
// reported UP even though it answers 401 to an unauthenticated caller.
func TestFleetProbeReportsCrossOriginPeerUp(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
	}))
	defer peer.Close()

	status, body := postProbe(t, cpProbeServer(t), "admin-secret", []string{peer.URL})
	if status != http.StatusOK {
		t.Fatalf("want 200, got %d (%v)", status, body)
	}
	hosts, _ := body["hosts"].([]any)
	if len(hosts) != 1 {
		t.Fatalf("want 1 host result, got %v", body["hosts"])
	}
	row, _ := hosts[0].(map[string]any)
	if reachable, _ := row["reachable"].(bool); !reachable {
		t.Fatalf("cross-origin peer should be reachable, got %v", row)
	}
}

// The SSRF guard has to hold at the HTTP boundary, not only in the package.
func TestFleetProbeRefusesMetadataAddressOverHTTP(t *testing.T) {
	_, body := postProbe(t, cpProbeServer(t), "admin-secret", []string{"http://169.254.169.254/latest/meta-data/"})
	hosts, _ := body["hosts"].([]any)
	if len(hosts) != 1 {
		t.Fatalf("want 1 host result, got %v", body["hosts"])
	}
	row, _ := hosts[0].(map[string]any)
	if reachable, _ := row["reachable"].(bool); reachable {
		t.Fatal("instance metadata must never be reported reachable")
	}
	if msg, _ := row["error"].(string); !strings.Contains(msg, "link-local") {
		t.Errorf("want a link-local refusal, got %q", msg)
	}
}
