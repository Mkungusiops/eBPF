package controlplane_test

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
	"github.com/jeffmk/ebpf-poc-engine/internal/controlplane"
	"github.com/jeffmk/ebpf-poc-engine/internal/mtls"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
)

func newCPHTTP(t *testing.T) string {
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
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: cp.HTTP()}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + lis.Addr().String()
}

func postCommand(t *testing.T, base, bearer string, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", base+"/api/admin/command", bytes.NewReader(raw))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestCommandEndpoint(t *testing.T) {
	base := newCPHTTP(t)

	// Authorized admin dispatches a SetMode command → enqueued, command_id back.
	// (No agent is connected, so status stays empty — the enqueue is the assertion.)
	code, out := postCommand(t, base, "admin-secret", map[string]any{
		"tenant": "tenant-a", "agent_id": "agent-x", "set_mode": "detect",
	})
	if code != 200 {
		t.Fatalf("authorized command = %d, want 200", code)
	}
	if id, _ := out["command_id"].(string); id == "" {
		t.Fatalf("no command_id returned: %v", out)
	}

	// Unauthenticated is rejected.
	if code, _ := postCommand(t, base, "", map[string]any{"tenant": "tenant-a", "agent_id": "a", "set_mode": "detect"}); code != http.StatusUnauthorized {
		t.Fatalf("no-auth command = %d, want 401", code)
	}

	// A wrong bearer authenticates as nobody → 401.
	if code, _ := postCommand(t, base, "not-the-token", map[string]any{"tenant": "tenant-a", "agent_id": "a", "set_mode": "detect"}); code != http.StatusUnauthorized {
		t.Fatalf("bad-token command = %d, want 401", code)
	}

	// Missing action is a 400.
	if code, _ := postCommand(t, base, "admin-secret", map[string]any{"tenant": "tenant-a", "agent_id": "a"}); code != http.StatusBadRequest {
		t.Fatalf("no-action command = %d, want 400", code)
	}

	// Missing tenant/agent is a 400.
	if code, _ := postCommand(t, base, "admin-secret", map[string]any{"set_mode": "detect"}); code != http.StatusBadRequest {
		t.Fatalf("missing-target command = %d, want 400", code)
	}

	// Jail with a valid tier enqueues.
	if code, out := postCommand(t, base, "admin-secret", map[string]any{
		"tenant": "tenant-a", "agent_id": "agent-x", "jail": map[string]any{"exec_id": "e", "pid": 7, "tier": "tarpit"},
	}); code != 200 || out["command_id"] == "" {
		t.Fatalf("jail command = %d %v, want 200 + id", code, out)
	}
	// Jail with a bogus tier is rejected.
	if code, _ := postCommand(t, base, "admin-secret", map[string]any{
		"tenant": "tenant-a", "agent_id": "agent-x", "jail": map[string]any{"exec_id": "e", "pid": 7, "tier": "nope"},
	}); code != http.StatusBadRequest {
		t.Fatalf("bad-tier jail = %d, want 400", code)
	}
	// Thaw enqueues.
	if code, out := postCommand(t, base, "admin-secret", map[string]any{
		"tenant": "tenant-a", "agent_id": "agent-x", "thaw": map[string]any{"exec_id": "e", "pid": 7},
	}); code != 200 || out["command_id"] == "" {
		t.Fatalf("thaw command = %d %v, want 200 + id", code, out)
	}

	// whoami advertises the admin's respond capability so the UI can gate actions.
	who := getJSON(t, base+"/api/whoami", "admin-secret")
	if who["can_respond"] != true {
		t.Fatalf("whoami can_respond = %v, want true", who["can_respond"])
	}
}
