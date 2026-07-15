package controlplane_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
	"github.com/jeffmk/ebpf-poc-engine/internal/controlplane"
	"github.com/jeffmk/ebpf-poc-engine/internal/enrollment"
	"github.com/jeffmk/ebpf-poc-engine/internal/mtls"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
)

// TestFleetChokeEndpoints proves the central Fleet/Choke views: an enrolled
// agent sends a heartbeat carrying a choke snapshot, and the tenant-scoped HTTP
// endpoints reflect it — while another tenant sees nothing (isolation).
func TestFleetChokeEndpoints(t *testing.T) {
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
	glis, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = cp.GRPC().Serve(glis) }()
	t.Cleanup(cp.GRPC().Stop)
	hlis, _ := net.Listen("tcp", "127.0.0.1:0")
	hsrv := &http.Server{Handler: cp.HTTP()}
	go func() { _ = hsrv.Serve(hlis) }()
	t.Cleanup(func() { _ = hsrv.Close() })
	httpBase := "http://" + hlis.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Enroll an agent for tenant-a and send a heartbeat with a choke snapshot.
	body := adminReq(t, "POST", httpBase+"/api/admin/enroll-token", "admin-secret", map[string]any{"tenant": "tenant-a"})
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(body["ca_bundle_pem"].(string)))
	boot, _ := grpc.NewClient(glis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(mtls.BootstrapTLSConfig(pool, "127.0.0.1"))))
	en, err := enrollment.Enroll(ctx, boot, body["token"].(string), &ebpfsocv1.AgentInfo{Hostname: "h1", AgentVersion: "0.2.0-agent"})
	boot.Close()
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	cfg, _ := mtls.ClientTLSConfig(en.CertPEM, en.KeyPEM, pool, "127.0.0.1")
	mcc, _ := grpc.NewClient(glis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	defer mcc.Close()
	_, err = ebpfsocv1.NewHeartbeatServiceClient(mcc).Heartbeat(ctx, &ebpfsocv1.HeartbeatRequest{
		AgentInfo:  &ebpfsocv1.AgentInfo{Hostname: "h1", AgentVersion: "0.2.0-agent"},
		DataPlane:  &ebpfsocv1.DataPlaneState{Mode: ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DETECT_ONLY},
		Chokes:     []*ebpfsocv1.ChokeSummary{{Binary: "/usr/bin/curl", State: "throttle", Score: 12, Pid: 42, ExecId: "x"}},
	})
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}

	// Fleet: the agent shows up for tenant-a with a choke_count of 1.
	fleet := getJSON(t, httpBase+"/api/fleet?tenant=tenant-a", "admin-secret")
	if int(fleet["count"].(float64)) != 1 {
		t.Fatalf("fleet count = %v, want 1", fleet["count"])
	}
	agents := fleet["agents"].([]any)
	if a := agents[0].(map[string]any); a["agent_id"] != en.AgentID || int(a["choke_count"].(float64)) != 1 {
		t.Fatalf("fleet agent = %v", a)
	}

	// Choke: the reported choke is visible, scoped to tenant-a.
	choke := getJSON(t, httpBase+"/api/choke?tenant=tenant-a", "admin-secret")
	if int(choke["count"].(float64)) != 1 {
		t.Fatalf("choke count = %v, want 1", choke["count"])
	}
	if c := choke["chokes"].([]any)[0].(map[string]any); c["binary"] != "/usr/bin/curl" || c["state"] != "throttle" {
		t.Fatalf("choke row = %v", c)
	}

	// Isolation: a different tenant sees an empty fleet, and unauth is 401.
	if other := getJSON(t, httpBase+"/api/fleet?tenant=tenant-b", "admin-secret"); int(other["count"].(float64)) != 0 {
		t.Fatalf("tenant-b fleet count = %v, want 0", other["count"])
	}
	req, _ := http.NewRequest("GET", httpBase+"/api/fleet?tenant=tenant-a", nil)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth fleet = %d, want 401", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func getJSON(t *testing.T, url, bearer string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s = %d", url, resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}
