package controlplane_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
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
	storepkg "github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/uplink"
)

// TestControlPlaneEnrollIngestRead is the Phase-1 vertical proof through the
// ASSEMBLED control plane: an operator mints a token over HTTP → an agent
// enrolls over mTLS gRPC → streams telemetry → the operator reads it back
// tenant-scoped over HTTP. Two tenants stay partitioned end to end.
func TestControlPlaneEnrollIngestRead(t *testing.T) {
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

	grpcLis, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = cp.GRPC().Serve(grpcLis) }()
	t.Cleanup(cp.GRPC().Stop)
	httpLis, _ := net.Listen("tcp", "127.0.0.1:0")
	httpSrv := &http.Server{Handler: cp.HTTP()}
	go func() { _ = httpSrv.Serve(httpLis) }()
	t.Cleanup(func() { _ = httpSrv.Close() })

	grpcAddr := grpcLis.Addr().String()
	httpBase := "http://" + httpLis.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Operator mints a token (HTTP admin), agent enrolls (mTLS gRPC).
	enrollAgent := func(tenant string) *enrollment.Enrolled {
		body := adminReq(t, "POST", httpBase+"/api/admin/enroll-token", "admin-secret", map[string]any{"tenant": tenant})
		token, _ := body["token"].(string)
		caPEM, _ := body["ca_bundle_pem"].(string)
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(caPEM))
		cc, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(credentials.NewTLS(mtls.BootstrapTLSConfig(pool, "127.0.0.1"))))
		if err != nil {
			t.Fatal(err)
		}
		defer cc.Close()
		en, err := enrollment.Enroll(ctx, cc, token, &ebpfsocv1.AgentInfo{Hostname: "h-" + tenant})
		if err != nil {
			t.Fatalf("enroll %s: %v", tenant, err)
		}
		return en
	}

	stream := func(en *enrollment.Enrolled, n int) {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(en.CABundlePEM)
		cfg, _ := mtls.ClientTLSConfig(en.CertPEM, en.KeyPEM, pool, "127.0.0.1")
		cc, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
		if err != nil {
			t.Fatal(err)
		}
		defer cc.Close()
		buf := uplink.NewBuffer()
		for i := 1; i <= n; i++ {
			buf.Enqueue(uplink.EventRecord(&storepkg.Event{ID: int64(i), ExecID: fmt.Sprintf("e-%d", i)}))
		}
		if err := uplink.DrainOnce(ctx, ebpfsocv1.NewTelemetryServiceClient(cc), buf, 10); err != nil {
			t.Fatalf("drain: %v", err)
		}
	}

	readCount := func(tenant string) int {
		body := adminReq(t, "GET", httpBase+"/api/telemetry?tenant="+tenant, "admin-secret", nil)
		n, _ := body["count"].(float64)
		return int(n)
	}

	// Two tenants, separate agents, identical record keys → separate partitions.
	stream(enrollAgent("tenant-a"), 2)
	stream(enrollAgent("tenant-b"), 1)

	if got := readCount("tenant-a"); got != 2 {
		t.Fatalf("tenant-a read = %d, want 2", got)
	}
	if got := readCount("tenant-b"); got != 1 {
		t.Fatalf("tenant-b read = %d, want 1", got)
	}

	// whoami reflects the admin (cross-tenant) principal.
	who := adminReq(t, "GET", httpBase+"/api/whoami", "admin-secret", nil)
	if who["cross_tenant"] != true {
		t.Fatalf("whoami cross_tenant = %v, want true", who["cross_tenant"])
	}

	// Unauthenticated read is rejected.
	if r, _ := http.Get(httpBase + "/api/telemetry?tenant=tenant-a"); r == nil || r.StatusCode != 401 { //nolint:bodyclose // status-only probe
		t.Fatalf("unauthenticated read status = %v, want 401", r.StatusCode)
	}
}

func adminReq(t *testing.T, method, url, token string, body any) map[string]any {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("%s %s -> %d: %s", method, url, resp.StatusCode, data)
	}
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	return m
}
