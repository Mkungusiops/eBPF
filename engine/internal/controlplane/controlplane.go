// Package controlplane assembles the proven Phase-1 packages into a running,
// single-node multi-tenant control plane: the agent-facing mTLS gRPC services
// (enrollment, tenant-stamped ingest → central store, command dispatch,
// heartbeat, fleet policy distribution) plus an operator HTTP API (health, a
// tenant-scoped read surface, and enrollment-token minting) gated by authz.
//
// It is the concrete realization of architecture.md §3 — every isolation layer
// is enforced here: tenant is derived from the agent's mTLS cert (Layer 1),
// stamped at ingest (Layer 2), stored tenant-partitioned (Layer 3), and read
// only through an authz decision (Layer 4).
package controlplane

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/bff"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
	"github.com/jeffmk/ebpf-poc-engine/internal/command"
	"github.com/jeffmk/ebpf-poc-engine/internal/enrollment"
	"github.com/jeffmk/ebpf-poc-engine/internal/fleet"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
	"github.com/jeffmk/ebpf-poc-engine/internal/mtls"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
)

// Config wires the control plane. CA, FleetSigner and Store are constructed by
// the caller (cmd/controlplane) so their lifecycle/persistence is its concern.
type Config struct {
	CA          *mtls.CA
	ServerName  string // gRPC cert SAN — the host/IP agents connect to
	FleetSigner signing.Signer
	FleetKeyID  string
	Store       centralstore.TenantStore // ingest sink + operator read source
	// Firehose, when set, receives a best-effort mirror of every ingested
	// record (e.g. ClickHouse for the high-volume events firehose + retention),
	// while Store stays the authoritative read source. nil = single-store.
	Firehose ingest.Sink

	CertTTL   time.Duration // issued agent-cert lifetime
	EnrollTTL time.Duration // bootstrap-token lifetime

	UplinkEndpoint  string // advertised to agents in the enroll response
	CommandEndpoint string

	// Operator auth: exactly one path is used. If BFF is set, HTTP identity comes
	// from the OIDC session; otherwise AdminToken (a bearer) maps to an msoc-admin
	// principal for headless/dev use.
	BFF        *bff.Handler
	AdminToken string

	Logf func(string, ...any)
}

// Server is an assembled control plane.
type Server struct {
	cfg        Config
	ca         *mtls.CA
	gs         *grpc.Server
	httpH      http.Handler
	tokens     *enrollment.TokenStore
	fleet      *fleet.Service
	registry   *heartbeat.Registry
	dispatcher *command.Dispatcher
	auditor    *authz.MemAuditor
}

// New builds the gRPC + HTTP surfaces. It does not listen; call Serve (or drive
// GRPC()/HTTP() directly, e.g. in tests).
func New(cfg Config) (*Server, error) {
	if cfg.CA == nil {
		return nil, errors.New("controlplane: CA required")
	}
	if cfg.Store == nil {
		return nil, errors.New("controlplane: store required")
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.CertTTL == 0 {
		cfg.CertTTL = 90 * 24 * time.Hour
	}
	if cfg.EnrollTTL == 0 {
		cfg.EnrollTTL = 15 * time.Minute
	}
	if cfg.ServerName == "" {
		cfg.ServerName = "localhost"
	}

	serverCertPEM, serverKeyPEM, err := cfg.CA.IssueServer(cfg.ServerName, cfg.CertTTL)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := mtls.ServerTLSConfigVerifyOptional(serverCertPEM, serverKeyPEM, cfg.CA.Pool())
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:        cfg,
		ca:         cfg.CA,
		tokens:     enrollment.NewTokenStore(),
		fleet:      fleet.NewService(cfg.FleetSigner, cfg.FleetKeyID),
		registry:   heartbeat.NewRegistry(),
		dispatcher: command.NewDispatcher(cfg.FleetSigner, time.Minute),
		auditor:    authz.NewMemAuditor(),
	}

	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	ebpfsocv1.RegisterEnrollmentServiceServer(gs, enrollment.NewServer(cfg.CA, s.tokens, cfg.CertTTL, cfg.UplinkEndpoint, cfg.CommandEndpoint))
	// Store satisfies ingest.Sink; when a firehose is configured, fan out to it.
	var telemetrySink ingest.Sink = cfg.Store
	if cfg.Firehose != nil {
		telemetrySink = ingest.NewFanOut(cfg.Store, cfg.Logf, cfg.Firehose)
	}
	ebpfsocv1.RegisterTelemetryServiceServer(gs, ingest.NewServer(telemetrySink))
	ebpfsocv1.RegisterCommandServiceServer(gs, s.dispatcher)
	ebpfsocv1.RegisterHeartbeatServiceServer(gs, heartbeat.NewServer(s.registry, 30*time.Second))
	ebpfsocv1.RegisterPolicyServiceServer(gs, fleet.NewPolicyServer(s.fleet))
	s.gs = gs
	s.httpH = s.buildHTTP()
	return s, nil
}

// GRPC is the agent-facing mTLS gRPC server.
func (s *Server) GRPC() *grpc.Server { return s.gs }

// HTTP is the operator HTTP handler.
func (s *Server) HTTP() http.Handler { return s.httpH }

// CABundlePEM is the trust anchor agents pin.
func (s *Server) CABundlePEM() []byte { return s.ca.CertPEM() }

// Tokens is the enrollment token store (operators mint via the HTTP admin API).
func (s *Server) Tokens() *enrollment.TokenStore { return s.tokens }

// Fleet is the policy-bundle / rollout service.
func (s *Server) Fleet() *fleet.Service { return s.fleet }

// Serve listens on grpcAddr (mTLS) and httpAddr and runs until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, grpcAddr, httpAddr string) error {
	grpcLis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return err
	}
	httpLis, err := net.Listen("tcp", httpAddr)
	if err != nil {
		_ = grpcLis.Close()
		return err
	}
	httpSrv := &http.Server{Handler: s.httpH, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 2)
	go func() { errc <- s.gs.Serve(grpcLis) }()
	go func() { errc <- httpSrv.Serve(httpLis) }()
	s.cfg.Logf("[controlplane] gRPC(mTLS)=%s http=%s", grpcLis.Addr(), httpLis.Addr())

	select {
	case <-ctx.Done():
		s.gs.GracefulStop()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
		return ctx.Err()
	case err := <-errc:
		s.gs.Stop()
		_ = httpSrv.Close()
		return err
	}
}
